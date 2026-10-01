/*
 * Minimal DPDK primary for validating the cpworker `dpdk` feature against a
 * real port (cloud-probe-rs-1eu).
 *
 * The production deployment runs an external primary (Netis's capture daemon,
 * or `testpmd`); the cpworker DPDK capturer is the *secondary*. This program is
 * the smallest primary that exercises the same contract:
 *
 *   1. EAL init on a given port,
 *   2. `rte_pdump_init()` so the primary registers the `mp_pdump` server,
 *   3. an `rte_eth_rx_burst()` loop so RX pdump has frames to deliver.
 *
 * RX pdump clones every packet inside the RX callback, so the primary's RX
 * throughput is what bounds a pdump secondary. A single queue on a single lcore
 * therefore caps capture far below line rate; this program runs one lcore per RX
 * queue (RSS spreads the flow) so a multi-queue benchmark is representative.
 *
 * Build (must match the DPDK the cpworker secondary links):
 *
 *   cc -O2 primary.c -o dpdk_primary $(pkg-config --cflags --libs libdpdk)
 *
 * Usage (as root, after hugepages are set up):
 *
 *   ./dpdk_primary -l 4-7 -a 0000:b8:00.1
 *
 * Environment:
 *   PRIMARY_RXQ   RX queues (default 1). Needs ~one worker lcore each for the
 *                 queue to be polled in parallel; the master handles any
 *                 remainder in a round-robin loop.
 *   PRIMARY_MBUF  mbuf pool size (default 65536).
 *   PRIMARY_DESC  RX descriptors per queue (default 4096).
 *   PRIMARY_STATS Write cumulative RX/pdump counters to this JSON path.
 *   PRIMARY_TOUCH Read packet bytes in the RX worker (presence enables it).
 *   PRIMARY_PCAP  In-process pcap writer: /dev/null or a local file prefix.
 *   PRIMARY_INSPECT Count external-buffer and multi-segment packets.
 *
 * It prints the probed port's driver and MAC, per-second RX totals while it
 * polls, and a final `rx total` on SIGINT/SIGTERM.
 */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pdump.h>

#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#define BURST 64
#define MAX_LQUEUE 256

static volatile int g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }

/* Per-queue RX totals, sampled by the master without racing queue workers. */
/* Keep diagnostic writes from bouncing one cache line between RX lcores. */
struct rx_counter {
    _Alignas(64) _Atomic unsigned long packets;
    _Atomic unsigned long external;
    _Atomic unsigned long scattered;
};
static struct rx_counter g_rx[MAX_LQUEUE];
static FILE *g_pcap[MAX_LQUEUE];
static int g_touch;
static int g_inspect;
static volatile uint64_t g_checksums[MAX_LQUEUE];

/* Validate that MPRQ delivered externally attached DMA buffers, rather than
 * its optional small-packet memcpy path. Opt in with PRIMARY_INSPECT=1. */
static void inspect_burst(uint16_t q, struct rte_mbuf **bufs, uint16_t n) {
    unsigned external = 0, scattered = 0;
    for (uint16_t i = 0; i < n; i++) {
        external += RTE_MBUF_HAS_EXTBUF(bufs[i]) != 0;
        scattered += bufs[i]->nb_segs != 1;
    }
    atomic_fetch_add_explicit(&g_rx[q].external, external, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_rx[q].scattered, scattered, memory_order_relaxed);
}

/* Optional in-process capture: original RX mbufs, no pdump clone or ring.
 * Each queue owns its writer. PRIMARY_PCAP=/dev/null measures serialization;
 * a filename prefix measures buffered filesystem writes (not durable I/O).
 * PRIMARY_TOUCH=1 reads packet bytes without writing them. */
static void capture_burst(uint16_t q, struct rte_mbuf **bufs, uint16_t n) {
    struct timeval tv;
    if (g_pcap[q] != NULL) gettimeofday(&tv, NULL);
    uint64_t sum = g_checksums[q];
    for (uint16_t i = 0; i < n; i++) {
        struct rte_mbuf *m = bufs[i];
        if (g_touch) {
            const unsigned char *p = rte_pktmbuf_mtod(m, const unsigned char *);
            for (uint16_t j = 0; j < m->data_len; j += 8) sum += p[j];
        }
        if (g_pcap[q] != NULL) {
            uint32_t hdr[4] = {tv.tv_sec, tv.tv_usec, m->pkt_len, m->pkt_len};
            if (fwrite(hdr, sizeof(hdr), 1, g_pcap[q]) != 1) g_stop = 1;
            for (struct rte_mbuf *seg = m; seg != NULL; seg = seg->next) {
                if (fwrite(rte_pktmbuf_mtod(seg, void *), seg->data_len, 1,
                           g_pcap[q]) != 1) g_stop = 1;
            }
        }
    }
    if (g_touch) g_checksums[q] = sum;
}

/* Atomic file replacement gives the controller a consistent cumulative
 * snapshot. DPDK accepted counts successful copies before ring enqueue;
 * delivered = accepted - ringfull, not accepted itself. */
static void report_stats(uint16_t nq) {
    const char *path = getenv("PRIMARY_STATS");
    if (path == NULL) return;
    char tmp[1024];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) return;
    FILE *f = fopen(tmp, "w");
    if (f == NULL) return;
    struct rte_pdump_stats pd = {0};
    struct rte_eth_stats eth = {0};
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    rte_pdump_stats(0, &pd);
    rte_eth_stats_get(0, &eth);
    unsigned long total = 0, external = 0, scattered = 0;
    for (uint16_t q = 0; q < nq; q++) {
        total += atomic_load(&g_rx[q].packets);
        external += atomic_load(&g_rx[q].external);
        scattered += atomic_load(&g_rx[q].scattered);
    }
    fprintf(f, "{\"time\":%.9f,\"rx\":%lu,\"accepted\":%lu,"
            "\"ringfull\":%lu,\"nombuf\":%lu,\"filtered\":%lu,"
            "\"imissed\":%lu,\"rx_nombuf\":%lu,\"external\":%lu,\"scattered\":%lu,\"queues\":[",
            ts.tv_sec + ts.tv_nsec / 1e9, total,
            (unsigned long)pd.accepted, (unsigned long)pd.ringfull,
            (unsigned long)pd.nombuf, (unsigned long)pd.filtered,
            (unsigned long)eth.imissed, (unsigned long)eth.rx_nombuf, external, scattered);
    for (uint16_t q = 0; q < nq; q++)
        fprintf(f, "%s%lu", q ? "," : "", atomic_load(&g_rx[q].packets));
    fprintf(f, "]}\n");
    fclose(f);
    rename(tmp, path);
}

static int rx_worker(void *arg) {
    uint16_t q = (uint16_t)(uintptr_t)arg;
    struct rte_mbuf *bufs[BURST];
    while (!g_stop) {
        uint16_t n = rte_eth_rx_burst(0, q, bufs, BURST);
        if (n != 0) {
            atomic_fetch_add_explicit(&g_rx[q].packets, n, memory_order_relaxed);
            if (g_inspect) inspect_burst(q, bufs, n);
            if (g_touch || g_pcap[q] != NULL) capture_burst(q, bufs, n);
            rte_pktmbuf_free_bulk(bufs, n);
        }
    }
    return 0;
}

static unsigned long rx_sum(uint16_t nq) {
    unsigned long s = 0;
    for (uint16_t q = 0; q < nq; q++) s += atomic_load_explicit(&g_rx[q].packets, memory_order_relaxed);
    return s;
}

int main(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0) {
        fprintf(stderr, "dpdk_primary: EAL init failed\n");
        return 1;
    }
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    uint16_t nq = getenv("PRIMARY_RXQ") ? (uint16_t)atoi(getenv("PRIMARY_RXQ")) : 1;
    if (nq < 1) nq = 1;
    if (nq > MAX_LQUEUE) nq = MAX_LQUEUE;
    g_touch = getenv("PRIMARY_TOUCH") != NULL;
    g_inspect = getenv("PRIMARY_INSPECT") != NULL;
    const char *pcap = getenv("PRIMARY_PCAP");
    if (pcap != NULL) {
        for (uint16_t q = 0; q < nq; q++) {
            char path[1024];
            if (strcmp(pcap, "/dev/null") == 0) snprintf(path, sizeof(path), "%s", pcap);
            else snprintf(path, sizeof(path), "%s-q%u.pcap", pcap, q);
            g_pcap[q] = fopen(path, "wb");
            if (g_pcap[q] == NULL) { perror(path); return 1; }
            setvbuf(g_pcap[q], NULL, _IOFBF, 1024 * 1024);
            const uint32_t header[6] = {0xa1b2c3d4, 0x00040002, 0, 0, 65535, 1};
            if (fwrite(header, sizeof(header), 1, g_pcap[q]) != 1) return 1;
        }
    }
    unsigned nb_mbuf = getenv("PRIMARY_MBUF") ? (unsigned)atol(getenv("PRIMARY_MBUF")) : 65536;
    uint16_t rx_desc = getenv("PRIMARY_DESC") ? (uint16_t)atoi(getenv("PRIMARY_DESC")) : 4096;

    uint16_t port = 0;
    struct rte_eth_dev_info info;
    memset(&info, 0, sizeof(info));
    if (rte_eth_dev_info_get(port, &info) != 0) {
        fprintf(stderr, "dpdk_primary: no port %u\n", port);
        return 1;
    }

    struct rte_mempool *mp = rte_pktmbuf_pool_create(
        "FIELD_PRIMARY_MBUF", nb_mbuf, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
        (int)rte_socket_id());
    if (mp == NULL) {
        fprintf(stderr, "dpdk_primary: mempool create failed\n");
        return 1;
    }

    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    // Without RSS the PMD delivers every frame to queue 0, so extra queues
    // never help. Enable RSS (clamped to what the PMD advertises) whenever
    // more than one queue is requested.
    if (nq > 1) {
        uint64_t rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP;
        rss_hf &= info.flow_type_rss_offloads;
        if (rss_hf != 0) {
            conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
            conf.rx_adv_conf.rss_conf.rss_hf = rss_hf;
        } else {
            fprintf(stderr, "dpdk_primary: PMD advertises no RSS offloads\n");
        }
    }
    if (rte_eth_dev_configure(port, nq, nq, &conf) < 0) {
        fprintf(stderr, "dpdk_primary: configure %u queues failed\n", nq);
        return 1;
    }
    for (uint16_t q = 0; q < nq; q++) {
        if (rte_eth_rx_queue_setup(port, q, rx_desc, rte_eth_dev_socket_id(port),
                                   NULL, mp) < 0) {
            fprintf(stderr, "dpdk_primary: rx queue %u setup failed\n", q);
            return 1;
        }
    }
    if (rte_eth_dev_start(port) < 0) {
        fprintf(stderr, "dpdk_primary: dev start failed\n");
        return 1;
    }
    rte_eth_promiscuous_enable(port);

    if (rte_pdump_init() < 0) {
        fprintf(stderr, "dpdk_primary: rte_pdump_init failed\n");
        return 1;
    }

    struct rte_ether_addr mac;
    rte_eth_macaddr_get(port, &mac);
    fprintf(stderr,
            "dpdk_primary: port=%u driver=%s mac=%02x:%02x:%02x:%02x:%02x:%02x "
            "queues=%u pdump_init=ok polling\n",
            port, info.driver_name ? info.driver_name : "?", mac.addr_bytes[0],
            mac.addr_bytes[1], mac.addr_bytes[2], mac.addr_bytes[3],
            mac.addr_bytes[4], mac.addr_bytes[5], nq);
    fflush(stderr);

    /* One worker lcore per queue where available. */
    unsigned workers[MAX_LQUEUE];
    int nw = 0;
    unsigned lcore;
    RTE_LCORE_FOREACH_WORKER(lcore) {
        if (nw >= nq) break;
        workers[nw++] = lcore;
    }
    for (int i = 0; i < nw; i++) {
        if (rte_eal_remote_launch(rx_worker, (void *)(uintptr_t)i, workers[i]) != 0) {
            fprintf(stderr, "dpdk_primary: failed to launch lcore %u\n", workers[i]);
            return 1;
        }
    }
    fprintf(stderr, "dpdk_primary: workers=%d/%u (master polls the rest)\n", nw, nq);
    fflush(stderr);

    /* Master polls any queue without a dedicated worker, round-robin. */
    struct rte_mbuf *bufs[BURST];
    unsigned long master_total = 0;
    uint16_t q = (uint16_t)nw;
    time_t last = time(NULL);
    unsigned long last_sum = 0;
    while (!g_stop) {
        if (nw < nq) {
            uint16_t n = rte_eth_rx_burst(port, q, bufs, BURST);
            if (n != 0) {
                master_total += n;
                atomic_fetch_add_explicit(&g_rx[q].packets, n, memory_order_relaxed);
                if (g_inspect) inspect_burst(q, bufs, n);
                if (g_touch || g_pcap[q] != NULL) capture_burst(q, bufs, n);
                rte_pktmbuf_free_bulk(bufs, n);
            }
            if (++q >= nq) q = (uint16_t)nw;
        } else {
            struct timespec ts = {0, 1000000}; /* 1 ms when master idles */
            nanosleep(&ts, NULL);
        }
        time_t now = time(NULL);
        if (now != last) {
            unsigned long s = rx_sum(nq);
            fprintf(stderr, "dpdk_primary: rx %lu pps (rx total %lu)\n",
                    s - last_sum, s);
            fflush(stderr);
            report_stats(nq);
            last = now;
            last_sum = s;
        }
    }

    g_stop = 1;
    rte_eal_mp_wait_lcore();
    report_stats(nq);
    for (uint16_t i = 0; i < nq; i++) if (g_pcap[i] != NULL) fclose(g_pcap[i]);
    fprintf(stderr, "dpdk_primary: rx total %lu (master %lu)\n", rx_sum(nq),
            master_total);

    rte_eth_dev_stop(port);
    rte_eth_dev_close(port);
    rte_pdump_uninit();
    return 0;
}
