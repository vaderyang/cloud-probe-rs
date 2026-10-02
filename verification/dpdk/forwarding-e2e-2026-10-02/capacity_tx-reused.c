/* Paced, short 64-byte UDP lab traffic. Template mbufs retain payload on reuse.
 * Build against the generator's installed DPDK, outside any product binary.
 * CAP_TX_MPPS, CAP_TX_SECONDS, CAP_TX_QUEUES control aggregate offered traffic.
 */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_cycles.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXQ 16
#define BURST 32
static struct rte_mempool *pools[MAXQ];
static unsigned nq;
static double mpps;
static uint64_t start_tsc, end_tsc;
static volatile sig_atomic_t stop_flag;
static _Atomic uint64_t sent[MAXQ];
static struct rte_ether_addr src;
static const struct rte_ether_addr dst = {{0x1a,0xca,0x0a,0x26,0xa8,0x8c}};

static void stop(int s) { (void)s; stop_flag = 1; }

static void template(struct rte_mempool *mp, void *arg, void *obj, unsigned idx) {
    (void)mp;
    unsigned q = (unsigned)(uintptr_t)arg;
    struct rte_mbuf *m = obj;
    unsigned char *data = rte_pktmbuf_mtod(m, unsigned char *);
    memset(data, 0, 64);
    struct rte_ether_hdr *eth = (void *)data;
    eth->src_addr = src;
    eth->dst_addr = dst;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    struct rte_ipv4_hdr *ip = (void *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->total_length = rte_cpu_to_be_16(50);
    ip->time_to_live = 64;
    ip->next_proto_id = 17;
    ip->src_addr = rte_cpu_to_be_32(0x0a02000c);
    ip->dst_addr = rte_cpu_to_be_32(0x0a02000b);
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    struct rte_udp_hdr *udp = (void *)(ip + 1);
    udp->src_port = rte_cpu_to_be_16(1024 + ((idx + q * 4096) % 60000));
    udp->dst_port = rte_cpu_to_be_16(49001);
    udp->dgram_len = rte_cpu_to_be_16(30);
}

static int transmit(void *arg) {
    unsigned q = (unsigned)(uintptr_t)arg;
    struct rte_mbuf *bufs[BURST];
    uint64_t now;
    while (!stop_flag && (now = rte_rdtsc()) < start_tsc) rte_pause();
    double interval = (double)rte_get_tsc_hz() * BURST * nq / (mpps * 1e6);
    double next = start_tsc;
    uint64_t total = 0;
    while (!stop_flag && (now = rte_rdtsc()) < end_tsc) {
        if ((double)now < next) { rte_pause(); continue; }
        /* Avoid a catch-up flood after scheduler preemption. */
        if ((double)now > next + 2 * interval) next = now;
        if (rte_pktmbuf_alloc_bulk(pools[q], bufs, BURST) != 0) continue;
        for (unsigned i = 0; i < BURST; i++) {
            bufs[i]->data_len = 64;
            bufs[i]->pkt_len = 64;
        }
        unsigned n = rte_eth_tx_burst(0, q, bufs, BURST);
        for (unsigned i = n; i < BURST; i++) rte_pktmbuf_free(bufs[i]);
        total += n;
        next += interval;
        atomic_store_explicit(&sent[q], total, memory_order_relaxed);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0) return 1;
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    nq = getenv("CAP_TX_QUEUES") ? atoi(getenv("CAP_TX_QUEUES")) : 4;
    mpps = getenv("CAP_TX_MPPS") ? atof(getenv("CAP_TX_MPPS")) : 1;
    double seconds = getenv("CAP_TX_SECONDS") ? atof(getenv("CAP_TX_SECONDS")) : 12;
    if (nq < 1 || nq > MAXQ || mpps <= 0 || seconds <= 0) return 2;
    struct rte_eth_conf conf = {0};
    if (rte_eth_dev_configure(0, 1, nq, &conf) < 0) return 3;
    rte_eth_macaddr_get(0, &src);
    for (unsigned q = 0; q < nq; q++) {
        char name[32];
        snprintf(name, sizeof(name), "CAP_TX_POOL_%u", q);
        pools[q] = rte_pktmbuf_pool_create(name, 16383, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if (!pools[q]) return 4;
        rte_mempool_obj_iter(pools[q], template, (void *)(uintptr_t)q);
        if (rte_eth_tx_queue_setup(0, q, 2048, rte_socket_id(), NULL) < 0) return 5;
    }
    if (rte_eth_rx_queue_setup(0, 0, 1024, rte_socket_id(), NULL, pools[0]) < 0) return 6;
    if (rte_eth_dev_start(0) < 0) return 7;
    start_tsc = rte_rdtsc() + rte_get_tsc_hz();
    end_tsc = start_tsc + seconds * rte_get_tsc_hz();
    unsigned q = 0, core;
    RTE_LCORE_FOREACH_WORKER(core) {
        if (q == nq) break;
        rte_eal_remote_launch(transmit, (void *)(uintptr_t)q++, core);
    }
    if (q != nq) { fprintf(stderr, "need %u worker lcores\n", nq); stop_flag = 1; return 8; }
    fprintf(stderr, "CAP_TX_READY queues=%u target_mpps=%.3f seconds=%.3f\n", nq, mpps, seconds);
    fflush(stderr);
    rte_eal_mp_wait_lcore();
    uint64_t total = 0;
    for (q = 0; q < nq; q++) total += atomic_load(&sent[q]);
    fprintf(stderr, "CAP_TX_DONE total=%lu\n", (unsigned long)total);
    rte_eth_dev_stop(0);
    rte_eth_dev_close(0);
    rte_eal_cleanup();
    return 0;
}
