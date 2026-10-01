/* Benchmark-only pdump consumer controls: shared MC ring versus one SC ring
 * and pool per RX queue. Every delivered mbuf is counted and freed exactly
 * once. This bounds transport cost; it is not a product output benchmark. */
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_pdump.h>
#include <rte_pcapng.h>
#include <rte_ring.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static volatile sig_atomic_t quit;
static struct rte_ring *rings[16];
static struct rte_mempool *pools[16];
struct counter { _Atomic unsigned long packets; char pad[56]; };
static struct counter counts[16];
static int per_queue;
static void stop(int signum) { (void)signum; quit = 1; }

static int drain(void *arg) {
    unsigned id = (uintptr_t)arg;
    struct rte_ring *ring = rings[per_queue ? id : 0];
    struct rte_mbuf *bufs[64];
    while (!quit) {
        unsigned n = per_queue ? rte_ring_sc_dequeue_burst(ring, (void **)bufs, 64, NULL)
                               : rte_ring_mc_dequeue_burst(ring, (void **)bufs, 64, NULL);
        if (n != 0) {
            atomic_fetch_add_explicit(&counts[id].packets, n, memory_order_relaxed);
            rte_pktmbuf_free_bulk(bufs, n);
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0 || rte_pdump_init() < 0) return 1;
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    unsigned nc = getenv("PERF_CONSUMERS") ? atoi(getenv("PERF_CONSUMERS")) : 1;
    unsigned size = getenv("PERF_RING") ? atoi(getenv("PERF_RING")) : 2048;
    unsigned cache = getenv("PERF_CACHE") ? atoi(getenv("PERF_CACHE")) : 32;
    per_queue = getenv("PERF_PER_QUEUE") ? atoi(getenv("PERF_PER_QUEUE")) : 0;
    if (nc < 1 || nc > 16 || nc >= rte_lcore_count()) return 1;
    unsigned nr = per_queue ? nc : 1;
    for (unsigned i = 0; i < nr; i++) {
        char name[32];
        snprintf(name, sizeof(name), "perf_ring_%u", i);
        /* pdump rejects rings flagged SP/SC even for a single queue. The
         * consumer may still use the SC dequeue operation on an MC ring. */
        rings[i] = rte_ring_create(name, size, 1, 0);
        snprintf(name, sizeof(name), "perf_pool_%u", i);
        pools[i] = rte_pktmbuf_pool_create_by_ops(name, 2 * size, cache, 0,
                rte_pcapng_mbuf_size(2048), 1, "ring_mp_mc");
        if (rings[i] == NULL || pools[i] == NULL) return 1;
        if (rte_pdump_enable_bpf(0, per_queue ? i : RTE_PDUMP_ALL_QUEUES,
                RTE_PDUMP_FLAG_RX, 2048, rings[i], pools[i], NULL) < 0) return 1;
    }
    unsigned id = 0, lcore;
    RTE_LCORE_FOREACH_WORKER(lcore) {
        if (id == nc) break;
        if (rte_eal_remote_launch(drain, (void *)(uintptr_t)id, lcore) != 0) return 1;
        id++;
    }
    fprintf(stderr, "drain ready: consumers=%u per_queue=%d ring=%u cache=%u\n",
            nc, per_queue, size, cache);
    while (!quit) {
        unsigned long total = 0;
        for (unsigned i = 0; i < nc; i++) total += atomic_load(&counts[i].packets);
        FILE *f = fopen("/tmp/cpperf-drain.json.tmp", "w");
        if (f != NULL) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            fprintf(f, "{\"captured\":%lu,\"time\":%.9f}\n", total,
                    ts.tv_sec + ts.tv_nsec / 1e9);
            fclose(f);
            rename("/tmp/cpperf-drain.json.tmp", "/tmp/cpperf-drain.json");
        }
        struct timespec ts = {0, 100000000};
        nanosleep(&ts, NULL);
    }
    rte_pdump_disable(0, RTE_PDUMP_ALL_QUEUES, RTE_PDUMP_FLAG_RX);
    rte_eal_mp_wait_lcore();
    for (unsigned i = 0; i < nr; i++) {
        struct rte_mbuf *bufs[64];
        unsigned n;
        while ((n = rte_ring_dequeue_burst(rings[i], (void **)bufs, 64, NULL)) != 0)
            rte_pktmbuf_free_bulk(bufs, n);
        rte_ring_free(rings[i]);
        rte_mempool_free(pools[i]);
    }
    rte_pdump_uninit();
    return rte_eal_cleanup() != 0;
}
