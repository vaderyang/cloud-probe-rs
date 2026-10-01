/* Benchmark-only LD_PRELOAD override. Keep production config semantics intact
 * while isolating clone-pool capacity, lcore cache and NUMA placement. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct rte_mempool *rte_pktmbuf_pool_create_by_ops(const char *name,
        unsigned n, unsigned cache, uint16_t priv, uint16_t room,
        int socket, const char *ops) {
    typedef struct rte_mempool *(*create_fn)(const char *, unsigned,
            unsigned, uint16_t, uint16_t, int, const char *);
    create_fn real_create = (create_fn)dlsym(RTLD_NEXT, "rte_pktmbuf_pool_create_by_ops");
    if (real_create == NULL) return NULL;
    if (strncmp(name, "cpworker_capture_mbufs", 21) == 0) {
        const char *value = getenv("PERF_POOL_FACTOR");
        if (value != NULL) n = n / 2 * strtoul(value, NULL, 10);
        value = getenv("PERF_POOL_CACHE");
        if (value != NULL) cache = strtoul(value, NULL, 10);
        value = getenv("PERF_POOL_SOCKET");
        if (value != NULL) socket = strtol(value, NULL, 10);
        fprintf(stderr, "perf_pool: n=%u cache=%u room=%u socket=%d ops=%s\n",
                n, cache, room, socket, ops);
    }
    return real_create(name, n, cache, priv, room, socket, ops);
}
