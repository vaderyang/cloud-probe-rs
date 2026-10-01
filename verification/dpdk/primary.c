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
 * Build (must match the DPDK the cpworker secondary links):
 *
 *   cc -O2 primary.c -o dpdk_primary $(pkg-config --cflags --libs libdpdk)
 *
 * Usage (as root, after hugepages are set up):
 *
 *   ./dpdk_primary -l 4-7 -a 0000:b8:00.1
 *
 * It prints the probed port's driver and MAC, then polls until SIGINT/SIGTERM.
 */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pdump.h>

#include <signal.h>
#include <stdio.h>
#include <string.h>

#define NB_MBUF 16384
#define RX_DESC 4096
#define BURST 32

static volatile int g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }

int main(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0) {
        fprintf(stderr, "dpdk_primary: EAL init failed\n");
        return 1;
    }
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    uint16_t port = 0;
    struct rte_eth_dev_info info;
    memset(&info, 0, sizeof(info));
    if (rte_eth_dev_info_get(port, &info) != 0) {
        fprintf(stderr, "dpdk_primary: no port %u\n", port);
        return 1;
    }

    struct rte_mempool *mp = rte_pktmbuf_pool_create(
        "FIELD_PRIMARY_MBUF", NB_MBUF, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
        (int)rte_socket_id());
    if (mp == NULL) {
        fprintf(stderr, "dpdk_primary: mempool create failed\n");
        return 1;
    }

    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    if (rte_eth_dev_configure(port, 1, 1, &conf) < 0) {
        fprintf(stderr, "dpdk_primary: configure failed\n");
        return 1;
    }
    if (rte_eth_rx_queue_setup(port, 0, RX_DESC, rte_eth_dev_socket_id(port),
                               NULL, mp) < 0) {
        fprintf(stderr, "dpdk_primary: rx queue setup failed\n");
        return 1;
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
            "pdump_init=ok polling\n",
            port, info.driver_name ? info.driver_name : "?",
            mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
            mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);
    fflush(stderr);

    struct rte_mbuf *bufs[BURST];
    unsigned long total = 0;
    while (!g_stop) {
        uint16_t n = rte_eth_rx_burst(port, 0, bufs, BURST);
        if (n != 0) {
            total += n;
            rte_pktmbuf_free_bulk(bufs, n);
        }
    }
    fprintf(stderr, "dpdk_primary: rx total %lu\n", total);

    rte_eth_dev_stop(port);
    rte_eth_dev_close(port);
    rte_pdump_uninit();
    return 0;
}
