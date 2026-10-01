/* Isolated lab flow controller. The uplink PF is isolated before configure,
 * so unmatched traffic stays on its NFS kernel queues. Representors and
 * VFs in a negative legacy-mode probe use ordinary port configuration.
 * The rule matches the lab destination MAC, mirrors to capture VF1 and keeps
 * the original on VF0. FLOW_CONTROL_ONLY=1 leaves probed ports unstarted. */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t quit;
static void stop(int signum) { (void)signum; quit = 1; }

int main(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0) return 1;
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    uint16_t port, original = UINT16_MAX, mirror = UINT16_MAX, control = 0;
    int repr = 0;
    struct rte_mempool *mp = rte_pktmbuf_pool_create("flow_control_pool",
            8192, 128, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 1);
    if (mp == NULL) return 1;
    RTE_ETH_FOREACH_DEV(port) {
        char name[RTE_ETH_NAME_MAX_LEN];
        struct rte_eth_dev_info info = {0};
        rte_eth_dev_get_name_by_port(port, name);
        if (rte_eth_dev_info_get(port, &info) != 0) return 1;
        fprintf(stderr, "port=%u name=%s flags=%lu\n",
                port, name, (unsigned long)*info.dev_flags);
        if (*info.dev_flags & RTE_ETH_DEV_REPRESENTOR) {
            repr = 1;
            if (strstr(name, "vf0") != NULL) original = port;
            if (strstr(name, "vf1") != NULL) mirror = port;
        }
    }
    if (!repr) { original = 0; mirror = 1; }
    if (original == UINT16_MAX || mirror == UINT16_MAX) return 1;
    control = repr ? 0 : original;
    if (getenv("FLOW_CONTROL_ONLY") == NULL) {
        uint16_t endpoints[3] = {original, mirror, 0};
        if (repr) {
            struct rte_flow_error isolation_error = {0};
            if (rte_flow_isolate(0, 1, &isolation_error) != 0) return 1;
            endpoints[0] = 0;
            endpoints[1] = original;
            endpoints[2] = mirror;
        }
        for (unsigned i = 0; i < (repr ? 3u : 2u); i++) {
            port = endpoints[i];
            struct rte_eth_conf conf = {0};
            if (rte_eth_dev_configure(port, 1, 1, &conf) != 0 ||
                rte_eth_rx_queue_setup(port, 0, 256, 1, NULL, mp) != 0 ||
                rte_eth_tx_queue_setup(port, 0, 256, 1, NULL) != 0 ||
                rte_eth_dev_start(port) != 0) return 1;
        }
    }
    struct rte_flow_item_eth spec = {0}, mask = {0};
    const uint8_t dst[6] = {0x1a, 0xca, 0x0a, 0x26, 0xa8, 0x8c};
    memcpy(spec.hdr.dst_addr.addr_bytes, dst, 6);
    memset(mask.hdr.dst_addr.addr_bytes, 0xff, 6);
    /* Match the represented uplink (wire ingress), rather than the implicit
     * VF source inherited from the representor used to install the rule. */
    struct rte_flow_item_ethdev uplink = {.port_id = 0};
    struct rte_flow_item pattern[] = {
        {.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT, .spec = &uplink},
        {.type = RTE_FLOW_ITEM_TYPE_ETH, .spec = &spec, .mask = &mask},
        {.type = RTE_FLOW_ITEM_TYPE_END}
    };
    struct rte_flow_action_ethdev dest = {.port_id = mirror};
    struct rte_flow_action_ethdev keep = {.port_id = original};
    struct rte_flow_action sub[] = {
        {.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT, .conf = &dest},
        {.type = RTE_FLOW_ACTION_TYPE_END}
    };
    struct rte_flow_action_sample sample = {.ratio = 1, .actions = sub};
    struct rte_flow_action_count count = {0};
    struct rte_flow_action actions[] = {
        {.type = RTE_FLOW_ACTION_TYPE_COUNT, .conf = &count},
        {.type = RTE_FLOW_ACTION_TYPE_SAMPLE, .conf = &sample},
        {.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT, .conf = &keep},
        {.type = RTE_FLOW_ACTION_TYPE_END}
    };
    struct rte_flow_attr attr = {.transfer = 1};
    struct rte_flow_error error = {0};
    int no_count = getenv("FLOW_NO_COUNT") != NULL;
    const struct rte_flow_action *rule_actions = actions + (no_count ? 1 : 0);
    int ret = rte_flow_validate(control, &attr, pattern, rule_actions, &error);
    fprintf(stderr, "mirror validate=%d errno=%d type=%d message=%s\n", ret,
            rte_errno, error.type, error.message ? error.message : "none");
    if (ret != 0) return 2;
    struct rte_flow *flow = rte_flow_create(control, &attr, pattern, rule_actions, &error);
    fprintf(stderr, "mirror create=%s errno=%d type=%d message=%s\n",
            flow ? "ok" : "failed", rte_errno, error.type,
            error.message ? error.message : "none");
    if (flow == NULL) return 3;
    fprintf(stderr, "mirror ready original=%u capture=%u\n", original, mirror);
    while (!quit) {
        struct rte_flow_query_count hits = {0};
        struct rte_flow_action query = {.type = RTE_FLOW_ACTION_TYPE_COUNT};
        if (!no_count && rte_flow_query(control, flow, &query, &hits, &error) == 0)
            fprintf(stderr, "mirror hits=%lu\n", (unsigned long)hits.hits);
        sleep(1);
    }
    rte_flow_destroy(control, flow, &error);
    rte_eth_dev_stop(mirror);
    rte_eth_dev_stop(original);
    if (repr) rte_eth_dev_stop(0);
    rte_eal_cleanup();
    return 0;
}
