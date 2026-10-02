/*
 * fanout_capture.c - does per-socket PACKET_FANOUT lift the single TPACKET_V3
 * socket ceiling measured for this port?
 *
 * BENCHMARK.md records ~2.5 Mpps from one AF_PACKET V3 socket on the 100 GbE
 * port, with four NIC RX queues not helping, and attributes it to the ring block
 * lock. That was never turned into a discriminating experiment: if N sockets in
 * one fanout group each own a ring and the kernel spreads packets over them, the
 * ceiling should move; if it does not, the limit is elsewhere and cpworker should
 * not grow a fanout backend (cloud-probe-rs-f7x).
 *
 * usage: fanout_capture <iface> <nsocks> <mode> <seconds>
 *   mode: lb | hash | cpu | rrw | rollover | none
 *         ("none" opens N sockets without a fanout group: every socket then sees
 *          every packet, which is the control case for duplicated work)
 *
 * Each socket gets its own TPACKET_V3 ring and its own pthread. Counts come from
 * tpacket_hdr_v1::num_pkts, so no per-packet walk is needed - this measures the
 * delivery path, not the parsing path.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BLOCK_SIZE  (1u << 20)
#define BLOCK_NR    64u
#define FRAME_SIZE  2048u
#define MAX_SOCKS   32

struct worker {
    int fd;
    void *map;
    size_t map_len;
    unsigned long count;
    int stop;
};

static void *reader(void *arg) {
    struct worker *w = arg;
    unsigned long n = 0;
    while (!w->stop) {
        int progressed = 0;
        for (unsigned int b = 0; b < BLOCK_NR; b++) {
            struct tpacket_block_desc *blk =
                (struct tpacket_block_desc *)((char *)w->map + (size_t)b * BLOCK_SIZE);
            if ((blk->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
                continue;
            }
            n += blk->hdr.bh1.num_pkts;
            blk->hdr.bh1.block_status = TP_STATUS_KERNEL;
            progressed = 1;
        }
        if (!progressed) {
            struct pollfd p = { .fd = w->fd, .events = POLLIN };
            poll(&p, 1, 1);
        }
    }
    w->count = n;
    return NULL;
}

static int fanout_flag(const char *mode) {
    if (strcmp(mode, "hash") == 0)     return PACKET_FANOUT_HASH;
    if (strcmp(mode, "lb") == 0)       return PACKET_FANOUT_LB;
    if (strcmp(mode, "cpu") == 0)      return PACKET_FANOUT_CPU;
    if (strcmp(mode, "rrw") == 0)      return PACKET_FANOUT_ROLLOVER;
    if (strcmp(mode, "none") == 0)     return -1;
    fprintf(stderr, "unknown mode %s (lb|hash|cpu|rrw|none)\n", mode);
    exit(2);
}

static int open_ring(const char *iface, int ifindex, int fanout_id, int fanout_mode,
                     struct worker *w) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return -1; }

    int ver = TPACKET_V3;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) < 0) {
        perror("PACKET_VERSION (kernel without V3?)"); return -1;
    }

    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = BLOCK_SIZE;
    req.tp_block_nr = BLOCK_NR;
    req.tp_frame_size = FRAME_SIZE;
    req.tp_frame_nr = (BLOCK_SIZE / FRAME_SIZE) * BLOCK_NR;
    req.tp_retire_blk_tov = 1;                 /* ms: never wait for a full block */
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        perror("PACKET_RX_RING"); return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); return -1;
    }

    if (fanout_mode >= 0) {
        /* Fanout id must be < 2^16 and identical across the group. */
        int arg = (fanout_id & 0xffff) | fanout_mode;
        if (setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &arg, sizeof(arg)) < 0) {
            perror("PACKET_FANOUT"); return -1;
        }
    }

    /* The generator addresses the VF MAC, but promiscuous removes a whole class
     * of "why did we capture nothing" failures. */
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    (void)setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    size_t len = (size_t)BLOCK_SIZE * BLOCK_NR;
    void *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); return -1; }

    w->fd = fd;
    w->map = map;
    w->map_len = len;
    w->count = 0;
    w->stop = 0;
    (void)iface;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <iface> <nsocks> <mode> <seconds>\n", argv[0]);
        return 2;
    }
    const char *iface = argv[1];
    int nsocks = atoi(argv[2]);
    const char *mode = argv[3];
    double seconds = atof(argv[4]);
    if (nsocks < 1 || nsocks > MAX_SOCKS) {
        fprintf(stderr, "nsocks must be 1..%d\n", MAX_SOCKS);
        return 2;
    }
    int fanout_mode = fanout_flag(mode);

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "no such interface: %s\n", iface);
        return 2;
    }

    struct worker w[MAX_SOCKS];
    pthread_t th[MAX_SOCKS];
    int fanout_id = getpid() & 0xffff;
    for (int i = 0; i < nsocks; i++) {
        if (open_ring(iface, ifindex, fanout_id, fanout_mode, &w[i]) != 0) {
            fprintf(stderr, "socket %d failed\n", i);
            return 3;
        }
    }
    for (int i = 0; i < nsocks; i++) {
        if (pthread_create(&th[i], NULL, reader, &w[i]) != 0) {
            perror("pthread_create");
            return 3;
        }
    }

    fprintf(stderr, "FANOUT_READY iface=%s nsocks=%d mode=%s id=%d\n",
            iface, nsocks, mode, fanout_id);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    /* The caller starts the generator after READY; give it time to ramp and
     * measure a steady window rather than the ramp itself. */
    double total = seconds;
    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double el = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        if (el >= total) break;
        struct timespec s = { .tv_sec = 0, .tv_nsec = 200000000L };
        nanosleep(&s, NULL);
    }
    for (int i = 0; i < nsocks; i++) w[i].stop = 1;
    for (int i = 0; i < nsocks; i++) pthread_join(th[i], NULL);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double el = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    unsigned long sum = 0;
    for (int i = 0; i < nsocks; i++) {
        fprintf(stderr, "FANOUT_SOCK sock=%d packets=%lu mpps=%.3f\n",
                i, w[i].count, (double)w[i].count / el / 1e6);
        sum += w[i].count;
    }
    fprintf(stderr, "FANOUT_DONE nsocks=%d mode=%s seconds=%.3f packets=%lu mpps=%.3f\n",
            nsocks, mode, el, sum, (double)sum / el / 1e6);
    return 0;
}
