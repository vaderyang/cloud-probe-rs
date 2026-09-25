// Protocol parity harness: drives the REAL, unmodified cpworker output code
// (output_gre.c / output_vxlan.c / output_zmq.c) but intercepts the actual
// syscall/libzmq send with linker --wrap, so we capture the exact wire bytes
// without touching the network or needing privileges.
//
// Build (see run.sh):
//   gcc c_proto.c output_gre.c output_vxlan.c output_zmq.c stats.c log.c \
//       errorf.c ratelimit.c -lpcap -lzmq -Wl,--wrap=sendto -Wl,--wrap=zmq_send
//
// Input (stdin):
//   gre    <service_tag> <slice>
//   vxlan  <vni> <vni_version> <capture_time> <slice>
//   zmq    <service_tag> <slice> <heartbeat_ms> <uuid>
//   pkt    <ts_sec> <ts_usec> <caplen> <len> <direct> <hex>
// Output (stdout): one hex line per captured send()/zmq_send() call.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "config.h"
#include "gre.h"
#include "log.h"
#include "output_gre.h"
#include "output_vxlan.h"
#include "output_zmq.h"
#include "pkt_dir.h"
#include "stats.h"
#include "vxlan.h"

void log_log(int level, const char *file, int line, const char *fmt, ...)
{
    (void)level;
    (void)file;
    (void)line;
    (void)fmt;
}

extern int zmq_flush_packet(zmq_output_t *output);

static void dump_hex(const void *buf, size_t len)
{
    const uint8_t *p = buf;
    for (size_t i = 0; i < len; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* ---- intercepted sends ---- */
ssize_t __wrap_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr,
                      socklen_t addrlen)
{
    (void)sockfd;
    (void)flags;
    (void)dest_addr;
    (void)addrlen;
    dump_hex(buf, len);
    return (ssize_t)len;
}

int __wrap_zmq_send(void *s, const void *buf, size_t len, int flags)
{
    (void)s;
    (void)flags;
    dump_hex(buf, len);
    return (int)len;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int uuid_to_bytes(const char *uuid, uint8_t out[16])
{
    uint8_t clean[32];
    int n = 0;
    for (const char *p = uuid; *p; p++)
    {
        if (*p == '-')
            continue;
        if (n >= 32)
            return 0;
        clean[n++] = (uint8_t)*p;
    }
    if (n != 32)
        return 0;
    for (int i = 0; i < 16; i++)
    {
        int hi = hexval((char)clean[i * 2]);
        int lo = hexval((char)clean[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: %s <mode> <input|->\n", argv[0]);
        return 2;
    }
    FILE *in = (argc >= 3 && strcmp(argv[2], "-") != 0) ? fopen(argv[2], "r") : stdin;
    if (!in)
    {
        perror("fopen");
        return 2;
    }

    char mode[32] = {0};
    fscanf(in, "%31s", mode);

    output_stats_t stats;
    memset(&stats, 0, sizeof(stats));

    gre_output_t *gre = NULL;
    vxlan_output_t *vx = NULL;
    zmq_output_t *zm = NULL;

    char line[1 << 20];
    if (strcmp(mode, "gre") == 0)
    {
        uint32_t st;
        int slice;
        fscanf(in, "%u %d", &st, &slice);
        gre = calloc(1, sizeof(gre_output_t));
        gre->base.stats = &stats;
        gre->service_tag = st;
        gre->slice = slice;
        gre->rate_limit_mbps = 0;
        // Mirror gre_output_new(): flags/protocol live in buf and persist.
        struct gre_header gh;
        gh.flags = htons(0x2000);
        gh.protocol = htons(0x6558);
        gh.keybit = htonl(st);
        memcpy(gre->buf, &gh, GRE_HEADER_LEN);
    }
    else if (strcmp(mode, "vxlan") == 0)
    {
        uint32_t vni;
        unsigned vni_version;
        int capture_time, slice;
        fscanf(in, "%u %u %d %d", &vni, &vni_version, &capture_time, &slice);
        vx = calloc(1, sizeof(vxlan_output_t));
        vx->base.stats = &stats;
        vx->vni = vni;
        vx->vni_version = (uint8_t)vni_version;
        vx->capture_time = capture_time != 0;
        vx->slice = slice;
        vx->rate_limit_mbps = 0;
        vx->split.max_payload_size = 0;
        // Mirror vxlan_output_new(): vx_flags/vx_vni are initialised in buf.
        {
            uint32_t flags = htonl(0x08000000);
            uint32_t vni0 = htonl(vni << 8);
            memcpy(vx->buf, &flags, 4);
            memcpy(vx->buf + 4, &vni0, 4);
        }
    }
    else if (strcmp(mode, "zmq") == 0)
    {
        uint32_t st;
        int slice, heartbeat_ms;
        char uuid[64];
        fscanf(in, "%u %d %d %63s", &st, &slice, &heartbeat_ms, uuid);
        zm = calloc(1, sizeof(zmq_output_t));
        zm->base.stats = &stats;
        zm->service_tag = (uint16_t)st;
        zm->slice = slice;
        zm->rate_limit_mbps = 0;
        zm->heartbeat_ms = heartbeat_ms;
        zm->pkts_buf.batch_hdr.version = htons(ZMQ_BATCH_PKTS_VERSION);
        zm->pkts_buf.batch_hdr.pkts_num = 0;
        zm->pkts_buf.batch_hdr.keybit = htonl(st);
        uuid_to_bytes(uuid, zm->pkts_buf.batch_hdr.uuid);
        zm->pkts_buf.batch_bufpos = sizeof(zmq_pkt_batch_hdr_t);
        zm->pkts_buf.first_pktsec = 0;
        gettimeofday(&zm->last_pkt_tv, NULL);
    }
    else
    {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }

    // consume to end of cfg line
    fgets(line, sizeof(line), in);

    while (fgets(line, sizeof(line), in))
    {
        char tag[16];
        if (sscanf(line, "%15s", tag) != 1)
            continue;
        if (strcmp(tag, "pkt") != 0)
            continue;

        long ts_sec, ts_usec;
        long caplen, len;
        int direct;
        char hex[1 << 20];
        int n = sscanf(line, "%15s %ld %ld %ld %ld %d %s", tag, &ts_sec, &ts_usec, &caplen, &len, &direct, hex);
        if (n < 7)
            continue;

        uint8_t pkt[65536];
        size_t pktlen = strlen(hex) / 2;
        if (pktlen > sizeof(pkt))
            pktlen = sizeof(pkt);
        for (size_t i = 0; i < pktlen; i++)
        {
            int hi = hexval(hex[i * 2]);
            int lo = hexval(hex[i * 2 + 1]);
            pkt[i] = (uint8_t)((hi << 4) | lo);
        }

        struct pcap_pkthdr hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.ts.tv_sec = ts_sec;
        hdr.ts.tv_usec = ts_usec;
        hdr.caplen = (uint32_t)caplen;
        hdr.len = (uint32_t)len;

        if (gre)
            gre_send_packet(&gre->base, &hdr, pkt, direct);
        else if (vx)
            vxlan_send_packet(&vx->base, &hdr, pkt, direct);
        else if (zm)
            zmq_send_packet(&zm->base, &hdr, pkt, direct);
    }

    if (zm)
        zmq_flush_packet(zm);

    return 0;
}
