/*
 * Minimal reproducer for a heap/stack out-of-bounds memcpy in
 * cpworker/src/output_zmq.c (zmq_send_packet).
 *
 * A VLAN-tagged frame is truncated by `slice`. The VLAN walk uses
 * `length = sliced_caplen + MPLS_HDR_SIZE` as its bound, so it over-counts one
 * VLAN tag; `payload_copy_len = length - 14 - 4 - vlan_total_size` then
 * underflows (size_t) and a wild memcpy() is performed.
 *
 * Build:
 *   gcc -fsanitize=address -g -I cpworker/src -I rust/parity/shim \
 *       repro_zmq_slice.c cpworker/src/output_zmq.c cpworker/src/stats.c \
 *       cpworker/src/errorf.c cpworker/src/ratelimit.c cpworker/src/packet_split.c \
 *       -lpcap -lzmq -o repro_zmq_slice
 * Run: ./repro_zmq_slice
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "output.h"
#include "output_zmq.h"

extern int zmq_flush_packet(zmq_output_t *output);

int main(void)
{
    output_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    char errbuf[256];

    zmq_options_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.host = "127.0.0.1";
    opts.port = 5555;
    opts.hwm = 1000;
    opts.service_tag = 1;
    opts.uuid = "11111111-1111-1111-1111-111111111111";
    opts.rate_limit_mbps = 0;
    opts.slice = 26; /* truncates the 1500-byte frame mid-VLAN-stack */
    opts.heartbeat_ms = 0;

    zmq_output_t *out = zmq_output_new(opts, &stats, errbuf);
    if (!out)
    {
        printf("init failed: %s\n", errbuf);
        return 1;
    }

    static uint8_t pkt[1500];
    memset(pkt, 0, sizeof(pkt));
    /* dst(6) src(6) then stacked VLANs: 0x9200,0x8100,0x9100,0x9200 -> 0x86dd */
    pkt[12] = 0x92;
    pkt[13] = 0x00;
    pkt[16] = 0x81;
    pkt[17] = 0x00;
    pkt[20] = 0x91;
    pkt[21] = 0x00;
    pkt[24] = 0x92;
    pkt[25] = 0x00;
    pkt[28] = 0x86;
    pkt[29] = 0xdd;

    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = 1;
    hdr.caplen = 1500;
    hdr.len = 1500;

    int ret = zmq_send_packet(&out->base, &hdr, pkt, 1);
    printf("zmq_send_packet ret=%d batch_bufpos=%u\n", ret, out->pkts_buf.batch_bufpos);
    zmq_flush_packet(out);
    zmq_output_destroy(&out->base);
    return 0;
}
