# [cpworker] ZMQ output: VLAN walk over-counts → `size_t` underflow → out-of-bounds `memcpy` (heap corruption)

**Title (for the issue tracker):**

> `[cpworker] output_zmq.c: VLAN-aware slicing causes size_t underflow and out-of-bounds memcpy`

**TL;DR（中文）**：`cpworker/src/output_zmq.c` 的 `zmq_send_packet()` 在配置了 `slice` 且截断
带 VLAN 的报文时，VLAN 遍历会多算一个标签，导致 `payload_copy_len` 发生 `size_t` 下溢（-4→2^64），
随后 `memcpy` 越界读写，可被网络流量触发（堆破坏）。ASAN 证据见下。

## Environment

* Repo: `netis/cloud-probe`
* Branch: `0.9.x`
* Commit: `f925e5f6d27c7df2443f05add547211d534e6361`
* Build: gcc + AddressSanitizer, Ubuntu 24.04 x86_64
* Component: `cpworker/src/output_zmq.c`

## Summary

`zmq_send_packet()` walks stacked VLAN tags to insert an MPLS header. When an
output is configured with a `slice` smaller than a VLAN-tagged capture, the
walk's bound (`length = sliced_caplen + sizeof(mpls_header)`) lets it count one
more VLAN tag than the truncated frame actually contains. `vlan_total_size` can
then exceed `length - sizeof(ether_header) - sizeof(mpls_header)`, so

```c
const size_t payload_copy_len =
    length - sizeof(struct ether_header) - sizeof(mpls_header) - vlan_total_size;
```

underflows (`size_t`) to a huge value, and the following `memcpy()` performs an
out-of-bounds read from the packet buffer and an out-of-bounds write into the
batch buffer (heap corruption / crash).

The same bound also permits a 4-byte **out-of-bounds read** past the captured
data even when no underflow occurs, because the loop reads up to
`length == caplen + 4` bytes from a `caplen`-byte buffer.

The packets that trigger this come from the network and `slice` is a normal
output option, so this is remotely triggerable heap corruption, not just a
theoretical parser bug.

## Root cause

`cpworker/src/output_zmq.c`:

```c
// line 234: bound is `length` (== caplen + MPLS_HDR_SIZE), not the captured length
if (vlan_offset + sizeof(struct vlan_header) > length)
    break;
...
// lines 267-269
const size_t payload_offset = sizeof(struct ether_header) + vlan_total_size;
const size_t payload_copy_len =
    length - sizeof(struct ether_header) - sizeof(mpls_header) - vlan_total_size;
memcpy(&(pkts_buf->buf[buff_pos]), pkt_data + payload_offset, payload_copy_len);
```

Note that `length` already includes the 4-byte MPLS header (line ~166:
`length = min(caplen, 65531) + sizeof(mpls_header)`), but the VLAN loop treats
it as if it were the available packet length. Once `vlan_total_size` reaches
`length - 18`, `payload_copy_len` becomes negative and wraps.

The loop also counts a "tag" based on the *next* tag's ethertype, which is why
it can accept a tag at the very end of the truncated window.

## Steps to reproduce (standalone)

Build & run this self-contained program (no capture privileges or network needed):

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "output.h"
#include "output_zmq.h"

extern int zmq_flush_packet(zmq_output_t *output);

int main(void)
{
    output_stats_t stats; memset(&stats, 0, sizeof(stats));
    char errbuf[256];

    zmq_options_t opts; memset(&opts, 0, sizeof(opts));
    opts.host = "127.0.0.1";
    opts.port = 5555;
    opts.hwm = 1000;
    opts.service_tag = 1;
    opts.uuid = "11111111-1111-1111-1111-111111111111";
    opts.slice = 26;      /* truncates the 1500-byte frame mid-VLAN-stack */
    opts.heartbeat_ms = 0;

    zmq_output_t *out = zmq_output_new(opts, &stats, errbuf);
    if (!out) { printf("init failed: %s\n", errbuf); return 1; }

    static uint8_t pkt[1500];
    memset(pkt, 0, sizeof(pkt));
    /* dst(6) src(6) then stacked VLANs: 0x9200,0x8100,0x9100,0x9200 -> 0x86dd */
    pkt[12] = 0x92; pkt[13] = 0x00;
    pkt[16] = 0x81; pkt[17] = 0x00;
    pkt[20] = 0x91; pkt[21] = 0x00;
    pkt[24] = 0x92; pkt[25] = 0x00;
    pkt[28] = 0x86; pkt[29] = 0xdd;

    struct pcap_pkthdr hdr; memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = 1;
    hdr.caplen = 1500;
    hdr.len = 1500;

    int ret = zmq_send_packet(&out->base, &hdr, pkt, 1);
    printf("zmq_send_packet ret=%d batch_bufpos=%u\n", ret, out->pkts_buf.batch_bufpos);
    zmq_flush_packet(out);
    zmq_output_destroy(&out->base);
    return 0;
}
```

```bash
# save as repro.c in the repo root
gcc -fsanitize=address -g -I cpworker/src \
    repro.c cpworker/src/output_zmq.c cpworker/src/stats.c \
    cpworker/src/errorf.c cpworker/src/ratelimit.c cpworker/src/packet_split.c \
    -lpcap -lzmq -o repro && ./repro
```

### ASAN output

```
=================================================================
==59500==ERROR: AddressSanitizer: negative-size-param: (size=-4)
    #0 memcpy
    #1 zmq_send_packet cpworker/src/output_zmq.c:269
    #2 main repro_zmq_slice.c:70
0x56292692061e is located 30 bytes inside of global variable 'pkt'
  defined in 'repro_zmq_slice.c:50:20' of size 1500
SUMMARY: AddressSanitizer: negative-size-param ... in memcpy
```

### Realistic repro

Any `zmq` output with `slice` set (e.g. `"slice": 26`) receiving a frame whose
VLAN stack is cut by the slice, e.g. `tcpdump`-captured `0x9200 -> 0x8100 ->
0x9100 -> 0x9200` tagged frames. With `slice = 0` the fast path is unaffected.

## Impact

* Out-of-bounds read and write in the worker process; with attacker-controlled
  packet contents this is potential memory corruption, not merely a crash.
* Affects `zmq` outputs whenever `slice` truncates a VLAN-tagged frame.

## Suggested fix

Bound the VLAN walk by the real captured length and reserve room for the MPLS
header (and never let `vlan_total_size` exceed `length - 18`):

```c
// `length` includes the MPLS header; the captured payload is length - 4.
const size_t data_len = length - sizeof(mpls_header);

while (ether_type == ETHERTYPE_VLAN || ...) {
    size_t vlan_offset = sizeof(struct ether_header) + vlan_total_size;
    if (vlan_offset + sizeof(struct vlan_header) + sizeof(mpls_header) > length)
        break;
    if (vlan_offset + sizeof(struct vlan_header) > data_len)
        break;   // don't read past the captured data
    ...
}
```

Alternatively, compute `vlan_total_size` first with a safe bound and skip the
packet (as we do in the Rust port) if
`sizeof(ether_header) + sizeof(mpls_header) + vlan_total_size > length`.

## Notes

Discovered while writing a differential/fuzz test that compares the C output
modules against a Rust port. The fix should be trivial; we are happy to send a
PR against `0.9.x` if you'd like.
