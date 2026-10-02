# Is the AF_PACKET ceiling a ring-lock limit that PACKET_FANOUT can lift? (2026-10-02)

`cloud-probe-rs-f7x`. `BENCHMARK.md` recorded ~2.5 Mpps from one AF_PACKET
TPACKET_V3 socket and said "4 NIC RX queues did not help; a single socket
serializes on the ring block lock", then noted that the discriminating experiment
was never run. This is that experiment.

**Answer: no. Adding sockets does not lift the ceiling, and the ring-block lock was
not the limit. The kernel's mlx5 VF receive path is.** So cpworker should **not**
grow a per-queue fanout backend.

## Method

laojun testpmd `txonly`, 64-byte frames, `--txonly-multi-flow`, 7 forward cores —
the same configuration family that reached 148.76 Mpps (true 64B line rate with
PAUSE off) in `BENCHMARK.md` — onto the yinjiao VF (`ens8v0`). On yinjiao,
`fanout_capture.c` opens N `AF_PACKET`/`SOCK_RAW` sockets, each with its own
TPACKET_V3 ring (64 blocks × 1 MiB, `tp_retire_blk_tov = 1 ms`), all sharing one
`PACKET_FANOUT` group, each read by its own pthread. Counts come from
`tpacket_hdr_v1::num_pkts`. PAUSE off, VF `max_tx_rate 0`, serially under the
shared physical lock; both hosts restored afterwards.

`mode=none` opens N sockets **without** a fanout group: every socket then sees
every packet, so its aggregate is inflated by duplication and it exists purely as
a control.

## Result (captured Mpps, 14 s window each)

| Sockets | mode | captured Mpps | socket spread | sysfs `rx_packets` over the window |
|---|---|---|---|---|
| 1 | none (control) | 1.759 | — | 33.5 M |
| 2 | none (control) | 2.710 *(≈2× duplicated)* | — | 32.1 M |
| 1 | lb | 1.610 | — | 31.5 M |
| 2 | lb | 2.537 | — | 47.5 M |
| 4 | lb | 2.830 | 0.62–0.78 per socket | 55.5 M |
| 8 | lb | **3.186** | 0.32–0.46 per socket | 56.2 M |
| 4 | hash | 3.145 | 0.69–0.86 | 55.3 M |
| 4 | cpu | 2.889 | 0.64–0.79 | 56.2 M |

- One socket: **1.6–1.8 Mpps**, the same order as the 2.5 Mpps recorded earlier
  (this tool's ring is 64 MiB with a 1 ms retire timer, and it does not copy the
  payload, so the two are not bit-identical configurations).
- Eight sockets: **3.19 Mpps** — about **1.8×**, not 8×, and every socket carries a
  similar small share rather than the group scaling out.
- All four fanout modes land in 2.9–3.2 Mpps at 4 sockets: the mode does not matter.
- `sysfs` `rx_packets` agrees with the ring counts (2.2–4.0 Mpps), so the sockets
  are not the thing being starved.

Meanwhile the device reported `rx_out_of_buffer` in the hundreds of millions per
trial at the same time as these ~3 Mpps delivered — i.e. the offer is far above
what the kernel path absorbs and the rest is dropped before it ever reaches a
socket.

## Caveats (do not over-read the numbers)

- **The `rx_out_of_buffer` delta is not trustworthy as an absolute count.** One
  trial read *negative* (−3.4e9), so this counter is not monotonic across reads on
  this VF; treat it as an indicator that the device is dropping heavily, not as a
  measurement. The conclusion above deliberately rests on the *delivered* rates,
  which come from our own ring counters and from `sysfs`, and which agree.
- The exact offered rate in these trials was not sampled from testpmd (the helper
  script does not ask for port stats). The claim is only that the offer was far
  above ~3 Mpps, which the device-drop indicator and the earlier 148.76 Mpps
  line-rate result both support.
- Two sockets in `none` mode report 2.710 Mpps *aggregate*, which is ≈2× a real
  1.35 Mpps — that row is a duplication control, not a capacity result.
- Short bursts (14 s), one VF, one NIC, one flow mix (`--txonly-multi-flow`); the
  numbers are laboratory bounds.

## Consequence

- `cloud-probe-rs-f7x` is answered: a `PACKET_FANOUT` multi-queue backend would add
  a second capture path for at most ~1.8×, in a regime where the kernel path is
  already discarding the overwhelming majority of frames. Not worth it.
- `BENCHMARK.md`'s parenthetical "a single socket serializes on the ring block
  lock" attributed the ceiling to the wrong place and is corrected there. What the
  ceiling is: the kernel mlx5 VF receive path, which is consistent with the earlier
  observation that the worker used only ~10–12% of a core while the customer-visible
  rate stopped at ~2.4 Mpps, and with DPDK `pdump`/primary RX on the same port
  reaching tens of Mpps (those bypass this path entirely).
- Reproduce with `fanout_test.sh` + `fanout_capture.c` (both in this directory).
