# cpsim — Deterministic Simulation Testing (DST)

A single-threaded, fully deterministic simulation of the Cloud Probe forwarding
pipeline. Every decision — packet bytes, rate-limit outcome, network
loss/duplication/reordering/corruption, batch/heartbeat flush timing — is
derived from a seed, so any failing run can be replayed exactly.

## What it exercises

The probe side calls the **real cpworker code**:

* `cpworker::output::gre::gre_header`
* `cpworker::output::vxlan::vxlan_encapsulate`
* `cpworker::output::zmq::BatchBuilder`
* `cpworker::ratelimit::TokenBucket`
* `cpworker::packet_split::{parse_packet, calculate_fragment_count, build_fragment}`

The collector decodes GRE / VXLAN / ZMQ-batch frames and reconciles them against
a journal of everything the probe emitted.

## Properties

* **Virtual clock** — no `Instant`/`SystemTime`; time is advanced by the event
  queue, so timing behaviour is reproducible.
* **Seeded RNG** — ChaCha8 (`rand_chacha`), stable across platforms.
* **Fault injection** — loss, duplication, reordering, bit-flip corruption and
  one-way delay (`chaos::Chaos`).
* **Trace digest** — an FNV-1a hash of the whole run; two runs with the same
  seed must produce the same digest.

## Run

```bash
cargo test -p cpsim --test dst
```

Replay a specific seed after a failure:

```bash
DST_SEED=7 cargo test -p cpsim --test dst
```

Print a trace digest (cross-process reproducibility):

```bash
cargo run -p cpsim --example trace -- 7 zmq
cargo run -p cpsim --example trace -- 7 zmq harsh
```

## Tests

| Test | Checks |
|---|---|
| `determinism_same_seed` | same seed ⇒ identical trace for gre/vxlan/zmq |
| `different_seeds_diverge` | distinct seeds ⇒ distinct traces |
| `clean_network_all_outputs` | no drops, zero decode errors, invariants hold |
| `harsh_network_invariants` | loss/dup/reorder/corruption accounting holds |
| `harsh_network_determinism` | fault injection itself is deterministic |
| `zmq_heartbeat_and_batch_invariants` | heartbeat frames emitted and decoded |
| `zmq_vlan_slice_never_corrupts` | regression for the upstream VLAN-walk overflow (issue #231): slicing VLAN frames must never corrupt a batch |
| `vxlan_fragmentation` | fragmenter produces valid, reconciling frames |
| `vxlan_v1_capture_time` | VXLAN v1 + capture-time path decodes cleanly |
| `ratelimit_drops_when_exceeded` | low rate ⇒ drops, disabled ⇒ none |

## Invariants

`SimResult::check()` asserts, for every seed:

* `delivered == sent_frames - dropped + duplicated`
* `decode_errors <= corrupted`
* every delivered frame's decoded packet count matches the probe journal.
