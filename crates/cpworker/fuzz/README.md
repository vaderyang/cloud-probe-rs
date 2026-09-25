# Fuzz targets (cargo-fuzz / libFuzzer)

Coverage-guided fuzzing for the Rust port. Complements the C-vs-Rust
differential fuzzers in `parity/`.

## Run

```bash
fuzz.sh                 # all targets, 30s each
fuzz.sh 120 config      # one target, 2 minutes
fuzz.sh --check         # CI smoke test (5s each)
FUZZ_SEED=7 fuzz.sh 60 zmq_batch
fuzz.sh repro zmq_batch fuzz/artifacts/zmq_batch/crash-...
```

## Targets

| Target | Crate | What it covers |
|---|---|---|
| `packet_split` | cpworker | `parse_packet` + `calculate_fragment_count` + `build_fragment` |
| `config` | cpworker | JSON config parser + `bpf_filter_exclude_task_output_hosts` |
| `vxlan` | cpworker | `vxlan_encapsulate` (checksum + capture-time path) |
| `zmq_batch` | cpworker | `BatchBuilder` ZMQ batch + VLAN/MPLS rewrite (regression for issue #231) |
| `sim_dst` | cpsim | the whole deterministic simulator + invariants |

## Input formats

* `packet_split` / `config` / `vxlan`: raw bytes / UTF-8.
* `zmq_batch`: `service_tag(LE u32) | slice(u8) | uuid(16) | { caplen(BE u16) |
  direct(u8) | frame }*`.
* `sim_dst`: `seed(LE u64) | out(u8) | num_packets(u8) | slice(u8) |
  heartbeat(u8)`.

Hand-written seeds live in `seeds/<target>/` (copied into the ignored
`corpus/<target>/` by `fuzz.sh`). `seeds/zmq_batch/vlan_slice.bin` exercises the
safety guard added for upstream issue #231.
