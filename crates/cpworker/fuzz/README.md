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
| `bpf` | cpworker | the pure-Rust BPF parser/compiler/interpreter |
| `zmtp_wire` | cpworker | ZMTP greeting/frame/command codec (`zmtp::codec`) |
| `zmtp_client` | cpworker | the non-blocking ZMTP client state machine (mock peer: malformed handshakes, disconnects, HWM) |
| `diff_oracle` | cpworker | Differential vs the **original C** implementation (persistent subprocess oracle); see `parity/difffuzz.sh` |

## Input formats

* `packet_split` / `config` / `vxlan`: raw bytes / UTF-8.
* `zmq_batch`: `service_tag(LE u32) | slice(u8) | uuid(16) | { caplen(BE u16) |
  direct(u8) | frame }*`.
* `sim_dst`: `seed(LE u64) | out(u8) | num_packets(u8) | slice(u8) |
  heartbeat(u8)`.

Hand-written seeds live in `seeds/<target>/` (copied into the ignored
`corpus/<target>/` by `fuzz.sh`). `seeds/zmq_batch/vlan_slice.bin` exercises the
safety guard added for upstream issue #231.

### Differential fuzzing (`diff_oracle`)

Unlike the other targets, `diff_oracle` compares Rust against the real
original code from `netis/cloud-probe`. The C modules run as a persistent
oracle subprocess; the fingerprint modes use a Go oracle (`parity/difffuzz/go/`).
It is driven by `parity/difffuzz.sh` (not `fuzz.sh`) because it needs those
sides compiled:

```bash
parity/difffuzz.sh 60 all          # all modes, 60s each
parity/difffuzz.sh 120 task_fingerprint
```

Modes:

| `DIFF_MODE` | Rust vs | Oracle protocol |
|---|---|---|
| `packet_split` | C `packet_split.c` | `c_harness.c --sentinel` |
| `config` | C `config.c` | `c_config.c --sentinel` |
| `req_pattern` | C `req_pattern.c` | `c_req_pattern.c --sentinel` |
| `fingerprint` | Go `pkg/common` | `difffuzz/go/oracle.go` (`L` prefix) |
| `task_fingerprint` | Go `pkg/worker` reflection | `difffuzz/go/oracle.go` (`J` prefix) |

`DIFF_ORACLE` points at the compiled oracle (`DIFF_C_ORACLE` also accepted).
Divergences abort the run and are written to `/tmp/difffuzz_last.txt`; known
intentional divergences (PARITY.md §2.2/§2.3) are classified and filtered so
the fuzzer keeps looking for new ones.
