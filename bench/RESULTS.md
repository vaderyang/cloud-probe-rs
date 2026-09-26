# cpworker: C vs Rust — benchmark results

Generated: 2026-09-26 08:33:43

Machine: 4 cores, Intel(R) Core(TM) M-5Y31 CPU @ 0.90GHz, 7.7 GiB RAM, Linux 6.14.0-37-generic

Workload: 1000000 packets (417.5 MB) replayed from a PCAP file; median of 3 runs (after a warmup).


| Scenario | Impl | Throughput (pps) | Throughput (MB/s) | Time (s) | Peak RSS (MB) |
|---|---|---:|---:|---:|---:|
| null | C | 3.23 M | 1350.2 | 0.309 | 7.0 |
| null | Rust | 2.57 M | 1074.6 | 0.389 | 6.4 |
| file | C | 1.28 M | 535.8 | 0.779 | 7.0 |
| file | Rust | 1.23 M | 512.7 | 0.814 | 6.4 |
| vxlan-split | C | 0.13 M | 53.2 | 7.854 | 7.1 |
| vxlan-split | Rust | 0.12 M | 51.9 | 8.039 | 6.5 |
