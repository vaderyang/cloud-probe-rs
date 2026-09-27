# cpworker: C vs Rust — benchmark results

Generated: 2026-09-27 19:58:44

Machine: 4 cores, Intel(R) Core(TM) M-5Y31 CPU @ 0.90GHz, 7.7 GiB RAM, Linux 7.0.0-34-generic

Workload: 1000000 packets (417.1 MB) replayed from a PCAP file; median of 5 runs (after a warmup).


| Scenario | Impl | Throughput (pps) | Throughput (MB/s) | Time (s) | Peak RSS (MB) |
|---|---|---:|---:|---:|---:|
| null | C | 3.30 M | 1374.8 | 0.303 | 7.3 |
| null | Rust | 4.98 M | 2077.0 | 0.201 | 2.8 |
| file | C | 1.36 M | 565.4 | 0.738 | 7.3 |
| file | Rust | 1.82 M | 759.1 | 0.549 | 2.8 |
| vxlan-split | C | 0.11 M | 44.5 | 9.373 | 7.3 |
| vxlan-split | Rust | 0.11 M | 46.4 | 8.995 | 2.9 |
