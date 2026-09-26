# cpworker: C vs Rust — benchmark results

Generated: 2026-09-26 09:58:29

Machine: 4 cores, Intel(R) Core(TM) M-5Y31 CPU @ 0.90GHz, 7.7 GiB RAM, Linux 6.14.0-37-generic

Workload: 1000000 packets (417.1 MB) replayed from a PCAP file; median of 5 runs (after a warmup).


| Scenario | Impl | Throughput (pps) | Throughput (MB/s) | Time (s) | Peak RSS (MB) |
|---|---|---:|---:|---:|---:|
| null | C | 2.83 M | 1181.4 | 0.353 | 7.1 |
| null | Rust | 3.05 M | 1272.6 | 0.328 | 6.5 |
| file | C | 1.16 M | 484.9 | 0.860 | 7.1 |
| file | Rust | 1.27 M | 531.7 | 0.784 | 6.4 |
| vxlan-split | C | 0.10 M | 43.0 | 9.692 | 7.1 |
| vxlan-split | Rust | 0.10 M | 41.1 | 10.159 | 6.6 |
