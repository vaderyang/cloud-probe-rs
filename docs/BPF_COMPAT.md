# BPF Filter Compatibility Matrix

Bead **cloud-probe-rs-j36.1** ("field BPF expression distribution"). No field
config dump was available, so this document delivers the *capability* side: an
exact list of which libpcap/tcpdump filter primitives the pure-Rust compiler
(`crates/cpworker/src/bpf/`) accepts, how each compares with the C oracle, and
which expressions are guaranteed unsupported. Any field expression can be checked
against this matrix without a live CPM config.

## 1. What is compared

| Column | Meaning |
|---|---|
| **Rust** | `cpworker::bpf::compile()` accepts the construct and the compiler emits a cBPF program. |
| **Oracle** | The C reference compiles the construct. The oracle is **libpcap** `pcap_compile()` for `DLT_EN10MB` (`cpworker/src/libpcap.c:232`, `pcap_file.c:88`, `dpdk/pdump.c:63`); `bpf_util.c` only pre-expands `nic.<ifname>`. |
| **Parity** | Whether the *decisions* are byte-for-byte identical, checked by `parity/verify_bpf.sh` (libpcap `pcap_offline_filter` vs the Rust interpreter). |

The oracle rows were produced with `pcap_compile` on this box (libpcap from the
distro); see §6 to reproduce. "Yes" for Rust means the construct compiles **and**
is covered by an accept/reject frame in `crates/cpworker/tests/bpf_compat.rs`.

Legend: ✅ supported · ❌ hard error · ⚠️ supported by Rust but diverges from the
oracle · — not applicable.

## 2. Supported constructs (the whole "Rust = yes" grammar)

### 2.1 Boolean composition

| Construct | Syntax example | Rust | Oracle | Parity | Notes |
|---|---|---|---|---|---|
| AND | `tcp and port 80` | ✅ | ✅ | ✅ | `and` / `&&`, left-assoc |
| OR | `port 80 or port 443` | ✅ | ✅ | ✅ | `or` / `\|\|` |
| NOT | `not host 10.0.0.9` | ✅ | ✅ | ✅ | `not` / `!` |
| Grouping | `(port 80 or 443) and tcp` | ✅ | ✅ | ✅ | nesting ≤ 256 |
| Precedence | `ip or tcp and udp` | ✅ | ✅ | ✅ | `and` binds tighter than `or`, like tcpdump |
| Long jump chains | 50 × `not host …` | ✅ | ✅ | ✅ | conditional reach >255 uses a `JA` trampoline |

### 2.2 Protocol keywords

| Construct | Syntax example | Rust | Oracle | Parity | Notes |
|---|---|---|---|---|---|
| IPv4 | `ip` | ✅ | ✅ | ✅ | EtherType `0x0800` |
| IPv6 | `ip6` | ✅ | ✅ | ✅ | EtherType `0x86dd` |
| ARP | `arp` | ✅ | ✅ | ✅ | EtherType `0x0806` |
| RARP | `rarp` | ✅ | ✅ | ✅ | EtherType `0x8035` |
| TCP | `tcp` | ✅ | ✅ | ✅ | IPv4 + IPv6; follows an IPv6 fragment header |
| UDP | `udp` | ✅ | ✅ | ✅ | ditto |
| ICMPv4 | `icmp` | ✅ | ✅ | ✅ | IP proto 1 |
| ICMPv6 | `icmp6` | ✅ | ✅ | ✅ | IP proto 58; follows an IPv6 fragment header |
| IPv4 proto number | `ip proto 6` | ✅ | ✅ | ✅ | `0..=255`; out-of-range is an error |
| IPv6 proto number | `ip6 proto 17` | ✅ | ✅ | ✅ | follows an IPv6 fragment header, like libpcap |

### 2.3 Host / net

| Construct | Syntax example | Rust | Oracle | Parity | Notes |
|---|---|---|---|---|---|
| host | `host 10.0.0.1` | ✅ | ✅ | ✅ | IPv4 covers `ip` + ARP + RARP; IPv6 covers IPv6 |
| src / dst host | `src host 10.0.0.1`, `dst host fe80::1` | ✅ | ✅ | ✅ | |
| proto-qualified host | `ip host X`, `arp src host X`, `ip6 host X`, `rarp dst host X` | ✅ | ✅ | ✅ | qualifier must match the address family |
| host name | `host api.example.com` | ✅ | ✅ | ✅ | resolves to **every** A/AAAA answer (OR), capped at 64 |
| net prefix | `net 10.0.0.0/8`, `net 2001:db8::/32` | ✅ | ✅ | ✅ | for `arp`-less `net`, ARP/RARP protocol addresses are included |
| net mask | `net 10.0.0.0 mask 255.0.0.0` | ✅ | ✅ | ✅ | mask must be a literal address, never a name |
| net name | `net pool.example/24` | ✅ | ✅ | ✅ | expands to every answer, like `host` |
| net src/dst | `ip src net 10.0.0.0/8` | ✅ | ✅ | ✅ | |

### 2.4 Ports

| Construct | Syntax example | Rust | Oracle | Parity | Notes |
|---|---|---|---|---|---|
| bare port | `port 80` | ✅ | ✅ | ✅ | matches TCP, UDP **and SCTP** (like tcpdump) |
| tcp/udp port | `tcp port 80`, `udp port 53` | ✅ | ✅ | ✅ | |
| portrange | `portrange 1000-2000` | ✅ | ✅ | ✅ | inclusive; low ≤ high enforced |
| direction | `src port 80`, `tcp dst port 80` | ✅ | ✅ | ✅ | |
| tcp/udp portrange | `tcp dst portrange 70-90` | ✅ | ✅ | ✅ | |
| IPv4 options | `tcp port 80` on IHL > 5 | ✅ | ✅ | ✅ | L4 offset comes from the IHL nibble |
| IPv4 fragments | `port 80` on a non-first fragment | ✅ | ✅ | ✅ | rejected by the fragment-offset test, like libpcap |

### 2.5 Link layer

| Construct | Syntax example | Rust | Oracle | Parity | Notes |
|---|---|---|---|---|---|
| ether host | `ether host 00:11:22:33:44:55` | ✅ | ✅ | ✅ | either direction |
| ether src/dst | `ether src host …`, `ether dst host …` | ✅ | ✅ | ✅ | colon or dash separators |
| MAC with dash | `ether host aa-bb-cc-dd-ee-ff` | ✅ | ✅ | ✅ | |
| ether proto | `ether proto 0x0800`, `ether proto 2048`, `ether proto \ip` | ✅ | ✅ | ✅ | value > 1500 → `ldh [12]; jeq N`; value ≤ 1500 is treated as an 802.3 length (compares the LLC byte at offset 14), exactly like libpcap. Named escapes `\ip`/`\ip6`/`\arp`/`\rarp` supported (bead **57d**). |

### 2.6 `nic.<ifname>` tokens (pre-processing, not grammar)

| Construct | Rust | Oracle | Notes |
|---|---|---|---|
| `nic.<ifname>` in a filter | ✅ | ✅ | expanded to the interface address *before* compilation; see `netutil.rs` / `bpf_util.c`. Byte-for-byte token rules aligned with upstream #281. |

## 3. Gaps — accepted by the oracle, rejected by Rust

These are the constructs that must be flagged if a field expression uses them.
Each is locked by `unsupported_constructs_are_rejected` in
`tests/bpf_compat.rs`; the `#[ignore]`d `oracle_accepts_but_rust_rejects_today`
is the to-do list.

| Construct | Syntax example | Rust | Oracle | Notes / impact |
|---|---|---|---|---|
| VLAN | `vlan`, `vlan 100`, `vlan and tcp` | ❌ | ✅ | **field-relevant**: trunk/SPAN captures. Note: on a real NIC, non-promiscuous capture already *drops* unregistered-VLAN frames before BPF (`FIELD_CONFIRMATION.md` §2/§4). |
| MPLS | `mpls`, `mpls and ip` | ❌ | ✅ | |
| PPPoE session | `pppoes` | ❌ | ✅ | |
| Length comparisons | `greater 64`, `less 64`, `len > 64`, `len >= 64`, `len = 64`, `len != 64` | ❌ | ✅ | |
| Byte access | `ether[0] = 0`, `ip[0] & 0xf = 5`, `tcp[13] & 2 != 0`, `icmp[0] = 8`, `ip6[6] = 6` | ❌ | ✅ | raw offset loads |
| Proto chain | `protochain 6`, `ip6 protochain 6` | ❌ | ✅ | walks extension headers |
| Bare proto | `proto 6` | ❌ | ✅ | |
| Combined direction | `src or dst port 80`, `src and dst host 1.2.3.4`, `dst or src net …` | ❌ | ✅ | only one leading `src`/`dst` is parsed |
| Classful net | `net 10.0.0.0` (no `/prefix`, no `mask`) | ❌ | ✅ | Rust requires an explicit prefix or mask |
| Multicast/broadcast | `broadcast`, `multicast`, `ip multicast`, `ip6 multicast`, `ether broadcast` | ❌ | ✅ | `ip broadcast` needs a known netmask; not tested here |
| Arithmetic | `ether[0] + 1 = 2`, `len + 0 > 64` | ❌ | ✅ | |
| Direction before proto | `src tcp`, `tcp src` | ❌ | ❌ | no gap: libpcap rejects them too |

Unsupported constructs fail with a clear error (`,` never silently compile to a
filter with different semantics). Examples: `unsupported filter keyword 'vlan'`,
`expected 'host' after 'ether'`, `net '10.0.0.0' needs a /prefix or an explicit 'mask'`.

## 4. Rust-only supersets (oracle rejects, Rust accepts)

Behavioural divergence in the other direction. These are deliberate, documented
extensions — a config using them would fail on the C worker and work here — so a
field expression that must be portable should avoid them. Locked by
`rust_superset_forms_the_oracle_rejects`.

| Construct | Syntax example | Rust | Oracle | Notes |
|---|---|---|---|---|
| `ipv6` alias | `ipv6`, `ipv6 host fe80::1` | ✅ | ❌ | Rust accepts `ipv6`/`icmpv6`; libpcap only knows `ip6`/`icmp6` |
| `icmpv6` alias | `icmpv6` | ✅ | ❌ | ditto |
| Non-canonical net | `net 10.1.2.3/8` | ✅ | ❌ | Rust masks the host bits; libpcap errors `non-network bits set` |
| Zero-width prefix | `net 10.0.0.0/0` | ✅ | ❌ | Rust treats it as `0.0.0.0/0`; libpcap rejects it |

## 5. How to check a field expression

```bash
# Rust: compile only (fast; names resolve via the system resolver)
cargo run -q -p cpworker-parity --bin bpf_eval -- <exprs.txt> <pkts.txt>

# Oracle: compile with libpcap
cc -O2 -o /tmp/c_bpf parity/c_bpf.c -lpcap
/tmp/c_bpf <exprs.txt> <pkts.txt>

# Full differential over a seeded random corpus (expressions × frames)
bash parity/verify_bpf.sh [seed] [n_pkts] [n_exprs]
```

`bpf_eval` prints `OK <bits>` (one bit per packet) or `ERR <message>`; the
oracle prints the same shape. A field expression that is `ERR` here and not in
§3 (or vice versa) is a new finding.

## 6. Reproducing the oracle column

A one-liner with `pcap_open_dead(DLT_EN10MB, …)` + `pcap_compile`, e.g.
`tcpdump -ddd -i eth0 '<expr>'` (tcpdump uses the same libpcap compiler), reports
the same accept/reject verdict.

## 7. Enforcement

| Matrix section | Test |
|---|---|
| §2 all "yes" rows | `crates/cpworker/tests/bpf_compat.rs::matrix_yes_rows_accept_and_reject` (accept + reject frame per row) |
| §3 all "no" rows (today) | `unsupported_constructs_are_rejected` |
| §3 as future work | `oracle_accepts_but_rust_rejects_today` (`#[ignore]`) |
| §4 supersets | `rust_superset_forms_the_oracle_rejects` |
| Long chains | `long_not_host_chain_uses_trampolines_and_filters_correctly` |

Beyond the matrix, `parity/verify_bpf.sh` performs the full random differential
against libpcap (default: 80 expressions × 400 frames, seed `20260927`); it is
green on the supported grammar across seeds `20260927`, `1`, `7`, `12345`.

> Note: the parser already hard-errors outside the §2 grammar (the audit
> requirement is "never silently compile to a different filter"). The only
> divergence left is §4, which is more permissive, not a mis-compilation.

See also [`PARITY.md` §4](../PARITY.md#bpf-子集cratescpworkersrcbpf) and
[`FIELD_CONFIRMATION.md` §1](../FIELD_CONFIRMATION.md).
