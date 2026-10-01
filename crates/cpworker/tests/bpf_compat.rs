//! Regression suite for the BPF compatibility matrix in `docs/BPF_COMPAT.md`.
//!
//! The matrix must not rot into prose: every **yes** row is a table entry with a
//! frame the expression must *accept* and one it must *reject*, so a wrong load
//! offset, constant or jump distance changes the verdict. The **no** rows are
//! locked by [`unsupported_constructs_are_rejected`]; the constructs libpcap
//! accepts but this port does not are additionally listed in the `#[ignore]`d
//! [`oracle_accepts_but_rust_rejects_today`] (un-ignore it when one is
//! implemented), and the deliberate Rust-superset forms the oracle rejects are
//! locked by [`rust_superset_forms_the_oracle_rejects`].
//!
//! Frames are built byte-for-byte to the documented wire layout so each verdict
//! is a real behavioural assertion, not a parse-only check.

use cpworker::bpf;

// ---------------------------------------------------------------------------
// Frame builders (Ethernet / IPv4 / IPv6 / ARP).
// ---------------------------------------------------------------------------

const MAC_SRC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_DST: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

fn eth(ethertype: u16) -> Vec<u8> {
    let mut p = vec![0u8; 14];
    p[12..14].copy_from_slice(&ethertype.to_be_bytes());
    p
}

fn tcp_l4(sport: u16, dport: u16) -> Vec<u8> {
    let mut l4 = vec![0u8; 20];
    l4[0..2].copy_from_slice(&sport.to_be_bytes());
    l4[2..4].copy_from_slice(&dport.to_be_bytes());
    l4
}

fn udp_l4(sport: u16, dport: u16) -> Vec<u8> {
    let mut l4 = vec![0u8; 8];
    l4[0..2].copy_from_slice(&sport.to_be_bytes());
    l4[2..4].copy_from_slice(&dport.to_be_bytes());
    l4
}

/// IPv4 frame with `opt_bytes` bytes of header options (must be a multiple of 4).
fn ipv4_ihl(src: [u8; 4], dst: [u8; 4], proto: u8, opt_bytes: usize, l4: &[u8]) -> Vec<u8> {
    let ihl = 5 + opt_bytes / 4;
    let mut p = eth(0x0800);
    let mut ip = vec![0u8; 20 + opt_bytes];
    ip[0] = (4 << 4) | u8::try_from(ihl).expect("IHL fits in 4 bits for test frames");
    ip[9] = proto;
    ip[12..16].copy_from_slice(&src);
    ip[16..20].copy_from_slice(&dst);
    p.extend_from_slice(&ip);
    p.extend_from_slice(l4);
    p
}

fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    ipv4_ihl(src, dst, proto, 0, l4)
}

fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, l4: &[u8]) -> Vec<u8> {
    let mut p = eth(0x86dd);
    let mut ip = [0u8; 40];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(
        &u16::try_from(l4.len())
            .expect("test L4 fits in u16")
            .to_be_bytes(),
    );
    ip[6] = next;
    ip[7] = 64; // hop limit
    ip[8..24].copy_from_slice(&src);
    ip[24..40].copy_from_slice(&dst);
    p.extend_from_slice(&ip);
    p.extend_from_slice(l4);
    p
}

/// IPv6 frame carrying a fragment header (`next = 44`) whose inner next-header is
/// `inner`, followed by `l4`.
fn ipv6_frag(inner: u8, l4: &[u8]) -> Vec<u8> {
    let mut fh = vec![0u8; 8];
    fh[0] = inner;
    fh.extend_from_slice(l4);
    ipv6(
        v6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        v6(0xfe80, 0, 0, 0, 0, 0, 0, 2),
        44,
        &fh,
    )
}

#[allow(clippy::too_many_arguments)]
fn v6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, w) in [a, b, c, d, e, f, g, h].iter().enumerate() {
        out[2 * i..2 * i + 2].copy_from_slice(&w.to_be_bytes());
    }
    out
}

fn arp(ethertype: u16, oper: u16, spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
    let mut p = eth(ethertype);
    let mut a = [0u8; 28];
    a[0..2].copy_from_slice(&1u16.to_be_bytes()); // htype = Ethernet
    a[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype = IPv4
    a[4] = 6; // hlen
    a[5] = 4; // plen
    a[6..8].copy_from_slice(&oper.to_be_bytes());
    a[14..18].copy_from_slice(&spa); // sender protocol address
    a[24..28].copy_from_slice(&tpa); // target protocol address
    p.extend_from_slice(&a);
    p
}

/// The named corpus the table below draws on.
struct Frames {
    v4_tcp: Vec<u8>,
    v4_tcp_other: Vec<u8>,
    v4_udp: Vec<u8>,
    v4_icmp: Vec<u8>,
    v4_sctp: Vec<u8>,
    v4_ihl6_tcp: Vec<u8>,
    net192: Vec<u8>,
    v6_tcp: Vec<u8>,
    v6_udp: Vec<u8>,
    v6_icmp6: Vec<u8>,
    v6_db8_tcp: Vec<u8>,
    v6_frag_tcp: Vec<u8>,
    v6_frag_udp: Vec<u8>,
    arp: Vec<u8>,
    arp_10: Vec<u8>,
    rarp: Vec<u8>,
    mac: Vec<u8>,
}

impl Frames {
    fn new() -> Self {
        let mut mac = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, &tcp_l4(1234, 80));
        mac[0..6].copy_from_slice(&MAC_DST);
        mac[6..12].copy_from_slice(&MAC_SRC);
        Self {
            v4_tcp: ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, &tcp_l4(1234, 80)),
            v4_tcp_other: ipv4([10, 0, 0, 9], [10, 0, 0, 8], 6, &tcp_l4(1, 2)),
            v4_udp: ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp_l4(53, 53)),
            v4_icmp: ipv4([10, 0, 0, 1], [10, 0, 0, 2], 1, &[0u8; 8]),
            v4_sctp: ipv4([10, 0, 0, 1], [10, 0, 0, 2], 132, &tcp_l4(1, 9999)),
            v4_ihl6_tcp: ipv4_ihl([10, 0, 0, 1], [10, 0, 0, 2], 6, 4, &tcp_l4(1111, 2222)),
            net192: ipv4([192, 168, 1, 1], [192, 168, 1, 2], 6, &tcp_l4(1, 2)),
            v6_tcp: ipv6(
                v6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                v6(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                6,
                &tcp_l4(1111, 2222),
            ),
            v6_udp: ipv6(
                v6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                v6(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                17,
                &udp_l4(53, 53),
            ),
            v6_icmp6: ipv6(
                v6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                v6(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                58,
                &[0u8; 8],
            ),
            v6_db8_tcp: ipv6(
                v6(0x2001, 0x0db8, 0x1234, 0, 0, 0, 0, 1),
                v6(0x2001, 0x0db8, 0xabcd, 0, 0, 0, 0, 2),
                6,
                &tcp_l4(1, 2),
            ),
            v6_frag_tcp: ipv6_frag(6, &tcp_l4(1111, 2222)),
            v6_frag_udp: ipv6_frag(17, &udp_l4(53, 53)),
            arp: arp(0x0806, 1, [192, 0, 2, 1], [192, 0, 2, 2]),
            arp_10: arp(0x0806, 1, [10, 0, 0, 1], [10, 0, 0, 2]),
            rarp: arp(0x8035, 3, [198, 51, 100, 7], [198, 51, 100, 8]),
            mac,
        }
    }
}

/// Every **yes** row of `docs/BPF_COMPAT.md`, with one accept and one reject
/// frame. A compile failure is a failure too: "supported" means it must compile.
#[test]
fn matrix_yes_rows_accept_and_reject() {
    let f = Frames::new();
    let cases: &[(&str, &[u8], &[u8])] = &[
        // -- protocol keywords: EtherType / L4 chain ----------------------
        ("ip", &f.v4_tcp, &f.v6_tcp),
        ("ip6", &f.v6_tcp, &f.v4_tcp),
        ("arp", &f.arp, &f.rarp),
        ("rarp", &f.rarp, &f.arp),
        ("tcp", &f.v4_tcp, &f.v4_udp),
        ("udp", &f.v4_udp, &f.v4_tcp),
        ("icmp", &f.v4_icmp, &f.v6_icmp6),
        ("icmp6", &f.v6_icmp6, &f.v4_icmp),
        // -- ether proto (bead 57d): value > 1500 compares the ethertype ---
        ("ether proto 0x0800", &f.v4_tcp, &f.v6_tcp),
        ("ether proto 0x86dd", &f.v6_tcp, &f.v4_tcp),
        ("ether proto \\ip", &f.v4_tcp, &f.v6_tcp),
        ("ether proto 0x8035", &f.rarp, &f.v4_tcp),
        // IPv6 fragment header: `tcp` follows next-header 44 -> 6.
        ("tcp", &f.v6_frag_tcp, &f.v6_frag_udp),
        ("udp", &f.v6_frag_udp, &f.v6_frag_tcp),
        // -- host (IPv4 + ARP/RARP, IPv6) ---------------------------------
        ("host 10.0.0.1", &f.v4_tcp, &f.v4_tcp_other),
        ("src host 10.0.0.1", &f.v4_tcp, &f.v4_tcp_other),
        ("dst host 10.0.0.2", &f.v4_tcp, &f.v4_tcp_other),
        ("host 192.0.2.1", &f.arp, &f.v4_tcp),
        ("host fe80::1", &f.v6_tcp, &f.v4_tcp),
        ("src host fe80::1", &f.v6_tcp, &f.v6_db8_tcp),
        ("dst host fe80::2", &f.v6_tcp, &f.v6_db8_tcp),
        ("ip host 10.0.0.1", &f.v4_tcp, &f.arp_10),
        ("arp host 10.0.0.1", &f.arp_10, &f.v4_tcp),
        ("arp src host 10.0.0.1", &f.arp_10, &f.v4_tcp),
        ("arp dst host 10.0.0.2", &f.arp_10, &f.v4_tcp),
        ("rarp src host 198.51.100.7", &f.rarp, &f.v4_tcp),
        ("ip6 host fe80::1", &f.v6_tcp, &f.v6_db8_tcp),
        // -- net: prefix, explicit mask, ARP inclusion, IPv6 --------------
        ("net 10.0.0.0/8", &f.v4_tcp, &f.net192),
        ("net 192.168.0.0/16", &f.net192, &f.v4_tcp),
        ("net 10.0.0.0 mask 255.0.0.0", &f.v4_tcp, &f.net192),
        ("net 10.0.0.0/8", &f.arp_10, &f.arp),
        ("ip src net 10.0.0.0/8", &f.v4_tcp, &f.net192),
        ("ip dst net 10.0.0.0/8", &f.v4_tcp, &f.net192),
        ("net 2001:db8::/32", &f.v6_db8_tcp, &f.v6_tcp),
        ("ip6 src net 2001:db8::/32", &f.v6_db8_tcp, &f.v6_tcp),
        // -- port / portrange, direction, SCTP, IPv4 IHL options ----------
        ("port 80", &f.v4_tcp, &f.v4_udp),
        ("port 9999", &f.v4_sctp, &f.v4_tcp),
        ("tcp port 80", &f.v4_tcp, &f.v4_udp),
        ("udp port 53", &f.v4_udp, &f.v4_tcp),
        ("src port 1234", &f.v4_tcp, &f.v4_tcp_other),
        ("dst port 80", &f.v4_tcp, &f.v4_tcp_other),
        ("tcp dst port 80", &f.v4_tcp, &f.v4_tcp_other),
        ("udp src port 53", &f.v4_udp, &f.v4_tcp),
        ("portrange 70-90", &f.v4_tcp, &f.v4_tcp_other),
        ("tcp dst portrange 70-90", &f.v4_tcp, &f.v4_udp),
        // A non-zero IPv4 IHL must move the L4 offset, not break the match.
        ("tcp src port 1111", &f.v4_ihl6_tcp, &f.v4_tcp),
        ("port 2222", &f.v4_ihl6_tcp, &f.v4_tcp),
        // -- ether host ---------------------------------------------------
        ("ether host aa:bb:cc:dd:ee:ff", &f.mac, &f.v4_tcp),
        ("ether src host 00:11:22:33:44:55", &f.mac, &f.v4_tcp),
        ("ether dst host aa:bb:cc:dd:ee:ff", &f.mac, &f.v4_tcp),
        // -- ip/ip6 proto ------------------------------------------------
        ("ip proto 6", &f.v4_tcp, &f.v4_udp),
        ("ip proto 132", &f.v4_sctp, &f.v4_tcp),
        ("ip6 proto 17", &f.v6_udp, &f.v6_tcp),
        ("ip6 proto 58", &f.v6_icmp6, &f.v6_tcp),
        ("ip6 proto 6", &f.v6_frag_tcp, &f.v6_frag_udp),
        // -- boolean structure and aliases -------------------------------
        ("ip and tcp", &f.v4_tcp, &f.v4_udp),
        ("ip && tcp", &f.v4_tcp, &f.v4_udp),
        ("ip or udp", &f.v4_udp, &f.v6_tcp),
        ("ip || udp", &f.v4_udp, &f.v6_tcp),
        ("not host 10.0.0.9", &f.v4_tcp, &f.v4_tcp_other),
        ("!ip", &f.v6_tcp, &f.v4_tcp),
        ("(port 80 or port 443) and tcp", &f.v4_tcp, &f.v4_udp),
        ("not (host 10.0.0.1 or host 10.0.0.9)", &f.net192, &f.v4_tcp),
    ];

    for (expr, accept, reject) in cases {
        let prog = bpf::compile(expr).unwrap_or_else(|e| panic!("`{expr}` must compile: {e}"));
        assert!(
            prog.apply(accept),
            "`{expr}` must accept the matching frame; insns={}",
            prog.insns.len()
        );
        assert!(
            !prog.apply(reject),
            "`{expr}` must reject the non-matching frame; insns={}",
            prog.insns.len()
        );
    }
}

/// The `#[ignore]`d counterpart to the matrix's **no** rows: these are the
/// constructs libpcap (the oracle) accepts but this port rejects today. The test
/// asserts acceptance, so it is intentionally red until the feature lands —
/// un-ignore it (and flip the doc row to **yes**) when implementing one.
///
/// Run explicitly with `cargo test -p cpworker --test bpf_compat -- --ignored`.
#[test]
#[ignore = "expected-unsupported: libpcap accepts these; Rust rejects them (docs/BPF_COMPAT.md)"]
fn oracle_accepts_but_rust_rejects_today() {
    for expr in [
        "vlan 100",
        "vlan",
        "mpls",
        "pppoes",
        "greater 64",
        "less 64",
        "len > 64",
        "len >= 64",
        "len = 64",
        "len != 64",
        "ether[0] = 0",
        "ip[0] & 0xf = 5",
        "tcp[13] & 2 != 0",
        "icmp[0] = 8",
        "protochain 6",
        "ip6 protochain 6",
        "proto 6",
        "src or dst port 80",
        "src and dst host 1.2.3.4",
        "net 10.0.0.0",
        "broadcast",
        "multicast",
        "ip multicast",
        "ether broadcast",
    ] {
        assert!(
            bpf::compile(expr).is_ok(),
            "`{expr}` is accepted by libpcap and is not implemented yet"
        );
    }
}

/// The **no** rows of the matrix as enforced today: every construct the oracle
/// accepts but this port does not must fail loudly (never silently compile to a
/// different filter). `src tcp` / `tcp src` are included because libpcap rejects
/// them too — no compatibility gap there, just a shared restriction.
#[test]
fn unsupported_constructs_are_rejected() {
    for expr in [
        "vlan 100",
        "vlan",
        "mpls",
        "pppoes",
        "greater 64",
        "less 64",
        "len > 64",
        "len >= 64",
        "len = 64",
        "len != 64",
        "ether[0] = 0",
        "ip[0] & 0xf = 5",
        "tcp[13] & 2 != 0",
        "icmp[0] = 8",
        "protochain 6",
        "ip6 protochain 6",
        "proto 6",
        "src or dst port 80",
        "src and dst host 1.2.3.4",
        "net 10.0.0.0",
        "broadcast",
        "multicast",
        "ip multicast",
        "ether broadcast",
        "src tcp",
        "tcp src",
    ] {
        let err = bpf::compile(expr)
            .err()
            .unwrap_or_else(|| panic!("`{expr}` must be rejected, but it compiled"));
        assert!(
            !err.to_string().is_empty(),
            "`{expr}` must report why it was rejected"
        );
    }
}

/// Deliberate Rust supersets: these compile here but libpcap rejects them. They
/// are documented divergences (not silent mis-compiles) and must keep compiling
/// so the matrix's "oracle parity = Rust-only" rows are enforced.
#[test]
fn rust_superset_forms_the_oracle_rejects() {
    let f = Frames::new();
    for (expr, accept, reject) in [
        // `ipv6` / `icmpv6` aliases (libpcap only knows `ip6` / `icmp6`).
        ("ipv6", &f.v6_tcp, &f.v4_tcp),
        ("icmpv6", &f.v6_icmp6, &f.v4_icmp),
        // A non-canonical network address: Rust masks it, libpcap errors with
        // "non-network bits set".
        ("net 10.1.2.3/8", &f.v4_tcp, &f.net192),
        // A zero-width prefix: Rust accepts it, libpcap rejects it.
        ("net 10.0.0.0/0", &f.v4_tcp, &f.v6_tcp),
    ] {
        let prog = bpf::compile(expr).unwrap_or_else(|e| panic!("`{expr}` must compile: {e}"));
        assert!(prog.apply(accept), "`{expr}` must accept the frame");
        assert!(!prog.apply(reject), "`{expr}` must reject the frame");
    }
}

/// The long-jump-chain **yes** row: a `not host` chain past the 255-instruction
/// conditional reach exercises the `JA` trampoline path and must still filter
/// correctly.
#[test]
fn long_not_host_chain_uses_trampolines_and_filters_correctly() {
    let expr = (0..50u8)
        .map(|i| format!("not host 10.9.0.{i}"))
        .collect::<Vec<_>>()
        .join(" and ");
    let prog = bpf::compile(&expr).expect("long chain compiles");
    assert!(
        prog.insns.iter().any(|i| i.code == JMP_JA),
        "a 50-host exclusion chain must use a JA trampoline"
    );
    let excluded = ipv4([10, 0, 0, 1], [10, 9, 0, 7], 6, &tcp_l4(1, 2));
    let allowed = ipv4([10, 0, 0, 1], [10, 9, 0, 200], 6, &tcp_l4(1, 2));
    assert!(!prog.apply(&excluded));
    assert!(prog.apply(&allowed));
}

/// Guard against the table silently accepting a frame that only matches because
/// a shorter-than-14-byte frame terminates the interpreter with a drop: every
/// frame the table uses must be a full Ethernet frame.
#[test]
fn corpus_frames_are_well_formed() {
    let f = Frames::new();
    for (name, frame) in [
        ("v4_tcp", &f.v4_tcp),
        ("v4_tcp_other", &f.v4_tcp_other),
        ("v4_udp", &f.v4_udp),
        ("v4_icmp", &f.v4_icmp),
        ("v4_sctp", &f.v4_sctp),
        ("v4_ihl6_tcp", &f.v4_ihl6_tcp),
        ("net192", &f.net192),
        ("v6_tcp", &f.v6_tcp),
        ("v6_udp", &f.v6_udp),
        ("v6_icmp6", &f.v6_icmp6),
        ("v6_db8_tcp", &f.v6_db8_tcp),
        ("v6_frag_tcp", &f.v6_frag_tcp),
        ("v6_frag_udp", &f.v6_frag_udp),
        ("arp", &f.arp),
        ("arp_10", &f.arp_10),
        ("rarp", &f.rarp),
        ("mac", &f.mac),
    ] {
        assert!(frame.len() >= 42, "{name} must carry Ethernet + IP + L4");
    }
}

// Re-exported so the test's trampoline assertion uses the real opcode rather
// than a magic number. `cpworker::bpf` does not expose `codes`, so pin the value
// the compiler emits (`JMP_JA == 0x05`, matching Linux `struct sock_filter`).
const JMP_JA: u16 = 0x05;
