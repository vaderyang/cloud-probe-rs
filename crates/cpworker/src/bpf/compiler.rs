//! Lowering and code generation from the parsed [`Ast`] to classic BPF.
//!
//! Every atomic test is *self-contained*: it re-checks the link-layer ethertype
//! (and, for ports, the IP header length / fragment bits) so the boolean
//! structure can be assembled purely from `and` / `or` / `not`. This mirrors
//! what tcpdump generates and keeps the emitter simple.

use std::net::IpAddr;

use crate::error::{Error, Result};

use super::codes::*;
use super::parser::{Ast, Dir, PortSpec, Proto, L4};
use super::{Insn, Program};

/// Verdict returned when the filter matches. Any non-zero value accepts; a
/// value >= the packet length lets the whole frame through.
const ACCEPT: u32 = 0x40000;

/// Ethernet IPv4 ethertype.
const ETH_IP: u32 = 0x0800;
/// Ethernet IPv6 ethertype.
const ETH_IP6: u32 = 0x86dd;
/// Ethernet ARP ethertype.
const ETH_ARP: u32 = 0x0806;
/// Ethernet RARP ethertype.
const ETH_RARP: u32 = 0x8035;
/// Largest value libpcap treats as an 802.3 *length* field rather than an
/// ethertype (`0x05dc` = 1500). See [`Builder::emit_test`] for `EtherType`.
const ETHERNET_8023_MAX: u32 = 0x05dc;
/// IPv6 fragment-header next-header value.
const IPPROTO_FRAGMENT: u32 = 0x2c;
/// IPv4 fragment-offset mask in the flags/fragment field.
const IPV4_FRAG_MASK: u32 = 0x1fff;

/// Normalized boolean tree. Leaves are [`Test`]s.
#[derive(Debug)]
enum NExpr {
    And(Box<NExpr>, Box<NExpr>),
    Or(Box<NExpr>, Box<NExpr>),
    Not(Box<NExpr>),
    Test(Test),
}

/// A self-contained atomic packet test.
#[derive(Debug)]
enum Test {
    EtherType(u32),
    EtherHost {
        off: u16,
        mac: [u8; 6],
    },
    IpV4 {
        off: u16,
        addr: [u8; 4],
        mask: [u8; 4],
    },
    IpV6 {
        off: u16,
        addr: [u8; 16],
        mask: [u8; 16],
    },
    Arp {
        ethertype: u16,
        off: u16,
        addr: [u8; 4],
        mask: [u8; 4],
    },
    L4Proto {
        v6: bool,
        proto: u8,
        frag: bool,
    },
    Port {
        v6: bool,
        proto: u8,
        off: u16,
        spec: PortSpec,
    },
}

fn t(x: Test) -> NExpr {
    NExpr::Test(x)
}

fn or(a: NExpr, b: NExpr) -> NExpr {
    NExpr::Or(Box::new(a), Box::new(b))
}

fn and(a: NExpr, b: NExpr) -> NExpr {
    NExpr::And(Box::new(a), Box::new(b))
}

/// Fold atomic tests into an `or` chain.
///
/// An empty list is reported as an error instead of panicking (AUDIT4 P5-23):
/// the release profile uses `panic = "abort"`, so a panic anywhere on the
/// filter-compilation path - which is driven by config files, CPM task updates
/// and SIGHUP reloads - would take the whole worker down instead of failing the
/// one task. Callers keep the `Result` so the failure surfaces as a filter
/// error naming the expression.
fn or_all(v: Vec<NExpr>) -> Result<NExpr> {
    let mut it = v.into_iter();
    // Every current caller passes a fixed, non-empty set of alternatives, so the
    // Err arm below is an internal-invariant violation. It stays an error rather
    // than a debug_assert: the message says so, and a future caller that gets it
    // wrong fails its own task visibly in *every* profile instead of aborting
    // the worker in release.
    let Some(first) = it.next() else {
        return Err(Error::new(
            "bpf: internal lowering error (empty alternative list)",
        ));
    };
    Ok(it.fold(first, or))
}

/// Compile a parsed expression into a cBPF [`Program`].
///
/// # Errors
/// Returns an error for address/protocol mismatches or if the generated program
/// exceeds the cBPF branch-distance limit.
pub fn compile_ast(ast: &Ast) -> Result<Program> {
    let lowered = lower(ast)?;
    let mut b = Builder::default();
    let m = b.new_label();
    let n = b.new_label();
    b.compile(&lowered, m, n)?;
    b.bind(m);
    b.emit(RET_K, ACCEPT);
    b.bind(n);
    b.emit(RET_K, 0);
    b.finish()
}

fn lower(ast: &Ast) -> Result<NExpr> {
    Ok(match ast {
        Ast::And(a, b) => and(lower(a)?, lower(b)?),
        Ast::Or(a, b) => or(lower(a)?, lower(b)?),
        Ast::Not(a) => NExpr::Not(Box::new(lower(a)?)),
        Ast::Proto(p) => lower_proto(*p),
        Ast::EtherProto { ethertype } => t(Test::EtherType(*ethertype)),
        Ast::IpProto { v6, num } => t(Test::L4Proto {
            v6: *v6,
            proto: *num,
            frag: *v6,
        }),
        Ast::EtherHost { dir, mac } => lower_ether(*dir, *mac),
        Ast::Host { dir, proto, addr } => lower_host(*dir, *proto, *addr)?,
        Ast::Net {
            dir,
            proto,
            addr,
            mask,
        } => lower_net(*dir, *proto, *addr, *mask)?,
        Ast::Port { dir, l4, spec } => lower_port(*dir, *l4, *spec)?,
    })
}

fn lower_proto(p: Proto) -> NExpr {
    match p {
        Proto::Ip => t(Test::EtherType(ETH_IP)),
        Proto::Ip6 => t(Test::EtherType(ETH_IP6)),
        Proto::Arp => t(Test::EtherType(ETH_ARP)),
        Proto::Rarp => t(Test::EtherType(ETH_RARP)),
        Proto::Tcp => or(
            t(Test::L4Proto {
                v6: false,
                proto: 6,
                frag: false,
            }),
            t(Test::L4Proto {
                v6: true,
                proto: 6,
                frag: true,
            }),
        ),
        Proto::Udp => or(
            t(Test::L4Proto {
                v6: false,
                proto: 17,
                frag: false,
            }),
            t(Test::L4Proto {
                v6: true,
                proto: 17,
                frag: true,
            }),
        ),
        Proto::Icmp => t(Test::L4Proto {
            v6: false,
            proto: 1,
            frag: false,
        }),
        Proto::Icmp6 => t(Test::L4Proto {
            v6: true,
            proto: 58,
            frag: true,
        }),
    }
}

fn lower_ether(dir: Dir, mac: [u8; 6]) -> NExpr {
    match dir {
        Dir::Src => t(Test::EtherHost { off: 6, mac }),
        Dir::Dst => t(Test::EtherHost { off: 0, mac }),
        Dir::Either => or(
            t(Test::EtherHost { off: 6, mac }),
            t(Test::EtherHost { off: 0, mac }),
        ),
    }
}

fn full4() -> [u8; 4] {
    [0xff; 4]
}

fn ipv4(a: [u8; 4], dir: Dir) -> NExpr {
    let mk = |off: u16| {
        t(Test::IpV4 {
            off,
            addr: a,
            mask: full4(),
        })
    };
    match dir {
        Dir::Src => mk(26),
        Dir::Dst => mk(30),
        Dir::Either => or(mk(26), mk(30)),
    }
}

fn ipv6(a: [u8; 16], dir: Dir) -> NExpr {
    let mk = |off: u16| {
        t(Test::IpV6 {
            off,
            addr: a,
            mask: [0xff; 16],
        })
    };
    match dir {
        Dir::Src => mk(22),
        Dir::Dst => mk(38),
        Dir::Either => or(mk(22), mk(38)),
    }
}

fn arp(ethertype: u16, a: [u8; 4], dir: Dir) -> NExpr {
    let mk = |off: u16| {
        t(Test::Arp {
            ethertype,
            off,
            addr: a,
            mask: full4(),
        })
    };
    match dir {
        Dir::Src => mk(28),
        Dir::Dst => mk(38),
        Dir::Either => or(mk(28), mk(38)),
    }
}

fn lower_host(dir: Dir, proto: Option<Proto>, addr: IpAddr) -> Result<NExpr> {
    match (proto, addr) {
        (None, IpAddr::V4(a)) => or_all(vec![
            ipv4(a.octets(), dir),
            arp(ETH_ARP as u16, a.octets(), dir),
            arp(ETH_RARP as u16, a.octets(), dir),
        ]),
        (None, IpAddr::V6(a)) => Ok(ipv6(a.octets(), dir)),
        (Some(Proto::Ip), IpAddr::V4(a)) => Ok(ipv4(a.octets(), dir)),
        (Some(Proto::Ip6), IpAddr::V6(a)) => Ok(ipv6(a.octets(), dir)),
        (Some(Proto::Arp), IpAddr::V4(a)) => Ok(arp(ETH_ARP as u16, a.octets(), dir)),
        (Some(Proto::Rarp), IpAddr::V4(a)) => Ok(arp(ETH_RARP as u16, a.octets(), dir)),
        (Some(p), _) => Err(Error::new(format!(
            "protocol qualifier not valid for host: {p:?}",
        ))),
    }
}

fn lower_net(dir: Dir, proto: Option<Proto>, addr: IpAddr, mask: IpAddr) -> Result<NExpr> {
    match (addr, mask) {
        (IpAddr::V4(a), IpAddr::V4(m)) => {
            let (a, m) = (a.octets(), m.octets());
            let ip = |dir: Dir| match dir {
                Dir::Src => t(Test::IpV4 {
                    off: 26,
                    addr: a,
                    mask: m,
                }),
                Dir::Dst => t(Test::IpV4 {
                    off: 30,
                    addr: a,
                    mask: m,
                }),
                Dir::Either => or(
                    t(Test::IpV4 {
                        off: 26,
                        addr: a,
                        mask: m,
                    }),
                    t(Test::IpV4 {
                        off: 30,
                        addr: a,
                        mask: m,
                    }),
                ),
            };
            let arp_net = |et: u16, dir: Dir| match dir {
                Dir::Src => t(Test::Arp {
                    ethertype: et,
                    off: 28,
                    addr: a,
                    mask: m,
                }),
                Dir::Dst => t(Test::Arp {
                    ethertype: et,
                    off: 38,
                    addr: a,
                    mask: m,
                }),
                Dir::Either => or(
                    t(Test::Arp {
                        ethertype: et,
                        off: 28,
                        addr: a,
                        mask: m,
                    }),
                    t(Test::Arp {
                        ethertype: et,
                        off: 38,
                        addr: a,
                        mask: m,
                    }),
                ),
            };
            Ok(match proto {
                None => or_all(vec![
                    ip(dir),
                    arp_net(ETH_ARP as u16, dir),
                    arp_net(ETH_RARP as u16, dir),
                ])?,
                Some(Proto::Ip) => ip(dir),
                Some(Proto::Arp) => arp_net(ETH_ARP as u16, dir),
                Some(Proto::Rarp) => arp_net(ETH_RARP as u16, dir),
                Some(p) => {
                    return Err(Error::new(format!(
                        "protocol qualifier not valid for net: {p:?}"
                    )))
                }
            })
        }
        (IpAddr::V6(a), IpAddr::V6(m)) => {
            let (a, m) = (a.octets(), m.octets());
            let ip = |dir: Dir| match dir {
                Dir::Src => t(Test::IpV6 {
                    off: 22,
                    addr: a,
                    mask: m,
                }),
                Dir::Dst => t(Test::IpV6 {
                    off: 38,
                    addr: a,
                    mask: m,
                }),
                Dir::Either => or(
                    t(Test::IpV6 {
                        off: 22,
                        addr: a,
                        mask: m,
                    }),
                    t(Test::IpV6 {
                        off: 38,
                        addr: a,
                        mask: m,
                    }),
                ),
            };
            match proto {
                None | Some(Proto::Ip6) => Ok(ip(dir)),
                Some(p) => Err(Error::new(format!(
                    "protocol qualifier not valid for net: {p:?}"
                ))),
            }
        }
        _ => Err(Error::new("net address and mask family mismatch")),
    }
}

fn lower_port(dir: Dir, l4: L4, spec: PortSpec) -> Result<NExpr> {
    // Bare `port` matches TCP, UDP and SCTP, like tcpdump.
    let protos: &[u8] = match l4 {
        L4::Tcp => &[6],
        L4::Udp => &[17],
        L4::Any => &[132, 6, 17],
    };
    let mut alts = Vec::new();
    for &p in protos {
        for v6 in [false, true] {
            let mk = |off: u16| {
                t(Test::Port {
                    v6,
                    proto: p,
                    off,
                    spec,
                })
            };
            alts.push(match dir {
                Dir::Src => mk(0),
                Dir::Dst => mk(2),
                Dir::Either => or(mk(0), mk(2)),
            });
        }
    }
    or_all(alts)
}

fn w4(b: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*b)
}

fn w16(b: &[u8; 16], i: usize) -> u32 {
    u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
}

type Label = usize;

#[derive(Default)]
struct Builder {
    insns: Vec<Insn>,
    /// For each instruction, the `(jt, jf)` target labels when it is a
    /// conditional jump (parallel to `insns`).
    branches: Vec<Option<(Label, Label)>>,
    labels: Vec<Option<usize>>,
}

impl Builder {
    fn new_label(&mut self) -> Label {
        self.labels.push(None);
        self.labels.len() - 1
    }

    fn bind(&mut self, l: Label) {
        self.labels[l] = Some(self.insns.len());
    }

    fn emit(&mut self, code: u16, k: u32) -> usize {
        self.insns.push(Insn {
            code,
            jt: 0,
            jf: 0,
            k,
        });
        self.branches.push(None);
        self.insns.len() - 1
    }

    /// Emit a conditional jump with two target labels.
    fn branch(&mut self, op: u16, k: u32, jt: Label, jf: Label) {
        self.insns.push(Insn {
            code: op,
            jt: 0,
            jf: 0,
            k,
        });
        self.branches.push(Some((jt, jf)));
    }

    fn jump(&mut self, op: u16, k: u32, jt: Label, jf: Label) {
        self.branch(op, k, jt, jf);
    }

    /// Emit a conditional that falls through when `A == k` and jumps to `fail`
    /// otherwise.
    fn test_eq(&mut self, k: u32, fail: Label) {
        let cont = self.new_label();
        self.branch(JMP_JEQ_K, k, cont, fail);
        self.bind(cont);
    }

    /// Emit a conditional that falls through when none of `mask`'s bits are set
    /// and jumps to `fail` otherwise.
    fn test_clear(&mut self, mask: u32, fail: Label) {
        let cont = self.new_label();
        self.branch(JMP_JSET_K, mask, fail, cont);
        self.bind(cont);
    }

    fn masked_eq_final(&mut self, mask: u32, val: u32, m: Label, n: Label) {
        if mask != u32::MAX {
            self.emit(ALU_AND_K, mask);
        }
        self.jump(JMP_JEQ_K, val & mask, m, n);
    }

    fn masked_eq_cont(&mut self, mask: u32, val: u32, n: Label) {
        if mask != u32::MAX {
            self.emit(ALU_AND_K, mask);
        }
        self.test_eq(val & mask, n);
    }

    fn emit_port_spec(&mut self, spec: &PortSpec, m: Label, n: Label) {
        match spec {
            PortSpec::One(p) => {
                self.jump(JMP_JEQ_K, u32::from(*p), m, n);
            }
            PortSpec::Range(lo, hi) => {
                let ge = self.new_label();
                self.jump(JMP_JGE_K, u32::from(*lo), ge, n);
                self.bind(ge);
                self.jump(JMP_JGT_K, u32::from(*hi), n, m);
            }
        }
    }

    fn emit_test(&mut self, test: &Test, m: Label, n: Label) {
        match test {
            Test::EtherType(et) => {
                self.emit(LD_H_ABS, 12);
                if *et > ETHERNET_8023_MAX {
                    self.jump(JMP_JEQ_K, *et, m, n);
                } else {
                    // libpcap reads an `ether proto` value <= 1500 as an 802.3
                    // *length* and compares the LLC byte at offset 14 instead of
                    // the frame's ethertype. Reproduced here so a numeric value
                    // decides identically to `pcap_offline_filter` (values above
                    // 0xff can never match, exactly as in libpcap).
                    let not_length = self.new_label();
                    self.branch(JMP_JGT_K, ETHERNET_8023_MAX, n, not_length);
                    self.bind(not_length);
                    self.emit(LD_B_ABS, 14);
                    self.jump(JMP_JEQ_K, *et, m, n);
                }
            }
            Test::EtherHost { off, mac } => {
                self.emit(LD_H_ABS, u32::from(*off));
                self.test_eq(u32::from(u16::from_be_bytes([mac[0], mac[1]])), n);
                self.emit(LD_W_ABS, u32::from(*off) + 2);
                self.jump(
                    JMP_JEQ_K,
                    u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]),
                    m,
                    n,
                );
            }
            Test::IpV4 { off, addr, mask } => {
                self.emit(LD_H_ABS, 12);
                self.test_eq(ETH_IP, n);
                self.emit(LD_W_ABS, u32::from(*off));
                self.masked_eq_final(w4(mask), w4(addr), m, n);
            }
            Test::IpV6 { off, addr, mask } => {
                self.emit(LD_H_ABS, 12);
                self.test_eq(ETH_IP6, n);
                for i in 0..4 {
                    self.emit(LD_W_ABS, u32::from(*off) + 4 * i as u32);
                    if i < 3 {
                        self.masked_eq_cont(w16(mask, i), w16(addr, i), n);
                    } else {
                        self.masked_eq_final(w16(mask, i), w16(addr, i), m, n);
                    }
                }
            }
            Test::Arp {
                ethertype,
                off,
                addr,
                mask,
            } => {
                self.emit(LD_H_ABS, 12);
                self.test_eq(u32::from(*ethertype), n);
                self.emit(LD_W_ABS, u32::from(*off));
                self.masked_eq_final(w4(mask), w4(addr), m, n);
            }
            Test::L4Proto { v6, proto, frag } => {
                let et = if *v6 { ETH_IP6 } else { ETH_IP };
                self.emit(LD_H_ABS, 12);
                self.test_eq(et, n);
                if *v6 && *frag {
                    self.emit(LD_B_ABS, 20);
                    let frag_l = self.new_label();
                    self.jump(JMP_JEQ_K, u32::from(*proto), m, frag_l);
                    self.bind(frag_l);
                    self.test_eq(IPPROTO_FRAGMENT, n);
                    self.emit(LD_B_ABS, 54);
                    self.jump(JMP_JEQ_K, u32::from(*proto), m, n);
                } else {
                    let off = if *v6 { 20 } else { 23 };
                    self.emit(LD_B_ABS, off);
                    self.jump(JMP_JEQ_K, u32::from(*proto), m, n);
                }
            }
            Test::Port {
                v6,
                proto,
                off,
                spec,
            } => {
                let et = if *v6 { ETH_IP6 } else { ETH_IP };
                self.emit(LD_H_ABS, 12);
                self.test_eq(et, n);
                if *v6 {
                    self.emit(LD_B_ABS, 20);
                    self.test_eq(u32::from(*proto), n);
                    self.emit(LD_H_ABS, 54 + u32::from(*off));
                } else {
                    self.emit(LD_B_ABS, 23);
                    self.test_eq(u32::from(*proto), n);
                    self.emit(LD_H_ABS, 20);
                    self.test_clear(IPV4_FRAG_MASK, n);
                    self.emit(LDX_MSH, 14);
                    self.emit(LD_H_IND, 14 + u32::from(*off));
                }
                self.emit_port_spec(spec, m, n);
            }
        }
    }

    fn compile(&mut self, e: &NExpr, m: Label, n: Label) -> Result<()> {
        match e {
            NExpr::And(a, b) => {
                let mid = self.new_label();
                self.compile(a, mid, n)?;
                self.bind(mid);
                self.compile(b, m, n)?;
            }
            NExpr::Or(a, b) => {
                let mid = self.new_label();
                self.compile(a, m, mid)?;
                self.bind(mid);
                self.compile(b, m, n)?;
            }
            NExpr::Not(a) => self.compile(a, n, m)?,
            NExpr::Test(test) => self.emit_test(test, m, n),
        }
        Ok(())
    }

    fn finish(self) -> Result<Program> {
        let n = self.insns.len();
        let mut label_old = Vec::with_capacity(self.labels.len());
        for l in &self.labels {
            label_old.push(l.ok_or_else(|| Error::new("bpf: unbound jump label"))?);
        }

        // Reverse-assemble. `rev` holds the program reversed: a rev index `r`
        // maps to final index `len - 1 - r`. Conditional branches reach at most
        // 255 instructions, so any longer branch is routed through an
        // unconditional `JMP_JA` trampoline (32-bit reach) placed immediately
        // after it in the final program. Because everything only jumps forward,
        // a target processed earlier (higher old index) already has its final
        // rev index, so distances are exact.
        let mut rev: Vec<Insn> = Vec::with_capacity(n + 16);
        let mut rev_index: Vec<isize> = vec![0; n + 1];
        rev_index[n] = -1; // one-past-the-end

        for i in (0..n).rev() {
            let Some((jt_l, jf_l)) = self.branches[i] else {
                rev_index[i] = rev.len() as isize;
                rev.push(self.insns[i]);
                continue;
            };
            let jt_old = label_old[jt_l];
            let jf_old = label_old[jf_l];
            if jt_old <= i || jf_old <= i {
                return Err(Error::new("bpf: backward jump not supported"));
            }

            let p0 = rev.len() as isize;
            let jt_dist = p0 - rev_index[jt_old] - 1;
            let jf_dist = p0 - rev_index[jf_old] - 1;
            if jt_dist < 0 || jf_dist < 0 {
                return Err(Error::new("bpf: backward jump not supported"));
            }

            // Decide which fields need a trampoline. Inserting one increases the
            // other field's distance, so re-check until stable.
            let mut need_jt = jt_dist > 255;
            let mut need_jf = jf_dist > 255;
            loop {
                let t = need_jt as isize + need_jf as isize;
                let jt_ok = need_jt || jt_dist + t <= 255;
                let jf_ok = need_jf || jf_dist + t <= 255;
                if jt_ok && jf_ok {
                    break;
                }
                if !jt_ok {
                    need_jt = true;
                }
                if !jf_ok {
                    need_jf = true;
                }
            }

            let mut jt_tramp = None;
            let mut jf_tramp = None;
            if need_jt {
                let tp = rev.len() as isize;
                let k = u32::try_from(tp - rev_index[jt_old] - 1)
                    .map_err(|_| Error::new("bpf: jump offset overflow"))?;
                rev.push(Insn {
                    code: JMP_JA,
                    jt: 0,
                    jf: 0,
                    k,
                });
                jt_tramp = Some(tp);
            }
            if need_jf {
                let tp = rev.len() as isize;
                let k = u32::try_from(tp - rev_index[jf_old] - 1)
                    .map_err(|_| Error::new("bpf: jump offset overflow"))?;
                rev.push(Insn {
                    code: JMP_JA,
                    jt: 0,
                    jf: 0,
                    k,
                });
                jf_tramp = Some(tp);
            }

            let p = rev.len() as isize;
            let mut ins = self.insns[i];
            ins.jt = u8::try_from(match jt_tramp {
                Some(tp) => p - tp - 1,
                None => p - rev_index[jt_old] - 1,
            })
            .map_err(|_| Error::new("bpf: filter too complex (jt > 255)"))?;
            ins.jf = u8::try_from(match jf_tramp {
                Some(tp) => p - tp - 1,
                None => p - rev_index[jf_old] - 1,
            })
            .map_err(|_| Error::new("bpf: filter too complex (jf > 255)"))?;
            rev_index[i] = p;
            rev.push(ins);
        }

        rev.reverse();
        Ok(Program { insns: rev })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::parser;

    fn build(s: &str) -> Program {
        compile_ast(&parser::parse(s).unwrap()).unwrap()
    }

    fn eth_ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 14];
        p[12..14].copy_from_slice(&[0x08, 0x00]);
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // IHL=5
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        p.extend_from_slice(&ip);
        let mut l4 = vec![0u8; 20];
        l4[0..2].copy_from_slice(&sport.to_be_bytes());
        l4[2..4].copy_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&l4);
        p
    }

    #[test]
    fn matches_ip_host_and_port() {
        let pkt = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80);
        assert!(build("host 10.0.0.1").apply(&pkt));
        assert!(build("host 10.0.0.2").apply(&pkt));
        assert!(!build("host 10.0.0.3").apply(&pkt));
        assert!(build("src host 10.0.0.1").apply(&pkt));
        assert!(!build("src host 10.0.0.2").apply(&pkt));
        assert!(build("tcp port 80").apply(&pkt));
        assert!(!build("tcp port 81").apply(&pkt));
        assert!(build("port 80").apply(&pkt));
        assert!(build("ip").apply(&pkt));
        assert!(build("not host 10.0.0.3").apply(&pkt));
        assert!(build("host 10.0.0.1 and port 80").apply(&pkt));
        assert!(!build("host 10.0.0.1 and port 81").apply(&pkt));
        assert!(build("port 80 or port 443").apply(&pkt));
    }

    #[test]
    fn rejects_fragmented_port_match() {
        let mut pkt = eth_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80);
        // Set a non-zero fragment offset (low byte of the flags/fragment field).
        pkt[21] = 1;
        assert!(!build("tcp port 80").apply(&pkt));
        // Protocol-only matches regardless.
        assert!(build("tcp").apply(&pkt));
    }

    #[test]
    fn short_packet_does_not_match() {
        let pkt = vec![0u8; 4];
        assert!(!build("host 10.0.0.1").apply(&pkt));
        assert!(!build("udp port 53").apply(&pkt));
    }

    /// AUDIT4 P5-23: this used to be `expect("or_all called with empty list")`.
    /// Under `panic = "abort"` (release profile) that would have killed the whole
    /// worker - and the filter path is reachable from config files, CPM task
    /// updates and SIGHUP reloads. It is a plain error now.
    #[test]
    fn or_all_rejects_an_empty_alternative_list_without_panicking() {
        let e = or_all(Vec::new()).unwrap_err().to_string();
        assert!(e.contains("empty alternative list"), "{e}");
        // Non-empty lists keep their fold semantics.
        let one = or_all(vec![t(Test::EtherType(0x0800))]).expect("one alternative");
        assert!(matches!(one, NExpr::Test(Test::EtherType(0x0800))));
        let two = or_all(vec![t(Test::EtherType(0x0800)), t(Test::EtherType(0x86dd))])
            .expect("two alternatives");
        assert!(matches!(two, NExpr::Or(_, _)));
    }

    #[test]
    fn long_not_host_chain_uses_trampolines_and_matches() {
        // 11+ hosts used to fail with "filter too complex (jt > 255)"; this is
        // the shape the config layer auto-generates for output-host exclusion.
        let expr = (0..50u8)
            .map(|i| format!("not host 10.9.0.{i}"))
            .collect::<Vec<_>>()
            .join(" and ");
        let p = build(&expr);
        // The program must contain at least one JA trampoline.
        assert!(
            p.insns.iter().any(|i| i.code == JMP_JA),
            "expected a JA trampoline"
        );
        let excluded = eth_ipv4_tcp([10, 0, 0, 1], [10, 9, 0, 7], 1, 2);
        let allowed = eth_ipv4_tcp([10, 0, 0, 1], [10, 9, 0, 200], 1, 2);
        assert!(!p.apply(&excluded));
        assert!(p.apply(&allowed));
    }

    #[test]
    fn long_port_or_chain_compiles() {
        let p = build("port 1000 or port 1001 or port 1002 or port 1003 or port 1004");
        let hit = eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 5, 1002);
        assert!(p.apply(&hit));
        let miss = eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 5, 1005);
        assert!(!p.apply(&miss));
    }

    #[test]
    fn ip_proto_matches() {
        let pkt = eth_ipv4_tcp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2);
        assert!(build("ip proto 6").apply(&pkt));
        assert!(!build("ip proto 17").apply(&pkt));
    }

    // -----------------------------------------------------------------------
    // Semantic matrix. Each `Test` variant the compiler can emit is matched
    // against a packet built to the documented wire layout, in both the
    // matching and non-matching direction, so a wrong load offset/constant or a
    // wrong jump distance changes the verdict.
    // -----------------------------------------------------------------------

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

    fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut p = eth(0x0800);
        let mut ip = [0u8; 20];
        ip[0] = 0x45; // IHL=5
        ip[2..4].copy_from_slice(&(20 + l4.len() as u16).to_be_bytes());
        ip[9] = proto;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        p.extend_from_slice(&ip);
        p.extend_from_slice(l4);
        p
    }

    fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, l4: &[u8]) -> Vec<u8> {
        let mut p = eth(0x86dd);
        let mut ip = [0u8; 40];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&(l4.len() as u16).to_be_bytes());
        ip[6] = next;
        ip[7] = 64; // hop limit
        ip[8..24].copy_from_slice(&src);
        ip[24..40].copy_from_slice(&dst);
        p.extend_from_slice(&ip);
        p.extend_from_slice(l4);
        p
    }

    fn arp(ethertype: u16, oper: u16, spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
        let mut p = eth(ethertype);
        let mut a = [0u8; 28];
        a[0..2].copy_from_slice(&1u16.to_be_bytes()); // htype
        a[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype
        a[4] = 6; // hlen
        a[5] = 4; // plen
        a[6..8].copy_from_slice(&oper.to_be_bytes());
        a[14..18].copy_from_slice(&spa);
        a[24..28].copy_from_slice(&tpa);
        p.extend_from_slice(&a);
        p
    }

    #[allow(clippy::too_many_arguments)]
    fn v6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, w) in [a, b, c, d, e, f, g, h].iter().enumerate() {
            out[2 * i..2 * i + 2].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn apply(expr: &str, pkt: &[u8]) -> bool {
        build(expr).apply(pkt)
    }

    #[test]
    fn protocol_keywords_match_their_family() {
        let v4_tcp = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, &tcp_l4(1, 2));
        let v4_udp = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp_l4(1, 2));
        let v4_icmp = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 1, &[0u8; 8]);
        let v6_tcp = ipv6(
            v6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            v6(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            6,
            &tcp_l4(1, 2),
        );
        let v6_udp = ipv6(
            v6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            v6(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            17,
            &udp_l4(1, 2),
        );
        let v6_icmp6 = ipv6(
            v6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            v6(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            58,
            &[0u8; 8],
        );
        let a = arp(0x0806, 1, [192, 0, 2, 1], [192, 0, 2, 2]);
        let r = arp(0x8035, 3, [192, 0, 2, 1], [192, 0, 2, 2]);

        assert!(apply("ip", &v4_tcp));
        assert!(!apply("ip", &v6_tcp));
        assert!(apply("ip6", &v6_tcp));
        assert!(!apply("ip6", &v4_tcp));
        assert!(apply("arp", &a));
        assert!(!apply("arp", &r));
        assert!(apply("rarp", &r));
        assert!(!apply("rarp", &a));

        assert!(apply("tcp", &v4_tcp));
        assert!(apply("tcp", &v6_tcp));
        assert!(!apply("tcp", &v4_udp));
        assert!(apply("udp", &v4_udp));
        assert!(apply("udp", &v6_udp));
        assert!(!apply("udp", &v4_tcp));
        assert!(apply("icmp", &v4_icmp));
        assert!(!apply("icmp", &v6_icmp6));
        assert!(apply("icmp6", &v6_icmp6));
        assert!(!apply("icmp6", &v4_icmp));

        assert!(apply("ip proto 6", &v4_tcp));
        assert!(!apply("ip proto 17", &v4_tcp));
        assert!(apply("ip6 proto 17", &v6_udp));
        assert!(!apply("ip6 proto 6", &v6_udp));
    }

    #[test]
    fn host_matches_ip_arp_and_rarp_in_both_directions() {
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, &tcp_l4(1, 2));
        assert!(apply("host 10.0.0.1", &pkt));
        assert!(apply("host 10.0.0.2", &pkt));
        assert!(!apply("host 10.0.0.3", &pkt));
        assert!(apply("src host 10.0.0.1", &pkt));
        assert!(!apply("src host 10.0.0.2", &pkt));
        assert!(apply("dst host 10.0.0.2", &pkt));
        assert!(!apply("dst host 10.0.0.1", &pkt));
        assert!(apply("ip src host 10.0.0.1", &pkt));
        assert!(!apply("arp host 10.0.0.1", &pkt));

        let a = arp(0x0806, 1, [192, 0, 2, 1], [192, 0, 2, 2]);
        assert!(apply("host 192.0.2.1", &a)); // sender protocol address
        assert!(apply("host 192.0.2.2", &a)); // target protocol address
        assert!(!apply("host 192.0.2.3", &a));
        assert!(apply("src host 192.0.2.1", &a));
        assert!(apply("dst host 192.0.2.2", &a));
        assert!(apply("arp src host 192.0.2.1", &a));
        assert!(apply("arp dst host 192.0.2.2", &a));
        assert!(!apply("ip host 192.0.2.1", &a));

        let r = arp(0x8035, 3, [198, 51, 100, 7], [198, 51, 100, 8]);
        assert!(apply("host 198.51.100.7", &r));
        assert!(apply("rarp src host 198.51.100.7", &r));
        assert!(apply("rarp dst host 198.51.100.8", &r));
    }

    #[test]
    fn ipv6_host_covers_every_32_bit_word() {
        let src = v6(
            0x2001, 0x0db8, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,
        );
        let dst = v6(0xfe80, 0, 0, 0, 0, 0, 0, 0x0001);
        let pkt = ipv6(src, dst, 6, &tcp_l4(1, 2));
        // Every word of a full-match address is checked, not just the first.
        let a = v6(
            0x2001, 0x0db8, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,
        );
        assert!(apply("host 2001:db8:1111:2222:3333:4444:5555:6666", &pkt));
        let b = v6(
            0x2001, 0x0db8, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6667,
        );
        assert!(!apply("host 2001:db8:1111:2222:3333:4444:5555:6667", &pkt));
        assert_eq!(a, src);
        assert_eq!(b[15], 0x67);
        assert!(!apply("src host fe80::1", &pkt));
        assert!(apply("dst host fe80::1", &pkt));
        assert!(apply("ip6 dst host fe80::1", &pkt));
        assert!(apply("host fe80::1", &pkt));
    }

    #[test]
    fn net_matches_prefix_and_explicit_mask() {
        let pkt = ipv4([10, 1, 2, 3], [192, 168, 1, 1], 6, &tcp_l4(1, 2));
        assert!(apply("net 10.0.0.0/8", &pkt));
        assert!(!apply("net 11.0.0.0/8", &pkt));
        assert!(apply("net 192.168.0.0/16", &pkt));
        assert!(!apply("net 192.169.0.0/16", &pkt));
        assert!(apply("net 10.0.0.0 mask 255.0.0.0", &pkt));
        assert!(!apply("net 10.2.0.0 mask 255.255.0.0", &pkt));
        assert!(apply("ip src net 10.0.0.0/8", &pkt));
        assert!(!apply("ip src net 192.168.0.0/16", &pkt));

        let v6pkt = ipv6(
            v6(0x2001, 0x0db8, 0x1234, 0, 0, 0, 0, 1),
            v6(0x2001, 0x0db8, 0xabcd, 0, 0, 0, 0, 2),
            6,
            &tcp_l4(1, 2),
        );
        // /48 keeps the first three words under the mask and ignores the rest;
        // a wrong `&`/`|` on the masked words would change the verdict.
        assert!(apply("net 2001:db8:1234::/48", &v6pkt));
        assert!(!apply("net 2001:db8:9999::/48", &v6pkt));
        assert!(apply("net 2001:db8::/32", &v6pkt));
        assert!(!apply("net 2001:db9::/32", &v6pkt));
        assert!(apply("net 2001:db8:abcd::/48", &v6pkt));
        assert!(apply("ip6 src net 2001:db8:1234::/48", &v6pkt));
        assert!(!apply("ip6 dst net 2001:db8:1234::/48", &v6pkt));
    }

    #[test]
    fn ether_host_matches_src_and_dst() {
        let mut pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, &tcp_l4(1, 2));
        pkt[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt[6..12].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert!(apply("ether host 00:11:22:33:44:55", &pkt));
        assert!(apply("ether host aa:bb:cc:dd:ee:ff", &pkt));
        assert!(!apply("ether host 00:11:22:33:44:56", &pkt));
        assert!(apply("ether dst host 00:11:22:33:44:55", &pkt));
        assert!(!apply("ether src host 00:11:22:33:44:55", &pkt));
        assert!(apply("ether src host aa:bb:cc:dd:ee:ff", &pkt));
        assert!(apply("ether host aa-bb-cc-dd-ee-ff", &pkt));
    }

    #[test]
    fn ports_match_direction_protocol_and_range() {
        let tcp = ipv4([1, 1, 1, 1], [2, 2, 2, 2], 6, &tcp_l4(1234, 80));
        assert!(apply("port 80", &tcp));
        assert!(apply("port 1234", &tcp));
        assert!(!apply("port 81", &tcp));
        assert!(apply("tcp port 80", &tcp));
        assert!(!apply("udp port 80", &tcp));
        assert!(apply("tcp src port 1234", &tcp));
        assert!(!apply("tcp src port 80", &tcp));
        assert!(apply("tcp dst port 80", &tcp));
        assert!(apply("tcp dst portrange 70-90", &tcp));
        assert!(!apply("tcp dst portrange 81-90", &tcp));
        assert!(apply("portrange 1234-1234", &tcp));

        let udp = ipv4([1, 1, 1, 1], [2, 2, 2, 2], 17, &udp_l4(53, 53));
        assert!(apply("udp port 53", &udp));
        assert!(apply("port 53", &udp));
        assert!(!apply("tcp port 53", &udp));

        // Bare `port` also covers SCTP (proto 132), like tcpdump.
        let sctp = ipv4([1, 1, 1, 1], [2, 2, 2, 2], 132, &tcp_l4(1, 9999));
        assert!(apply("port 9999", &sctp));
        assert!(!apply("tcp port 9999", &sctp));
        assert!(!apply("udp port 9999", &sctp));

        let v6tcp = ipv6(
            v6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            v6(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            6,
            &tcp_l4(1111, 2222),
        );
        assert!(apply("tcp dst port 2222", &v6tcp));
        assert!(apply("tcp src port 1111", &v6tcp));
        assert!(!apply("tcp src port 2222", &v6tcp));
    }

    #[test]
    fn boolean_structure_and_fragment_header() {
        let pkt = ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, &tcp_l4(1, 80));
        assert!(apply("not host 10.0.0.9", &pkt));
        assert!(!apply("not host 10.0.0.1", &pkt));
        assert!(apply("ip and port 80", &pkt));
        assert!(!apply("ip and port 81", &pkt));
        assert!(apply("ip or port 81", &pkt));
        assert!(!apply("ip6 or port 81", &pkt));
        assert!(apply("host 10.0.0.1 and host 10.0.0.2", &pkt));
        assert!(!apply("host 10.0.0.1 and host 10.0.0.3", &pkt));
        assert!(apply("(port 80 or port 443) and tcp", &pkt));

        // IPv6 fragment header: `tcp` must follow the next-header chain.
        let mut frag = vec![0u8; 8];
        frag[0] = 6; // next header inside the fragment header
        let v6frag = ipv6(
            v6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            v6(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            44,
            &frag,
        );
        assert!(apply("tcp", &v6frag));
        assert!(!apply("udp", &v6frag));
    }

    // -----------------------------------------------------------------------
    // Golden instruction sequences. These pin the exact wire encoding (load
    // offsets, ethertype/address constants, jump distances) for the shapes the
    // semantic matrix exercises only indirectly.
    // -----------------------------------------------------------------------

    fn opname(code: u16) -> &'static str {
        match code {
            LD_H_ABS => "ldh",
            LD_W_ABS => "ldw",
            LD_B_ABS => "ldb",
            LD_H_IND => "ldh[x",
            LDX_MSH => "ldxb4",
            ALU_AND_K => "and",
            JMP_JEQ_K => "jeq",
            JMP_JGE_K => "jge",
            JMP_JGT_K => "jgt",
            JMP_JSET_K => "jset",
            JMP_JA => "ja",
            RET_K => "ret",
            _ => "???",
        }
    }

    fn disasm(p: &Program) -> String {
        p.insns
            .iter()
            .map(|i| format!("{} {} {} {}", opname(i.code), i.jt, i.jf, i.k))
            .collect::<Vec<_>>()
            .join(" | ")
    }

    fn disasm_slice(insns: &[Insn]) -> String {
        insns
            .iter()
            .map(|i| format!("{} {} {} {}", opname(i.code), i.jt, i.jf, i.k))
            .collect::<Vec<_>>()
            .join(" | ")
    }

    fn assert_disasm(expr: &str, expected: &str) {
        let got = disasm(&build(expr));
        assert_eq!(got, expected, "compiled cBPF for `{expr}`");
    }

    /// The reverse assembler inserts a `JA` trampoline when a conditional's
    /// target is more than 255 instructions away. `not host` chains put the
    /// success target at the far drop, so 11 of them are exactly enough to force
    /// one; the resulting length, trampoline offsets and tail pin the arithmetic
    /// that decides trampoline placement.
    #[test]
    fn golden_long_chain_places_trampolines() {
        let expr = (0..11u8)
            .map(|i| format!("not host 10.9.0.{i}"))
            .collect::<Vec<_>>()
            .join(" and ");
        let p = build(&expr);
        assert_eq!(p.insns.len(), 268, "program length");
        assert_eq!(
            disasm_slice(&p.insns[..12]),
            "ldh 0 0 12 | jeq 0 3 2048 | ldw 0 0 26 | jeq 0 1 168361984 | \
             ja 0 0 262 | ldh 0 0 12 | jeq 0 3 2048 | ldw 0 0 30 | \
             jeq 0 1 168361984 | ja 0 0 257 | ldh 0 0 12 | jeq 0 2 2054"
        );
        let jas: Vec<(usize, u32)> = p
            .insns
            .iter()
            .enumerate()
            .filter(|(_, i)| i.code == JMP_JA)
            .map(|(idx, i)| (idx, i.k))
            .collect();
        assert_eq!(jas, vec![(4, 262), (9, 257)], "trampoline offsets");
        for (idx, k) in &jas {
            assert_eq!(
                idx + 1 + *k as usize,
                p.insns.len() - 1,
                "every trampoline must land on the drop RET"
            );
        }
        let n = p.insns.len();
        assert_eq!(p.insns[n - 3].k, 168361994);
        assert_eq!(p.insns[n - 3].jt, 1);
        assert_eq!(p.insns[n - 2].k, ACCEPT);
        assert_eq!(p.insns[n - 1].k, 0);
    }

    fn fnv1a(s: &str) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in s.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// A 50-host chain forces 236 trampolines and exercises the refinement loop
    /// (a branch whose two targets are both far). The whole encoding is pinned by
    /// a stable fingerprint; see the n=11 test for a readable slice.
    #[test]
    fn golden_very_long_chain_is_stable() {
        let expr = (0..50u8)
            .map(|i| format!("not host 10.9.0.{i}"))
            .collect::<Vec<_>>()
            .join(" and ");
        let p = build(&expr);
        let jas = p.insns.iter().filter(|i| i.code == JMP_JA).count();
        let d = disasm(&p);
        assert_eq!(p.insns.len(), 1438, "len");
        assert_eq!(jas, 236, "trampolines");
        assert_eq!(
            fnv1a(&d),
            0xa4bd_a0e3_5b92_9989,
            "len={} jas={jas}",
            p.insns.len()
        );
    }

    #[test]
    fn golden_protocol_and_ethertype() {
        assert_disasm(
            "ip",
            "ldh 0 0 12 | jeq 0 1 2048 | ret 0 0 262144 | ret 0 0 0",
        );
        assert_disasm(
            "ip6",
            "ldh 0 0 12 | jeq 0 1 34525 | ret 0 0 262144 | ret 0 0 0",
        );
        assert_disasm(
            "arp",
            "ldh 0 0 12 | jeq 0 1 2054 | ret 0 0 262144 | ret 0 0 0",
        );
        assert_disasm(
            "rarp",
            "ldh 0 0 12 | jeq 0 1 32821 | ret 0 0 262144 | ret 0 0 0",
        );
        // `ether proto N` for N > 1500 is the same straight compare libpcap emits.
        assert_disasm(
            "ether proto 0x88b5",
            "ldh 0 0 12 | jeq 0 1 34997 | ret 0 0 262144 | ret 0 0 0",
        );
        // For N <= 1500 libpcap treats N as an 802.3 length and compares the LLC
        // byte at offset 14; the length gate must be part of the encoding.
        assert_disasm(
            "ether proto 100",
            "ldh 0 0 12 | jgt 3 0 1500 | ldb 0 0 14 | jeq 0 1 100 | ret 0 0 262144 | ret 0 0 0",
        );
    }

    /// `ether proto` regression for the field report. The exact ethertype from
    /// the rejected config is matched, the named escapes agree with their
    /// numeric form, and the 802.3-length quirk decides like libpcap.
    #[test]
    fn ether_proto_matches_ethertype_and_8023_length() {
        let tagged = eth(0x88b5);
        assert!(apply("ether proto 0x88b5", &tagged));
        assert!(!apply("ether proto 0x88b6", &tagged));
        assert!(apply("ether proto 0x88b5 or ether proto 0x0800", &tagged));

        let ip = ipv4([1, 1, 1, 1], [2, 2, 2, 2], 6, &tcp_l4(1, 2));
        assert!(apply(r"ether proto \ip", &ip));
        assert!(!apply(r"ether proto \ip6", &ip));
        assert!(apply("ether proto 0x0800", &ip));

        // The composite shape from the field report must compile. `qinq`
        // ethertypes are included to pin the VLAN-tagged link-layer values.
        let expr =
            "ether proto 0x88b5 or ether proto 0x0800 or ether proto 0x8100 or ether proto 0x88a8";
        assert!(apply(expr, &tagged));
        assert!(apply(expr, &ip));
        assert!(apply(expr, &eth(0x8100)));
        assert!(apply(expr, &eth(0x88a8)));
        assert!(!apply(expr, &eth(0x0806)));

        // libpcap reads a value <= 1500 as an 802.3 length and compares the byte
        // at offset 14; a real ethertype at offset 12 must not satisfy it.
        let mut length = vec![0u8; 20];
        length[12..14].copy_from_slice(&100u16.to_be_bytes());
        length[14] = 100;
        assert!(apply("ether proto 100", &length));
        length[14] = 101;
        assert!(!apply("ether proto 100", &length));
        let mut not_length = vec![0u8; 20];
        not_length[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        not_length[14] = 100;
        assert!(!apply("ether proto 100", &not_length));
        // > 0xffff can never equal a 16-bit load, exactly like libpcap.
        assert!(!apply("ether proto 0x10000", &tagged));
    }

    #[test]
    fn golden_ether_host_and_ipv4_host() {
        assert_disasm(
            "ether src host 00:11:22:33:44:55",
            "ldh 0 0 6 | jeq 0 3 17 | ldw 0 0 8 | jeq 0 1 573785173 | ret 0 0 262144 | ret 0 0 0",
        );
        assert_disasm(
            "ip host 10.0.0.1",
            "ldh 0 0 12 | jeq 0 2 2048 | ldw 0 0 26 | jeq 4 0 167772161 | \
             ldh 0 0 12 | jeq 0 3 2048 | ldw 0 0 30 | jeq 0 1 167772161 | \
             ret 0 0 262144 | ret 0 0 0",
        );
    }

    #[test]
    fn golden_ipv6_and_masked_net() {
        assert_disasm(
            "ip6 dst host 2001:db8::1",
            "ldh 0 0 12 | jeq 0 9 34525 | ldw 0 0 38 | jeq 0 7 536939960 | \
             ldw 0 0 42 | jeq 0 5 0 | ldw 0 0 46 | jeq 0 3 0 | ldw 0 0 50 | jeq 0 1 1 | \
             ret 0 0 262144 | ret 0 0 0",
        );
        // `net` uses ALU_AND_K before the compare, so the mask/address pair and
        // the jump distances are part of the golden.
        assert_disasm(
            "ip src net 10.0.0.0/8",
            "ldh 0 0 12 | jeq 0 4 2048 | ldw 0 0 26 | and 0 0 4278190080 | \
             jeq 0 1 167772160 | ret 0 0 262144 | ret 0 0 0",
        );
    }

    #[test]
    fn golden_port_range() {
        assert_disasm(
            "tcp dst port 80",
            "ldh 0 0 12 | jeq 0 7 2048 | ldb 0 0 23 | jeq 0 5 6 | ldh 0 0 20 | \
             jset 3 0 8191 | ldxb4 0 0 14 | ldh[x 0 0 16 | jeq 6 0 80 | \
             ldh 0 0 12 | jeq 0 5 34525 | ldb 0 0 20 | jeq 0 3 6 | ldh 0 0 56 | \
             jeq 0 1 80 | ret 0 0 262144 | ret 0 0 0",
        );
    }

    /// Build a program whose single conditional branch at index 1 has exact
    /// jt/jf distances, so the reverse assembler's 255-instruction boundary and
    /// trampoline refinement loop can be tested directly.
    fn finish_branch(jt_d: usize, jf_d: usize) -> Program {
        let mut b = Builder::default();
        let m = b.new_label();
        let n = b.new_label();
        b.emit(LD_B_ABS, 0);
        b.branch(JMP_JEQ_K, 1, m, n);
        let m_at = jt_d + 2;
        let n_at = jf_d + 2;
        while b.insns.len() <= m_at.max(n_at) {
            let i = b.insns.len();
            if i == m_at {
                b.bind(m);
            }
            if i == n_at {
                b.bind(n);
            }
            b.emit(RET_K, 0xaa);
        }
        b.finish().expect("finish")
    }

    #[test]
    fn finish_handles_the_branch_distance_boundary() {
        // A distance of 255 is still direct (the test is `> 255`).
        for (jt, jf) in [(0usize, 0usize), (254, 0), (255, 0), (0, 255)] {
            let p = finish_branch(jt, jf);
            assert_eq!(usize::from(p.insns[1].jt), jt, "jt for ({jt},{jf})");
            assert_eq!(usize::from(p.insns[1].jf), jf, "jf for ({jt},{jf})");
            assert!(
                !p.insns.iter().any(|i| i.code == JMP_JA),
                "no trampoline for ({jt},{jf})"
            );
        }
        // 256 forces a trampoline; the branch points at it and the JA at the
        // true target.
        let p = finish_branch(256, 0);
        assert_eq!((p.insns[1].jt, p.insns[1].jf), (0, 1));
        assert_eq!(p.insns.len(), 260);
        assert_eq!(p.insns[2].code, JMP_JA);
        assert_eq!(p.insns[2].k, 256);

        let p = finish_branch(0, 256);
        assert_eq!((p.insns[1].jt, p.insns[1].jf), (1, 0));
        assert_eq!(p.insns[2].code, JMP_JA);
        assert_eq!(p.insns[2].k, 256);

        // jt=255 fits on its own, but jf=256 needs a trampoline and inserting it
        // pushes jt over the limit. The refinement loop must notice and insert a
        // second trampoline instead of emitting an out-of-range jt.
        let p = finish_branch(255, 256);
        assert_eq!((p.insns[1].jt, p.insns[1].jf), (1, 0));
        assert_eq!(p.insns.len(), 261);
        let jas: Vec<(usize, u32)> = p
            .insns
            .iter()
            .enumerate()
            .filter(|(_, i)| i.code == JMP_JA)
            .map(|(i, x)| (i, x.k))
            .collect();
        assert_eq!(jas, vec![(2, 257), (3, 255)]);

        let p = finish_branch(256, 255);
        assert_eq!((p.insns[1].jt, p.insns[1].jf), (1, 0));
        assert_eq!(p.insns.len(), 261);
        let jas: Vec<(usize, u32)> = p
            .insns
            .iter()
            .enumerate()
            .filter(|(_, i)| i.code == JMP_JA)
            .map(|(i, x)| (i, x.k))
            .collect();
        assert_eq!(jas, vec![(2, 256), (3, 256)]);
    }

    /// The reverse assembler only supports forward jumps. A label bound *before*
    /// the branch that uses it must be rejected: emitting a distance for it would
    /// either produce a program the kernel refuses or silently jump into the
    /// middle of an instruction.
    #[test]
    fn a_backward_branch_is_rejected() {
        let mut b = Builder::default();
        let back = b.new_label();
        let fwd = b.new_label();
        b.bind(back); // bound at index 0, i.e. behind the branch below
        b.emit(RET_K, 0);
        b.branch(JMP_JEQ_K, 1, back, fwd);
        b.bind(fwd);
        b.emit(RET_K, 0);
        let err = b.finish().expect_err("a backward jump must be rejected");
        assert!(err.to_string().contains("backward jump"), "{err}");
    }

    /// `ether proto N` decides at *exactly* N = `ETHERNET_8023_MAX` (1500): libpcap
    /// reads a value <= 1500 as an 802.3 length (compare the LLC byte at offset 14),
    /// a value > 1500 as a plain ethertype compare. Mutating `>` to `>=`
    /// (sweep mutant `compiler.rs:521:24`) moves that boundary by one, so both
    /// sides are pinned here: the encoding, because the two branches differ in
    /// instruction count, and the decision, because a frame that literally carries
    /// 1500 in its EtherType field must still not match `ether proto 1500`.
    #[test]
    fn ether_proto_length_boundary_is_exactly_the_8023_maximum() {
        assert_disasm(
            "ether proto 1500",
            "ldh 0 0 12 | jgt 3 0 1500 | ldb 0 0 14 | jeq 0 1 1500 | ret 0 0 262144 | ret 0 0 0",
        );
        assert_disasm(
            "ether proto 1501",
            "ldh 0 0 12 | jeq 0 1 1501 | ret 0 0 262144 | ret 0 0 0",
        );

        // 1500 is read as a length, so the byte at offset 14 decides; a byte can
        // never equal 1500, which is why the frame below does not match even
        // though its EtherType field holds the value.
        let mut length_frame = vec![0u8; 20];
        length_frame[12..14].copy_from_slice(&1500u16.to_be_bytes());
        assert!(!apply("ether proto 1500", &length_frame));
        length_frame[14] = 0xff;
        assert!(!apply("ether proto 1500", &length_frame));

        // One up is the straight 16-bit compare again.
        assert!(apply("ether proto 1501", &eth(1501)));
        assert!(!apply("ether proto 1501", &length_frame));
    }
}
