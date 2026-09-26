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
/// IPv6 fragment-header next-header value.
const IPPROTO_FRAGMENT: u32 = 0x2c;
/// IPv4 fragment-offset mask in the flags/fragment field.
const IPV4_FRAG_MASK: u32 = 0x1fff;

/// Normalized boolean tree. Leaves are [`Test`]s.
enum NExpr {
    And(Box<NExpr>, Box<NExpr>),
    Or(Box<NExpr>, Box<NExpr>),
    Not(Box<NExpr>),
    Test(Test),
}

/// A self-contained atomic packet test.
enum Test {
    EtherType(u16),
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

fn or_all(v: Vec<NExpr>) -> NExpr {
    let mut it = v.into_iter();
    let first = it.next().expect("or_all called with empty list");
    it.fold(first, or)
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
        Ast::Port { dir, l4, spec } => lower_port(*dir, *l4, *spec),
    })
}

fn lower_proto(p: Proto) -> NExpr {
    match p {
        Proto::Ip => t(Test::EtherType(ETH_IP as u16)),
        Proto::Ip6 => t(Test::EtherType(ETH_IP6 as u16)),
        Proto::Arp => t(Test::EtherType(ETH_ARP as u16)),
        Proto::Rarp => t(Test::EtherType(ETH_RARP as u16)),
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
        (None, IpAddr::V4(a)) => Ok(or_all(vec![
            ipv4(a.octets(), dir),
            arp(ETH_ARP as u16, a.octets(), dir),
            arp(ETH_RARP as u16, a.octets(), dir),
        ])),
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
                ]),
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

fn lower_port(dir: Dir, l4: L4, spec: PortSpec) -> NExpr {
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
                self.jump(JMP_JEQ_K, u32::from(*et), m, n);
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
}
