//! Tokenizer and recursive-descent parser for the supported tcpdump filter
//! subset.
//!
//! The grammar is intentionally small; anything outside it is a hard error, so
//! callers never silently get a filter that matches differently than intended:
//!
//! ```text
//! expr        := or
//! or          := and (('or' | '||') and)*
//! and         := unary (('and' | '&&') unary)*
//! unary       := ('not' | '!') unary | primary
//! primary     := '(' expr ')' | predicate
//! predicate   := [ 'src' | 'dst' ] (
//!                    'host' ADDR
//!                  | 'net' NET
//!                  | 'port' NUM
//!                  | 'portrange' NUM '-' NUM
//!                  | 'ether' 'host' MAC )
//!              | PROTO [ 'host' ADDR | 'net' NET | 'port' NUM | 'portrange' NUM '-' NUM ]
//! PROTO       := ip | ip6 | arp | rarp | tcp | udp | icmp | icmp6
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::str::FromStr;

use crate::error::{Error, Result};

/// Maximum filter expression length in bytes.
const MAX_FILTER_LEN: usize = 8192;
/// Maximum nesting depth (`not` / parentheses).
const MAX_DEPTH: usize = 256;
/// Maximum number of boolean/term nodes (bounds AST/lowering recursion).
const MAX_NODES: usize = 4096;

/// Direction qualifier (`src`, `dst`, or unspecified = either).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// Match the source field only.
    Src,
    /// Match the destination field only.
    Dst,
    /// Match either field.
    Either,
}

/// Network / transport protocol keyword.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    /// IPv4 (`ip`).
    Ip,
    /// IPv6 (`ip6`).
    Ip6,
    /// ARP (`arp`).
    Arp,
    /// RARP (`rarp`).
    Rarp,
    /// TCP (`tcp`).
    Tcp,
    /// UDP (`udp`).
    Udp,
    /// ICMPv4 (`icmp`).
    Icmp,
    /// ICMPv6 (`icmp6`).
    Icmp6,
}

/// Transport protocol selector for `port` / `portrange`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4 {
    /// `tcp port N`
    Tcp,
    /// `udp port N`
    Udp,
    /// Bare `port N` (matches TCP, UDP and SCTP, like tcpdump).
    Any,
}

/// Port match specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortSpec {
    /// A single port.
    One(u16),
    /// An inclusive range.
    Range(u16, u16),
}

/// Parsed filter expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ast {
    /// Logical AND.
    And(Box<Ast>, Box<Ast>),
    /// Logical OR.
    Or(Box<Ast>, Box<Ast>),
    /// Logical NOT.
    Not(Box<Ast>),
    /// A protocol keyword.
    Proto(Proto),
    /// `[src|dst] ether host MAC`
    EtherHost {
        /// Direction qualifier.
        dir: Dir,
        /// 6-byte MAC address.
        mac: [u8; 6],
    },
    /// `[src|dst] [proto] host ADDR`
    Host {
        /// Direction qualifier.
        dir: Dir,
        /// Optional protocol qualifier (`ip`, `ip6`, `arp`, `rarp`).
        proto: Option<Proto>,
        /// Matched address.
        addr: IpAddr,
    },
    /// `[src|dst] [proto] net ADDR/PLEN`
    Net {
        /// Direction qualifier.
        dir: Dir,
        /// Optional protocol qualifier.
        proto: Option<Proto>,
        /// Network address (already masked).
        addr: IpAddr,
        /// Network mask.
        mask: IpAddr,
    },
    /// `[src|dst] [tcp|udp] port NUM` / `portrange A-B`
    Port {
        /// Direction qualifier.
        dir: Dir,
        /// Transport selector.
        l4: L4,
        /// Port spec.
        spec: PortSpec,
    },
    /// `ip proto NUM` / `ip6 proto NUM`
    IpProto {
        /// True for IPv6 (`ip6 proto`).
        v6: bool,
        /// IP protocol number.
        num: u8,
    },
}

/// Turns a host name into addresses while a filter is being compiled.
///
/// Injectable so that the *size* bound on a resolution result (P2-9) and the
/// "expand every address" rule (P2-8) are testable without a name server, and so
/// that a cached/background resolver can be plugged in later without touching the
/// grammar. Implementations must be side-effect free with respect to the parser.
pub trait Resolver {
    /// All addresses of `host`, in any order (they are sorted/deduped by the
    /// parser). An empty `Ok` or an error means "unresolvable".
    ///
    /// # Errors
    /// Any resolver failure (unknown name, no address, DNS outage).
    fn lookup(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

/// The platform resolver: `getaddrinfo` through `ToSocketAddrs`.
#[derive(Clone, Copy, Debug, Default)]
pub struct DnsResolver;

impl Resolver for DnsResolver {
    fn lookup(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok((host, 0u16).to_socket_addrs()?.map(|sa| sa.ip()).collect())
    }
}

/// Parse a filter expression string into an [`Ast`] using the platform resolver.
///
/// # Errors
/// Returns an error for unknown keywords, malformed addresses, unresolvable
/// host names, a name with more answers than [`MAX_RESOLVED_ADDRS`], or trailing
/// garbage.
pub fn parse(input: &str) -> Result<Ast> {
    // Not the raw platform resolver: a filter is compiled while building tasks, and
    // the reload path used to re-resolve every name of every task while holding the
    // task-manager mutex. Results are memoised process-wide so a reload of an
    // unchanged configuration resolves nothing (AUDIT4 P2-10); the blocking call
    // itself is moved off the critical threads by `crate::task::ReloadWorker`.
    parse_with(input, &super::resolvers::CachedResolver::system())
}

/// [`parse`] with an injected [`Resolver`].
///
/// # Errors
/// As [`parse`], plus whatever the injected resolver reports.
pub fn parse_with(input: &str, resolver: &dyn Resolver) -> Result<Ast> {
    if input.len() > MAX_FILTER_LEN {
        return Err(Error::new(format!(
            "filter expression too long ({} > {MAX_FILTER_LEN} bytes)",
            input.len()
        )));
    }
    let toks = tokenize(input);
    if toks.is_empty() {
        return Err(Error::new("empty filter expression"));
    }
    let mut p = Parser {
        toks,
        pos: 0,
        depth: 0,
        nodes: 0,
        resolver,
    };
    let ast = p.parse_or()?;
    if p.pos != p.toks.len() {
        return Err(Error::new(format!(
            "unexpected token '{}' in filter",
            p.toks[p.pos]
        )));
    }
    Ok(ast)
}

/// Split an expression into tokens, separating parentheses and operators even
/// when they are not whitespace-delimited (`(udp and (port 1 or port 2))`).
fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut it = s.chars().peekable();
    macro_rules! flush {
        () => {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        };
    }
    while let Some(c) = it.next() {
        match c {
            c if c.is_whitespace() => flush!(),
            '(' | ')' => {
                flush!();
                out.push(c.to_string());
            }
            '!' => {
                flush!();
                out.push("!".to_string());
            }
            '&' => {
                flush!();
                if it.peek() == Some(&'&') {
                    it.next();
                }
                out.push("&&".to_string());
            }
            '|' => {
                flush!();
                if it.peek() == Some(&'|') {
                    it.next();
                }
                out.push("||".to_string());
            }
            _ => cur.push(c),
        }
    }
    flush!();
    out
}

struct Parser<'a> {
    toks: Vec<String>,
    pos: usize,
    depth: usize,
    nodes: usize,
    resolver: &'a dyn Resolver,
}

impl<'a> Parser<'a> {
    /// Account for one more nesting level, rejecting overly deep expressions
    /// (which would otherwise overflow the stack during parse/lower/compile).
    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Error::new(format!(
                "filter expression nesting too deep (> {MAX_DEPTH})"
            )));
        }
        Ok(())
    }

    /// Account for one more AST node, bounding total expression size.
    fn bump(&mut self) -> Result<()> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(Error::new(format!(
                "filter expression too complex (> {MAX_NODES} terms)"
            )));
        }
        Ok(())
    }

    fn peek(&self) -> Option<&str> {
        self.toks.get(self.pos).map(String::as_str)
    }

    fn next(&mut self) -> Option<String> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, word: &str) -> bool {
        if self.peek() == Some(word) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_or(&mut self) -> Result<Ast> {
        let mut left = self.parse_and()?;
        while self.peek() == Some("or") || self.peek() == Some("||") {
            self.pos += 1;
            let right = self.parse_and()?;
            self.bump()?;
            left = Ast::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Ast> {
        let mut left = self.parse_unary()?;
        while self.peek() == Some("and") || self.peek() == Some("&&") {
            self.pos += 1;
            let right = self.parse_unary()?;
            self.bump()?;
            left = Ast::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Ast> {
        if self.peek() == Some("not") || self.peek() == Some("!") {
            self.pos += 1;
            self.enter()?;
            self.bump()?;
            let inner = self.parse_unary()?;
            self.depth -= 1;
            return Ok(Ast::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Ast> {
        if self.eat("(") {
            self.enter()?;
            let e = self.parse_or()?;
            self.depth -= 1;
            if !self.eat(")") {
                return Err(Error::new("missing ')' in filter"));
            }
            return Ok(e);
        }
        self.parse_predicate()
    }

    fn parse_predicate(&mut self) -> Result<Ast> {
        let (dir, has_dir) = match self.peek() {
            Some("src") => {
                self.pos += 1;
                (Dir::Src, true)
            }
            Some("dst") => {
                self.pos += 1;
                (Dir::Dst, true)
            }
            _ => (Dir::Either, false),
        };

        let kw = self
            .next()
            .ok_or_else(|| Error::new("unexpected end of filter"))?;

        match kw.as_str() {
            "host" => {
                let t = self
                    .next()
                    .ok_or_else(|| Error::new("missing host address"))?;
                self.host_expr(dir, None, &t)
            }
            "net" => self.net_expr(dir, None),
            "port" => Ok(Ast::Port {
                dir,
                l4: L4::Any,
                spec: PortSpec::One(self.parse_u16("port")?),
            }),
            "portrange" => Ok(Ast::Port {
                dir,
                l4: L4::Any,
                spec: self.parse_range()?,
            }),
            "ether" => {
                if has_dir {
                    return Err(Error::new("src/dst not valid before 'ether'"));
                }
                let edir = if self.eat("src") {
                    Dir::Src
                } else if self.eat("dst") {
                    Dir::Dst
                } else {
                    Dir::Either
                };
                if !self.eat("host") {
                    return Err(Error::new("expected 'host' after 'ether'"));
                }
                Ok(Ast::EtherHost {
                    dir: edir,
                    mac: self.parse_mac()?,
                })
            }
            _ => {
                let Some(proto) = proto_from_keyword(&kw) else {
                    return Err(Error::new(format!("unsupported filter keyword '{kw}'")));
                };
                if has_dir {
                    return Err(Error::new(format!(
                        "src/dst not valid before protocol '{kw}'"
                    )));
                }
                self.parse_proto_qualified(proto)
            }
        }
    }

    fn parse_proto_qualified(&mut self, proto: Proto) -> Result<Ast> {
        // Optional inline direction, e.g. `tcp dst port 80`, `ip src host X`.
        let (dir, has_dir) = if self.eat("src") {
            (Dir::Src, true)
        } else if self.eat("dst") {
            (Dir::Dst, true)
        } else {
            (Dir::Either, false)
        };

        match self.peek() {
            Some("proto") => {
                if has_dir {
                    return Err(Error::new("src/dst not valid before 'proto'"));
                }
                if !matches!(proto, Proto::Ip | Proto::Ip6) {
                    return Err(Error::new("'proto' is only valid after 'ip'/'ip6'"));
                }
                self.pos += 1;
                let num = self.parse_u16("protocol")?;
                let num = u8::try_from(num)
                    .map_err(|_| Error::new(format!("IP protocol {num} out of range")))?;
                Ok(Ast::IpProto {
                    v6: proto == Proto::Ip6,
                    num,
                })
            }
            Some("host") if matches!(proto, Proto::Ip | Proto::Ip6 | Proto::Arp | Proto::Rarp) => {
                self.pos += 1;
                let t = self
                    .next()
                    .ok_or_else(|| Error::new("missing host address"))?;
                self.host_expr(dir, Some(proto), &t)
            }
            Some("net") if matches!(proto, Proto::Ip | Proto::Ip6 | Proto::Arp | Proto::Rarp) => {
                self.pos += 1;
                self.net_expr(dir, Some(proto))
            }
            Some("port") if matches!(proto, Proto::Tcp | Proto::Udp) => {
                self.pos += 1;
                let l4 = if proto == Proto::Tcp {
                    L4::Tcp
                } else {
                    L4::Udp
                };
                Ok(Ast::Port {
                    dir,
                    l4,
                    spec: PortSpec::One(self.parse_u16("port")?),
                })
            }
            Some("portrange") if matches!(proto, Proto::Tcp | Proto::Udp) => {
                self.pos += 1;
                let l4 = if proto == Proto::Tcp {
                    L4::Tcp
                } else {
                    L4::Udp
                };
                Ok(Ast::Port {
                    dir,
                    l4,
                    spec: self.parse_range()?,
                })
            }
            _ => {
                if has_dir {
                    return Err(Error::new(format!(
                        "unexpected src/dst after protocol '{proto:?}'"
                    )));
                }
                Ok(Ast::Proto(proto))
            }
        }
    }

    fn parse_u16(&mut self, what: &str) -> Result<u16> {
        let t = self
            .next()
            .ok_or_else(|| Error::new(format!("missing {what} value")))?;
        t.parse::<u16>()
            .map_err(|_| Error::new(format!("invalid {what} '{t}'")))
    }

    fn parse_range(&mut self) -> Result<PortSpec> {
        let t = self
            .next()
            .ok_or_else(|| Error::new("missing portrange value"))?;
        let (a, b) = t
            .split_once('-')
            .ok_or_else(|| Error::new(format!("invalid portrange '{t}'")))?;
        let lo = a
            .parse::<u16>()
            .map_err(|_| Error::new(format!("invalid portrange '{t}'")))?;
        let hi = b
            .parse::<u16>()
            .map_err(|_| Error::new(format!("invalid portrange '{t}'")))?;
        if lo > hi {
            return Err(Error::new(format!("portrange low > high in '{t}'")));
        }
        Ok(PortSpec::Range(lo, hi))
    }

    fn parse_mac(&mut self) -> Result<[u8; 6]> {
        let t = self
            .next()
            .ok_or_else(|| Error::new("missing MAC address"))?;
        parse_mac(&t)
    }

    /// Resolve a token to *all* of its addresses (deduplicated, deterministic
    /// order, bounded by [`MAX_RESOLVED_ADDRS`]).
    ///
    /// The bound is what stops DNS *data* from deciding the size of the compiled
    /// program: without it, one name with many A/AAAA records silently pushed the
    /// task past the kernel's instruction limit and into per-frame userspace
    /// filtering (AUDIT4 P2-9).
    fn resolve(&self, token: &str) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = IpAddr::from_str(token) {
            return Ok(vec![ip]);
        }
        let mut v: Vec<IpAddr> = match self.resolver.lookup(token) {
            Ok(v) => v,
            Err(_) => return Err(Error::new(format!("invalid host address '{token}'"))),
        };
        v.sort();
        v.dedup();
        if v.is_empty() {
            return Err(Error::new(format!("no address for host '{token}'")));
        }
        bounded_addrs(token, v)
    }

    /// Build `host` matching for *every* address a name resolves to.
    ///
    /// libpcap's `host <name>` expands to the logical OR over all A/AAAA
    /// answers; taking only the first would leave some addresses unfiltered
    /// (and, for the auto-generated output-host exclusion, risks mirroring our
    /// own traffic back).
    fn host_expr(&mut self, dir: Dir, proto: Option<Proto>, token: &str) -> Result<Ast> {
        let addrs = self.resolve(token)?;
        let mut expr: Option<Ast> = None;
        for addr in addrs {
            self.bump()?;
            let node = Ast::Host { dir, proto, addr };
            expr = Some(match expr {
                None => node,
                Some(prev) => Ast::Or(Box::new(prev), Box::new(node)),
            });
        }
        expr.ok_or_else(|| Error::new(format!("no address for host '{token}'")))
    }

    /// Build `net` matching for *every* address a name resolves to.
    ///
    /// `host <name>` was fixed to OR over all A/AAAA answers (P5-08), but
    /// `net <name>` still went through `parse_addr()`, which takes
    /// `to_socket_addrs().next()` - so a multi-homed name left every address but
    /// the first unfiltered, which is exactly the loopback-amplification hazard
    /// the exclusion of output hosts exists to prevent. Chosen behaviour: cover
    /// all addresses, like `host`, rather than reject host names - rejecting
    /// would break filters that work today (they would fail the task instead of
    /// filtering correctly), and the expansion is bounded by
    /// [`MAX_RESOLVED_ADDRS`].
    fn net_expr(&mut self, dir: Dir, proto: Option<Proto>) -> Result<Ast> {
        let t = self
            .next()
            .ok_or_else(|| Error::new("missing net address"))?;
        let spec = self.net_spec(&t)?;
        // Only the address/name part is resolvable; `/len` is the specification.
        let host = t.split_once('/').map_or(t.as_str(), |(h, _)| h);
        let mut expr: Option<Ast> = None;
        for (addr, mask) in net_masks(&t, &self.resolve(host)?, &spec)? {
            self.bump()?;
            let node = Ast::Net {
                dir,
                proto,
                addr,
                mask,
            };
            expr = Some(match expr {
                None => node,
                Some(prev) => Ast::Or(Box::new(prev), Box::new(node)),
            });
        }
        expr.ok_or_else(|| Error::new(format!("no address for net '{t}'")))
    }

    /// Parse the `/prefix` or `mask <netmask>` part of a `net` token.
    fn net_spec(&mut self, t: &str) -> Result<NetSpec> {
        if let Some((_, plen)) = t.split_once('/') {
            let plen: u8 = plen
                .parse()
                .map_err(|_| Error::new(format!("invalid prefix length in '{t}'")))?;
            return Ok(NetSpec::Prefix(plen));
        }
        if self.eat("mask") {
            let mt = self.next().ok_or_else(|| Error::new("missing net mask"))?;
            // A netmask is a bit pattern, never a name: resolving one would take
            // the first answer of a host record and silently mean something else.
            let mask =
                IpAddr::from_str(&mt).map_err(|_| Error::new(format!("invalid netmask '{mt}'")))?;
            return Ok(NetSpec::Mask(mask));
        }
        Err(Error::new(format!(
            "net '{t}' needs a /prefix or an explicit 'mask'"
        )))
    }
}

fn proto_from_keyword(kw: &str) -> Option<Proto> {
    Some(match kw {
        "ip" => Proto::Ip,
        "ip6" | "ipv6" => Proto::Ip6,
        "arp" => Proto::Arp,
        "rarp" => Proto::Rarp,
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        "icmp" => Proto::Icmp,
        "icmp6" | "icmpv6" => Proto::Icmp6,
        _ => return None,
    })
}

/// How a `net` token says which addresses belong to the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetSpec {
    /// CIDR prefix length (`10.0.0.0/8`).
    Prefix(u8),
    /// Explicit netmask (`net 10.0.0.0 mask 255.0.0.0`).
    Mask(IpAddr),
}

/// Turn a set of resolved addresses plus a net specification into the
/// `(network, mask)` pairs the filter must match.
///
/// Split out from the parser so `net <name>` covering *every* answer (P2-8) is
/// testable without DNS. Addresses of the wrong family are dropped when an
/// explicit mask names one family (an IPv6 answer cannot be masked by
/// `255.0.0.0`); a `/prefix` applies to each family with its own mask width.
///
/// Errors when nothing is left to match, so a filter never silently narrows to
/// "matches nothing".
fn net_masks(token: &str, addrs: &[IpAddr], spec: &NetSpec) -> Result<Vec<(IpAddr, IpAddr)>> {
    let mut out: Vec<(IpAddr, IpAddr)> = Vec::new();
    for addr in addrs {
        let (net, mask) = match spec {
            NetSpec::Prefix(plen) => {
                let mask = prefix_mask(*addr, *plen)?;
                (mask_addr(*addr, mask), mask)
            }
            NetSpec::Mask(m) => {
                if m.is_ipv4() != addr.is_ipv4() {
                    continue;
                }
                (mask_addr(*addr, *m), *m)
            }
        };
        if !out.contains(&(net, mask)) {
            out.push((net, mask));
        }
    }
    if out.is_empty() {
        return Err(Error::new(format!(
            "net '{token}': no resolved address matches the {}",
            match spec {
                NetSpec::Prefix(_) => "prefix",
                NetSpec::Mask(_) => "netmask family",
            }
        )));
    }
    Ok(out)
}

/// Largest number of addresses one hostname may contribute to a filter.
///
/// Each answer becomes its own leaf (~5-8 cBPF instructions), so an unbounded
/// answer set lets DNS data decide the size of the program: past
/// `bpf::BPF_MAXINSNS`(4096) the kernel refuses the program and the capturer
/// degrades to interpreting thousands of instructions *per frame* in userspace -
/// a throughput collapse with every counter still reporting 0 drops. A name with
/// more answers than this is refused with the name in the message.
pub const MAX_RESOLVED_ADDRS: usize = 64;

/// Reject a resolution result that is too large to compile into a filter.
///
/// Applied by [`Parser::resolve`] to every name lookup's result.
fn bounded_addrs(token: &str, addrs: Vec<IpAddr>) -> Result<Vec<IpAddr>> {
    if addrs.len() > MAX_RESOLVED_ADDRS {
        return Err(Error::new(format!(
            "host '{token}' resolved to {} addresses, more than the {MAX_RESOLVED_ADDRS} a \
             filter may expand; list the addresses explicitly instead of the name",
            addrs.len()
        )));
    }
    Ok(addrs)
}

fn parse_mac(t: &str) -> Result<[u8; 6]> {
    let sep = if t.contains(':') { ':' } else { '-' };
    let parts: Vec<&str> = t.split(sep).collect();
    if parts.len() != 6 {
        return Err(Error::new(format!("invalid MAC address '{t}'")));
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16)
            .map_err(|_| Error::new(format!("invalid MAC address '{t}'")))?;
    }
    Ok(mac)
}

fn prefix_mask(addr: IpAddr, plen: u8) -> Result<IpAddr> {
    match addr {
        IpAddr::V4(_) => {
            if plen > 32 {
                return Err(Error::new(format!("IPv4 prefix /{plen} out of range")));
            }
            let bits = if plen == 0 {
                0u32
            } else {
                u32::MAX << (32 - plen)
            };
            Ok(IpAddr::V4(Ipv4Addr::from(bits)))
        }
        IpAddr::V6(_) => {
            if plen > 128 {
                return Err(Error::new(format!("IPv6 prefix /{plen} out of range")));
            }
            let bits = if plen == 0 {
                0u128
            } else {
                u128::MAX << (128 - plen)
            };
            Ok(IpAddr::V6(Ipv6Addr::from(bits)))
        }
    }
}

fn mask_addr(addr: IpAddr, mask: IpAddr) -> IpAddr {
    match (addr, mask) {
        (IpAddr::V4(a), IpAddr::V4(m)) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & u32::from(m))),
        (IpAddr::V6(a), IpAddr::V6(m)) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & u128::from(m))),
        _ => addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_predicates() {
        assert!(matches!(parse("udp").unwrap(), Ast::Proto(Proto::Udp)));
        assert!(matches!(
            parse("host 10.0.0.1").unwrap(),
            Ast::Host {
                dir: Dir::Either,
                proto: None,
                ..
            }
        ));
        assert!(matches!(
            parse("src host 10.0.0.1").unwrap(),
            Ast::Host { dir: Dir::Src, .. }
        ));
        assert!(matches!(
            parse("ip6 host fe80::1").unwrap(),
            Ast::Host {
                proto: Some(Proto::Ip6),
                ..
            }
        ));
        assert!(matches!(
            parse("udp port 53").unwrap(),
            Ast::Port {
                l4: L4::Udp,
                spec: PortSpec::One(53),
                ..
            }
        ));
        assert!(matches!(
            parse("portrange 6000-6008").unwrap(),
            Ast::Port {
                spec: PortSpec::Range(6000, 6008),
                ..
            }
        ));
        assert!(matches!(
            parse("ether host 00:11:22:33:44:55").unwrap(),
            Ast::EtherHost { .. }
        ));
    }

    #[test]
    fn parses_boolean_expr() {
        let a = parse("(udp and port 53) or (tcp and port 80)").unwrap();
        assert!(matches!(a, Ast::Or(..)));
        let b = parse("not host 10.0.0.1").unwrap();
        assert!(matches!(b, Ast::Not(_)));
        let c = parse("(port 80) and not host 10.0.0.9").unwrap();
        assert!(matches!(c, Ast::And(..)));
    }

    #[test]
    fn net_prefix() {
        let a = parse("net 10.0.0.0/8").unwrap();
        if let Ast::Net { addr, mask, .. } = a {
            assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
            assert_eq!(mask, IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0)));
        } else {
            panic!("expected net");
        }
    }

    #[test]
    fn rejects_unsupported() {
        assert!(parse("vlan 5").is_err());
        assert!(parse("greater 100").is_err());
        assert!(parse("port 99999").is_err());
        assert!(parse("host").is_err());
        assert!(parse("udp and").is_err());
        assert!(parse("(udp").is_err());
    }

    #[test]
    fn parses_direction_and_proto_syntax() {
        assert!(matches!(
            parse("tcp dst port 80").unwrap(),
            Ast::Port {
                dir: Dir::Dst,
                l4: L4::Tcp,
                spec: PortSpec::One(80)
            }
        ));
        assert!(matches!(
            parse("udp src port 53").unwrap(),
            Ast::Port {
                dir: Dir::Src,
                l4: L4::Udp,
                ..
            }
        ));
        assert!(matches!(
            parse("tcp dst portrange 100-200").unwrap(),
            Ast::Port {
                dir: Dir::Dst,
                spec: PortSpec::Range(100, 200),
                ..
            }
        ));
        assert!(matches!(
            parse("ether src host 00:11:22:33:44:55").unwrap(),
            Ast::EtherHost { dir: Dir::Src, .. }
        ));
        assert!(matches!(
            parse("ether dst host 00:11:22:33:44:55").unwrap(),
            Ast::EtherHost { dir: Dir::Dst, .. }
        ));
        assert!(matches!(
            parse("ip proto 6").unwrap(),
            Ast::IpProto { v6: false, num: 6 }
        ));
        assert!(matches!(
            parse("ip6 proto 17").unwrap(),
            Ast::IpProto { v6: true, num: 17 }
        ));
        assert!(matches!(
            parse("ip src host 10.0.0.1").unwrap(),
            Ast::Host {
                dir: Dir::Src,
                proto: Some(Proto::Ip),
                ..
            }
        ));
        // `src ether host` is invalid, like tcpdump.
        assert!(parse("src ether host 00:11:22:33:44:55").is_err());
    }

    #[test]
    fn host_name_expands_to_every_resolved_address() {
        fn collect(ast: &Ast, out: &mut Vec<IpAddr>) {
            match ast {
                Ast::Or(a, b) => {
                    collect(a, out);
                    collect(b, out);
                }
                Ast::Host { addr, .. } => out.push(*addr),
                _ => {}
            }
        }
        let expected: std::collections::BTreeSet<IpAddr> = ("localhost", 0u16)
            .to_socket_addrs()
            .unwrap()
            .map(|s| s.ip())
            .collect();
        if expected.is_empty() {
            return; // environment has no localhost entry
        }
        let ast = parse_with("host localhost", &DnsResolver).unwrap();
        let mut got = Vec::new();
        collect(&ast, &mut got);
        let got: std::collections::BTreeSet<IpAddr> = got.into_iter().collect();
        assert_eq!(
            got, expected,
            "host <name> must cover every resolved address"
        );
    }

    /// Offline stand-in for a name server: P2-8 and P2-9 are both about the
    /// *number* of answers a name yields, which cannot be produced on demand by
    /// the real resolver (and an env-dependent test silently no-ops - this box
    /// resolves `localhost` to exactly one address).
    struct FixedResolver(Vec<IpAddr>);

    impl Resolver for FixedResolver {
        fn lookup(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn nets_in(ast: &Ast) -> Vec<(IpAddr, IpAddr)> {
        match ast {
            Ast::Or(a, b) => {
                let mut v = nets_in(a);
                v.extend(nets_in(b));
                v
            }
            Ast::Net { addr, mask, .. } => vec![(*addr, *mask)],
            _ => vec![],
        }
    }

    fn hosts_in(ast: &Ast) -> Vec<IpAddr> {
        match ast {
            Ast::Or(a, b) => {
                let mut v = hosts_in(a);
                v.extend(hosts_in(b));
                v
            }
            Ast::Host { addr, .. } => vec![*addr],
            _ => vec![],
        }
    }

    /// AUDIT4 P2-8: P5-08 ("cover every resolved address") was applied to
    /// `host <name>` only; `net <name>` still took `to_socket_addrs().next()`, so
    /// every answer but the first stayed unfiltered - the loopback-amplification
    /// hazard the output-host exclusion exists to prevent.
    #[test]
    fn net_name_expands_to_every_resolved_address() {
        let addrs = vec![v4(192, 0, 2, 5), v4(198, 51, 100, 9)];
        let ast = parse_with("net multi.example/24", &FixedResolver(addrs.clone()))
            .expect("parse net <name>");
        let got = nets_in(&ast);
        assert_eq!(
            got,
            vec![
                (v4(192, 0, 2, 0), v4(255, 255, 255, 0)),
                (v4(198, 51, 100, 0), v4(255, 255, 255, 0)),
            ],
            "`net <name>` must OR over every answer, not just the first"
        );
        // The `mask` form expands too, and drops answers of the other family.
        let mixed = vec![
            addrs[0],
            addrs[1],
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        ];
        let ast = parse_with(
            "ip dst net multi.example mask 255.255.255.0",
            &FixedResolver(mixed),
        )
        .expect("parse net <name> mask");
        assert_eq!(nets_in(&ast).len(), 2, "v6 answer must be dropped: {ast:?}");
        // Two answers in the same network collapse to one term, not two leaves.
        let ast = parse_with(
            "net dup.example/24",
            &FixedResolver(vec![v4(192, 0, 2, 5), v4(192, 0, 2, 9)]),
        )
        .expect("parse");
        assert_eq!(nets_in(&ast).len(), 1);
        // Literal addresses keep working, prefix and mask form alike.
        assert_eq!(nets_in(&parse("net 10.0.0.0/8").unwrap()).len(), 1);
        assert!(
            parse("net 10.0.0.0 mask localhost").is_err(),
            "a netmask is a bit pattern, never a name"
        );
        assert!(parse("net fe80::1/8").is_ok());
        assert!(parse("net 10.0.0.0/33").is_err());
    }

    /// An explicit mask names one family; if no answer matches it the filter must
    /// fail loudly instead of silently matching nothing.
    #[test]
    fn net_mask_without_matching_family_is_an_error() {
        let err = parse_with(
            "net v6only.example mask 255.255.255.0",
            &FixedResolver(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]),
        )
        .expect_err("nothing to mask");
        assert!(
            err.to_string().contains("v6only.example"),
            "the error must name the token: {err}"
        );
    }

    /// AUDIT4 P2-9: the number of answers was unbounded, so DNS *data* could grow
    /// the program past `bpf::BPF_MAXINSNS`(4096) and silently degrade the task
    /// into interpreting thousands of cBPF instructions per frame - a throughput
    /// collapse with `drop == 0` and every gate green.
    #[test]
    fn oversized_resolution_is_refused_by_name_not_silently_expanded() {
        let many: Vec<IpAddr> = (0..=MAX_RESOLVED_ADDRS as u32)
            .map(|i| v4(10, (i / 256) as u8, (i / 4) as u8, (i % 4) as u8))
            .collect();
        assert_eq!(many.len(), MAX_RESOLVED_ADDRS + 1);
        for expr in ["host many.example", "net many.example/24"] {
            let err = parse_with(expr, &FixedResolver(many.clone()))
                .expect_err(&format!("{expr} must be refused"));
            let msg = err.to_string();
            assert!(
                msg.contains("many.example"),
                "{expr}: the error must name the host: {msg}"
            );
            assert!(
                msg.contains(&many.len().to_string())
                    && msg.contains(&MAX_RESOLVED_ADDRS.to_string()),
                "{expr}: the error must give both counts: {msg}"
            );
        }
        // Exactly at the limit is accepted, and expands fully.
        let ast = parse_with(
            "host ok.example",
            &FixedResolver(many[..MAX_RESOLVED_ADDRS].to_vec()),
        )
        .expect("at the limit");
        assert_eq!(hosts_in(&ast).len(), MAX_RESOLVED_ADDRS);
    }

    #[test]
    fn rejects_over_long_or_deep() {
        assert!(parse(&("not ".repeat(1000) + "ip")).is_err());
        let paren = "(".repeat(2000) + "ip" + &")".repeat(2000);
        assert!(parse(&paren).is_err());
        assert!(parse(&("ip and ".repeat(2000) + "ip")).is_err());
        // A deep-but-legal expression still parses.
        assert!(parse(&("not ".repeat(100) + "ip")).is_ok());
    }

    // -----------------------------------------------------------------------
    // Tokenizer, grammar aliases, precedence, error paths and address math.
    // -----------------------------------------------------------------------

    #[test]
    fn tokenizer_splits_operators_and_parens() {
        let t = |s: &str| tokenize(s);
        assert_eq!(t("a&&b"), vec!["a", "&&", "b"]);
        assert_eq!(t("a||b"), vec!["a", "||", "b"]);
        // A lone `&`/`|` is normalized to the double form, not dropped.
        assert_eq!(t("a&b"), vec!["a", "&&", "b"]);
        assert_eq!(t("a|b"), vec!["a", "||", "b"]);
        assert_eq!(t("!a"), vec!["!", "a"]);
        assert_eq!(t("(a)"), vec!["(", "a", ")"]);
        assert_eq!(t("  \t\n "), Vec::<String>::new());
        assert_eq!(t("a  b"), vec!["a", "b"]);
        assert_eq!(
            t("(udp and (port 1 or port 2))"),
            vec!["(", "udp", "and", "(", "port", "1", "or", "port", "2", ")", ")"]
        );
    }

    #[test]
    fn boolean_aliases_and_precedence() {
        assert!(matches!(parse("ip && tcp").unwrap(), Ast::And(..)));
        assert!(matches!(parse("ip || tcp").unwrap(), Ast::Or(..)));
        assert!(matches!(parse("!ip").unwrap(), Ast::Not(_)));
        assert!(matches!(parse("ip and tcp and udp").unwrap(), Ast::And(..)));
        assert!(matches!(parse("ip or tcp or udp").unwrap(), Ast::Or(..)));
        assert!(matches!(
            parse("not not ip").unwrap(),
            Ast::Not(inner) if matches!(*inner, Ast::Not(_))
        ));
        // `and` binds tighter than `or`: `ip or tcp and udp` = ip or (tcp and udp).
        match parse("ip or tcp and udp").unwrap() {
            Ast::Or(left, right) => {
                assert!(matches!(*left, Ast::Proto(Proto::Ip)));
                assert!(matches!(*right, Ast::And(..)), "and must bind tighter");
            }
            other => panic!("expected Or, got {other:?}"),
        }
    }

    #[test]
    fn parse_errors_are_specific() {
        for bad in [
            "",
            "   ",
            "ip ip",
            "(ip",
            "ip)",
            "ip and",
            "and ip",
            "src ip",
            "ip src proto 6",
            "tcp proto 6",
            "ip proto 999",
            "ip proto abc",
            "tcp host 1.2.3.4",
            "tcp net 10.0.0.0/8",
            "ip portrange 1-2",
            "ip port 80",
            "port",
            "port abc",
            "portrange 200-100",
            "portrange 100",
            "portrange a-b",
            "net 10.0.0.0",
            "net 10.0.0.0/abc",
            "ether",
            "ether foo",
            "ether host 00:11:22:33:44",
            "ether host zz:11:22:33:44:55",
            "src ether host 00:11:22:33:44:55",
            "vlan 5",
            "greater 100",
        ] {
            assert!(parse(bad).is_err(), "`{bad}` must be rejected");
        }
    }

    #[test]
    fn proto_aliases_and_inline_direction() {
        assert!(matches!(parse("ipv6").unwrap(), Ast::Proto(Proto::Ip6)));
        assert!(matches!(parse("icmpv6").unwrap(), Ast::Proto(Proto::Icmp6)));
        assert!(matches!(
            parse("tcp dst port 80").unwrap(),
            Ast::Port {
                dir: Dir::Dst,
                l4: L4::Tcp,
                ..
            }
        ));
        assert!(matches!(
            parse("udp src portrange 1-2").unwrap(),
            Ast::Port {
                dir: Dir::Src,
                l4: L4::Udp,
                spec: PortSpec::Range(1, 2)
            }
        ));
        assert!(matches!(
            parse("ip dst net 10.0.0.0/8").unwrap(),
            Ast::Net {
                dir: Dir::Dst,
                proto: Some(Proto::Ip),
                ..
            }
        ));
        assert!(matches!(
            parse("arp src host 10.0.0.1").unwrap(),
            Ast::Host {
                dir: Dir::Src,
                proto: Some(Proto::Arp),
                ..
            }
        ));
        assert!(matches!(
            parse("ip6 dst host fe80::1").unwrap(),
            Ast::Host {
                dir: Dir::Dst,
                proto: Some(Proto::Ip6),
                ..
            }
        ));
    }

    #[allow(clippy::too_many_arguments)]
    fn v6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    #[test]
    fn prefix_mask_boundaries() {
        assert_eq!(prefix_mask(v4(1, 2, 3, 4), 0).unwrap(), v4(0, 0, 0, 0));
        assert_eq!(prefix_mask(v4(1, 2, 3, 4), 8).unwrap(), v4(255, 0, 0, 0));
        assert_eq!(
            prefix_mask(v4(1, 2, 3, 4), 32).unwrap(),
            v4(255, 255, 255, 255)
        );
        assert!(prefix_mask(v4(1, 2, 3, 4), 33).is_err());
        assert_eq!(
            prefix_mask(v6(0, 0, 0, 0, 0, 0, 0, 0), 0).unwrap(),
            v6(0, 0, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            prefix_mask(v6(1, 2, 3, 4, 5, 6, 7, 8), 128).unwrap(),
            v6(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)
        );
        assert_eq!(
            prefix_mask(v6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32).unwrap(),
            v6(0xffff, 0xffff, 0, 0, 0, 0, 0, 0)
        );
        assert!(prefix_mask(v6(0, 0, 0, 0, 0, 0, 0, 0), 129).is_err());
    }

    #[test]
    fn mask_addr_masks_or_passes_through() {
        assert_eq!(
            mask_addr(v4(10, 1, 2, 3), v4(255, 0, 0, 0)),
            v4(10, 0, 0, 0)
        );
        assert_eq!(
            mask_addr(
                v6(0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 1),
                v6(0xffff, 0xffff, 0, 0, 0, 0, 0, 0)
            ),
            v6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)
        );
        // A family mismatch is returned unchanged (the caller filters these).
        assert_eq!(
            mask_addr(v4(10, 1, 2, 3), v6(0xffff, 0, 0, 0, 0, 0, 0, 0)),
            v4(10, 1, 2, 3)
        );
    }

    #[test]
    fn net_masks_dedups_and_reports_the_reason() {
        // Two addresses in the same /24 collapse to one term.
        let out = net_masks(
            "t",
            &[v4(192, 0, 2, 5), v4(192, 0, 2, 9)],
            &NetSpec::Prefix(24),
        )
        .unwrap();
        assert_eq!(out, vec![(v4(192, 0, 2, 0), v4(255, 255, 255, 0))]);
        // Explicit mask with no matching family names the token.
        let err = net_masks(
            "v6only.example",
            &[v6(0, 0, 0, 0, 0, 0, 0, 1)],
            &NetSpec::Mask(v4(255, 0, 0, 0)),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("v6only.example"), "{err}");
        assert!(err.contains("netmask family"), "{err}");
    }

    #[test]
    fn parse_mac_accepts_colon_and_dash() {
        assert_eq!(
            parse_mac("00:11:22:33:44:55").unwrap(),
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        assert_eq!(
            parse_mac("aa-bb-cc-dd-ee-ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert!(parse_mac("00:11:22:33:44").is_err());
        assert!(parse_mac("00:11:22:33:44:55:66").is_err());
        assert!(parse_mac("gg:11:22:33:44:55").is_err());
    }

    #[test]
    fn resolve_sorts_dedups_and_bounds() {
        struct R(Vec<IpAddr>);
        impl Resolver for R {
            fn lookup(&self, _h: &str) -> std::io::Result<Vec<IpAddr>> {
                Ok(self.0.clone())
            }
        }
        // Duplicates are removed and the order is deterministic.
        let r = R(vec![v4(10, 0, 0, 2), v4(10, 0, 0, 1), v4(10, 0, 0, 2)]);
        let p = Parser {
            toks: vec![],
            pos: 0,
            depth: 0,
            nodes: 0,
            resolver: &r,
        };
        assert_eq!(
            p.resolve("x").unwrap(),
            vec![v4(10, 0, 0, 1), v4(10, 0, 0, 2)]
        );
        // A literal never reaches the resolver.
        assert_eq!(p.resolve("10.0.0.9").unwrap(), vec![v4(10, 0, 0, 9)]);
        // An empty answer is an error naming the host.
        let empty = Parser {
            toks: vec![],
            pos: 0,
            depth: 0,
            nodes: 0,
            resolver: &R(vec![]),
        };
        let err = empty.resolve("nowhere.example").unwrap_err().to_string();
        assert!(err.contains("nowhere.example"), "{err}");
    }

    #[test]
    fn filter_length_limit_is_enforced_before_parsing() {
        assert!(parse(&" ".repeat(MAX_FILTER_LEN + 1)).is_err());
        assert!(parse(&" ".repeat(MAX_FILTER_LEN)).is_err()); // still no tokens
                                                              // Exactly at the limit is accepted (the check is `>`, not `>=`).
        let padded = format!("ip{}", " ".repeat(MAX_FILTER_LEN - 2));
        assert_eq!(padded.len(), MAX_FILTER_LEN);
        assert!(matches!(parse(&padded).unwrap(), Ast::Proto(Proto::Ip)));
    }

    /// `enter`/`bump` are exercised directly so the limits are checked at the
    /// exact boundary (256 levels, 4096 nodes) rather than only far past them.
    #[test]
    fn depth_and_node_limits_are_checked_at_the_boundary() {
        let r = FixedResolver(vec![]);
        let mut p = Parser {
            toks: vec![],
            pos: 0,
            depth: 0,
            nodes: 0,
            resolver: &r,
        };
        for _ in 0..MAX_DEPTH {
            p.enter().expect("depth up to the limit is allowed");
        }
        let e = p.enter().unwrap_err().to_string();
        assert!(e.contains("nesting too deep"), "{e}");

        let mut p = Parser {
            toks: vec![],
            pos: 0,
            depth: 0,
            nodes: 0,
            resolver: &r,
        };
        for _ in 0..MAX_NODES {
            p.bump().expect("nodes up to the limit are allowed");
        }
        let e = p.bump().unwrap_err().to_string();
        assert!(e.contains("too complex"), "{e}");
    }

    #[test]
    fn depth_is_released_between_siblings() {
        // Each `not`/`(...)` must restore the depth on the way out. If it did
        // not, a long *flat* chain would be mistaken for deep nesting.
        let flat_not = std::iter::repeat_n("not ip", MAX_DEPTH + 1)
            .collect::<Vec<_>>()
            .join(" and ");
        assert!(parse(&flat_not).is_ok());
        let flat_paren = std::iter::repeat_n("(ip)", MAX_DEPTH + 1)
            .collect::<Vec<_>>()
            .join(" and ");
        assert!(parse(&flat_paren).is_ok());
        // And exactly MAX_DEPTH nesting is still accepted.
        assert!(parse(&("not ".repeat(MAX_DEPTH) + "ip")).is_ok());
        assert!(parse(&("not ".repeat(MAX_DEPTH + 1) + "ip")).is_err());
    }
}
