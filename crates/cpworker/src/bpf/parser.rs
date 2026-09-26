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
}

/// Parse a filter expression string into an [`Ast`].
///
/// # Errors
/// Returns an error for unknown keywords, malformed addresses, unresolvable
/// host names, or trailing garbage.
pub fn parse(input: &str) -> Result<Ast> {
    let toks = tokenize(input);
    if toks.is_empty() {
        return Err(Error::new("empty filter expression"));
    }
    let mut p = Parser { toks, pos: 0 };
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

struct Parser {
    toks: Vec<String>,
    pos: usize,
}

impl Parser {
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
            left = Ast::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Ast> {
        let mut left = self.parse_unary()?;
        while self.peek() == Some("and") || self.peek() == Some("&&") {
            self.pos += 1;
            let right = self.parse_unary()?;
            left = Ast::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Ast> {
        if self.peek() == Some("not") || self.peek() == Some("!") {
            self.pos += 1;
            return Ok(Ast::Not(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Ast> {
        if self.eat("(") {
            let e = self.parse_or()?;
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
            "host" => Ok(Ast::Host {
                dir,
                proto: None,
                addr: self.parse_addr()?,
            }),
            "net" => {
                let (addr, mask) = self.parse_net()?;
                Ok(Ast::Net {
                    dir,
                    proto: None,
                    addr,
                    mask,
                })
            }
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
                if !self.eat("host") {
                    return Err(Error::new("expected 'host' after 'ether'"));
                }
                Ok(Ast::EtherHost {
                    dir,
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
        match self.peek() {
            Some("host") => {
                self.pos += 1;
                Ok(Ast::Host {
                    dir: Dir::Either,
                    proto: Some(proto),
                    addr: self.parse_addr()?,
                })
            }
            Some("net") => {
                self.pos += 1;
                let (addr, mask) = self.parse_net()?;
                Ok(Ast::Net {
                    dir: Dir::Either,
                    proto: Some(proto),
                    addr,
                    mask,
                })
            }
            Some("port") if matches!(proto, Proto::Tcp | Proto::Udp) => {
                self.pos += 1;
                let l4 = if proto == Proto::Tcp {
                    L4::Tcp
                } else {
                    L4::Udp
                };
                Ok(Ast::Port {
                    dir: Dir::Either,
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
                    dir: Dir::Either,
                    l4,
                    spec: self.parse_range()?,
                })
            }
            _ => Ok(Ast::Proto(proto)),
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

    fn parse_addr(&mut self) -> Result<IpAddr> {
        let t = self
            .next()
            .ok_or_else(|| Error::new("missing host address"))?;
        parse_addr(&t)
    }

    fn parse_net(&mut self) -> Result<(IpAddr, IpAddr)> {
        let t = self
            .next()
            .ok_or_else(|| Error::new("missing net address"))?;
        let (addr, plen) = if let Some((ip, plen)) = t.split_once('/') {
            let addr = parse_addr(ip)?;
            let plen: u8 = plen
                .parse()
                .map_err(|_| Error::new(format!("invalid prefix length in '{t}'")))?;
            (addr, plen)
        } else {
            let addr = parse_addr(&t)?;
            if self.eat("mask") {
                let mt = self.next().ok_or_else(|| Error::new("missing net mask"))?;
                let mask = parse_addr(&mt)?;
                if mask.is_ipv4() != addr.is_ipv4() {
                    return Err(Error::new("net address and mask family mismatch"));
                }
                return Ok((mask_addr(addr, mask), mask));
            }
            return Err(Error::new(format!(
                "net '{t}' needs a /prefix or an explicit 'mask'"
            )));
        };
        let mask = prefix_mask(addr, plen)?;
        Ok((mask_addr(addr, mask), mask))
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

fn parse_addr(t: &str) -> Result<IpAddr> {
    if let Ok(ip) = IpAddr::from_str(t) {
        return Ok(ip);
    }
    // Fall back to resolving a host name, like libpcap's pcap_compile.
    match (t, 0u16).to_socket_addrs() {
        Ok(mut addrs) => addrs
            .next()
            .map(|sa| sa.ip())
            .ok_or_else(|| Error::new(format!("no address for host '{t}'"))),
        Err(_) => Err(Error::new(format!("invalid host address '{t}'"))),
    }
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
}
