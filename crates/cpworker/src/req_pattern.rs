//! Request/response direction detection. Port of `req_pattern.c`.
//!
//! Supports the same custom pattern mini-language:
//! `host <ip|nic.ifname> and|or port <n>`, with parentheses.

use crate::config::{
    ReqPatternConfig, LOG_INFO, REQ_PATTERN_TYPE_AUTO_STR, REQ_PATTERN_TYPE_CUSTOM_STR,
    REQ_PATTERN_TYPE_NONE_STR,
};
use crate::error::{Error, Result};
use crate::log::log;
use crate::netutil::{get_if_ip_addr, get_if_mac_addr};
use crate::packet::{
    extract_ipport, format_mac_addr, IpAddr, ETH_HDR_LEN, MAC_ADDR_LEN, PKT_DIR_INCOMING,
    PKT_DIR_NONCHECK, PKT_DIR_OUTGOING, PKT_DIR_UNKNOWN,
};

#[derive(Debug, Clone)]
/// AST node of a custom req-pattern expression.
pub enum Node {
    /// Matches a host address.
    Host(IpAddr),
    /// Matches a port.
    Port(u16),
    /// Logical AND of two nodes.
    And(Box<Node>, Box<Node>),
    /// Logical OR of two nodes.
    Or(Box<Node>, Box<Node>),
}

impl Node {
    fn evaluate(&self, ip: &IpAddr, port: u16) -> bool {
        match self {
            Node::Host(a) => a == ip,
            Node::Port(p) => *p == port,
            Node::And(l, r) => l.evaluate(ip, port) && r.evaluate(ip, port),
            Node::Or(l, r) => l.evaluate(ip, port) || r.evaluate(ip, port),
        }
    }
}

#[derive(Debug, Clone)]
/// Direction-matching strategy for a task.
pub enum ReqPattern {
    /// No direction checking.
    None,
    /// MAC-based matching against the interface MAC.
    Auto {
        /// The interface MAC address to match.
        mac: [u8; MAC_ADDR_LEN],
    },
    /// Custom expression matching.
    Custom {
        /// Parsed expression AST.
        ast: Box<Node>,
    },
}

impl ReqPattern {
    /// Port of `req_pattern_new_from_cfg_adv`.
    ///
    /// # Errors
    /// Returns an error if an auto pattern cannot resolve the interface MAC or
    /// a custom pattern fails to parse.
    pub fn new_from_cfg(cfg: &ReqPatternConfig, ifname: &str) -> Result<ReqPattern> {
        match cfg {
            ReqPatternConfig::None => Ok(ReqPattern::None),
            ReqPatternConfig::Auto => {
                let mac = get_if_mac_addr(ifname)?;
                log(
                    LOG_INFO,
                    &format!("interface '{ifname}' mac addr: {}", format_mac_addr(&mac)),
                );
                Ok(ReqPattern::Auto { mac })
            }
            ReqPatternConfig::Custom { pattern } => {
                let ast = parse_pattern(pattern)
                    .map_err(|e| Error::new(format!("invalid pattern: {pattern}: {e}")))?;
                Ok(ReqPattern::Custom { ast: Box::new(ast) })
            }
        }
    }

    /// Port of `req_pattern_judge_pkt_direction`.
    #[must_use]
    pub fn judge_pkt_direction(&self, pkt_data: &[u8]) -> i32 {
        match self {
            ReqPattern::None => PKT_DIR_NONCHECK,
            ReqPattern::Auto { mac } => {
                if pkt_data.len() < ETH_HDR_LEN {
                    return PKT_DIR_UNKNOWN;
                }
                if &pkt_data[6..12] == mac {
                    PKT_DIR_OUTGOING
                } else {
                    PKT_DIR_INCOMING
                }
            }
            ReqPattern::Custom { ast } => {
                let Some(info) = extract_ipport(pkt_data, 0) else {
                    return PKT_DIR_UNKNOWN;
                };
                if !info.has_ip {
                    return PKT_DIR_UNKNOWN;
                }
                if ast.evaluate(&info.src, info.sport) {
                    PKT_DIR_OUTGOING
                } else if ast.evaluate(&info.dst, info.dport) {
                    PKT_DIR_INCOMING
                } else {
                    PKT_DIR_UNKNOWN
                }
            }
        }
    }
}

#[must_use]
/// Evaluate a parsed custom pattern against an IP/port pair.
pub fn custom_match_by_ipport(node: &Node, ip: &IpAddr, port: u16) -> bool {
    node.evaluate(ip, port)
}

/// Canonical result token for a custom req-pattern query.
///
/// Exactly matches the C `c_req_pattern.c` output: one of `"0"`, `"1"`,
/// `"INIT_FAIL"`, or `"BAD_IP"`. Used by the differential harness and the
/// `diff_oracle` fuzz target.
#[must_use]
pub fn canonical_eval(pattern: &str, ip_str: &str, port: u16) -> &'static str {
    let ast = match parse_pattern(pattern) {
        Ok(a) => a,
        Err(_) => return "INIT_FAIL",
    };
    let ip = if let Ok(v4) = ip_str.parse::<std::net::Ipv4Addr>() {
        IpAddr::V4(v4.octets())
    } else if let Ok(v6) = ip_str.parse::<std::net::Ipv6Addr>() {
        IpAddr::V6(v6.octets())
    } else {
        return "BAD_IP";
    };
    if custom_match_by_ipport(&ast, &ip, port) {
        "1"
    } else {
        "0"
    }
}

/// Req-pattern type discriminant: no matching.
pub const REQ_PATTERN_TYPE_NONE: i32 = 0;
/// Req-pattern type discriminant: automatic matching.
pub const REQ_PATTERN_TYPE_AUTO: i32 = 1;
/// Req-pattern type discriminant: custom matching.
pub const REQ_PATTERN_TYPE_CUSTOM: i32 = 2;

#[allow(dead_code)]
fn type_name(ty: i32) -> &'static str {
    match ty {
        REQ_PATTERN_TYPE_NONE => REQ_PATTERN_TYPE_NONE_STR,
        REQ_PATTERN_TYPE_AUTO => REQ_PATTERN_TYPE_AUTO_STR,
        REQ_PATTERN_TYPE_CUSTOM => REQ_PATTERN_TYPE_CUSTOM_STR,
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Tokenizer + recursive-descent parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Host,
    Port,
    And,
    Or,
    LParen,
    RParen,
    Value(String),
    Eof,
}

struct Lexer<'a> {
    s: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(s: &'a str) -> Self {
        Lexer {
            s: s.as_bytes(),
            pos: 0,
        }
    }

    fn keyword(&mut self, kw: &[u8]) -> bool {
        if self.s[self.pos..].starts_with(kw) {
            let after = self.pos + kw.len();
            let next_alnum = self
                .s
                .get(after)
                .map(|c| c.is_ascii_alphanumeric())
                .unwrap_or(false);
            if !next_alnum {
                self.pos = after;
                return true;
            }
        }
        false
    }

    fn next_token(&mut self) -> Token {
        while self.pos < self.s.len() && (self.s[self.pos] as char).is_whitespace() {
            self.pos += 1;
        }
        if self.pos >= self.s.len() {
            return Token::Eof;
        }
        if self.keyword(b"host") {
            return Token::Host;
        }
        if self.keyword(b"port") {
            return Token::Port;
        }
        if self.keyword(b"and") {
            return Token::And;
        }
        if self.keyword(b"or") {
            return Token::Or;
        }
        match self.s[self.pos] {
            b'(' => {
                self.pos += 1;
                return Token::LParen;
            }
            b')' => {
                self.pos += 1;
                return Token::RParen;
            }
            _ => {}
        }

        let start = self.pos;
        while self.pos < self.s.len() {
            let c = self.s[self.pos];
            if (c as char).is_whitespace() || c == b'(' || c == b')' {
                break;
            }
            if self.s[self.pos..].starts_with(b"and")
                && !self
                    .s
                    .get(self.pos + 3)
                    .map(|x| x.is_ascii_alphanumeric())
                    .unwrap_or(false)
            {
                break;
            }
            if self.s[self.pos..].starts_with(b"or")
                && !self
                    .s
                    .get(self.pos + 2)
                    .map(|x| x.is_ascii_alphanumeric())
                    .unwrap_or(false)
            {
                break;
            }
            self.pos += 1;
        }
        Token::Value(String::from_utf8_lossy(&self.s[start..self.pos]).into_owned())
    }
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    cur: Token,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        let mut lexer = Lexer::new(s);
        let cur = lexer.next_token();
        Parser { lexer, cur }
    }

    fn advance(&mut self) {
        self.cur = self.lexer.next_token();
    }

    fn parse_expression(&mut self) -> Result<Node> {
        let mut left = self.parse_term()?;
        while self.cur == Token::Or {
            self.advance();
            let right = self.parse_term()?;
            left = Node::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_term(&mut self) -> Result<Node> {
        let mut left = self.parse_factor()?;
        while self.cur == Token::And {
            self.advance();
            let right = self.parse_factor()?;
            left = Node::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_factor(&mut self) -> Result<Node> {
        if self.cur == Token::LParen {
            self.advance();
            let expr = self.parse_expression()?;
            if self.cur != Token::RParen {
                return Err(Error::new("expected ')'"));
            }
            self.advance();
            Ok(expr)
        } else {
            self.parse_condition()
        }
    }

    fn parse_condition(&mut self) -> Result<Node> {
        match self.cur.clone() {
            Token::Host => {
                self.advance();
                let value = match self.cur.clone() {
                    Token::Value(v) => v,
                    _ => return Err(Error::new("expected host value")),
                };
                self.advance();
                Ok(Node::Host(resolve_host(&value)?))
            }
            Token::Port => {
                self.advance();
                let value = match self.cur.clone() {
                    Token::Value(v) => v,
                    _ => return Err(Error::new("expected port value")),
                };
                self.advance();
                // Upstream requires a *plain decimal* port: no sign and no
                // leading zero, because BPF would read `010` as octal, then the
                // usual `0..=65535` range. (`strtol(..., 10)` alone accepted `-0`
                // and `+80`; the guard in req_pattern.c rejects both now.)
                let bytes = value.as_bytes();
                let plain_decimal = !bytes.is_empty()
                    && bytes[0].is_ascii_digit()
                    && !(bytes[0] == b'0' && bytes.len() > 1);
                let port: u16 = if plain_decimal {
                    value
                        .parse()
                        .map_err(|_| Error::new(format!("invalid port: {value}")))?
                } else {
                    return Err(Error::new(format!("invalid port: {value}")));
                };
                Ok(Node::Port(port))
            }
            _ => Err(Error::new("expected condition")),
        }
    }
}

fn resolve_host(value: &str) -> Result<IpAddr> {
    if let Some(ifname) = value.strip_prefix("nic.") {
        let addr = get_if_ip_addr(ifname)
            .map_err(|_| Error::new(format!("get interface ip error for {ifname}")))?;
        log(
            LOG_INFO,
            &format!(
                "req_pattern interface {ifname} addresss is {}",
                addr.format()
            ),
        );
        return Ok(addr);
    }
    if let Ok(v4) = value.parse::<std::net::Ipv4Addr>() {
        return Ok(IpAddr::V4(v4.octets()));
    }
    if let Ok(v6) = value.parse::<std::net::Ipv6Addr>() {
        return Ok(IpAddr::V6(v6.octets()));
    }
    Err(Error::new(format!("invalid host address: {value}")))
}

/// Longest accepted custom pattern.
///
/// The parser is recursive descent, so an adversarial pattern with thousands of
/// nested `(` (or `and`/`or` operators, whose AST is also walked recursively)
/// would overflow the stack. C has the same recursion but no Rust-style bound -
/// its deep-recursion behaviour is UB (it survives longer only because its
/// frames are smaller) - so `parity/c_req_pattern.c` applies the same limit and
/// the differential compares only the defined domain. Real patterns are a few
/// dozen bytes (`host 1.2.3.4 and port 80`).
pub const MAX_PATTERN_LEN: usize = 512;

/// Parse a custom req_pattern expression into an AST.
///
/// # Errors
/// Returns an error if the expression is syntactically invalid or longer than
/// [`MAX_PATTERN_LEN`].
pub fn parse_pattern(pattern: &str) -> Result<Node> {
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(Error::new("pattern too long"));
    }
    let mut parser = Parser::new(pattern);
    let ast = parser.parse_expression()?;
    if parser.cur != Token::Eof {
        return Err(Error::new("unexpected trailing content in pattern"));
    }
    Ok(ast)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(pattern: &str, ip: &str, port: u16) -> bool {
        let ast = parse_pattern(pattern).unwrap();
        let addr = resolve_host(ip).unwrap();
        ast.evaluate(&addr, port)
    }

    #[test]
    fn port_parsing_requires_plain_decimal() {
        // Upstream `req_pattern.c` rejects anything that is not a plain decimal
        // (no sign, no leading zero - BPF reads `010` as octal), then range
        // checks `0..=65535`. Found by parity/difffuzz.sh (differential fuzzing),
        // which caught `port-0`: the C oracle returns INIT_FAIL while this side
        // used to accept it.
        assert!(parse_pattern("port 0").is_ok());
        assert!(parse_pattern("port 80").is_ok());
        assert!(parse_pattern("port 65535").is_ok());
        assert!(parse_pattern("port -0").is_err());
        assert!(parse_pattern("port -000").is_err());
        assert!(parse_pattern("port +80").is_err());
        assert!(parse_pattern("port 010").is_err());
        assert!(parse_pattern("port 00").is_err());
        assert!(parse_pattern("port -12").is_err());
        assert!(parse_pattern("port 65536").is_err());
        assert!(parse_pattern("port 0x50").is_err());
        assert!(parse_pattern("port 12x").is_err());
        // The exact input the differential fuzzer reported (mode=req_pattern):
        // C returns INIT_FAIL, so the harness must too.
        assert_eq!(canonical_eval(" port-0 ", "127.0.0.1", 32), "INIT_FAIL");
    }

    #[test]
    fn an_over_long_pattern_is_rejected_not_a_stack_overflow() {
        // Found by parity/difffuzz.sh: thousands of nested `(` overflowed the
        // recursive-descent parser (and, for operator chains, the recursive AST
        // walk). Both the Rust parser and the C oracle now reject at the same
        // length; C's deeper recursion is UB, so the limit is the comparison
        // domain.
        assert!(parse_pattern("host 127.0.0.1").is_ok());
        let deep = format!(
            "{}{}",
            "(".repeat(MAX_PATTERN_LEN),
            ")".repeat(MAX_PATTERN_LEN)
        );
        assert!(parse_pattern(&deep).is_err());
        assert_eq!(canonical_eval(&deep, "127.0.0.1", 80), "INIT_FAIL");
        let chain = "host 127.0.0.1 and ".repeat(MAX_PATTERN_LEN);
        assert_eq!(canonical_eval(&chain, "127.0.0.1", 80), "INIT_FAIL");
    }

    #[test]
    fn and_or_precedence() {
        assert!(eval("host 10.0.0.1 and port 80", "10.0.0.1", 80));
        assert!(!eval("host 10.0.0.1 and port 80", "10.0.0.2", 80));
        // 'and' binds tighter than 'or'
        assert!(eval(
            "host 10.0.0.1 and port 80 or host 10.0.0.2 and port 443",
            "10.0.0.2",
            443
        ));
    }

    #[test]
    fn parentheses() {
        assert!(!eval(
            "(host 10.0.0.1 or host 10.0.0.2) and port 80",
            "10.0.0.2",
            443
        ));
        assert!(eval(
            "(host 10.0.0.1 or host 10.0.0.2) and port 80",
            "10.0.0.2",
            80
        ));
    }

    #[test]
    fn trailing_error() {
        assert!(parse_pattern("host 10.0.0.1 port 80").is_err());
    }

    /// Ethernet frame wrapping an IPv4/UDP datagram, for the direction tests.
    fn eth_frame(ether_type: u16, body: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR_LEN];
        f[12..14].copy_from_slice(&ether_type.to_be_bytes());
        f.extend_from_slice(body);
        f
    }

    fn ipv4_udp(frame_src: [u8; 4], frame_dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // IPv4, IHL 5
        ip[2..4].copy_from_slice(&28u16.to_be_bytes()); // 20 IP + 8 UDP
        ip[9] = crate::packet::IPPROTO_UDP;
        ip[12..16].copy_from_slice(&frame_src);
        ip[16..20].copy_from_slice(&frame_dst);
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&sport.to_be_bytes());
        udp[2..4].copy_from_slice(&dport.to_be_bytes());
        ip.extend_from_slice(&udp);
        ip
    }

    fn ipv4_udp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        eth_frame(
            crate::packet::ETHERTYPE_IP,
            &ipv4_udp(src, dst, sport, dport),
        )
    }

    /// Ethernet + two stacked VLAN tags (QinQ: 0x88a8 then 0x8100) around IPv4/UDP.
    fn qinq_ipv4_udp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR_LEN];
        f[12..14].copy_from_slice(&crate::packet::ETHERTYPE_DOT1AD.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x01]); // outer tag TCI
        f.extend_from_slice(&crate::packet::ETHERTYPE_VLAN.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x02]); // inner tag TCI
        f.extend_from_slice(&crate::packet::ETHERTYPE_IP.to_be_bytes());
        f.extend_from_slice(&ipv4_udp(src, dst, sport, dport));
        f
    }

    /// Every config variant maps to its `ReqPattern`, and a bad custom pattern is
    /// reported as such rather than silently becoming a different strategy.
    #[test]
    fn new_from_cfg_builds_each_variant() {
        assert!(matches!(
            ReqPattern::new_from_cfg(&ReqPatternConfig::None, "lo").unwrap(),
            ReqPattern::None
        ));
        assert!(matches!(
            ReqPattern::new_from_cfg(&ReqPatternConfig::Auto, "lo").unwrap(),
            ReqPattern::Auto { .. }
        ));
        let custom = ReqPattern::new_from_cfg(
            &ReqPatternConfig::Custom {
                pattern: "port 80".into(),
            },
            "lo",
        )
        .unwrap();
        assert!(matches!(custom, ReqPattern::Custom { .. }));
        let err = ReqPattern::new_from_cfg(
            &ReqPatternConfig::Custom {
                pattern: "garbage".into(),
            },
            "lo",
        )
        .expect_err("an unparseable pattern must fail construction");
        assert!(
            err.to_string().contains("invalid pattern"),
            "error must name the pattern: {err}"
        );
    }

    /// `Auto` classifies by the frame's *source* MAC; a frame too short to hold
    /// one is `UNKNOWN`, never a bogus direction.
    #[test]
    fn auto_judge_uses_the_source_mac() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let p = ReqPattern::Auto { mac };
        let mut frame = vec![0u8; ETH_HDR_LEN];
        frame[6..12].copy_from_slice(&mac);
        assert_eq!(p.judge_pkt_direction(&frame), PKT_DIR_OUTGOING);
        frame[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(p.judge_pkt_direction(&frame), PKT_DIR_INCOMING);
        assert_eq!(
            p.judge_pkt_direction(&[0u8; 13]),
            PKT_DIR_UNKNOWN,
            "a truncated Ethernet header cannot carry a MAC"
        );
    }

    /// Custom patterns judge source first (outgoing), then destination
    /// (incoming), and leave anything that matches neither `UNKNOWN`.
    #[test]
    fn custom_judge_classifies_direction_and_unknown() {
        let p = ReqPattern::new_from_cfg(
            &ReqPatternConfig::Custom {
                pattern: "host 10.0.0.1 and port 80".into(),
            },
            "lo",
        )
        .unwrap();
        let outgoing = ipv4_udp_frame([10, 0, 0, 1], [10, 0, 0, 2], 80, 1234);
        assert_eq!(p.judge_pkt_direction(&outgoing), PKT_DIR_OUTGOING);
        let incoming = ipv4_udp_frame([10, 0, 0, 2], [10, 0, 0, 1], 1234, 80);
        assert_eq!(p.judge_pkt_direction(&incoming), PKT_DIR_INCOMING);
        let neither = ipv4_udp_frame([10, 0, 0, 3], [10, 0, 0, 4], 1, 2);
        assert_eq!(p.judge_pkt_direction(&neither), PKT_DIR_UNKNOWN);
        // A non-IP frame and a frame too short to parse are both UNKNOWN.
        assert_eq!(
            p.judge_pkt_direction(&eth_frame(0x0806, &[0u8; 40])),
            PKT_DIR_UNKNOWN
        );
        assert_eq!(p.judge_pkt_direction(&[0u8; 5]), PKT_DIR_UNKNOWN);
    }

    /// The stacked-VLAN descent added for QinQ (`packet::extract_ipport`) must be
    /// visible through the direction judge: the inner IPv4 address decides.
    #[test]
    fn custom_judge_descends_stacked_vlan() {
        let p = ReqPattern::new_from_cfg(
            &ReqPatternConfig::Custom {
                pattern: "host 10.0.0.1 and port 80".into(),
            },
            "lo",
        )
        .unwrap();
        let outgoing = qinq_ipv4_udp_frame([10, 0, 0, 1], [10, 0, 0, 2], 80, 1);
        assert_eq!(
            p.judge_pkt_direction(&outgoing),
            PKT_DIR_OUTGOING,
            "QinQ inner source must be matched"
        );
        let incoming = qinq_ipv4_udp_frame([10, 0, 0, 2], [10, 0, 0, 1], 1, 80);
        assert_eq!(
            p.judge_pkt_direction(&incoming),
            PKT_DIR_INCOMING,
            "QinQ inner destination must be matched"
        );
    }

    #[test]
    fn canonical_eval_matches_and_reports_bad_input() {
        assert_eq!(
            canonical_eval("host 10.0.0.1 and port 80", "10.0.0.1", 80),
            "1"
        );
        assert_eq!(
            canonical_eval("host 10.0.0.1 and port 80", "10.0.0.1", 81),
            "0"
        );
        assert_eq!(canonical_eval("host ::1", "::1", 0), "1");
        assert_eq!(
            canonical_eval("host 10.0.0.1", "not-an-ip", 0),
            "BAD_IP",
            "an unparseable address is distinct from a non-matching one"
        );
    }

    /// `type_name` is the human-readable form used in logs; each discriminant and
    /// the unknown fallback must map to a distinct string.
    #[test]
    fn type_name_covers_every_discriminant() {
        assert_eq!(type_name(REQ_PATTERN_TYPE_NONE), REQ_PATTERN_TYPE_NONE_STR);
        assert_eq!(type_name(REQ_PATTERN_TYPE_AUTO), REQ_PATTERN_TYPE_AUTO_STR);
        assert_eq!(
            type_name(REQ_PATTERN_TYPE_CUSTOM),
            REQ_PATTERN_TYPE_CUSTOM_STR
        );
        assert_eq!(type_name(42), "unknown");
    }

    /// `nic.<ifname>` resolves through `netutil`; a bad interface or a non-address
    /// string is an error, never a silently zeroed address.
    #[test]
    fn resolve_host_accepts_interface_and_rejects_bad_values() {
        assert_eq!(
            resolve_host("nic.lo").expect("loopback address"),
            IpAddr::V4([127, 0, 0, 1])
        );
        assert!(resolve_host("nic.definitely_not_real0").is_err());
        assert!(resolve_host("not-an-ip").is_err());
    }

    /// The lexer's keyword guards: a keyword prefix followed by an alphanumeric
    /// (`andrew`) is a value, not `and`; and a value running straight into
    /// `and`/`or` must stop at the operator.
    #[test]
    fn lexer_handles_keyword_prefixes_and_embedded_operators() {
        assert!(parse_pattern("andrew port 80").is_err());
        assert!(eval("host 10.0.0.1and port 80", "10.0.0.1", 80));
        assert!(eval("host 10.0.0.1or port 80", "10.0.0.1", 81));
        assert!(!eval("host 10.0.0.1or port 80", "10.0.0.2", 81));
    }

    #[test]
    fn parse_rejects_missing_operands() {
        assert!(parse_pattern("port").is_err());
        assert!(parse_pattern("host").is_err());
        assert!(parse_pattern("port 80 and").is_err());
    }
}
