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
}
