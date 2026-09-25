//! Request/response direction detection. Port of `req_pattern.c`.
//!
//! Supports the same custom pattern mini-language:
//! `host <ip|nic.ifname> and|or port <n>`, with parentheses.

use crate::error::{Error, Result};
use crate::netutil::{get_if_ip_addr, get_if_mac_addr};
use crate::packet::{
    be16, extract_ipport, format_mac_addr, IpAddr, ETH_HDR_LEN, MAC_ADDR_LEN, PKT_DIR_INCOMING,
    PKT_DIR_NONCHECK, PKT_DIR_OUTGOING, PKT_DIR_UNKNOWN,
};
use crate::config::{ReqPatternConfig, LOG_INFO, REQ_PATTERN_TYPE_AUTO_STR, REQ_PATTERN_TYPE_CUSTOM_STR, REQ_PATTERN_TYPE_NONE_STR};
use crate::log::log;

#[derive(Debug, Clone)]
pub enum Node {
    Host(IpAddr),
    Port(u16),
    And(Box<Node>, Box<Node>),
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
pub enum ReqPattern {
    None,
    Auto { mac: [u8; MAC_ADDR_LEN] },
    Custom { ast: Box<Node> },
}

impl ReqPattern {
    /// Port of `req_pattern_new_from_cfg_adv`.
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

pub fn custom_match_by_ipport(node: &Node, ip: &IpAddr, port: u16) -> bool {
    node.evaluate(ip, port)
}

pub const REQ_PATTERN_TYPE_NONE: i32 = 0;
pub const REQ_PATTERN_TYPE_AUTO: i32 = 1;
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
                let port: u16 = value
                    .parse()
                    .map_err(|_| Error::new(format!("invalid port: {value}")))?;
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
            &format!("req_pattern interface {ifname} addresss is {}", addr.format()),
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

/// Parse a custom req_pattern expression into an AST.
pub fn parse_pattern(pattern: &str) -> Result<Node> {
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
        assert!(!eval("(host 10.0.0.1 or host 10.0.0.2) and port 80", "10.0.0.2", 443));
        assert!(eval("(host 10.0.0.1 or host 10.0.0.2) and port 80", "10.0.0.2", 80));
    }

    #[test]
    fn trailing_error() {
        assert!(parse_pattern("host 10.0.0.1 port 80").is_err());
    }
}
