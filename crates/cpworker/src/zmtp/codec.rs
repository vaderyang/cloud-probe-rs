//! ZMTP 3.x wire-format codec (pure Rust).
//!
//! Implements just enough of ZMTP for a `PUSH` client talking to a `PULL`
//! collector over TCP with the `NULL` security mechanism:
//!
//! * the 64-byte greeting,
//! * the `READY` command (with `Socket-Type` metadata),
//! * message/command framing (short and long forms).
//!
//! The functions here are pure and side-effect free so they can be fuzzed
//! directly (see `fuzz/fuzz_targets/zmtp_wire.rs`).

use std::collections::BTreeMap;

/// Length of the ZMTP greeting.
pub const GREETING_LEN: usize = 64;
/// Frame flag: more parts follow (we always send single-part messages).
pub const FLAG_MORE: u8 = 0x01;
/// Frame flag: long frame (8-byte length).
pub const FLAG_LONG: u8 = 0x02;
/// Frame flag: this is a command frame.
pub const FLAG_COMMAND: u8 = 0x04;

/// Maximum frame body we are willing to allocate from a peer.
pub const MAX_FRAME_BODY: usize = 16 * 1024 * 1024;

/// Codec-level error (static message, no allocation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecError(pub &'static str);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Parsed peer greeting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    /// ZMTP version major.
    pub version_major: u8,
    /// ZMTP version minor.
    pub version_minor: u8,
    /// Security mechanism (e.g. `NULL`), NUL padded.
    pub mechanism: [u8; 20],
    /// Peer's `as-server` flag.
    pub as_server: u8,
}

impl Greeting {
    /// The mechanism as a trimmed string (no NUL padding).
    #[must_use]
    pub fn mechanism_str(&self) -> &str {
        let end = self
            .mechanism
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.mechanism.len());
        std::str::from_utf8(&self.mechanism[..end]).unwrap_or("")
    }
}

/// Build our client greeting (`NULL`, version 3.1, as-server = 0).
#[must_use]
pub fn greeting() -> [u8; GREETING_LEN] {
    let mut g = [0u8; GREETING_LEN];
    g[0] = 0xff;
    // libzmq uses 0x01 as the last signature byte (distinguishes from the
    // legacy ZMTP 1.0 signature); match it byte-for-byte.
    g[8] = 0x01;
    g[9] = 0x7f;
    g[10] = 3; // version major
    g[11] = 1; // version minor
    g[12..16].copy_from_slice(b"NULL");
    // mechanism bytes 16..32 stay zero (NUL padding)
    g[32] = 0; // as-server
               // filler 33..64 stay zero
    g
}

/// Parse a peer greeting from at least [`GREETING_LEN`] bytes.
///
/// # Errors
/// Returns an error if the buffer is too short or the signature/version/
/// mechanism is not something we can speak.
pub fn parse_greeting(buf: &[u8]) -> Result<Greeting, CodecError> {
    if buf.len() < GREETING_LEN {
        return Err(CodecError("greeting too short"));
    }
    if buf[0] != 0xff || buf[9] != 0x7f {
        return Err(CodecError("bad greeting signature"));
    }
    let mut mechanism = [0u8; 20];
    mechanism.copy_from_slice(&buf[12..32]);
    let g = Greeting {
        version_major: buf[10],
        version_minor: buf[11],
        mechanism,
        as_server: buf[32],
    };
    if g.version_major != 3 {
        return Err(CodecError("unsupported ZMTP major version"));
    }
    if g.mechanism_str() != "NULL" {
        return Err(CodecError("unsupported ZMTP mechanism"));
    }
    Ok(g)
}

/// A parsed command frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `READY` with its metadata properties.
    Ready(BTreeMap<String, Vec<u8>>),
    /// `ERROR` with a human-readable reason.
    Error(String),
    /// `PING` (optional trailing data).
    Ping(Vec<u8>),
    /// `PONG` (optional trailing data).
    Pong(Vec<u8>),
    /// Any other command name.
    Other(String),
}

/// Parse a `READY` command body: `name-len | name | metadata`.
fn parse_command_body(body: &[u8]) -> Result<Command, CodecError> {
    let Some(&name_len) = body.first() else {
        return Err(CodecError("empty command body"));
    };
    let name_len = name_len as usize;
    if body.len() < 1 + name_len {
        return Err(CodecError("command name truncated"));
    }
    let name = std::str::from_utf8(&body[1..1 + name_len])
        .map_err(|_| CodecError("command name not utf8"))?
        .to_string();
    let rest = &body[1 + name_len..];
    match name.as_str() {
        "READY" => Ok(Command::Ready(parse_metadata(rest)?)),
        "ERROR" => {
            let reason = String::from_utf8_lossy(
                rest.get(1..).unwrap_or(&[]), // first byte is reason length
            )
            .to_string();
            Ok(Command::Error(reason))
        }
        "PING" => Ok(Command::Ping(rest.to_vec())),
        "PONG" => Ok(Command::Pong(rest.to_vec())),
        _ => Ok(Command::Other(name)),
    }
}

/// Parse ZMTP metadata properties: repeated `name-len | name | value-len(4be) | value`.
fn parse_metadata(mut buf: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, CodecError> {
    let mut out = BTreeMap::new();
    while !buf.is_empty() {
        let name_len = buf[0] as usize;
        buf = &buf[1..];
        if buf.len() < name_len {
            return Err(CodecError("metadata name truncated"));
        }
        let name = std::str::from_utf8(&buf[..name_len])
            .map_err(|_| CodecError("metadata name not utf8"))?
            .to_string();
        buf = &buf[name_len..];
        if buf.len() < 4 {
            return Err(CodecError("metadata value length truncated"));
        }
        let vlen = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        buf = &buf[4..];
        if buf.len() < vlen {
            return Err(CodecError("metadata value truncated"));
        }
        out.insert(name, buf[..vlen].to_vec());
        buf = &buf[vlen..];
    }
    Ok(out)
}

/// Build a `READY` command frame advertising `socket_type`.
#[must_use]
pub fn ready_command(socket_type: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"READY");
    let mut body = {
        let mut b = vec![body.len() as u8];
        b.extend_from_slice(&body);
        b
    };
    append_metadata(&mut body, "Socket-Type", socket_type.as_bytes());
    append_metadata(&mut body, "Identity", b"");
    frame(FLAG_COMMAND, &body)
}

/// Build a `PONG` command frame (reply to `PING`).
#[must_use]
pub fn pong_command(ping_data: &[u8]) -> Vec<u8> {
    let mut body = vec![4];
    body.extend_from_slice(b"PONG");
    body.extend_from_slice(ping_data);
    frame(FLAG_COMMAND, &body)
}

fn append_metadata(buf: &mut Vec<u8>, name: &str, value: &[u8]) {
    buf.push(name.len() as u8);
    buf.extend_from_slice(name.as_bytes());
    buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buf.extend_from_slice(value);
}

/// Frame `body` with the given flag bits.
#[must_use]
pub fn frame(flags: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 9);
    if body.len() > 255 {
        out.push(flags | FLAG_LONG);
        out.extend_from_slice(&(body.len() as u64).to_be_bytes());
    } else {
        out.push(flags & !FLAG_LONG);
        out.push(body.len() as u8);
    }
    out.extend_from_slice(body);
    out
}

/// A parsed frame: flags plus body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Raw flag byte.
    pub flags: u8,
    /// Frame body.
    pub body: Vec<u8>,
}

impl Frame {
    /// Whether this is a command frame.
    #[must_use]
    pub fn is_command(&self) -> bool {
        self.flags & FLAG_COMMAND != 0
    }
}

/// Try to parse one frame from the front of `buf`.
///
/// Returns `Ok(None)` when more bytes are needed, `Ok(Some((frame, consumed)))`
/// on success, or an error for malformed input.
///
/// # Errors
/// Returns an error for a truncation-shaped malformed frame or an oversized
/// body declared by the peer.
pub fn parse_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, CodecError> {
    let Some(&flags) = buf.first() else {
        return Ok(None);
    };
    let (len, hdr) = if flags & FLAG_LONG != 0 {
        if buf.len() < 9 {
            return Ok(None);
        }
        let n = u64::from_be_bytes([
            buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
        ]);
        if n as usize > MAX_FRAME_BODY {
            return Err(CodecError("frame body too large"));
        }
        (n as usize, 9)
    } else {
        if buf.len() < 2 {
            return Ok(None);
        }
        (buf[1] as usize, 2)
    };
    if buf.len() < hdr + len {
        return Ok(None);
    }
    let body = buf[hdr..hdr + len].to_vec();
    Ok(Some((Frame { flags, body }, hdr + len)))
}

/// Decode a command frame body into a [`Command`].
///
/// # Errors
/// Returns an error if the frame is not a valid command.
pub fn decode_command(frame: &Frame) -> Result<Command, CodecError> {
    if !frame.is_command() {
        return Err(CodecError("not a command frame"));
    }
    parse_command_body(&frame.body)
}

/// Check whether a peer `Socket-Type` is compatible with our `PUSH` socket.
#[must_use]
pub fn peer_type_compatible(peer: &str) -> bool {
    // PUSH connects to PULL. We also tolerate a peer that reports PUSH/ROUTER
    // so we do not reject a collector that omits/forwards metadata, but the
    // standard case is PULL.
    matches!(peer, "PULL" | "ROUTER" | "PUSH")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_roundtrip() {
        let g = greeting();
        let parsed = parse_greeting(&g).unwrap();
        assert_eq!(parsed.version_major, 3);
        assert_eq!(parsed.mechanism_str(), "NULL");
        assert_eq!(parsed.as_server, 0);
    }

    #[test]
    fn ready_roundtrip() {
        let r = ready_command("PUSH");
        let (f, n) = parse_frame(&r).unwrap().unwrap();
        assert_eq!(n, r.len());
        match decode_command(&f).unwrap() {
            Command::Ready(md) => {
                assert_eq!(md.get("Socket-Type").map(Vec::as_slice), Some(&b"PUSH"[..]));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn frame_short_and_long() {
        let short = frame(0, b"hello");
        assert_eq!(short[0], 0);
        assert_eq!(short[1], 5);
        let long = frame(0, &vec![7u8; 300]);
        assert_eq!(long[0], FLAG_LONG);
        let (f, _) = parse_frame(&long).unwrap().unwrap();
        assert_eq!(f.body.len(), 300);
    }

    #[test]
    fn oversized_frame_rejected() {
        let mut buf = vec![FLAG_LONG];
        buf.extend_from_slice(&(MAX_FRAME_BODY as u64 + 1).to_be_bytes());
        assert!(parse_frame(&buf).is_err());
    }

    #[test]
    fn incomplete_is_none() {
        assert_eq!(parse_frame(&[]).unwrap(), None);
        assert_eq!(parse_frame(&[0x00]).unwrap(), None);
        assert_eq!(parse_frame(&[0x00, 5, 1, 2]).unwrap(), None);
    }

    #[test]
    fn pong_command_roundtrips() {
        let p = pong_command(b"xyz");
        let (f, _) = parse_frame(&p).unwrap().unwrap();
        match decode_command(&f).unwrap() {
            Command::Pong(data) => assert_eq!(data, b"xyz"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn peer_type_compat() {
        assert!(peer_type_compatible("PULL"));
        assert!(!peer_type_compatible("SUB"));
        assert!(!peer_type_compatible(""));
    }
    #[test]
    fn constants_and_display_are_exact() {
        assert_eq!(MAX_FRAME_BODY, 16 * 1024 * 1024);
        assert_eq!(FLAG_MORE, 0x01);
        assert_eq!(FLAG_LONG, 0x02);
        assert_eq!(FLAG_COMMAND, 0x04);
        assert_eq!(CodecError("boom").to_string(), "boom");
    }

    #[test]
    fn parse_greeting_rejects_short_and_bad_signature() {
        assert!(parse_greeting(&[0u8; 10]).is_err(), "short buffer");
        // Short but with a valid-looking signature prefix: a broken length guard
        // would read past the end here instead of rejecting.
        let mut short_valid = [0u8; 20];
        short_valid[0] = 0xff;
        short_valid[9] = 0x7f;
        assert!(parse_greeting(&short_valid).is_err(), "short but signed");
        let mut bad_first = greeting();
        bad_first[0] = 0x00;
        assert!(parse_greeting(&bad_first).is_err());
        let mut bad_second = greeting();
        bad_second[9] = 0x00;
        assert!(parse_greeting(&bad_second).is_err());
    }

    #[test]
    fn parse_command_body_rejects_truncated_name() {
        // name_len = 5 but only the length byte + 4 name bytes are present.
        let body = [5u8, b'R', b'E', b'A', b'D'];
        assert!(parse_command_body(&body).is_err());
    }

    #[test]
    fn error_command_is_decoded() {
        let mut body = vec![5u8];
        body.extend_from_slice(b"ERROR");
        body.push(3); // reason length prefix
        body.extend_from_slice(b"bad");
        let f = Frame {
            flags: FLAG_COMMAND,
            body,
        };
        match decode_command(&f).unwrap() {
            Command::Error(reason) => assert_eq!(reason, "bad"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn frame_boundary_at_255_uses_the_short_form() {
        let f = frame(0, &[0u8; 255]);
        assert_eq!(f[0], 0, "no long flag at exactly 255 bytes");
        assert_eq!(f[1], 255);
        let f = frame(0, &[0u8; 256]);
        assert_eq!(f[0], FLAG_LONG);
    }

    #[test]
    fn frame_body_at_the_size_limit_is_not_rejected() {
        let mut buf = vec![FLAG_LONG];
        buf.extend_from_slice(&(MAX_FRAME_BODY as u64).to_be_bytes());
        // Declares exactly the limit but no body yet: Ok(None), not an error.
        assert_eq!(parse_frame(&buf).unwrap(), None);
    }

    #[test]
    fn empty_short_frame_is_parsed() {
        let (f, n) = parse_frame(&[0x00, 0x00]).unwrap().unwrap();
        assert_eq!(n, 2);
        assert_eq!(f.body, Vec::<u8>::new());
    }

    /// The three truncation points in `parse_metadata` are distinguishable, and
    /// which field is short is what the daemon logs; a collision between them
    /// would silently mislabel a malformed peer.
    #[test]
    fn metadata_truncation_reports_which_field_is_short() {
        // name-len = 5 but only one name byte follows.
        assert_eq!(
            parse_metadata(&[0x05, b'a']).unwrap_err(),
            CodecError("metadata name truncated")
        );
        // The name fills the buffer exactly, so it is the 4-byte value length
        // that is missing -- not the name.
        assert_eq!(
            parse_metadata(&[0x01, b'a']).unwrap_err(),
            CodecError("metadata value length truncated")
        );
        // value-len says 4 bytes but only two follow.
        assert_eq!(
            parse_metadata(&[0x01, b'a', 0, 0, 0, 4, 0xAA, 0xBB]).unwrap_err(),
            CodecError("metadata value truncated")
        );
    }

    /// The long flag is a function of the body length, so a caller-supplied
    /// `FLAG_LONG` must not be toggled away for a long body (nor kept for a
    /// short one).
    #[test]
    fn frame_normalises_the_long_flag_from_the_body_length() {
        assert_eq!(frame(FLAG_LONG, &[0u8; 256])[0] & FLAG_LONG, FLAG_LONG);
        assert_eq!(frame(FLAG_LONG, &[0u8; 4])[0] & FLAG_LONG, 0);
        assert_eq!(frame(FLAG_COMMAND, &[0u8; 256])[0] & FLAG_LONG, FLAG_LONG);
    }
}
