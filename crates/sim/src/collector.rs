//! Simulated collector: decodes wire frames and records the outcome.

use cpworker::packet::{be16, be32};

use crate::{FrameKind, Message};

#[derive(Debug, Clone)]
pub enum Decode {
    Ok { pkt_count: u16, detail: String },
    Malformed { reason: String },
}

#[derive(Debug, Clone)]
pub struct Delivered {
    pub serial: u64,
    pub kind: FrameKind,
    pub decode: Decode,
}

#[derive(Debug, Default, Clone)]
pub struct Collector {
    pub frames: Vec<Delivered>,
}

impl Collector {
    /// Decode a delivered frame. Returns the represented packet count on
    /// success, or a reason string on malformed input.
    ///
    /// # Errors
    /// Returns a `String` describing why the frame could not be decoded.
    pub fn consume(&mut self, msg: &Message) -> Result<u16, String> {
        let decode = match msg.kind {
            FrameKind::Gre => decode_gre(&msg.bytes),
            FrameKind::Vxlan => decode_vxlan(&msg.bytes),
            FrameKind::ZmqBatch | FrameKind::ZmqHeartbeat => decode_zmq(&msg.bytes),
        };
        let res = match &decode {
            Decode::Ok { pkt_count, .. } => Ok(*pkt_count),
            Decode::Malformed { reason } => Err(reason.clone()),
        };
        self.frames.push(Delivered {
            serial: msg.serial,
            kind: msg.kind,
            decode,
        });
        res
    }
}

fn decode_gre(b: &[u8]) -> Decode {
    if b.len() < 8 {
        return Decode::Malformed {
            reason: "gre: short".into(),
        };
    }
    if be16(&b[0..2]) != 0x2000 {
        return Decode::Malformed {
            reason: "gre: bad flags".into(),
        };
    }
    if be16(&b[2..4]) != 0x6558 {
        return Decode::Malformed {
            reason: "gre: bad protocol".into(),
        };
    }
    Decode::Ok {
        pkt_count: 1,
        detail: format!("inner_len={}", b.len() - 8),
    }
}

fn decode_vxlan(b: &[u8]) -> Decode {
    if b.len() < 8 {
        return Decode::Malformed {
            reason: "vxlan: short".into(),
        };
    }
    if be32(&b[0..4]) != 0x0800_0000 {
        return Decode::Malformed {
            reason: "vxlan: bad flags".into(),
        };
    }
    Decode::Ok {
        pkt_count: 1,
        detail: format!("inner_len={}", b.len() - 8),
    }
}

fn decode_zmq(b: &[u8]) -> Decode {
    if b.len() < 24 {
        return Decode::Malformed {
            reason: "zmq: short header".into(),
        };
    }
    if be16(&b[0..2]) != 2 {
        return Decode::Malformed {
            reason: "zmq: bad version".into(),
        };
    }
    let num = be16(&b[2..4]);
    let mut off = 24usize;
    let mut seen = 0u16;
    while seen < num {
        if off + 18 > b.len() {
            return Decode::Malformed {
                reason: "zmq: truncated packet header".into(),
            };
        }
        let dlen = be16(&b[off..off + 2]) as usize;
        off += 2 + 16;
        if off + dlen > b.len() {
            return Decode::Malformed {
                reason: "zmq: truncated packet data".into(),
            };
        }
        off += dlen;
        seen += 1;
    }
    if off != b.len() {
        return Decode::Malformed {
            reason: format!("zmq: trailing bytes ({off} != {})", b.len()),
        };
    }
    Decode::Ok {
        pkt_count: num,
        detail: format!("batch_pkts={num}"),
    }
}
