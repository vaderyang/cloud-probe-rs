//! Null output. Port of `output_null.c`.

use std::sync::Arc;

use super::{Output, PacketHeader};
use crate::config::OutputConfig;
use crate::packet::PKT_DIR_UNKNOWN;
use crate::ratelimit::TokenBucket;
use crate::stats::OutputStats;

pub struct NullOutput {
    stats: Arc<OutputStats>,
    rate_limit_mbps: u64,
    throttle: Option<TokenBucket>,
    slice: i32,
}

impl NullOutput {
    pub fn new(cfg: &OutputConfig, stats: Arc<OutputStats>) -> Self {
        let throttle = if cfg.rate_limit_mbps > 0 {
            Some(TokenBucket::new(cfg.rate_limit_mbps * 1_000_000))
        } else {
            None
        };
        NullOutput {
            stats,
            rate_limit_mbps: cfg.rate_limit_mbps,
            throttle,
            slice: cfg.slice,
        }
    }
}

impl Output for NullOutput {
    fn send_packet(&mut self, hdr: &PacketHeader, _pkt: &[u8], direct: i32) -> i32 {
        let mut length = hdr.caplen;
        if self.slice > 0 && (self.slice as u32) < length {
            length = self.slice as u32;
        }

        if direct == PKT_DIR_UNKNOWN {
            self.stats.direction_drop_bytes.add(length as u64);
            self.stats.direction_drop_packets.add(1);
            return -1;
        }

        if self.rate_limit_mbps > 0 {
            let tb = self.throttle.as_mut().unwrap();
            if !tb.consume(length as usize, hdr.ts()) {
                self.stats.ratelimit_drop_bytes.add(length as u64);
                self.stats.ratelimit_drop_packets.add(1);
                return -1;
            }
        }
        self.stats.fwd_bytes.add(length as u64);
        self.stats.fwd_packets.add(1);
        0
    }
}
