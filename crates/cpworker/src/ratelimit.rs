//! Token-bucket rate limiter. Port of `ratelimit.c`.

#[derive(Debug)]
pub struct TokenBucket {
    rate_bps: u64,
    capacity: u64,
    tokens: u64,
    last_ts: Option<(i64, i64)>,
}

impl TokenBucket {
    #[must_use]
    pub fn new(rate_bps: u64) -> Self {
        TokenBucket {
            rate_bps,
            capacity: rate_bps,
            tokens: rate_bps,
            last_ts: None,
        }
    }

    /// Try to consume `bytes` worth of tokens at timestamp `ts` (sec, usec).
    pub fn consume(&mut self, bytes: usize, ts: (i64, i64)) -> bool {
        if let Some(last) = self.last_ts {
            let sec = ts.0 - last.0;
            let mut usec = ts.1 - last.1;
            let (sec, _) = if usec < 0 {
                usec += 1_000_000;
                (sec - 1, usec)
            } else {
                (sec, usec)
            };
            let elapsed = sec as f64 + usec as f64 / 1e6;
            if elapsed >= 1.0 {
                self.tokens = self.tokens.saturating_add(self.rate_bps);
            } else if elapsed > 0.0 {
                self.tokens = self
                    .tokens
                    .saturating_add((elapsed * self.rate_bps as f64) as u64);
            }
            if self.tokens > self.capacity {
                self.tokens = self.capacity;
            }
        }
        self.last_ts = Some(ts);

        let required = (bytes as u64).saturating_mul(8);
        if self.tokens >= required {
            self.tokens -= required;
            true
        } else {
            false
        }
    }
}
