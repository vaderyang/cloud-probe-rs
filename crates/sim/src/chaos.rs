//! Fault-injection model for the simulated network.

#[derive(Debug, Clone)]
pub struct Chaos {
    /// Probability a frame is dropped.
    pub loss: f64,
    /// Probability a frame is duplicated.
    pub dup: f64,
    /// Probability a frame has one random bit flipped.
    pub corrupt: f64,
    /// Probability a frame is delayed (reordered).
    pub reorder: f64,
    /// Base one-way delay (virtual microseconds).
    pub base_delay_us: u64,
    /// Additional random jitter (virtual microseconds).
    pub jitter_us: u64,
    /// Extra delay applied to reordered frames.
    pub reorder_delay_us: u64,
}

impl Default for Chaos {
    fn default() -> Self {
        Chaos {
            loss: 0.0,
            dup: 0.0,
            corrupt: 0.0,
            reorder: 0.0,
            base_delay_us: 50,
            jitter_us: 100,
            reorder_delay_us: 1_000,
        }
    }
}

impl Chaos {
    /// A moderately hostile network, used by the default DST suite.
    #[must_use]
    pub fn harsh() -> Self {
        Chaos {
            loss: 0.05,
            dup: 0.02,
            corrupt: 0.02,
            reorder: 0.05,
            base_delay_us: 100,
            jitter_us: 500,
            reorder_delay_us: 5_000,
        }
    }
}
