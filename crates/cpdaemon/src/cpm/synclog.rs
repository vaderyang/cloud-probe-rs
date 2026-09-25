//! Sync log ring buffer. Port of `cpdaemon/pkg/cpm/synclog.go`.

use std::sync::Arc;

use parking_lot::Mutex;

use super::models::LogEntry;

pub const SYNC_LOG_BUF_SIZE: usize = 200;

pub struct SyncLogBuffer {
    entries: Vec<LogEntry>,
    start: usize,
    end: usize,
}

impl Default for SyncLogBuffer {
    fn default() -> Self {
        SyncLogBuffer {
            entries: vec![LogEntry::default(); SYNC_LOG_BUF_SIZE],
            start: 0,
            end: 0,
        }
    }
}

impl SyncLogBuffer {
    pub fn write(&mut self, ts_sec: i64, ts_micro: i64, level: &str, details: String) {
        self.entries[self.end] = LogEntry {
            timestamp: ts_sec,
            micro_timestamp: ts_micro % 1_000_000,
            level: level.to_string(),
            details,
        };
        self.end = (self.end + 1) % SYNC_LOG_BUF_SIZE;
        if self.end == self.start {
            self.start = (self.start + 1) % SYNC_LOG_BUF_SIZE;
        }
    }

    /// Drain the buffer. Port of `Clear`.
    pub fn clear(&mut self) -> Vec<LogEntry> {
        let n = (self.end + SYNC_LOG_BUF_SIZE - self.start) % SYNC_LOG_BUF_SIZE;
        let mut result = Vec::with_capacity(n);
        let mut start = self.start;
        while start != self.end {
            result.push(self.entries[start].clone());
            start = (start + 1) % SYNC_LOG_BUF_SIZE;
        }
        self.start = 0;
        self.end = 0;
        for e in self.entries.iter_mut() {
            *e = LogEntry::default();
        }
        result
    }
}

/// Shared handle used by the logging layer.
pub type SharedSyncLogBuffer = Arc<Mutex<SyncLogBuffer>>;
