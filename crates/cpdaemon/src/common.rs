//! Fingerprint helpers. The implementation lives in `cpgolib` (shared with the
//! differential fuzz harness); re-exported here for the daemon.

pub use cpgolib::fingerprint::{fingerprint_uuid_string, labels_to_fingerprint};
pub use cpgolib::worker_fingerprint::task_fingerprint_labels;
