//! Worker configuration model. Moved to `cpgolib` so the differential fuzz
//! harness can share it; re-exported here to keep `crate::worker_config::*`
//! paths working.

pub use cpgolib::worker_config::*;
