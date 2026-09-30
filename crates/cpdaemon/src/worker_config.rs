//! Worker configuration model. Moved to `cpgolib` so the differential fuzz
//! harness can share it; re-exported here to keep `crate::worker_config::*`
//! paths working.

pub use cpgolib::worker_config::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// Snapshot of upstream issue #237: Go's `encoding/json` matches object
    /// keys to struct fields **case-insensitively** and **zero-fills** absent
    /// fields, so a config with `snAplen` (instead of `snaplen`) or with a
    /// missing `capturer`/`outputs` block decodes successfully upstream.
    /// Serde does neither: a case-mismatched key is an unknown key (ignored,
    /// leaving the field at its default) and a field without `#[serde(default)]`
    /// is a hard error.
    ///
    /// These tests pin the Rust side of that divergence. The Go side is the
    /// reference oracle (`parity/difffuzz/go/oracle.go`), which decodes **all
    /// three shapes below successfully**; the fuzzer classifies the resulting
    /// one-sided `PARSE_FAIL` as a known benign divergence (PARITY.md §2.3),
    /// because `TaskConfig` JSON decoding is not a production input path in
    /// the port (the daemon builds `Config` in code).
    fn libpcap(snaplen_key: &str) -> String {
        format!(
            r#"{{"capturer":{{"type":"libpcap","libpcap":{{"interface":"eth0","{snaplen_key}":1234}}}},"outputs":[]}}"#
        )
    }

    fn snaplen(t: &TaskConfig) -> Option<i32> {
        t.capturer.libpcap.as_ref().and_then(|l| l.snaplen)
    }

    /// The divergence is not merely accept-vs-reject: Go *applies* the value
    /// (its oracle yields the same fingerprint for `snaplen` and `snAplen`),
    /// while serde drops it as an unknown key. The fingerprint is the only
    /// operation this decoder is used for in the port, so the difference is
    /// observable there.
    #[test]
    fn a_case_mismatched_key_is_ignored_not_applied() {
        let canonical: TaskConfig =
            serde_json::from_str(&libpcap("snaplen")).expect("canonical key accepted");
        let mismatched: TaskConfig =
            serde_json::from_str(&libpcap("snAplen")).expect("unknown key ignored");
        assert_eq!(snaplen(&canonical), Some(1234));
        assert_eq!(
            snaplen(&mismatched),
            None,
            "a case-mismatched key must not populate the field"
        );
        assert_ne!(
            cpgolib::worker_fingerprint::task_fingerprint(&canonical),
            cpgolib::worker_fingerprint::task_fingerprint(&mismatched),
            "Go applies `snAplen`; serde drops it, so the fingerprints differ"
        );
        // Go oracle: `snaplen` and `snAplen` both -> 96857b284cc98c99.
    }

    /// Go zero-fills the missing `capturer` (`CapturerConfig{}`) and `outputs`
    /// (`nil`) and still decodes; serde rejects each.
    #[test]
    fn a_missing_required_block_is_rejected() {
        for json in [
            r#"{"outputs":[]}"#,
            r#"{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}}}"#,
            r#"{"interface":"eth0"}"#,
        ] {
            assert!(
                serde_json::from_str::<TaskConfig>(json).is_err(),
                "serde must reject a missing required block: {json}"
            );
        }
    }

    /// An unknown key is ignored by *both* decoders - the one leniency they
    /// share, and the port relies on it (the fuzzer's `task_fingerprint` mode
    /// feeds extra keys). This pins that serde does not start rejecting.
    #[test]
    fn an_unknown_key_is_accepted_and_ignored() {
        let plain =
            r#"{"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[]}"#;
        let unknown = r#"{"bogus_unknown_key":1,"capturer":{"type":"libpcap","libpcap":{"interface":"eth0"}},"outputs":[]}"#;
        let a: TaskConfig = serde_json::from_str(plain).expect("plain accepted");
        let b: TaskConfig = serde_json::from_str(unknown).expect("unknown key ignored");
        assert_eq!(
            cpgolib::worker_fingerprint::task_fingerprint(&a),
            cpgolib::worker_fingerprint::task_fingerprint(&b),
            "an unknown key must not change the decoded value"
        );
    }
}
