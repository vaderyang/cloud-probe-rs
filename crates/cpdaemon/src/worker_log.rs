//! cpworker log line parsing. Port of `cpdaemon/pkg/worker/log.go`.

/// Parse a `2006-01-02T15:04:05 LEVEL message` line.
/// Returns (level, message) or None if the line is not a valid log line.
#[allow(dead_code)] // ported parser, not yet wired (PARITY.md §5)
pub fn parse_log_line(line: &str) -> Option<(&'static str, String)> {
    let (ts, rest) = line.split_once(' ')?;
    // Validate timestamp shape yyyy-mm-ddThh:mm:ss.
    if ts.len() != 19 || ts.as_bytes().get(10) != Some(&b'T') {
        return None;
    }
    chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S").ok()?;

    let rest = rest.trim_start();
    let (level_str, msg) = rest.split_once(' ')?;
    let level = match level_str.to_ascii_lowercase().as_str() {
        "trace" | "debug" => "debug",
        "info" => "info",
        "warn" => "warn",
        "error" | "fatal" => "error",
        _ => "info",
    };
    Some((level, msg.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_line() {
        let r = parse_log_line("2024-01-02T03:04:05 INFO hello world").unwrap();
        assert_eq!(r.0, "info");
        assert_eq!(r.1, "hello world");
    }

    #[test]
    fn rejects_invalid() {
        assert!(parse_log_line("not a log line").is_none());
        assert!(parse_log_line("2024-01-02T03:04:05").is_none());
    }
}
