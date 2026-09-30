//! Differential harness for the Rust config parser.
//! Same protocol as `c_config.c`.

use std::io::{self, BufRead, Write};

use cpworker::config::{canonical_dump, Config};

/// Parse and canonicalize one config line, writing either the canonical dump or
/// the `PARSE_FAIL`/`---` pair. Blank lines produce no output.
fn process_line<W: Write>(line: &str, out: &mut W) {
    if line.trim().is_empty() {
        return;
    }
    match Config::parse_str(line) {
        Ok(c) => {
            let _ = write!(out, "{}", canonical_dump(&c));
        }
        Err(_) => {
            let _ = writeln!(out, "PARSE_FAIL");
            let _ = writeln!(out, "---");
        }
    }
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        process_line(&line, &mut out);
    }
}

#[cfg(test)]
mod tests {
    use super::process_line;

    fn render(line: &str) -> String {
        let mut out = Vec::new();
        process_line(line, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn blank_lines_are_skipped() {
        assert_eq!(render(""), "");
        assert_eq!(render("   \t "), "");
    }

    #[test]
    fn valid_config_is_canonicalized() {
        let out = render(r#"{"log_level":"info","tasks":[]}"#);
        assert_eq!(
            out,
            "log_level=2\nexec_model=rtc\ncpu=\npipeline_mb=0\ncontrol none\ntasks=0\nexclude_bpf=\n---\n"
        );
    }

    #[test]
    fn invalid_config_emits_the_fail_sentinel() {
        assert_eq!(render("this is not json"), "PARSE_FAIL\n---\n");
    }

    #[test]
    fn consecutive_lines_are_concatenated_in_order() {
        let out = render(r#"{"log_level":"debug","tasks":[]}"#);
        let mut two = out.clone();
        two.push_str(&render("bad"));
        assert!(two.ends_with("PARSE_FAIL\n---\n"));
        assert!(two.starts_with("log_level="));
        // Two records, each terminated by its `---` delimiter line.
        assert_eq!(two.matches("---\n").count(), 2);
    }
}
