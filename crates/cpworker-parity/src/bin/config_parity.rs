//! Differential harness for the Rust config parser.
//! Same protocol as `c_config.c`.

use std::io::{self, BufRead, Write};

use cpworker::config::{canonical_dump, Config};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }

        match Config::parse_str(&line) {
            Ok(c) => {
                let _ = write!(out, "{}", canonical_dump(&c));
            }
            Err(_) => {
                let _ = writeln!(out, "PARSE_FAIL");
                let _ = writeln!(out, "---");
            }
        }
    }
}
