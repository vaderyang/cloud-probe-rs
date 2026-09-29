//! CLI definitions. Port of `cpctl/cmd/base.go`.

use std::time::Duration;

use clap::{Parser, Subcommand};

#[derive(Debug, Clone)]
pub struct Globals {
    pub unix: Option<String>,
    pub format: String,
    pub timeout: Duration,
}

impl Globals {
    /// Returns an error if `--unix` was not set.
    pub fn require_unix(&self) -> anyhow::Result<String> {
        match &self.unix {
            Some(u) if !u.is_empty() => Ok(format!("unix://{u}")),
            _ => anyhow::bail!("--unix/-u is required (e.g. /var/run/cloud-probe/cpworker.sock)"),
        }
    }

    pub fn format(&self) -> anyhow::Result<Format> {
        Format::parse(&self.format)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Jsonl,
}

impl Format {
    pub fn parse(s: &str) -> anyhow::Result<Format> {
        match s.to_ascii_lowercase().as_str() {
            "text" => Ok(Format::Text),
            "jsonl" | "ndjson" => Ok(Format::Jsonl),
            other => {
                anyhow::bail!("invalid --format {other:?} (text|jsonl, ndjson accepted as alias)")
            }
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "cpctl",
    version,
    about = "Control utility for cpworker",
    arg_required_else_help = true
)]
pub struct Cli {
    /// path to cpworker unix control socket, e.g. /var/run/cloud-probe/cpworker.sock
    #[arg(short = 'u', long, global = true)]
    pub unix: Option<String>,

    /// output format: text|jsonl (ndjson accepted as alias for jsonl)
    #[arg(short = 'f', long, global = true, default_value = "text")]
    pub format: String,

    /// per-RPC timeout
    #[arg(short = 'W', long, global = true, default_value = "3s", value_parser = humantime::parse_duration)]
    pub timeout: Duration,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Show cpctl version and build info
    Version,
    /// Show cpworker process info (version, pid, uptime, config_path, working_dir)
    Info,
    /// Send ping RPCs to cpworker and report RTT
    Ping {
        /// number of pings to send (0 = run forever)
        #[arg(short = 'n', long, default_value_t = 0)]
        count: i32,
        /// interval between pings
        #[arg(short = 'i', long, default_value = "1s", value_parser = humantime::parse_duration)]
        interval: Duration,
        /// suppress per-ping output, show only the summary
        #[arg(short = 'q', long, default_value_t = false)]
        quiet: bool,
    },
    /// Show cpworker stats (raw at -n=1, rates at -n>=2 or -n=0)
    Stats {
        /// number of samples (0 = run forever)
        #[arg(short = 'n', long, default_value_t = 0)]
        count: i32,
        /// interval between samples
        #[arg(short = 'i', long, default_value = "2s", value_parser = humantime::parse_duration)]
        interval: Duration,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn globals(unix: Option<&str>) -> Globals {
        Globals {
            unix: unix.map(str::to_string),
            format: "text".into(),
            timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn format_parses_text_and_the_jsonl_aliases() {
        assert_eq!(Format::parse("text").unwrap(), Format::Text);
        assert_eq!(Format::parse("TEXT").unwrap(), Format::Text);
        assert_eq!(Format::parse("jsonl").unwrap(), Format::Jsonl);
        assert_eq!(Format::parse("ndjson").unwrap(), Format::Jsonl);
        assert!(Format::parse("yaml").is_err());
    }

    #[test]
    fn require_unix_rejects_missing_or_empty() {
        assert!(globals(None).require_unix().is_err());
        assert!(globals(Some("")).require_unix().is_err());
        assert_eq!(
            globals(Some("/tmp/cpworker.sock")).require_unix().unwrap(),
            "unix:///tmp/cpworker.sock"
        );
    }
}
