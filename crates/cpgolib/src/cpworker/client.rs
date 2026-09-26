//! cpworker unix-socket client. Port of `cpgolib/cpworker`.

use super::stats::StatsSummary;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid connStr: {0}")]
    InvalidConnStr(String),
    #[error("dial {path} failed: {source}")]
    Dial {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("no OK response: {0}")]
    NotOk(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoSummary {
    pub version: String,
    pub pid: i32,
    pub uptime_sec: i64,
    pub config_path: String,
    pub working_dir: String,
    pub log_destination: String,
    pub started_at_sec: i64,
}

impl InfoSummary {
    #[must_use]
    pub fn started_at(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(self.started_at_sec, 0).unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct PingResult {
    pub seq: i32,
    pub rtt: Duration,
    pub when: std::time::SystemTime,
}

/// Client trait mirroring the Go `Client` interface.
pub trait Client {
    /// # Errors
    /// Returns an error if the connection cannot be closed.
    fn close(&mut self) -> Result<()>;
    /// # Errors
    /// Returns an error if the connection cannot be established.
    fn dial(&mut self) -> Result<()>;
    /// # Errors
    /// Returns an error on transport failure or if the timeout elapses.
    fn collect_stats_summary(&mut self, timeout: Duration) -> Result<StatsSummary>;
    /// # Errors
    /// Returns an error on transport failure or if the timeout elapses.
    fn ping(&mut self, timeout: Duration) -> Result<PingResult>;
    /// # Errors
    /// Returns an error on transport failure or if the timeout elapses.
    fn info(&mut self, timeout: Duration) -> Result<InfoSummary>;
    /// # Errors
    /// Returns an error on transport failure or if the timeout elapses.
    fn reload_config(&mut self, timeout: Duration) -> Result<()>;
}

pub struct UnixClient {
    socket_path: String,
    default_timeout: Duration,
    conn: Option<UnixStream>,
}

impl UnixClient {
    /// Create a client with the default timeout.
    ///
    /// # Errors
    /// Returns an error if `conn_str` is not a valid `unix://path` string.
    pub fn new(conn_str: &str) -> Result<Self> {
        Self::with_timeout(conn_str, DEFAULT_TIMEOUT)
    }

    /// Create a client with an explicit timeout (zero means the default).
    ///
    /// # Errors
    /// Returns an error if `conn_str` is not a valid `unix://path` string.
    pub fn with_timeout(conn_str: &str, timeout: Duration) -> Result<Self> {
        let (typ, addr) = conn_str
            .split_once("://")
            .ok_or_else(|| Error::InvalidConnStr(conn_str.to_string()))?;
        if typ != "unix" {
            return Err(Error::InvalidConnStr(conn_str.to_string()));
        }
        Ok(UnixClient {
            socket_path: addr.to_string(),
            default_timeout: if timeout.is_zero() {
                DEFAULT_TIMEOUT
            } else {
                timeout
            },
            conn: None,
        })
    }

    fn timeout_for(&self, timeout: Duration) -> Duration {
        if timeout.is_zero() {
            self.default_timeout
        } else {
            timeout
        }
    }

    fn ensure_conn(&mut self, timeout: Duration) -> Result<&mut UnixStream> {
        if self.conn.is_none() {
            self.dial_with_timeout(timeout)?;
        }
        Ok(self.conn.as_mut().unwrap())
    }

    fn dial_with_timeout(&mut self, timeout: Duration) -> Result<()> {
        if self.conn.is_some() {
            return Ok(());
        }
        let conn = UnixStream::connect(&self.socket_path).map_err(|source| Error::Dial {
            path: self.socket_path.clone(),
            source,
        })?;
        let t = self.timeout_for(timeout);
        conn.set_read_timeout(Some(t))?;
        conn.set_write_timeout(Some(t))?;
        self.conn = Some(conn);
        self.handshake(timeout)?;
        Ok(())
    }

    fn handshake(&mut self, timeout: Duration) -> Result<()> {
        let data = serde_json::to_vec(&json!({"version": "v1"})).unwrap();
        self.send_raw(timeout, &data)?;
        let resp = self.recv_raw(timeout)?;
        let v: Value =
            serde_json::from_slice(&resp).map_err(|e| Error::InvalidResponse(e.to_string()))?;
        if v.get("status").and_then(Value::as_str) != Some("OK") {
            return Err(Error::NotOk(format!("{v}")));
        }
        Ok(())
    }

    fn send_raw(&mut self, timeout: Duration, data: &[u8]) -> Result<()> {
        let t = self.timeout_for(timeout);
        let conn = self.conn.as_mut().unwrap();
        conn.set_write_timeout(Some(t))?;
        conn.write_all(data)?;
        conn.write_all(b"\n")?;
        conn.flush()?;
        Ok(())
    }

    fn recv_raw(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        let t = self.timeout_for(timeout);
        let conn = self.conn.as_mut().unwrap();
        conn.set_read_timeout(Some(t))?;
        let mut reader = BufReader::new(conn);
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line)?;
        Ok(line)
    }

    /// Send an arbitrary command and return the response object.
    ///
    /// # Errors
    /// Returns an error on transport failure or if the timeout elapses.
    pub fn run_command(
        &mut self,
        command: &str,
        arguments: Option<Value>,
        timeout: Duration,
    ) -> Result<Value> {
        // Ensure connected (dial + handshake).
        if self.conn.is_none() {
            self.dial_with_timeout(timeout)?;
        }

        let mut cmd = json!({ "command": command });
        if let Some(args) = arguments {
            cmd["arguments"] = args;
        }
        let data = serde_json::to_vec(&cmd).unwrap();
        if let Err(e) = self.send_raw(timeout, &data) {
            let _ = self.close();
            return Err(e);
        }
        let raw = match self.recv_raw(timeout) {
            Ok(r) => r,
            Err(e) => {
                let _ = self.close();
                return Err(e);
            }
        };
        let resp: Value =
            serde_json::from_slice(&raw).map_err(|e| Error::InvalidResponse(e.to_string()))?;
        if resp.get("status").and_then(Value::as_str) != Some("OK") {
            return Err(Error::NotOk(format!("{resp}")));
        }
        Ok(resp)
    }
}

impl Client for UnixClient {
    fn close(&mut self) -> Result<()> {
        if let Some(conn) = self.conn.take() {
            conn.shutdown(std::net::Shutdown::Both).ok();
        }
        Ok(())
    }

    fn dial(&mut self) -> Result<()> {
        self.dial_with_timeout(self.default_timeout)
    }

    fn collect_stats_summary(&mut self, timeout: Duration) -> Result<StatsSummary> {
        let resp = self.run_command("collect_stats_summary", None, timeout)?;
        serde_json::from_value(resp)
            .map_err(|e| Error::InvalidResponse(format!("invalid stats summary: {e}")))
    }

    fn ping(&mut self, timeout: Duration) -> Result<PingResult> {
        let start = Instant::now();
        self.run_command("ping", None, timeout)?;
        Ok(PingResult {
            seq: 0,
            rtt: start.elapsed(),
            when: std::time::SystemTime::now(),
        })
    }

    fn info(&mut self, timeout: Duration) -> Result<InfoSummary> {
        let resp = self.run_command("info", None, timeout)?;
        serde_json::from_value(resp)
            .map_err(|e| Error::InvalidResponse(format!("invalid info summary: {e}")))
    }

    fn reload_config(&mut self, timeout: Duration) -> Result<()> {
        self.run_command("reload_config", None, timeout)?;
        Ok(())
    }
}

/// Construct a client from a `unix://path` connection string.
///
/// # Errors
/// Returns an error if `conn_str` is not a valid `unix://path` string.
pub fn new_client(conn_str: &str) -> Result<UnixClient> {
    UnixClient::new(conn_str)
}

/// Construct a client with an explicit timeout.
///
/// # Errors
/// Returns an error if `conn_str` is not a valid `unix://path` string.
pub fn new_client_with_timeout(conn_str: &str, timeout: Duration) -> Result<UnixClient> {
    UnixClient::with_timeout(conn_str, timeout)
}
