//! `dockerpid` — print the host PID of a Docker container.
//!
//! Rust port of `cptools/dockerpid/main.go`. Speaks the Docker Engine HTTP API
//! directly so there is no heavy client dependency. API-version negotiation via
//! the unversioned `/_ping` endpoint is preserved: it lets us talk to old
//! daemons (Docker on CentOS 7 / older k8s nodes, max API 1.39) whose version
//! is below what modern clients negotiate.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

const DEFAULT_UNIX_SOCKET: &str = "/var/run/docker.sock";
const DEFAULT_TCP: &str = "127.0.0.1:2375";

enum Stream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Unix(s) => s.read(buf),
            Stream::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Unix(s) => s.write(buf),
            Stream::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Unix(s) => s.flush(),
            Stream::Tcp(s) => s.flush(),
        }
    }
}

fn connect() -> Result<Stream> {
    let host = std::env::var("DOCKER_HOST").unwrap_or_default();
    let addr = if host.is_empty() {
        format!("unix://{DEFAULT_UNIX_SOCKET}")
    } else {
        host
    };

    if let Some(path) = addr.strip_prefix("unix://") {
        let s = UnixStream::connect(path)
            .with_context(|| format!("connect to docker socket {path}"))?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Stream::Unix(s))
    } else if let Some(rest) = addr.strip_prefix("tcp://") {
        let target = if rest.is_empty() { DEFAULT_TCP } else { rest };
        let s =
            TcpStream::connect(target).with_context(|| format!("connect to docker {target}"))?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Stream::Tcp(s))
    } else {
        bail!("unsupported DOCKER_HOST: {addr}");
    }
}

struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn http_get(stream: &mut Stream, path: &str) -> Result<HttpResponse> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed HTTP response"))?;
    let head = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = head.lines();
    let status_line = lines.next().ok_or_else(|| anyhow!("empty HTTP response"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bad status line: {status_line}"))?;

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let mut body = raw[header_end + 4..].to_vec();
    if headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        body = decode_chunked(&body)?;
    }

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn decode_chunked(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let line_end = data[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| pos + p)
            .ok_or_else(|| anyhow!("bad chunked encoding"))?;
        let size_str = std::str::from_utf8(&data[pos..line_end])?.trim();
        let size = usize::from_str_radix(size_str, 16)
            .with_context(|| format!("bad chunk size: {size_str}"))?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        out.extend_from_slice(&data[pos..pos + size]);
        pos += size + 2;
    }
    Ok(out)
}

/// Ping the daemon and return the advertised API version, clamped away from
/// nothing (we simply return what the daemon reports).
fn negotiate_api_version() -> Result<Option<String>> {
    let mut stream = connect()?;
    let resp = http_get(&mut stream, "/_ping")?;
    if resp.status != 200 {
        return Ok(None);
    }
    Ok(resp.headers.get("api-version").cloned())
}

fn container_pid(api_version: Option<&str>, container_id: &str) -> Result<i64> {
    let mut stream = connect()?;
    let path = match api_version {
        Some(v) => format!("/v{v}/containers/{container_id}/json"),
        None => format!("/containers/{container_id}/json"),
    };
    let resp = http_get(&mut stream, &path)?;
    if resp.status != 200 {
        bail!(
            "docker inspect failed (HTTP {}): {}",
            resp.status,
            String::from_utf8_lossy(&resp.body)
        );
    }
    let v: serde_json::Value =
        serde_json::from_slice(&resp.body).context("invalid docker inspect response")?;
    let pid = v
        .get("State")
        .and_then(|s| s.get("Pid"))
        .and_then(|p| p.as_i64())
        .ok_or_else(|| anyhow!("Pid not found in container inspect response"))?;
    Ok(pid)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        let prog = args.first().map(String::as_str).unwrap_or("dockerpid");
        eprintln!("Usage: {prog} <containerId>");
        eprintln!("Example: {prog} abc123def456");
        std::process::exit(1);
    }
    let container_id = &args[1];

    if let Err(e) = run(container_id) {
        eprintln!("Failed to get container info: {e:#}");
        std::process::exit(1);
    }
}

fn run(container_id: &str) -> Result<()> {
    // DOCKER_API_VERSION takes precedence; skip negotiation when set.
    let api_version = if std::env::var("DOCKER_API_VERSION")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        None
    } else {
        negotiate_api_version().unwrap_or(None)
    };

    let pid = container_pid(api_version.as_deref(), container_id)?;
    println!("{pid}");
    Ok(())
}
