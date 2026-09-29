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
        let end = pos
            .checked_add(size)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| anyhow!("truncated chunked encoding"))?;
        out.extend_from_slice(&data[pos..end]);
        pos = end + 2;
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
    parse_container_pid(&resp.body)
}

/// Extract `State.Pid` from a Docker `containers/{id}/json` body.
fn parse_container_pid(body: &[u8]) -> Result<i64> {
    let v: serde_json::Value =
        serde_json::from_slice(body).context("invalid docker inspect response")?;
    v.get("State")
        .and_then(|s| s.get("Pid"))
        .and_then(|p| p.as_i64())
        .ok_or_else(|| anyhow!("Pid not found in container inspect response"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn decodes_a_single_chunk() {
        assert_eq!(
            decode_chunked(b"5\r\nhello\r\n0\r\n\r\n").unwrap(),
            b"hello"
        );
    }

    #[test]
    fn decodes_multiple_chunks_until_the_zero_chunk() {
        assert_eq!(
            decode_chunked(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").unwrap(),
            b"hello world"
        );
    }

    #[test]
    fn rejects_a_bad_chunk_size() {
        assert!(decode_chunked(b"zz\r\nhi\r\n0\r\n\r\n").is_err());
        assert!(decode_chunked(b"5\r\nhi").is_err());
    }

    #[test]
    fn parses_state_pid_from_an_inspect_body() {
        assert_eq!(
            parse_container_pid(br#"{"State":{"Pid":4321}}"#).unwrap(),
            4321
        );
        // Extra fields and a plus sign must not confuse it.
        assert_eq!(
            parse_container_pid(br#"{"Id":"x","State":{"Running":true,"Pid":7}}"#).unwrap(),
            7
        );
    }

    #[test]
    fn rejects_inspect_bodies_without_a_numeric_pid() {
        assert!(parse_container_pid(b"not json").is_err());
        assert!(parse_container_pid(br#"{"State":{}}"#).is_err());
        assert!(parse_container_pid(br#"{"State":{"Pid":"4321"}}"#).is_err());
    }

    /// Serve one canned response on a local TCP port and return the connect target.
    fn one_shot_http(response: &'static str) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ = s.write_all(response.as_bytes());
        });
        addr
    }

    #[test]
    fn http_get_parses_status_headers_and_a_chunked_body() {
        let addr = one_shot_http(
            "HTTP/1.1 200 OK\r\nApi-Version: 1.41\r\nTransfer-Encoding: chunked\r\n\r\n\
             5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        );
        let mut stream = Stream::Tcp(TcpStream::connect(addr).unwrap());
        let resp = http_get(&mut stream, "/_ping").unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("api-version").map(String::as_str),
            Some("1.41")
        );
        assert_eq!(resp.body, b"hello world");
    }

    #[test]
    fn http_get_parses_a_fixed_length_body() {
        let addr = one_shot_http(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n{a:1}",
        );
        let mut stream = Stream::Tcp(TcpStream::connect(addr).unwrap());
        let resp = http_get(&mut stream, "/containers/x/json").unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"{a:1}");
    }

    #[test]
    fn http_get_rejects_a_malformed_response() {
        let addr = one_shot_http("not http at all");
        let mut stream = Stream::Tcp(TcpStream::connect(addr).unwrap());
        assert!(http_get(&mut stream, "/_ping").is_err());
    }
}
