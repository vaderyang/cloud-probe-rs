//! Real-TCP integration tests for the pure-Rust ZMTP client.
//!
//! A small server thread speaks the server side of the ZMTP `NULL` handshake
//! (using the same codec) and reads message frames. These tests cover the happy
//! path, an unexpected mid-stream disconnect (client must reconnect and redeliver
//! later messages), and concurrent sending while the peer reads slowly.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use cpworker::zmtp::{codec, tcp_connector, SendOutcome, ZmtpPush};

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> bool {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) | Err(_) => return false,
            Ok(k) => n += k,
        }
    }
    true
}

/// Read one frame; returns `(flags, body)`.
fn read_frame(r: &mut impl Read) -> Option<(u8, Vec<u8>)> {
    let mut flag = [0u8; 1];
    if !read_full(r, &mut flag) {
        return None;
    }
    let len = if flag[0] & codec::FLAG_LONG != 0 {
        let mut l = [0u8; 8];
        if !read_full(r, &mut l) {
            return None;
        }
        u64::from_be_bytes(l) as usize
    } else {
        let mut l = [0u8; 1];
        if !read_full(r, &mut l) {
            return None;
        }
        l[0] as usize
    };
    let mut body = vec![0u8; len];
    if !read_full(r, &mut body) {
        return None;
    }
    Some((flag[0], body))
}

/// Accept one connection and complete the server-side NULL handshake.
fn accept_server(listener: &TcpListener) -> Option<TcpStream> {
    let (mut s, _) = listener.accept().ok()?;
    s.write_all(&codec::greeting()).ok()?;
    s.write_all(&codec::ready_command("PULL")).ok()?;
    let mut g = [0u8; codec::GREETING_LEN];
    read_full(&mut s, &mut g);
    let _ = read_frame(&mut s); // client READY
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    Some(s)
}

fn wait_connected(z: &mut ZmtpPush, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !z.is_connected() {
        z.poll();
        if Instant::now() >= deadline {
            panic!("client did not connect within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn real_tcp_delivers_messages() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut s = accept_server(&listener).expect("accept");
        let mut got = Vec::new();
        for _ in 0..3 {
            match read_frame(&mut s) {
                Some((flags, body)) if flags & codec::FLAG_COMMAND == 0 => got.push(body),
                _ => break,
            }
        }
        got
    });

    let connector = tcp_connector("127.0.0.1", addr.port()).unwrap();
    let mut z = ZmtpPush::new(connector, 100);
    wait_connected(&mut z, Duration::from_secs(3));
    z.send(b"one");
    z.send(b"two");
    z.send(b"three");
    z.drain_for(Duration::from_secs(2));

    let got = server.join().unwrap();
    assert_eq!(
        got,
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
    );
}

#[test]
fn real_tcp_reconnects_after_disconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        // First connection: handshake, read one message, then drop the socket.
        let mut s = accept_server(&listener).expect("accept 1");
        let first = read_frame(&mut s).map(|(_, b)| b);
        tx.send(first).ok();
        drop(s);
        // Second connection: the client must reconnect and deliver.
        let mut s2 = accept_server(&listener).expect("accept 2");
        read_frame(&mut s2).map(|(_, b)| b)
    });

    let connector = tcp_connector("127.0.0.1", addr.port()).unwrap();
    let mut z = ZmtpPush::new(connector, 100);
    wait_connected(&mut z, Duration::from_secs(3));
    z.send(b"first");
    z.drain_for(Duration::from_secs(1));

    // Wait for the client to notice the closed connection.
    let deadline = Instant::now() + Duration::from_secs(5);
    while z.is_connected() && Instant::now() < deadline {
        z.poll();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!z.is_connected(), "client did not detect the disconnect");

    wait_connected(&mut z, Duration::from_secs(5));
    z.send(b"second");
    z.drain_for(Duration::from_secs(2));

    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        Some(b"first".to_vec())
    );
    assert_eq!(server.join().unwrap(), Some(b"second".to_vec()));
}

#[test]
fn real_tcp_concurrent_send_and_slow_reader() {
    const N: usize = 300;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut s = accept_server(&listener).expect("accept");
        let mut got = Vec::with_capacity(N);
        for _ in 0..N {
            match read_frame(&mut s) {
                Some((flags, body)) if flags & codec::FLAG_COMMAND == 0 => {
                    got.push(body);
                    // Slow reader: let TCP backpressure build up.
                    if got.len() % 50 == 0 {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
                _ => break,
            }
        }
        got
    });

    let connector = tcp_connector("127.0.0.1", addr.port()).unwrap();
    let mut z = ZmtpPush::new(connector, 64);
    wait_connected(&mut z, Duration::from_secs(3));

    let mut queued = Vec::with_capacity(N);
    for i in 0..N {
        let msg = format!("message-{i:04}").into_bytes();
        if z.send(&msg) == SendOutcome::Queued {
            queued.push(msg);
        }
        z.poll();
        if i % 20 == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    z.drain_for(Duration::from_secs(5));

    let got = server.join().unwrap();
    // The connection is stable, so every accepted (Queued) message must arrive
    // in order and uncorrupted; messages that hit the HWM were Dropped.
    assert_eq!(got, queued);
}
