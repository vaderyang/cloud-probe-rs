//! Resource (fd) soak for the cpworker client.
//!
//! `cpdaemon` opens a new connection to `cpworker` for every command and dials
//! again after each failure, for the whole life of the daemon. A socket that is
//! created but never released is therefore not a benchmark curiosity but a
//! guaranteed `EMFILE` in a long-lived deployment, which is exactly the class of
//! defect a unit test cannot see: the connection *works*.
//!
//! This runs in its own test binary so that no other test's sockets are open
//! while the descriptor table is being compared (`/proc/self/fd` is per-process,
//! and `cargo test` shares one process between all tests of a target).
//!
//! See `verification/system.toml` (`fd-soak`) and VERIFICATION_COVERAGE.md §8.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use cpgolib::cpworker::{Client, Error, UnixClient};

/// The three tests below share this process, and the descriptor table is
/// per-process, so they must not overlap. Poisoning just means another test
/// failed mid-soak; the table is still readable.
static SOAK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn hold_sockets_exclusive() -> std::sync::MutexGuard<'static, ()> {
    SOAK_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Socket descriptors currently open in this process, as inode identifiers.
///
/// Only sockets are compared, and the fd *numbers* are ignored: the invariant
/// under test is "the set of live sockets is unchanged", and descriptor numbers
/// legitimately move around. The directory fd that `read_dir` opens for
/// `/proc/self/fd` shows up in its own listing, so it is dropped explicitly.
fn open_sockets() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir("/proc/self/fd").expect("read /proc/self/fd") {
        let entry = entry.expect("fd entry");
        // Another thread may close a descriptor between the directory listing
        // and the readlink; that descriptor is by definition not open anymore.
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let target = target.to_string_lossy().to_string();
        if target.starts_with("socket:[") {
            out.insert(target);
        }
    }
    out
}

fn temp_socket(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("cpgolib-soak-{}-{tag}.sock", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// Accept connections forever, answering each handshake with `reply`.
///
/// One ack is sent per connection, and only after *every* descriptor that
/// connection needed has been closed (the `BufReader`'s clone and the stream
/// itself). The caller can therefore take snapshots at two points where the
/// server is in exactly the same state: blocked in `accept()` holding nothing
/// but the listener.
///
/// Sending a line containing `shutdown` makes the thread exit.
fn serve(
    path: &Path,
    reply: &'static str,
) -> (std::sync::mpsc::Receiver<()>, std::thread::JoinHandle<()>) {
    let listener = UnixListener::bind(path).expect("bind soak socket");
    let (tx, rx) = channel();
    let handle = std::thread::spawn(move || serve_inner(listener, reply, tx));
    (rx, handle)
}

fn serve_inner(listener: UnixListener, reply: &'static str, acks: Sender<()>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { break };
        // A stalled test must not hang the soak forever; the fd snapshot is
        // taken after an ack, so a timeout here only ends the server.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
        let handshake = {
            let mut reader = BufReader::new(stream.try_clone().expect("try_clone"));
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => line,
            } // reader and its duplicated fd die here
        };
        if handshake.contains("shutdown") {
            break;
        }
        let _ = stream.write_all(reply.as_bytes());
        let _ = stream.write_all(b"\n");
        let _ = stream.flush();
        drop(stream);
        if acks.send(()).is_err() {
            break;
        }
    }
}

/// Tell the server thread to finish and wait for it, so its listener is closed
/// before the next test in this binary takes its own baseline. The caller must
/// snapshot the descriptors *before* calling this: the listener is part of the
/// baseline too.
fn shutdown_server(path: &Path, handle: std::thread::JoinHandle<()>) {
    if let Ok(mut stream) = UnixStream::connect(path) {
        let _ = stream.write_all(b"shutdown\n");
        let _ = stream.flush();
    }
    let _ = handle.join();
}

/// Reconnecting over and over must not accumulate sockets: dial, handshake,
/// drop, repeat.
#[test]
fn reconnect_cycles_do_not_leak_socket_descriptors() {
    const ROUNDS: usize = 500;
    let _exclusive = hold_sockets_exclusive();
    let path = temp_socket("reconnect");
    let (acks, server) = serve(&path, r#"{"status":"OK"}"#);
    let url = format!("unix://{}", path.display());

    // Warm up: descriptor work that happens once per process (lazy loader,
    // stdio, the ack channel's own fds) must not land inside the measured span.
    for _ in 0..3 {
        let mut client = UnixClient::new(&url).expect("new client");
        client.dial().expect("handshake");
        acks.recv().expect("server ack");
    }
    let baseline = open_sockets();

    for round in 0..ROUNDS {
        let mut client = UnixClient::new(&url).expect("new client");
        client
            .dial()
            .unwrap_or_else(|e| panic!("round {round}: handshake: {e}"));
        assert!(
            Client::close(&mut client).is_ok(),
            "round {round}: close must succeed"
        );
        drop(client);
        acks.recv()
            .unwrap_or_else(|e| panic!("round {round}: server stopped: {e}"));
    }

    let after = open_sockets();
    shutdown_server(&path, server);
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        baseline, after,
        "{ROUNDS} dial/close cycles changed the socket set"
    );
}

/// The failure paths must release the socket too: `dial` keeps the connection
/// while the handshake is in flight, so a rejected handshake has to tear it down
/// when the client is dropped.
#[test]
fn rejected_handshake_does_not_leak_socket_descriptors() {
    const ROUNDS: usize = 100;
    let _exclusive = hold_sockets_exclusive();
    let path = temp_socket("notok");
    let (acks, server) = serve(&path, r#"{"status":"ERROR","message":"soak"}"#);
    let url = format!("unix://{}", path.display());

    let mut client = UnixClient::new(&url).expect("new client");
    assert!(matches!(client.dial(), Err(Error::NotOk(_))));
    drop(client);
    acks.recv().expect("server ack");
    let baseline = open_sockets();

    for round in 0..ROUNDS {
        let mut client = UnixClient::new(&url).expect("new client");
        match client.dial() {
            Err(Error::NotOk(_)) => {}
            Err(err) => panic!("round {round}: expected NotOk, got {err}"),
            Ok(()) => panic!("round {round}: the soak server rejects the handshake"),
        }
        drop(client);
        acks.recv().expect("server ack");
    }

    let after = open_sockets();
    shutdown_server(&path, server);
    let _ = std::fs::remove_file(&path);
    assert_eq!(baseline, after, "{ROUNDS} failed handshakes leaked sockets");
}

/// A socket that could never be connected must not linger either.
#[test]
fn dial_failure_does_not_leak_socket_descriptors() {
    const ROUNDS: usize = 200;
    let _exclusive = hold_sockets_exclusive();
    let url = format!(
        "unix://{}/cpgolib-soak-{}-absent.sock",
        std::env::temp_dir().display(),
        std::process::id()
    );

    let mut client = UnixClient::new(&url).expect("new client");
    assert!(matches!(client.dial(), Err(Error::Dial { .. })));
    let baseline = open_sockets();

    for round in 0..ROUNDS {
        let mut client = UnixClient::new(&url).expect("new client");
        match client.dial() {
            Err(Error::Dial { .. }) => {}
            Err(err) => panic!("round {round}: expected a dial error, got {err}"),
            Ok(()) => panic!("round {round}: nothing listens on {url}"),
        }
    }

    let after = open_sockets();
    assert_eq!(
        baseline, after,
        "{ROUNDS} failed dials changed the socket set"
    );
}
