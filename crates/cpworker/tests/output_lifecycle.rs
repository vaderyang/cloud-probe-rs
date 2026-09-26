//! Lifecycle regression tests for the output pipeline (AUDIT4 P5-04).
//!
//! `Output::destroy()` is the only place an output drains what it has buffered.
//! These tests replay a pcap file through a real `TaskManager` and assert that
//! the shutdown / reload paths hand every output the chance to flush:
//!
//! * a ZMQ output whose batches are still sitting in the ZMTP send queue must
//!   deliver them to the peer before the connection is torn down;
//! * a pcap file output must have its buffered records on disk.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use cpworker::config::Config;
use cpworker::output::pcap_writer::PcapWriter;
use cpworker::output::PacketHeader;
use cpworker::task::TaskManager;
use cpworker::zmtp::codec;

const PKT_LEN: usize = 4096;
/// ~24 MiB of batched payload: far more than the socket buffers involved, so
/// the ZMTP send queue is guaranteed to still hold batches at stop() time.
const N_PKTS: usize = 6000;

fn write_pcap(path: &std::path::Path) {
    let mut w = PcapWriter::create(path, 65535).expect("create pcap");
    let mut body = vec![0u8; PKT_LEN];
    body[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4
    body[PKT_LEN - 1] = 0xe7;
    for i in 0..N_PKTS {
        let hdr = PacketHeader {
            ts_sec: 1_000 + (i as i64 / 1000), // non-zero, so stale-flush works
            ts_usec: (i as i64) % 1_000_000,
            caplen: PKT_LEN as u32,
            len: PKT_LEN as u32,
        };
        w.write(&hdr, &body).expect("write pcap record");
    }
    w.flush().expect("flush pcap");
}

fn worker_config(pcap: &std::path::Path, port: u16, hwm: i32) -> String {
    format!(
        r#"{{"execution_model":"rtc","log_level":"ERROR","tasks":[{{
            "capturer": {{"type":"pcap_file","pcap_file":{{"file_name":"{}"}}}},
            "outputs": [{{"type":"zmq","zmq":{{
                "host":"127.0.0.1","port":{port},"hwm":{hwm},
                "service_tag":1,"uuid":"550e8400-e29b-41d4-a716-446655440000",
                "heartbeat_ms":0
            }}}}]
        }}]}}"#,
        pcap.display()
    )
}

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

/// Complete the server-side NULL handshake, then hold the receive queue closed
/// (never reading) until `go` fires; from then on read everything the peer
/// sends until EOF, returning the total number of packets carried in batches.
fn stalled_peer(listener: TcpListener, go: mpsc::Receiver<()>) -> usize {
    let (mut s, _) = listener.accept().expect("accept");
    // Small receive buffer: the peer (cpworker) must run out of socket buffer
    // and park its batches in the ZMTP send queue instead.
    if let Err(e) = socket2::SockRef::from(&s).set_recv_buffer_size(64 * 1024) {
        eprintln!("set_recv_buffer_size: {e}");
    }
    s.write_all(&codec::greeting()).expect("greeting");
    s.write_all(&codec::ready_command("PULL")).expect("ready");
    let mut g = [0u8; codec::GREETING_LEN];
    assert!(read_full(&mut s, &mut g), "client greeting");
    assert!(read_frame(&mut s).is_some(), "client READY");

    go.recv_timeout(Duration::from_secs(30)).ok();
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();

    let mut packets = 0usize;
    while let Some((flags, body)) = read_frame(&mut s) {
        if flags & codec::FLAG_COMMAND != 0 {
            continue;
        }
        // Batch header: version(2) pkts_num(2) keybit(4) uuid(16).
        assert!(body.len() >= 24, "batch shorter than the header");
        assert_eq!(&body[0..2], &[0, 2], "batch version");
        packets += u16::from_be_bytes([body[2], body[3]]) as usize;
    }
    let _ = s.shutdown(std::net::Shutdown::Both);
    packets
}

fn packets_stat(summary: &serde_json::Value, key: &str) -> u64 {
    summary["output"][key]["packets"]
        .as_u64()
        .expect("packets counter")
}

fn pump_all(mgr: &mut TaskManager) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while mgr.poll_packets_batch(512) > 0 {
        if Instant::now() > deadline {
            panic!("replaying the pcap file did not finish");
        }
    }
    // One more pass so the capturer's end-of-file heartbeat flushes the last
    // (partial) batch into the send queue.
    assert_eq!(mgr.poll_packets_batch(8), 0);
}

#[test]
fn stop_drains_batches_queued_in_zmtp() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("in.pcap");
    write_pcap(&pcap);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (go_tx, go_rx) = mpsc::channel();
    let peer = std::thread::spawn(move || stalled_peer(listener, go_rx));

    let mut mgr = TaskManager::new(
        Config::parse_str(&worker_config(&pcap, port, 200)).expect("parse"),
        "test.json".into(),
        dir.path().display().to_string(),
    )
    .expect("task manager");
    pump_all(&mut mgr);

    // Every batch that was accepted into the send queue must be counted as
    // forwarded, and the HWM must not have been reached (24 MiB / 1 MiB
    // batches, hwm 200), so `fwd_packets` is exactly what the peer should see.
    let summary = mgr.collect_stats_summary();
    let fwd = packets_stat(&summary, "fwd_packets");
    let dropped = packets_stat(&summary, "error_drop_packets");
    assert_eq!(dropped, 0, "no batch may hit the HWM in this test");
    assert!(
        fwd > 4000,
        "expected most of the {N_PKTS} packets to be queued for sending, got {fwd}"
    );

    go_tx.send(()).expect("release the peer");
    // The single destroy() call point: this must linger until the queue is dry.
    mgr.stop();

    let delivered = peer.join().expect("peer thread") as u64;
    assert_eq!(
        delivered, fwd,
        "stop() dropped {} packets that were still queued in the ZMTP send queue: \
         the peer saw {delivered} of {fwd} forwarded packets (ZMQ linger never ran)",
        fwd.saturating_sub(delivered)
    );
}

#[test]
fn reload_drains_batches_queued_in_zmtp() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = dir.path().join("in2.pcap");
    write_pcap(&pcap);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (go_tx, go_rx) = mpsc::channel();
    let peer = std::thread::spawn(move || stalled_peer(listener, go_rx));

    let cfg = worker_config(&pcap, port, 200);
    let mut mgr = TaskManager::new(
        Config::parse_str(&cfg).expect("parse"),
        "test.json".into(),
        dir.path().display().to_string(),
    )
    .expect("task manager");
    pump_all(&mut mgr);
    let fwd = packets_stat(&mgr.collect_stats_summary(), "fwd_packets");
    assert!(fwd > 4_000, "packets queued for sending: {fwd}");

    go_tx.send(()).expect("release the peer");
    mgr.reload(Config::parse_str(&cfg).expect("parse"))
        .expect("reload");

    let delivered = peer.join().expect("peer thread") as u64;
    assert_eq!(
        delivered, fwd,
        "reload() dropped queued batches: peer saw {delivered} of {fwd} \
         forwarded packets (the replaced outputs were released without destroy())"
    );
}

/// A file output must be flushed by the same call point.
#[test]
fn stop_flushes_pcap_file_output() {
    let dir = tempfile::tempdir().unwrap();
    let pcap_in = dir.path().join("in3.pcap");
    write_pcap(&pcap_in);
    let out_file = dir.path().join("out.pcap");

    let cfg = format!(
        r#"{{"execution_model":"rtc","log_level":"ERROR","tasks":[{{
            "capturer": {{"type":"pcap_file","pcap_file":{{"file_name":"{}"}}}},
            "outputs": [{{"type":"file","file":{{"name":"{}"}}}}]
        }}]}}"#,
        pcap_in.display(),
        out_file.display()
    );
    let mut mgr = TaskManager::new(Config::parse_str(&cfg).expect("parse"), "t.json".into(), dir
        .path()
        .display()
        .to_string())
    .expect("task manager");
    pump_all(&mut mgr);
    let fwd = packets_stat(&mgr.collect_stats_summary(), "fwd_packets");
    assert!(fwd > 4_000, "packets forwarded: {fwd}");

    mgr.stop();
    // The output is gone; what it wrote must be readable and complete.
    let on_disk = std::fs::metadata(&out_file).expect("output file").len();
    assert_eq!(
        on_disk as usize,
        24 + fwd as usize * (16 + PKT_LEN),
        "the pcap output must be fully written by stop()"
    );
}
