//! Ports of upstream `cpworker/tests/unit/output_zmq.c`.
//!
//! The C vectors bind a real libzmq `PULL` peer, create a `zmq_output_t`
//! pointing at it, drive `send_packet` / `zmq_flush_packet` and inspect the
//! received batch. The pure-Rust port speaks ZMTP 3.x over TCP, so the peer
//! here is a minimal server-side NULL handshake (the same helper shape as
//! `tests/zmtp_interop.rs`) that collects the batch frames. Assertions are on
//! the wire bytes the C test also read, plus the same batch-header fields.
//!
//! Production behaviour pinned here and missing from the initial port:
//! * an empty/omitted `uuid` is accepted and stays all-zero (#249);
//! * `destroy()` flushes the pending batch before disconnecting (#253);
//! * the VLAN walk is bounded by the captured length, so a slice that cuts a
//!   VLAN stack yields a correctly sized record instead of being dropped (#231,
//!   which upstream fixed in `output_zmq.c`).

use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cpworker::config::Config;
use cpworker::output::{new_output, Output, PacketHeader};
use cpworker::packet::PKT_DIR_INCOMING;
use cpworker::stats::OutputStats;
use cpworker::zmtp::codec;

const VALID_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";
const BATCH_HDR_SIZE: usize = 24;
/// `ZMQ_PKT_DATA_LEN_SIZE` (2) + `sizeof(zmq_pkt_hdr_t)` (16).
const RECORD_HDR_SIZE: usize = 2 + 16;
const MPLS_HDR_SIZE: usize = 4;

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

/// Read one ZMTP frame; returns `(flags, body)`.
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

/// Bind a `PULL` peer, complete the server handshake, and return every batch
/// body received until EOF. Accepts with a deadline so a client that never
/// connects cannot hang the test.
fn pull_server() -> (u16, JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((s, _)) => break Some(s),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() > deadline {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break None,
            }
        };
        let Some(mut s) = stream.take() else {
            return Vec::new();
        };
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        if s.write_all(&codec::greeting()).is_err() {
            return Vec::new();
        }
        if s.write_all(&codec::ready_command("PULL")).is_err() {
            return Vec::new();
        }
        let mut g = [0u8; codec::GREETING_LEN];
        if !read_full(&mut s, &mut g) {
            return Vec::new();
        }
        let _ = read_frame(&mut s); // client READY
        let mut batches = Vec::new();
        while let Some((flags, body)) = read_frame(&mut s) {
            if flags & codec::FLAG_COMMAND == 0 {
                batches.push(body);
            }
        }
        batches
    });
    (port, handle)
}

fn config_for(port: u16, slice: i32, uuid: Option<&str>) -> Config {
    let mut zmq = serde_json::json!({
        "host": "127.0.0.1",
        "port": port,
        "hwm": 100,
        "service_tag": 1,
        "heartbeat_ms": 0
    });
    if let Some(u) = uuid {
        zmq["uuid"] = serde_json::Value::String(u.to_string());
    }
    let cfg = serde_json::json!({
        "tasks": [{
            "capturer": {"type": "libpcap", "libpcap": {"interface": "eth0"}},
            "outputs": [{"type": "zmq", "zmq": zmq, "slice": slice, "rate_limit_mbps": 0}]
        }]
    });
    Config::parse_str(&cfg.to_string()).expect("parse zmq config")
}

/// `new_output()` from `output_zmq.c`: `uuid == None` omits the key (exercising
/// the default), `Some("")` sets it empty, `Some(u)` sets the value.
fn zmq_output(port: u16, slice: i32, uuid: Option<&str>) -> (Box<dyn Output>, Arc<OutputStats>) {
    let cfg = config_for(port, slice, uuid);
    let stats = Arc::new(OutputStats::default());
    let out =
        new_output(&cfg.tasks[0], &cfg.tasks[0].outputs[0], stats.clone()).expect("zmq output");
    (out, stats)
}

/// `output_send_packet()` with `PKT_DIR_INCOMING` and `ts.tv_sec = 1`.
fn send_frame(out: &mut dyn Output, frame: &[u8], caplen: u32) -> i32 {
    let hdr = PacketHeader {
        ts_sec: 1,
        ts_usec: 0,
        caplen,
        len: caplen,
    };
    out.send_packet(&hdr, frame, PKT_DIR_INCOMING)
}

/// Drive the non-blocking ZMTP client far enough to connect and handshake (the
/// C test's `zmq_connect` is synchronous).
fn drive(out: &mut dyn Output) {
    for _ in 0..100 {
        out.heartbeat(0);
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn batch_pkts_num(body: &[u8]) -> u16 {
    u16::from_be_bytes([body[2], body[3]])
}

// --- `test_default_empty_uuid_accepted` (#249) -----------------------------

#[test]
fn test_default_empty_uuid_accepted() {
    let (port, server) = pull_server();
    let (mut out, _stats) = zmq_output(port, 0, None);

    // No uuid key -> the batch header must carry an all-zero uuid.
    let frame = [0u8; 64];
    assert_eq!(send_frame(out.as_mut(), &frame, 64), 0);
    out.destroy();
    drop(out);

    let batches = server.join().unwrap();
    assert_eq!(batches.len(), 1, "expected one batch");
    assert_eq!(&batches[0][8..24], &[0u8; 16]);
}

// --- `test_invalid_uuid_rejected` ------------------------------------------

#[test]
fn test_invalid_uuid_rejected() {
    let cfg = config_for(1, 0, Some("xyz"));
    let err = new_output(
        &cfg.tasks[0],
        &cfg.tasks[0].outputs[0],
        Arc::new(OutputStats::default()),
    )
    .err()
    .expect("an invalid uuid must be rejected");
    assert!(
        err.to_string().contains("invalid uuid"),
        "error should name the invalid uuid: {err}"
    );
}

// --- `test_destroy_flushes_pending_batch` (#253) ---------------------------

#[test]
fn test_destroy_flushes_pending_batch() {
    let (port, server) = pull_server();
    let (mut out, _stats) = zmq_output(port, 0, Some(VALID_UUID));

    let mut frame = [0u8; 64];
    frame[12] = 0x08; // IPv4
    for _ in 0..3 {
        assert_eq!(send_frame(out.as_mut(), &frame, 64), 0);
    }

    out.destroy();
    drop(out);

    let batches = server.join().unwrap();
    assert_eq!(
        batches.len(),
        1,
        "the pending batch must be sent on destroy"
    );
    assert_eq!(batch_pkts_num(&batches[0]), 3);
}

// --- `test_destroy_empty_batch_sends_nothing` ------------------------------

#[test]
fn test_destroy_empty_batch_sends_nothing() {
    let (port, server) = pull_server();
    let (mut out, _stats) = zmq_output(port, 0, Some(VALID_UUID));

    drive(out.as_mut());
    out.destroy();
    drop(out);

    let batches = server.join().unwrap();
    assert!(batches.is_empty(), "an empty batch must not be sent");
}

// --- `assert_vlan_record()` + `test_vlan_stack_cut_by_slice` (#231) --------

fn assert_vlan_record(frame: &[u8], slice: i32, expected_vlan_size: usize) {
    let caplen = frame.len() as u32;
    let data_len = if slice > 0 && (slice as u32) < caplen {
        slice as u32
    } else {
        caplen
    };

    let (port, server) = pull_server();
    let (mut out, _stats) = zmq_output(port, slice, Some(VALID_UUID));

    assert_eq!(send_frame(out.as_mut(), frame, caplen), 0);
    out.destroy();
    drop(out);

    let batches = server.join().unwrap();
    assert_eq!(batches.len(), 1);
    let batch = &batches[0];
    assert_eq!(
        batch.len(),
        BATCH_HDR_SIZE + RECORD_HDR_SIZE + data_len as usize + MPLS_HDR_SIZE,
        "batch length must match the sliced record"
    );

    let rec = &batch[BATCH_HDR_SIZE + RECORD_HDR_SIZE..];
    let l2_size = 14 + expected_vlan_size;
    // Ethernet header and VLAN tags, except the innermost EtherType.
    assert_eq!(&rec[..l2_size - 2], &frame[..l2_size - 2]);
    assert_eq!(rec[l2_size - 2], 0x88);
    assert_eq!(rec[l2_size - 1], 0x47);
    // Payload after the MPLS header is the rest of the captured data.
    let payload_len = data_len as usize - l2_size;
    if payload_len > 0 {
        assert_eq!(
            &rec[l2_size + MPLS_HDR_SIZE..l2_size + MPLS_HDR_SIZE + payload_len],
            &frame[l2_size..l2_size + payload_len]
        );
    }
}

/// Reproducer from #231: `0x9200 -> 0x8100 -> 0x9100 -> 0x9200 -> 0x86dd`,
/// slice cuts the stack after three complete tags.
#[test]
fn test_vlan_stack_cut_by_slice() {
    let mut frame = vec![0u8; 1500];
    frame[12] = 0x92;
    frame[13] = 0x00;
    frame[16] = 0x81;
    frame[17] = 0x00;
    frame[20] = 0x91;
    frame[21] = 0x00;
    frame[24] = 0x92;
    frame[25] = 0x00;
    frame[28] = 0x86;
    frame[29] = 0xdd;

    // 26 captured bytes hold the Ethernet header and 3 complete tags.
    assert_vlan_record(&frame, 26, 12);
}

// --- `test_vlan_only_frame_without_slice` ----------------------------------

#[test]
fn test_vlan_only_frame_without_slice() {
    let mut frame = vec![0xaau8; 60];
    let mut i = 12;
    while i + 1 < frame.len() {
        frame[i] = 0x81;
        frame[i + 1] = 0x00;
        frame[i + 2] = 0x00;
        frame[i + 3] = 0x01;
        i += 4;
    }

    // 60 captured bytes hold the Ethernet header and 11 complete tags, 2 bytes
    // left over.
    assert_vlan_record(&frame, 0, 44);
}
