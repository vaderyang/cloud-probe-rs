#![no_main]
//! Fuzz the pure-Rust pcap savefile reader (AUDIT4 P5-20).
//!
//! The input is an arbitrary byte image of a pcap file. The reader must either
//! parse it or reject it — never panic, never hand out a record whose lengths
//! contradict each other, and never allocate an unbounded buffer for a single
//! record.
//!
//! Every input is replayed **twice**: once from a plain `Cursor` and once from a
//! `BufReader` with a 1-byte buffer. The second pass forces every multi-byte
//! field to straddle the source's read boundary, which is exactly where the old
//! `read()`-instead-of-`read_exact()` desync bug lived (PARITY.md §4): parsing must
//! not depend on how the source happens to chunk the bytes.

use std::io::{BufReader, Cursor, Read};

use libfuzzer_sys::fuzz_target;

use cpworker::capturer::pcap_file::{PcapReader, MAX_CAPLEN};

/// One replayed record: timestamps, the two length fields and the payload.
type Record = (i64, i64, u32, u32, Vec<u8>);

/// Bound the work one input may cause (the reader itself is bounded by
/// `MAX_CAPLEN`; this only keeps a 400 KiB input of tiny records cheap).
const MAX_RECORDS: usize = 64;
const MAX_BYTES: usize = 4 << 20;

fn drive<R: Read>(src: &str, r: R) -> Result<Vec<Record>, String> {
    let mut rd = match PcapReader::from_reader(src, r) {
        Ok(rd) => rd,
        Err(e) => return Err(e.to_string()),
    };
    let mut out: Vec<Record> = Vec::new();
    let mut total = 0usize;
    while out.len() < MAX_RECORDS {
        match rd.next_record() {
            Ok(true) => {
                // Invariants a caller (the offline capturer, and through it the
                // GRE/VXLAN/ZMQ outputs) relies on.
                assert_eq!(
                    rd.data.len(),
                    rd.caplen as usize,
                    "payload length must equal caplen"
                );
                assert!(
                    rd.caplen <= rd.len,
                    "caplen {} exceeds orig_len {}",
                    rd.caplen,
                    rd.len
                );
                assert!(
                    rd.caplen <= MAX_CAPLEN,
                    "caplen {} exceeds the allocation bound {MAX_CAPLEN}",
                    rd.caplen
                );
                assert_eq!(rd.linktype, cpworker::output::pcap_writer::DLT_EN10MB);
                total += rd.data.len();
                out.push((rd.ts_sec, rd.ts_usec, rd.caplen, rd.len, rd.data.clone()));
                if total > MAX_BYTES {
                    break;
                }
            }
            // Clean end of file.
            Ok(false) => break,
            // Rejecting a corrupt file is a valid outcome; the *reason* is
            // compared between the two passes below.
            Err(_) => break,
        }
    }
    Ok(out)
}

fuzz_target!(|data: &[u8]| {
    let plain = drive("fuzz", Cursor::new(data));
    let dribbled = drive("fuzz", BufReader::with_capacity(1, Cursor::new(data)));
    match (plain, dribbled) {
        (Ok(a), Ok(b)) => assert_eq!(
            a, b,
            "parsing must not depend on how the source chunks its bytes"
        ),
        (Err(a), Err(b)) => assert_eq!(a, b, "the two readers disagree on the rejection"),
        (Ok(_), Err(e)) => panic!("a valid file was rejected only when dribbled: {e}"),
        (Err(e), Ok(_)) => panic!("a valid file was rejected only when read at once: {e}"),
    }
});
