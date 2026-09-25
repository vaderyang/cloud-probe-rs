#![no_main]
//! Fuzz the packet parser + fragmenter (checksum / length arithmetic).

use libfuzzer_sys::fuzz_target;

use cpworker::packet::parse_packet;
use cpworker::packet_split::{build_fragment, calculate_fragment_count};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let max_payload = (data[0] as i32) * 8; // 0..2040
    let pkt = &data[1..];
    if let Some(r) = parse_packet(pkt) {
        let count = calculate_fragment_count(&r, max_payload);
        assert!(count >= 1);
        let mut buf = vec![0u8; 65536];
        for i in 0..count {
            let _ = build_fragment(&r, pkt, i, max_payload, true, &mut buf);
            let _ = build_fragment(&r, pkt, i, max_payload, false, &mut buf);
        }
    }
});
