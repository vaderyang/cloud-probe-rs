#![no_main]
//! Fuzz the ZMQ batch builder, including the VLAN walk that previously
//! underflowed `payload_copy_len` (upstream issue #231). Must never panic and
//! must never write past the batch buffer.

use libfuzzer_sys::fuzz_target;

use cpworker::output::zmq::BatchBuilder;

fuzz_target!(|data: &[u8]| {
    if data.len() < 22 {
        return;
    }
    let service_tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let slice = data[4] as usize;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&data[5..21]);

    let mut b = BatchBuilder::new(service_tag, &uuid);
    let mut off = 21usize;
    let mut appended = 0;

    while off + 3 <= data.len() && appended < 256 {
        let caplen = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        // Avoid PKT_DIR_UNKNOWN (-1) so a frame is always encoded.
        let direct = (data[off + 2] % 4) as i32;
        off += 3;

        let take = caplen.min(data.len() - off);
        let frame = &data[off..off + take];
        off += take;
        if frame.len() < 18 {
            continue;
        }

        // Apply the configured slice to the logical caplen.
        let mut cap = frame.len();
        if slice > 0 {
            let s = slice.checked_mul(4).unwrap_or(usize::MAX);
            if s < cap {
                cap = s;
            }
        }
        if cap < 18 {
            continue;
        }
        let length = cap.min(65531) + 4;
        let wire_len = frame.len() as u32 + 4;

        if b.num() == 0 {
            b.set_first_pktsec(1);
        }
        if b.should_flush(1, length) {
            let (_, len) = b.begin_flush();
            assert!(len <= b.buf.len());
            b.end_flush();
        }
        if b.first_pktsec() == 0 {
            b.set_first_pktsec(1);
        }
        let _ = b.append_packet(1, 2, length as u16, wire_len, frame, direct);
        appended += 1;
    }

    if b.num() > 0 {
        let (_, len) = b.begin_flush();
        assert!(len <= b.buf.len(), "batch buffer overflow: {len}");
    }
});
