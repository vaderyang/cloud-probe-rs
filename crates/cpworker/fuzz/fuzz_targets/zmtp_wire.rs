//! Coverage-guided fuzzing of the ZMTP wire-format codec.
//!
//! Feeds arbitrary bytes to the greeting/frame/command parsers. The parser must
//! never panic, must never allocate beyond the frame-size cap, and must report
//! `consumed <= input.len()`.

#![no_main]

use libfuzzer_sys::fuzz_target;

use cpworker::zmtp::codec;

fuzz_target!(|data: &[u8]| {
    let _ = codec::parse_greeting(data);

    if let Ok(Some((frame, consumed))) = codec::parse_frame(data) {
        assert!(consumed <= data.len());
        assert!(frame.body.len() <= codec::MAX_FRAME_BODY);
        if frame.is_command() {
            let _ = codec::decode_command(&frame);
        }
    }

    // Re-framing a body must always parse back.
    if data.len() < 4096 {
        let f = codec::frame(codec::FLAG_COMMAND, data);
        let (parsed, n) = codec::parse_frame(&f).unwrap().unwrap();
        assert_eq!(n, f.len());
        assert_eq!(parsed.body, data);
    }
});
