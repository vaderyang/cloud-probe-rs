#![no_main]
//! Fuzz the VXLAN encapsulator (checsum + capture-time path).

use libfuzzer_sys::fuzz_target;

use cpworker::output::vxlan::vxlan_encapsulate;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let vni = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let vni_version = data[4] & 1;
    let direct = (data[5] % 4) as i32;
    let capture_time = data[6] & 1 == 1;
    let inner = &data[7..];

    let mut buf = vec![0u8; 65551];
    let total = vxlan_encapsulate(
        &mut buf,
        vni,
        vni_version,
        direct,
        capture_time,
        1_700_000_000,
        123_456,
        inner,
    );
    assert!(total <= buf.len(), "vxlan overrun: {total}");
});
