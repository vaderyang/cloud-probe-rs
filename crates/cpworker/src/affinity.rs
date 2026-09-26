//! CPU affinity helpers. Port of `affinity_linux.c`.

use crate::error::{Error, Result};

/// Parse a CPU list exactly like the C `cpu_set_parse` (strtoul base-0
/// semantics). Returns the list of CPU indices, or an error. An empty string
/// yields an empty list.
///
/// # Errors
/// Returns an error if the value contains an invalid CPU range or index.
pub fn cpu_set_parse(value: &str) -> Result<Vec<u32>> {
    let b = value.as_bytes();
    let mut pos = 0usize;
    let mut cpus: Vec<u32> = Vec::new();

    while pos < b.len() {
        if !b[pos].is_ascii_digit() {
            return Err(Error::new(format!("invalid cpu affinity: {value}")));
        }
        let (v0, np) = parse_ulong(b, pos)?;
        pos = np;
        let mut v1 = v0;
        if pos >= b.len() {
            cpus.push(v0 as u32);
            return Ok(cpus);
        }
        if b[pos] == b'-' {
            pos += 1;
            let (val1, np) = parse_ulong(b, pos)?;
            if v0 > val1 {
                return Err(Error::new(format!("invalid cpu affinity range: {value}")));
            }
            v1 = val1;
            pos = np;
        }
        if pos < b.len() && b[pos] == b',' {
            for v in v0..=v1 {
                cpus.push(v as u32);
            }
            pos += 1;
            if pos >= b.len() {
                return Err(Error::new(format!("invalid cpu affinity: {value}")));
            }
        } else if pos >= b.len() {
            for v in v0..=v1 {
                cpus.push(v as u32);
            }
            return Ok(cpus);
        } else {
            return Err(Error::new(format!("invalid cpu affinity: {value}")));
        }
    }
    Ok(cpus)
}

/// `strtoul(s, &end, 0)`: returns (value, end_index). The caller guarantees
/// `b[i]` is an ASCII digit, so at least one digit is consumed.
fn parse_ulong(b: &[u8], mut i: usize) -> Result<(u64, usize)> {
    let start = i;
    let mut base: u64 = 10;
    if b[i] == b'0' {
        if i + 1 < b.len() && (b[i + 1] == b'x' || b[i + 1] == b'X') {
            base = 16;
            i += 2;
        } else {
            base = 8;
            i += 1;
        }
    }
    let digits_start = i;
    let mut value: u64 = 0;
    while i < b.len() {
        let d = match b[i] {
            c @ b'0'..=b'9' => (c - b'0') as u64,
            c @ b'a'..=b'f' => (c - b'a' + 10) as u64,
            c @ b'A'..=b'F' => (c - b'A' + 10) as u64,
            _ => break,
        };
        if d >= base {
            break;
        }
        value = value.saturating_mul(base).saturating_add(d);
        i += 1;
    }
    if i == digits_start && !(base == 8 && digits_start == start + 1) {
        // "0x" with no digits, or no digits at all.
        return Err(Error::new("invalid number"));
    }
    // For the octal case the leading '0' counts as the consumed digit.
    let _ = start;
    Ok((value, i))
}

/// Build a `cpu_set_t` from the parsed list and apply it to the current thread.
///
/// # Errors
/// Returns an error if `value` cannot be parsed or if the affinity syscall fails.
#[cfg(target_os = "linux")]
pub fn set_cpu_affinity(value: &str) -> Result<()> {
    let cpus = cpu_set_parse(value)?;
    // libc's `cpu_set_t` is a fixed-size bitmask; `CPU_SET` indexes into it and
    // would panic for a CPU index >= CPU_SETSIZE. Mirror the C kernel limit
    // explicitly instead of relying on the panic.
    let cpu_setsize = libc::CPU_SETSIZE as u32;
    for &cpu in &cpus {
        if cpu >= cpu_setsize {
            return Err(Error::new(format!(
                "cpu affinity index {cpu} out of range (max {})",
                cpu_setsize - 1
            )));
        }
    }
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::CPU_ZERO(&mut set) };
    for cpu in cpus {
        unsafe { libc::CPU_SET(cpu as usize, &mut set) };
    }
    let ret = unsafe {
        libc::sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &set as *const libc::cpu_set_t,
        )
    };
    if ret != 0 {
        return Err(Error::new(format!(
            "sched_setaffinity({value}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_cpu_affinity(_value: &str) -> Result<()> {
    Err(Error::new("cpu affinity not supported on this platform"))
}
