//! Linux-specific filter attachment (`SO_ATTACH_FILTER`).
//!
//! The compiler itself is platform-neutral; only this attach step is OS-specific,
//! so a Windows backend (e.g. Npcap's `pcap_setfilter`) can be added without
//! touching the code generator.

use std::io;
use std::os::fd::RawFd;

use super::Program;

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const super::Insn,
}

/// Attach a compiled classic-BPF program to `fd` via `SO_ATTACH_FILTER`.
///
/// # Errors
/// Returns an error if the program is too long for a `u16` length or if the
/// `setsockopt` call is rejected by the kernel.
pub fn attach(fd: RawFd, prog: &Program) -> io::Result<()> {
    if prog.insns.is_empty() {
        return Ok(());
    }
    let len = u16::try_from(prog.insns.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bpf program too long"))?;
    let fprog = SockFprog {
        len,
        filter: prog.insns.as_ptr(),
    };
    // SAFETY: `fprog` and the pointed-to instruction array live for the duration
    // of the call; the kernel copies the program synchronously.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            std::ptr::addr_of!(fprog).cast::<libc::c_void>(),
            std::mem::size_of::<SockFprog>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
