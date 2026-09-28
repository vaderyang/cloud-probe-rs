//! Pure-Rust classic-BPF (cBPF) compiler, interpreter and socket attachment.
//!
//! This replaces libpcap's filter compiler for the capture paths. The supported
//! tcpdump subset (see [`parse`]) is compiled to classic BPF for Ethernet
//! link-layer frames:
//!
//! * Live capture attaches the program with `SO_ATTACH_FILTER` (Linux).
//! * Offline pcap replay runs it with the built-in interpreter.
//!
//! The compiler is platform-neutral; only [`attach_filter`] is OS-specific, so a
//! Windows backend can be added later without changing code generation.

mod codes;
mod compiler;
mod interp;
mod parser;
mod resolvers;

#[cfg(target_os = "linux")]
mod linux;

use std::io;

use crate::error::Result;

pub use parser::{parse, parse_with, Ast, Dir, DnsResolver, NetSpec, Proto, Resolver, L4};
pub use resolvers::{clear_name_cache, name_cache_len, prewarm, CachedResolver, DEFAULT_TTL};

/// One classic-BPF instruction (matches `struct sock_filter`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    /// Opcode.
    pub code: u16,
    /// Jump offset when the test succeeds.
    pub jt: u8,
    /// Jump offset when the test fails.
    pub jf: u8,
    /// Immediate operand.
    pub k: u32,
}

/// A compiled classic-BPF program.
#[derive(Clone, Debug, Default)]
pub struct Program {
    /// The instruction sequence.
    pub insns: Vec<Insn>,
}

/// Maximum number of instructions the Linux kernel accepts for a socket filter
/// (`BPF_MAXINSNS`). A longer program cannot be installed with
/// `SO_ATTACH_FILTER` and must be applied in userspace instead.
pub const BPF_MAXINSNS: usize = 4096;

impl Program {
    /// True if the program has no instructions (matches everything).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// Evaluate the program against a raw link-layer frame.
    ///
    /// Returns the cBPF verdict: 0 means "drop", any non-zero value is the
    /// number of bytes to accept.
    #[must_use]
    pub fn evaluate(&self, pkt: &[u8]) -> u32 {
        interp::run(self, pkt)
    }

    /// True if the frame is accepted by the program.
    #[must_use]
    pub fn apply(&self, pkt: &[u8]) -> bool {
        self.evaluate(pkt) != 0
    }
}

/// Compile a tcpdump-subset expression into a classic-BPF program.
///
/// # Errors
/// Returns an error for syntax errors, unsupported keywords, unresolvable host
/// names, address/protocol mismatches, or programs exceeding the cBPF branch
/// limit.
pub fn compile(expr: &str) -> Result<Program> {
    let ast = parser::parse(expr)?;
    compiler::compile_ast(&ast)
}

/// Attach a compiled filter to a socket.
///
/// On Linux this uses `SO_ATTACH_FILTER`. On other platforms it returns
/// `Unsupported` (a per-OS backend, e.g. Npcap, would go here).
///
/// # Errors
/// Returns an error if the program is too long or the kernel rejects it.
#[cfg(target_os = "linux")]
pub fn attach_filter(fd: std::os::fd::RawFd, prog: &Program) -> io::Result<()> {
    linux::attach(fd, prog)
}

/// Attach a compiled filter to a socket (unsupported on this platform).
///
/// # Errors
/// Always returns `Unsupported` on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn attach_filter(_fd: std::os::fd::RawFd, _prog: &Program) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "BPF attachment is not implemented on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_empty_host_filter() {
        // The auto-generated exclusion used by the config layer.
        let p = compile("(port 80) and not host 10.0.0.9").unwrap();
        assert!(!p.is_empty());
    }

    #[test]
    fn evaluate_no_match_on_short_frame() {
        let p = compile("udp").unwrap();
        assert!(!p.apply(&[0, 1, 2]));
    }

    #[test]
    fn long_filters_exceed_the_kernel_instruction_limit() {
        // A realistic output-host exclusion chain reaches the kernel's
        // 4096-instruction cap quickly; the AF_PACKET capturer must then fall
        // back to userspace filtering instead of failing to attach.
        let expr = std::iter::once("port 80".to_string())
            .chain((0..150u32).map(|i| format!("not host 10.9.{}.{}", i / 256, i % 256)))
            .collect::<Vec<_>>()
            .join(" and ");
        let p = compile(&expr).unwrap();
        assert!(
            p.insns.len() > BPF_MAXINSNS,
            "expected > {BPF_MAXINSNS} instructions, got {}",
            p.insns.len()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_accepts_attached_program() {
        use std::os::fd::AsRawFd;
        // Any socket can carry a classic-BPF filter; this exercises the real
        // `SO_ATTACH_FILTER` path and validates the program with the kernel
        // verifier (no privileges required for an AF_INET socket).
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let p = compile("udp and port 53").unwrap();
        attach_filter(sock.as_raw_fd(), &p).expect("kernel rejected bpf program");
    }
}
