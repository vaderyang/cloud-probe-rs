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
/// Names in the expression are resolved through the platform resolver, memoised
/// process-wide (see [`resolvers`]); use [`compile_with`] to substitute one.
///
/// # Errors
/// Returns an error for syntax errors, unsupported keywords, unresolvable host
/// names, address/protocol mismatches, or programs exceeding the cBPF branch
/// limit.
pub fn compile(expr: &str) -> Result<Program> {
    compile_with(expr, &resolvers::CachedResolver::system())
}

/// [`compile`] with an injected [`Resolver`].
///
/// The compiler itself is pure; the only thing that can reach outside the process
/// is turning a host name into addresses. Handing that to the caller makes
/// compilation deterministic and side-effect free, which is what the fuzz target
/// needs: through [`compile`] a corpus entry containing `host <name>` performs a
/// real `getaddrinfo()` (glibc's resolver timeout is not ours to shorten), so the
/// run is slow, depends on the network, and cannot use a `-timeout=` gate.
///
/// # Errors
/// As [`compile`], plus whatever the injected resolver reports.
pub fn compile_with(expr: &str, resolver: &dyn Resolver) -> Result<Program> {
    let ast = parser::parse_with(expr, resolver)?;
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

    /// The injected-resolver entry point the fuzz target relies on: the addresses a
    /// name expands to must come from the caller's resolver, and nothing may reach
    /// for the network (which is what a `-timeout=` fuzz gate requires).
    #[test]
    fn compile_with_uses_the_injected_resolver_only() {
        use std::net::Ipv4Addr;

        #[derive(Default)]
        struct Counting {
            hits: std::sync::atomic::AtomicUsize,
        }
        impl Resolver for Counting {
            fn lookup(&self, host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
                self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // A name that the platform resolver cannot know: if anything ever
                // consulted DNS here, the filter below would fail to compile.
                assert_eq!(host, "fuzz-gate.invalid");
                Ok(vec![
                    std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
                    std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)),
                ])
            }
        }

        let r = Counting::default();
        let p = compile_with("host fuzz-gate.invalid", &r).expect("compile_with");
        assert_eq!(
            r.hits.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the injected resolver must be consulted exactly once per name"
        );
        // P2-8 semantics through the injected resolver: both addresses match.
        for last in [7u8, 8u8] {
            let mut frame = vec![0u8; 34];
            frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            frame[16] = 45;
            frame[23] = 17; // proto: UDP
            frame[26] = 192;
            frame[27] = 0;
            frame[28] = 2;
            frame[29] = last;
            assert!(p.apply(&frame), "host must match 192.0.2.{last}");
        }
        let mut other = vec![0u8; 34];
        other[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        other[16] = 45;
        other[23] = 17;
        other[26] = 192;
        other[27] = 0;
        other[28] = 2;
        other[29] = 9;
        assert!(
            !p.apply(&other),
            "192.0.2.9 is not one of the resolved addresses"
        );
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
