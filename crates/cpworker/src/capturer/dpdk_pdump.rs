//! DPDK `pdump` capturer. Port of `dpdk/pdump.c` (upstream `v0.9.x`).
//!
//! The capturer is **feature-gated** behind Cargo's `dpdk` feature. The default
//! build does not depend on DPDK at all: every pure piece (config mapping,
//! EAL-argument construction, ring-size rounding, pdump flags) is compiled and
//! tested unconditionally, while the `rte_*` call surface only exists under the
//! feature and is guarded at build time by [`build.rs`](../../build.rs).
//! `dpdk_pdump` config files keep parsing either way; without the feature the
//! dispatch in [`new_capturer`](super::new_capturer) refuses to open the task
//! with an explicit "built without the `dpdk` feature" error (PARITY.md §5.1).
//!
//! # Upstream mapping
//!
//! `dpdk_capture_new_from_cfg` (`pdump.c`) maps the parsed config onto
//! `dpdk_pdump_options_t` as:
//!
//! | option | source |
//! |---|---|
//! | `interface` | `dpdk_pdump.interface` |
//! | `snaplen` | `dpdk_pdump.snaplen` |
//! | `promiscuous_mode` | **hard-coded `true`** (`pdump.c:386`) |
//! | `bpf_filter` | `dpdk_pdump.bpf_filter` |
//! | `pool_name` | `"cpworker_capture_mbufs"` |
//! | `ring_name` | `"cpworker_capture_ring"` |
//! | `ring_size` | `dpdk_pdump.ring_size` |
//! | `num_mbufs` | `2 * ring_size` |
//!
//! The hard-coded promiscuous mode is the "sdt finding" recorded in
//! `FIELD_CONFIRMATION.md` §2: unlike the libpcap path (where C hard-codes
//! `promisc = 0`), the DPDK path has always enabled promiscuous mode and never
//! read it from JSON. The config surface is therefore kept *identical* to
//! upstream — no new key is introduced.
//!
//! # Runtime status (validated against real DPDK)
//!
//! The `rte_*` layer is compiled against the DPDK 21.11/22.11 ABI and has been
//! **linked and executed against a live DPDK** (DPDK 23.11.4, Ubuntu 24.04 VM,
//! bead `1eu`): `dpdk-testpmd` as the primary (a `net_pcap` vdev port) plus this
//! capturer as a secondary captured through pdump into the output pcap. The
//! primary-process monitor alarm remains a best-effort port.
//!
//! Direct linking is made possible by `dpdk_shim.c` (same directory), which
//! re-exports the helpers DPDK keeps `static __rte_always_inline` — notably
//! `rte_ring_sc_dequeue_burst_elem` (`rte_ring_elem.h`), which is not an
//! exported `librte_ring` symbol (`nm -D`: zero hits). `build.rs` compiles the
//! shim when the `dpdk` feature is enabled and links its object before the DPDK
//! libraries, so `cargo build --features dpdk` links out of the box on a DPDK
//! host. `rte_pktmbuf_pkt_len` is handled by reading the documented
//! `struct rte_mbuf` prefix directly. See `PARITY.md` §5.1.

// The pure layer is exercised by the unit tests and by the feature-gated
// runtime. In a plain `cargo build` (no `test`, no `dpdk`) it has no caller, so
// silence dead-code lints there rather than exporting internals as public API.
#![cfg_attr(not(any(test, feature = "dpdk")), allow(dead_code))]

use std::sync::Arc;

use super::Capturer;
use crate::config::{DpdkPdumpConfig, TaskConfig};
use crate::error::{Error, Result};
use crate::stats::CaptureStats;

/// Shared-memory mempool name (upstream literal, `pdump.c:386`).
pub(crate) const POOL_NAME: &str = "cpworker_capture_mbufs";
/// Shared ring name (upstream literal, `pdump.c:386`).
pub(crate) const RING_NAME: &str = "cpworker_capture_ring";
/// Upstream hard-codes promiscuous mode on for the DPDK pdump path.
pub(crate) const PROMISCUOUS_MODE: bool = true;
/// `MBUF_POOL_CACHE_SIZE` (`pdump.c`).
const MBUF_POOL_CACHE_SIZE: u32 = 32;
/// `BURST_SIZE` (`pdump.c`).
const BURST_SIZE: usize = 32;
/// `MONITOR_INTERVAL` in microseconds (`pdump.c`).
const MONITOR_INTERVAL_US: u64 = 500 * 1000;
/// `RTE_PDUMP_FLAG_RX | RTE_PDUMP_FLAG_TX`.
const RTE_PDUMP_FLAG_RXTX: u32 = 0b11;
/// `RTE_PDUMP_FLAG_PCAPNG`.
const RTE_PDUMP_FLAG_PCAPNG: u32 = 0b100;

/// The DPDK capturer's fully-resolved options (`dpdk_pdump_options_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DpdkPdumpOptions {
    /// Interface name or PCI address.
    pub(crate) interface: String,
    /// Snapshot length in bytes.
    pub(crate) snaplen: u32,
    /// Whether to enable promiscuous mode (always `true`, see module docs).
    pub(crate) promiscuous_mode: bool,
    /// Raw BPF filter expression (may be empty).
    pub(crate) bpf_filter: String,
    /// Shared mempool name.
    pub(crate) pool_name: String,
    /// Shared ring name.
    pub(crate) ring_name: String,
    /// Requested ring size (descriptors).
    pub(crate) ring_size: u32,
    /// Mempool size, `2 * ring_size`.
    pub(crate) num_mbufs: usize,
}

impl DpdkPdumpOptions {
    /// Mirror `dpdk_capture_new_from_cfg`'s struct initialiser.
    ///
    /// The config parser has already range-checked `snaplen` (`> 0` and clamped
    /// to [`crate::config::SNAPLEN_MAX`]) and `ring_size`
    /// ([`crate::config::RING_SIZE_MIN`]..=[`crate::config::RING_SIZE_MAX`]), so
    /// the `i32 -> u32` conversions cannot fail in practice; they are still
    /// checked rather than truncated.
    ///
    /// # Errors
    /// Returns an error if a config value is outside the range the DPDK API
    /// accepts.
    pub(crate) fn from_config(cfg: &DpdkPdumpConfig) -> Result<Self> {
        let snaplen = u32::try_from(cfg.snaplen)
            .map_err(|_| Error::new(format!("dpdk_pdump.snaplen {} is negative", cfg.snaplen)))?;
        let ring_size = u32::try_from(cfg.ring_size).map_err(|_| {
            Error::new(format!(
                "dpdk_pdump.ring_size {} is negative",
                cfg.ring_size
            ))
        })?;
        Ok(DpdkPdumpOptions {
            interface: cfg.interface.clone(),
            snaplen,
            promiscuous_mode: PROMISCUOUS_MODE,
            bpf_filter: cfg.bpf.clone(),
            pool_name: POOL_NAME.to_owned(),
            ring_name: RING_NAME.to_owned(),
            ring_size,
            num_mbufs: ring_size as usize * 2,
        })
    }
}

/// Round a ring size up to the next power of two.
///
/// Exact port of the arithmetic in `create_ring`: with `size: size_t`,
/// `log2 = sizeof(size) * 8 - __builtin_clzl(size - 1)` and `size = 1 << log2`.
/// A value that is already a power of two is returned unchanged; the caller
/// logs when rounding happened.
pub(crate) fn round_up_ring_size(ring_size: u32) -> u64 {
    let value = u64::from(ring_size);
    let log2 = 64 - value.saturating_sub(1).leading_zeros();
    1u64 << log2
}

/// The mutable EAL argument vector `dpdk_init` builds.
///
/// Upstream declares `{"dumpcap", "--proc-type", "secondary", "--log-level",
/// "notice"}`, replaces `argv[0]` with `"cpworker"` and passes all five entries
/// to `rte_eal_init`. `"--log-level" "notice"` is intentionally part of the
/// vector (it is `args[4]`, so `RTE_DIM(args) == 5`).
pub(crate) fn eal_args() -> Vec<String> {
    vec![
        "cpworker".to_owned(),
        "--proc-type".to_owned(),
        "secondary".to_owned(),
        "--log-level".to_owned(),
        "notice".to_owned(),
    ]
}

/// Build the `rte_pdump_enable_bpf` flags word.
///
/// `enable_pdump` always starts from `RTE_PDUMP_FLAG_RXTX` and ORs in
/// `RTE_PDUMP_FLAG_PCAPNG` when pcapng output is requested. Upstream passes
/// `use_pcapng = false`, so the pcapng bit is currently never set, but the
/// helper keeps the branch testable.
pub(crate) fn pdump_flags(use_pcapng: bool) -> u32 {
    if use_pcapng {
        RTE_PDUMP_FLAG_RXTX | RTE_PDUMP_FLAG_PCAPNG
    } else {
        RTE_PDUMP_FLAG_RXTX
    }
}

/// Build the DPDK pdump capturer, or explain why it is unavailable.
///
/// # Errors
/// Without the `dpdk` feature this always returns the feature-gate error. With
/// the feature it returns an error if EAL cannot be initialised, the interface
/// is unknown, the BPF filter cannot be converted, or a DPDK object cannot be
/// created.
pub(crate) fn new(
    tasks: &[TaskConfig],
    task: &TaskConfig,
    cfg: &DpdkPdumpConfig,
    stats: Arc<CaptureStats>,
) -> Result<Box<dyn Capturer>> {
    #[cfg(not(feature = "dpdk"))]
    {
        let _ = (tasks, task, cfg, stats);
        Err(Error::new(
            "dpdk_pdump capturer: cpworker was built without the `dpdk` feature; \
             rebuild with `--features dpdk` to enable it (PARITY.md §5.1)",
        ))
    }
    #[cfg(feature = "dpdk")]
    {
        runtime::DpdkPdumpCapturer::new(tasks, task, cfg, stats).map(|c| Box::new(c) as _)
    }
}

// ---------------------------------------------------------------------------
// Feature-gated runtime
// ---------------------------------------------------------------------------

#[cfg(feature = "dpdk")]
mod runtime {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_uint, c_void};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        eal_args, pdump_flags, round_up_ring_size, Capturer, DpdkPdumpOptions, BURST_SIZE,
        MBUF_POOL_CACHE_SIZE, MONITOR_INTERVAL_US, RTE_PDUMP_FLAG_RXTX,
    };
    use crate::capturer::{PacketHeader, PacketSink};
    use crate::config::{DpdkPdumpConfig, TaskConfig};
    use crate::error::{Error, Result};
    use crate::packet::PKT_DIR_NONCHECK;
    use crate::req_pattern::ReqPattern;
    use crate::stats::CaptureStats;

    // Direct bindings to the parts of the DPDK 21.11/22.11 ABI this capturer
    // uses. Symbols that are `static inline` in the DPDK headers
    // (`rte_pktmbuf_read`, `rte_pktmbuf_pkt_len`, and every
    // `rte_ring_*_dequeue_burst*` helper, including the `_elem` variant) are not
    // exported by the DPDK libraries, so a direct link would fail. The
    // declarations below are a *declarative* ABI mapping that compiles and
    // type-checks with `--features dpdk`; a live DPDK tree additionally needs a
    // C shim wrapping the static-inline `rte_ring_sc_dequeue_burst` (see the
    // module-level "Residual gaps" note), and the `rte_mbuf` prefix below
    // replaces the `rte_pktmbuf_pkt_len` accessor.
    unsafe extern "C" {
        fn rte_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
        fn rte_socket_id() -> c_uint;
        fn rte_free(ptr: *mut c_void);

        fn rte_eth_dev_get_port_by_name(name: *const c_char, port_id: *mut u16) -> c_int;
        fn rte_eth_promiscuous_enable(port_id: u16) -> c_int;
        fn rte_eth_promiscuous_disable(port_id: u16) -> c_int;

        fn rte_ring_lookup(name: *const c_char) -> *mut c_void;
        fn rte_ring_create(
            name: *const c_char,
            count: c_uint,
            socket_id: c_int,
            flags: c_uint,
        ) -> *mut c_void;
        fn rte_ring_free(ring: *mut c_void);
        fn rte_ring_sc_dequeue_burst_elem(
            ring: *mut c_void,
            obj_table: *mut c_void,
            esize: usize,
            n: c_uint,
            available: *mut c_uint,
        ) -> c_uint;

        fn rte_mempool_lookup(name: *const c_char) -> *mut c_void;
        fn rte_mempool_free(mp: *mut c_void);
        fn rte_pktmbuf_pool_create_by_ops(
            name: *const c_char,
            n: c_uint,
            cache_size: c_uint,
            priv_size: u16,
            data_room_size: u16,
            socket_id: c_int,
            ops_name: *const c_char,
        ) -> *mut c_void;
        fn rte_pcapng_mbuf_size(length: u32) -> u32;

        fn rte_pdump_enable_bpf(
            port_id: u16,
            queue: u16,
            flags: u32,
            snaplen: u32,
            ring: *mut c_void,
            mp: *mut c_void,
            prm: *const c_void,
        ) -> c_int;
        fn rte_pdump_disable(port: u16, queue: u16, flags: u32);

        fn rte_bpf_convert(prog: *const BpfProgram) -> *mut c_void;

        fn __rte_pktmbuf_read(
            m: *const c_void,
            off: u32,
            len: u32,
            buf: *mut c_void,
        ) -> *const c_void;
        fn rte_pktmbuf_free_bulk(mbufs: *mut *mut c_void, count: c_uint);

        fn rte_eal_primary_proc_alive(config_file_path: *const c_char) -> c_int;
        fn rte_eal_alarm_set(us: u64, cb: extern "C" fn(*mut c_void), cb_arg: *mut c_void)
            -> c_int;
        fn rte_eal_alarm_cancel(cb: extern "C" fn(*mut c_void), cb_arg: *mut c_void) -> c_int;
    }

    /// `struct bpf_program` from libpcap, the argument `rte_bpf_convert`
    /// expects. The instruction array layout matches [`crate::bpf::Insn`]
    /// (`struct bpf_insn`), so the pure-Rust compiler's output can be handed
    /// over without libpcap linkage.
    #[repr(C)]
    struct BpfProgram {
        bf_len: u32,
        bf_insns: *const crate::bpf::Insn,
    }

    /// The prefix of `struct rte_mbuf` up to `pkt_len`.
    ///
    /// DPDK exposes `rte_pktmbuf_pkt_len()` only as a macro, so the field is
    /// read directly. The layout is from DPDK 21.11/22.11 `rte_mbuf_core.h`:
    /// the `RTE_MARKER`/`RTE_MARKER64` members are zero-length arrays, so
    /// `buf_addr` starts at offset 0 and `pkt_len` at offset 36 on both
    /// 32- and 64-bit targets (the `__rte_aligned` on `buf_iova` forces the
    /// documented 8-byte alignment).
    #[repr(C)]
    struct RteMbufPrefix {
        buf_addr: *mut c_void,
        buf_iova: u64,
        data_off: u16,
        refcnt: u16,
        nb_segs: u16,
        port: u16,
        ol_flags: u64,
        packet_type: u32,
        pkt_len: u32,
    }

    /// `RTE_PDUMP_ALL_QUEUES` (`UINT16_MAX`).
    const ALL_QUEUES: u16 = u16::MAX;

    /// EAL is process-global and may only be initialised once. The result is
    /// memoised so a second task reports the original failure instead of
    /// re-entering `rte_eal_init`.
    static EAL: OnceLock<std::result::Result<(), String>> = OnceLock::new();

    /// Set by the primary-process monitor so a re-armed alarm stops.
    static MONITOR_QUIT: AtomicBool = AtomicBool::new(false);

    fn ensure_eal_init() -> Result<()> {
        match EAL.get_or_init(init_eal) {
            Ok(()) => Ok(()),
            Err(msg) => Err(Error::new(msg.clone())),
        }
    }

    fn init_eal() -> std::result::Result<(), String> {
        let args = eal_args();
        let mut owned = Vec::with_capacity(args.len());
        for arg in &args {
            owned.push(
                CString::new(arg.as_str()).map_err(|e| format!("invalid EAL argument: {e}"))?,
            );
        }
        let mut argv: Vec<*mut c_char> = owned
            .iter_mut()
            .map(|arg| arg.as_ptr().cast_mut())
            .collect();
        // `rte_eal_init` may retain the argument pointers for the lifetime of
        // the process, so both vectors are intentionally leaked once.
        let ret = unsafe { rte_eal_init(argv.len() as c_int, argv.as_mut_ptr()) };
        std::mem::forget(owned);
        std::mem::forget(argv);
        if ret < 0 {
            return Err("EAL init failed: is primary process running?".to_owned());
        }
        Ok(())
    }

    /// Read `mbuf->pkt_len` (the `rte_pktmbuf_pkt_len` macro).
    fn pktmbuf_pkt_len(m: *const c_void) -> u32 {
        // SAFETY: `m` is a live `struct rte_mbuf` handed to us by
        // `rte_ring_sc_dequeue_burst_elem`.
        unsafe { (*m.cast::<RteMbufPrefix>()).pkt_len }
    }

    /// `enable_primary_monitor`: re-arm every `MONITOR_INTERVAL` until the
    /// primary process is gone.
    extern "C" fn monitor_primary(_arg: *mut c_void) {
        if MONITOR_QUIT.load(Ordering::Relaxed) {
            return;
        }
        if unsafe { rte_eal_primary_proc_alive(ptr::null()) } != 0 {
            unsafe {
                rte_eal_alarm_set(MONITOR_INTERVAL_US, monitor_primary, ptr::null_mut());
            }
        } else {
            crate::log_error!("Primary process is no longer active, exiting...");
            MONITOR_QUIT.store(true, Ordering::Relaxed);
        }
    }

    /// `cleanup_pdump_resources`: only reached for a successfully-enabled port.
    fn cleanup_pdump_resources(port: u16, promiscuous_mode: bool) {
        unsafe {
            rte_pdump_disable(port, ALL_QUEUES, RTE_PDUMP_FLAG_RXTX);
            if promiscuous_mode {
                rte_eth_promiscuous_disable(port);
            }
        }
    }

    fn create_ring(opts: &DpdkPdumpOptions) -> Result<*mut c_void> {
        let name = CString::new(opts.ring_name.as_str())
            .map_err(|e| Error::new(format!("invalid ring name: {e}")))?;
        let mut ring = unsafe { rte_ring_lookup(name.as_ptr()) };
        if ring.is_null() {
            let size = round_up_ring_size(opts.ring_size);
            if size != u64::from(opts.ring_size) {
                crate::log_info!("ring size {} rounded up to {}", opts.ring_size, size);
            }
            ring = unsafe {
                rte_ring_create(name.as_ptr(), size as c_uint, rte_socket_id() as c_int, 0)
            };
            if ring.is_null() {
                return Err(Error::new(format!(
                    "could not create ring: {}",
                    opts.ring_name
                )));
            }
        }
        Ok(ring)
    }

    fn create_mempool(opts: &DpdkPdumpOptions) -> Result<*mut c_void> {
        let name = CString::new(opts.pool_name.as_str())
            .map_err(|e| Error::new(format!("invalid pool name: {e}")))?;
        let mut mp = unsafe { rte_mempool_lookup(name.as_ptr()) };
        if mp.is_null() {
            let data_room = unsafe { rte_pcapng_mbuf_size(opts.snaplen) };
            mp = unsafe {
                rte_pktmbuf_pool_create_by_ops(
                    name.as_ptr(),
                    opts.num_mbufs as c_uint,
                    MBUF_POOL_CACHE_SIZE,
                    0,
                    data_room as u16,
                    rte_socket_id() as c_int,
                    c"ring_mp_sc".as_ptr(),
                )
            };
            if mp.is_null() {
                return Err(Error::new(format!(
                    "mempool ({}) creation failed",
                    opts.pool_name
                )));
            }
        }
        Ok(mp)
    }

    /// A live DPDK pdump capturer.
    pub(crate) struct DpdkPdumpCapturer {
        stats: Arc<CaptureStats>,
        req_pattern: ReqPattern,
        port: u16,
        promiscuous_mode: bool,
        snaplen: u32,
        bpf_prm: *mut c_void,
        ring: *mut c_void,
        mp: *mut c_void,
        /// Scratch buffer for `rte_pktmbuf_read` when a frame is scattered.
        temp: Vec<u8>,
    }

    // The DPDK objects are owned by this capturer and used from the task
    // thread; sharing the type across threads is what `Capturer: Send` requires.
    unsafe impl Send for DpdkPdumpCapturer {}

    impl DpdkPdumpCapturer {
        pub(crate) fn new(
            _tasks: &[TaskConfig],
            task: &TaskConfig,
            cfg: &DpdkPdumpConfig,
            stats: Arc<CaptureStats>,
        ) -> Result<Self> {
            ensure_eal_init()?;
            let opts = DpdkPdumpOptions::from_config(cfg)?;
            let req_pattern = ReqPattern::new_from_cfg(&task.req_pattern, &opts.interface)
                .map_err(|e| Error::new(format!("create req_pattern_t error: {e}")))?;

            let ifname = CString::new(opts.interface.as_str())
                .map_err(|e| Error::new(format!("invalid interface name: {e}")))?;
            let mut port: u16 = 0;
            if unsafe { rte_eth_dev_get_port_by_name(ifname.as_ptr(), &mut port) } != 0 {
                return Err(Error::new(format!(
                    "interface {} not found",
                    opts.interface
                )));
            }

            // Convert the filter (upstream: pcap_compile + rte_bpf_convert).
            let mut bpf_prm: *mut c_void = ptr::null_mut();
            if !opts.bpf_filter.is_empty() {
                let program = crate::bpf::compile(&opts.bpf_filter)
                    .map_err(|e| Error::new(format!("pcap filter string not valid ({e})")))?;
                let bf = BpfProgram {
                    bf_len: program.insns.len() as u32,
                    bf_insns: program.insns.as_ptr(),
                };
                bpf_prm = unsafe { rte_bpf_convert(&bf) };
                if bpf_prm.is_null() {
                    return Err(Error::new("convert a bpf program to dpdk bpf code error"));
                }
            }

            let ring = match create_ring(&opts) {
                Ok(ring) => ring,
                Err(e) => {
                    unsafe {
                        rte_free(bpf_prm);
                    }
                    return Err(e);
                }
            };
            let mp = match create_mempool(&opts) {
                Ok(mp) => mp,
                Err(e) => {
                    unsafe {
                        rte_free(bpf_prm);
                        rte_ring_free(ring);
                    }
                    return Err(e);
                }
            };

            if let Err(e) = enable_pdump(port, &opts, ring, mp, bpf_prm) {
                unsafe {
                    rte_free(bpf_prm);
                    rte_ring_free(ring);
                    rte_mempool_free(mp);
                }
                return Err(e);
            }

            let _ =
                unsafe { rte_eal_alarm_set(MONITOR_INTERVAL_US, monitor_primary, ptr::null_mut()) };

            Ok(DpdkPdumpCapturer {
                stats,
                req_pattern,
                port,
                promiscuous_mode: opts.promiscuous_mode,
                snaplen: opts.snaplen,
                bpf_prm,
                ring,
                mp,
                temp: vec![0u8; opts.snaplen as usize],
            })
        }
    }

    fn enable_pdump(
        port: u16,
        opts: &DpdkPdumpOptions,
        ring: *mut c_void,
        mp: *mut c_void,
        bpf_prm: *mut c_void,
    ) -> Result<()> {
        if opts.promiscuous_mode {
            unsafe {
                rte_eth_promiscuous_enable(port);
            }
        }
        crate::log_info!("enter rte_pdump_enable_bpf, port {}", port);
        let ret = unsafe {
            rte_pdump_enable_bpf(
                port,
                ALL_QUEUES,
                pdump_flags(false),
                opts.snaplen,
                ring,
                mp,
                bpf_prm,
            )
        };
        if ret < 0 {
            return Err(Error::new(format!(
                "Packet dump enable failed: rte_pdump_enable_bpf returned {ret}"
            )));
        }
        crate::log_info!("exit rte_pdump_enable_bpf, port {}", port);
        Ok(())
    }

    impl Drop for DpdkPdumpCapturer {
        fn drop(&mut self) {
            unsafe {
                rte_eal_alarm_cancel(monitor_primary, ptr::null_mut());
                if !self.bpf_prm.is_null() {
                    rte_free(self.bpf_prm);
                }
                if !self.ring.is_null() {
                    rte_ring_free(self.ring);
                }
                if !self.mp.is_null() {
                    rte_mempool_free(self.mp);
                }
            }
            cleanup_pdump_resources(self.port, self.promiscuous_mode);
        }
    }

    impl Capturer for DpdkPdumpCapturer {
        fn capture_once(&mut self, sink: &mut dyn PacketSink) -> u64 {
            let mut pkts: [*mut c_void; BURST_SIZE] = [ptr::null_mut(); BURST_SIZE];
            let mut avail: c_uint = 0;
            let n = unsafe {
                rte_ring_sc_dequeue_burst_elem(
                    self.ring,
                    pkts.as_mut_ptr().cast(),
                    std::mem::size_of::<*mut c_void>(),
                    BURST_SIZE as c_uint,
                    &mut avail,
                )
            };
            if n == 0 {
                sink.on_heartbeat();
                return 0;
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            let ts_sec = now.as_secs() as i64;
            let ts_usec = i64::from(now.subsec_micros());

            for &m in &pkts[..n as usize] {
                if m.is_null() {
                    continue;
                }
                let len = pktmbuf_pkt_len(m);
                let caplen = len.min(self.snaplen);
                let data_ptr = unsafe {
                    __rte_pktmbuf_read(m, 0, caplen, self.temp.as_mut_ptr().cast::<c_void>())
                };
                if data_ptr.is_null() {
                    continue;
                }
                let data =
                    unsafe { std::slice::from_raw_parts(data_ptr.cast::<u8>(), caplen as usize) };
                let hdr = PacketHeader {
                    ts_sec,
                    ts_usec,
                    caplen,
                    len,
                };
                self.stats.cap_bytes.add(u64::from(caplen));
                self.stats.cap_packets.add(1);
                let direction = match &self.req_pattern {
                    ReqPattern::None => PKT_DIR_NONCHECK,
                    other => other.judge_pkt_direction(data),
                };
                sink.on_packet(&hdr, data, direction);
            }

            unsafe {
                rte_pktmbuf_free_bulk(pkts.as_mut_ptr(), n);
            }
            u64::from(n)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "dpdk"))]
    use crate::config::{CapturerConfig, CapturerKind, ReqPatternConfig};
    use crate::config::{DEFAULT_RING_SIZE, RING_SIZE_MAX, RING_SIZE_MIN};

    fn dpdk_cfg(interface: &str, snaplen: i32, bpf: &str, ring_size: i32) -> DpdkPdumpConfig {
        DpdkPdumpConfig {
            interface: interface.to_owned(),
            snaplen,
            bpf: bpf.to_owned(),
            ring_size,
        }
    }

    /// The options struct mirrors every field of `dpdk_pdump_options_t` and in
    /// particular hard-codes `promiscuous_mode = true` (`pdump.c:386`), which
    /// the libpcap path does not do (`FIELD_CONFIRMATION.md` §2).
    #[test]
    fn options_map_config_and_default_promiscuous_mode() {
        let cfg = dpdk_cfg("0000:00:08.0", 2048, "udp and port 5201", 2048);
        let opts = DpdkPdumpOptions::from_config(&cfg).expect("valid config");
        assert_eq!(opts.interface, "0000:00:08.0");
        assert_eq!(opts.snaplen, 2048);
        assert_eq!(opts.bpf_filter, "udp and port 5201");
        assert_eq!(opts.pool_name, POOL_NAME);
        assert_eq!(opts.ring_name, RING_NAME);
        assert_eq!(opts.ring_size, 2048);
        assert_eq!(opts.num_mbufs, 4096, "num_mbufs is 2 * ring_size");
        assert!(opts.promiscuous_mode, "DPDK pdump defaults promisc on");
        assert_eq!(opts.promiscuous_mode, PROMISCUOUS_MODE);
    }

    /// The promiscuous-mode default is independent of the BPF filter and the
    /// interface: nothing in the JSON config can turn it off.
    #[test]
    fn promiscuous_mode_is_always_on() {
        for cfg in [
            dpdk_cfg("eth0", 64, "", 2),
            dpdk_cfg("eth1", 262_144, "tcp", RING_SIZE_MAX as i32),
        ] {
            let opts = DpdkPdumpOptions::from_config(&cfg).expect("valid config");
            assert!(opts.promiscuous_mode);
        }
    }

    /// `ring_size` is used as parsed and `num_mbufs` is exactly `2 * ring_size`
    /// across the whole accepted range.
    #[test]
    fn num_mbufs_is_twice_the_ring_size_across_the_range() {
        for ring_size in [RING_SIZE_MIN as i32, DEFAULT_RING_SIZE as i32, 4096, 65536] {
            let opts =
                DpdkPdumpOptions::from_config(&dpdk_cfg("eth0", 2048, "", ring_size)).expect("");
            assert_eq!(opts.ring_size, ring_size as u32);
            assert_eq!(opts.num_mbufs, ring_size as usize * 2);
        }
    }

    /// A negative snap/ring size cannot get past the parser, but the options
    /// builder still refuses instead of wrapping (defence in depth).
    #[test]
    fn negative_values_are_rejected_not_wrapped() {
        assert!(DpdkPdumpOptions::from_config(&dpdk_cfg("eth0", -1, "", 2048)).is_err());
        assert!(DpdkPdumpOptions::from_config(&dpdk_cfg("eth0", 2048, "", -1)).is_err());
    }

    /// `round_up_ring_size` is the C `__builtin_clzl` computation: powers of two
    /// pass through, everything else rounds to the next one.
    #[test]
    fn round_up_ring_size_matches_the_c_computation() {
        for (given, want) in [
            (2u32, 2u64),
            (3, 4),
            (4, 4),
            (5, 8),
            (7, 8),
            (8, 8),
            (2047, 2048),
            (2048, 2048),
            (2049, 4096),
            (1 << 20, 1 << 20),
            (1 << 30, 1 << 30),
        ] {
            assert_eq!(round_up_ring_size(given), want, "ring_size {given}");
        }
    }

    /// The EAL argument vector matches `dpdk_init`: binary renamed to
    /// `cpworker`, then the four static arguments.
    #[test]
    fn eal_args_match_dpdk_init() {
        assert_eq!(
            eal_args(),
            vec![
                "cpworker",
                "--proc-type",
                "secondary",
                "--log-level",
                "notice",
            ]
        );
        assert_eq!(eal_args().len(), 5, "RTE_DIM(args) is 5");
    }

    /// `enable_pdump` always requests RXTX; the pcapng bit is added only when
    /// asked for (upstream passes `false`).
    #[test]
    fn pdump_flags_are_rxtx_and_optional_pcapng() {
        assert_eq!(pdump_flags(false), 0b011);
        assert_eq!(pdump_flags(true), 0b111);
    }

    /// The tunables `pdump.c` defines are ported verbatim.
    #[test]
    fn upstream_tunables_are_preserved() {
        assert_eq!(MBUF_POOL_CACHE_SIZE, 32);
        assert_eq!(BURST_SIZE, 32);
        assert_eq!(MONITOR_INTERVAL_US, 500_000);
        assert_eq!(POOL_NAME, "cpworker_capture_mbufs");
        assert_eq!(RING_NAME, "cpworker_capture_ring");
    }

    #[cfg(not(feature = "dpdk"))]
    fn dpdk_task(cfg: DpdkPdumpConfig) -> TaskConfig {
        TaskConfig {
            fingerprint: None,
            req_pattern: ReqPatternConfig::None,
            capturer: CapturerConfig {
                kind: CapturerKind::DpdkPdump(cfg),
            },
            outputs: Vec::new(),
        }
    }

    /// The default build keeps the config surface but refuses to open a task,
    /// with a message that names the missing feature (not a dead end).
    #[cfg(not(feature = "dpdk"))]
    #[test]
    fn new_without_the_feature_reports_the_gate() {
        let cfg = dpdk_cfg("eth0", 2048, "", 2048);
        let task = dpdk_task(cfg.clone());
        let err = match new(
            std::slice::from_ref(&task),
            &task,
            &cfg,
            Arc::new(CaptureStats::default()),
        ) {
            Ok(_) => panic!("dpdk capturer must not open without the feature"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("without the `dpdk` feature"), "{err}");
        assert!(err.contains("--features dpdk"), "{err}");
    }

    /// With the feature compiled in, the pure layer is still the same; this
    /// guarded test exists so `--features dpdk` builds exercise the module's
    /// non-FFI logic too.
    #[cfg(feature = "dpdk")]
    #[test]
    fn feature_build_keeps_the_pure_layer_intact() {
        assert_eq!(round_up_ring_size(3), 4);
        assert_eq!(pdump_flags(true), 0b111);
        assert_eq!(eal_args()[0], "cpworker");
        let opts = DpdkPdumpOptions::from_config(&dpdk_cfg("eth0", 128, "tcp", 8)).expect("valid");
        assert_eq!(opts.num_mbufs, 16);
        assert!(opts.promiscuous_mode);
    }
}
