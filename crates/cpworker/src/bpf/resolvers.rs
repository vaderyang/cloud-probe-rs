//! Name resolution for BPF compilation: memoised, process-wide.
//!
//! A filter may contain a host name, so compiling it calls `getaddrinfo()` - a
//! blocking call whose timeout the process does not control. That is dangerous here
//! for a specific reason (AUDIT4 P2-10): `bpf::compile()` runs while tasks are being
//! built, `TaskManager::reload()` holds the manager mutex that the capture loop and
//! the `cpctl stats` handler also take, and *every* reload re-resolved *every* name
//! of *every* task. One unreachable name server therefore froze packet polling and
//! RPC accounting for the full resolver timeout, with `drop_packets == 0`.
//!
//! Two bounds, neither of which involves a thread per lookup:
//!
//! * results are memoised in a bounded, TTL'd table shared process-wide, so a
//!   reload of an unchanged configuration performs no resolution at all;
//! * the work is moved *off* the threads that must not block - the reload path warms
//!   the cache before taking the manager lock, and the SIGHUP path does it on a
//!   worker thread (see `crate::task::ReloadWorker`), so the capture loop never
//!   waits on a name server.
//!
//! A previous revision bounded a single lookup with a detached worker thread instead.
//! That is what this module must not do: `cargo fuzz` caught it, because a detached
//! thread is still alive when the fuzz target exits, so LeakSanitizer reported
//! glibc's resolver buffer as a leak (`leak-592aa5…` under `fuzz/artifacts/bpf/`) and
//! the per-lookup `thread::spawn` drove fuzzing throughput to zero on name-heavy
//! inputs. Spawning threads around a resolver turns one stall into unbounded thread
//! churn; moving the call to a thread that is meant to block is the fix.
//!
//! Memoisation is a deliberate divergence from the C port, where `pcap_compile()`
//! asks the resolver every time: an answer can be up to [`DEFAULT_TTL`] stale, i.e.
//! a collector that changed its IP may be missed by the auto-generated output-host
//! exclusion for that long. Recorded in `PARITY.md §2.5`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::parser::{DnsResolver, Resolver};

/// How long a resolution result may be reused.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Maximum names remembered; the table is dropped when it would grow past this, so
/// a caller feeding an endless stream of unique names cannot grow it.
const MAX_CACHED_NAMES: usize = 512;

/// One memoised lookup: when it was answered, and with what.
type Entry = (Instant, Vec<IpAddr>);
/// The lookup table, shared by every clone of a [`CachedResolver`].
type Table = Arc<Mutex<BTreeMap<String, Entry>>>;

fn global_table() -> Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE
        .get_or_init(|| Arc::new(Mutex::new(BTreeMap::new())))
        .clone()
}

/// Forget every cached name resolution (a reload that must see fresh answers, and
/// the tests, call this).
pub fn clear_name_cache() {
    if let Ok(mut t) = global_table().lock() {
        t.clear();
    }
}

/// Number of names currently remembered process-wide (observability/testing).
#[must_use]
pub fn name_cache_len() -> usize {
    global_table().lock().map(|t| t.len()).unwrap_or(0)
}

/// A [`Resolver`] that answers from a shared table when it can.
///
/// `R` does the real lookup. Cloning shares the table (that is the point), so a
/// warm-up instance and the instance inside a later `compile()` see the same entries.
pub struct CachedResolver<R: Resolver> {
    inner: R,
    ttl: Duration,
    table: Table,
}

impl<R: Resolver + Clone> Clone for CachedResolver<R> {
    fn clone(&self) -> Self {
        CachedResolver {
            inner: self.inner.clone(),
            ttl: self.ttl,
            table: self.table.clone(),
        }
    }
}

impl CachedResolver<DnsResolver> {
    /// The resolver every production compile path uses: platform `getaddrinfo`,
    /// results shared process-wide for [`DEFAULT_TTL`].
    #[must_use]
    pub fn system() -> CachedResolver<DnsResolver> {
        CachedResolver {
            inner: DnsResolver,
            ttl: DEFAULT_TTL,
            table: global_table(),
        }
    }
}

impl<R: Resolver> CachedResolver<R> {
    /// Wrap `inner` with an explicit TTL and a *private* table (tests).
    #[must_use]
    pub fn with_ttl(inner: R, ttl: Duration) -> Self {
        CachedResolver {
            inner,
            ttl,
            table: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Entries held by this instance's table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.lock().map(|t| t.len()).unwrap_or(0)
    }

    /// True when this instance's table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forget everything this table holds (visible to clones, since it is shared).
    pub fn clear(&self) {
        if let Ok(mut t) = self.table.lock() {
            t.clear();
        }
    }
}

impl<R: Resolver> Resolver for CachedResolver<R> {
    fn lookup(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        let now = Instant::now();
        if let Ok(table) = self.table.lock() {
            if let Some((at, addrs)) = table.get(host) {
                if now.duration_since(*at) < self.ttl && !addrs.is_empty() {
                    return Ok(addrs.clone());
                }
            }
        }
        let addrs = self.inner.lookup(host)?;
        if let Ok(mut table) = self.table.lock() {
            if table.len() >= MAX_CACHED_NAMES {
                table.clear();
            }
            table.insert(host.to_string(), (now, addrs.clone()));
        }
        Ok(addrs)
    }
}

/// Compile `expr` purely for its side effects: validating the expression and putting
/// every name it needs into the shared table.
///
/// The program is discarded. Doing this before the task-manager lock is taken means
/// the build inside the lock resolves nothing (a cache hit), which is what keeps a
/// slow DNS from holding up packet polling and `cpctl stats`.
///
/// # Errors
/// Whatever [`super::compile`] reports - a filter that fails here fails later too,
/// and the caller gets the message before any running task is torn down.
pub fn prewarm(expr: &str) -> super::Result<()> {
    super::compile(expr).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, ToSocketAddrs};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts lookups and can be made slow, which is how "the caller never blocks"
    /// is observed without touching a name server.
    #[derive(Clone, Default)]
    pub struct Counting {
        pub calls: Arc<AtomicUsize>,
        pub addrs: Vec<IpAddr>,
        pub delay: Duration,
    }

    impl Counting {
        pub fn new(addrs: Vec<IpAddr>, delay: Duration) -> Self {
            Counting {
                calls: Arc::new(AtomicUsize::new(0)),
                addrs,
                delay,
            }
        }
    }

    impl Resolver for Counting {
        fn lookup(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.delay.is_zero() {
                std::thread::sleep(self.delay);
            }
            Ok(self.addrs.clone())
        }
    }

    fn addr(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
    }

    /// The reload path used to re-resolve every name in every task; a warm cache
    /// means only the first build pays.
    #[test]
    fn cached_names_are_reused_without_calling_the_resolver() {
        let inner = Counting::new(vec![addr(1), addr(2)], Duration::ZERO);
        let r = CachedResolver::with_ttl(inner.clone(), Duration::from_secs(60));
        let first = r.lookup("collector.example").expect("first");
        let second = r.lookup("collector.example").expect("second");
        assert_eq!(first, vec![addr(1), addr(2)], "every address must be kept");
        assert_eq!(second, first, "the cached answer must be identical");
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "the second lookup must be free"
        );
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn an_expired_entry_is_resolved_again() {
        let inner = Counting::new(vec![addr(1)], Duration::from_millis(2));
        // ttl = 0 -> nothing is ever fresh, so a stale answer would show up as a
        // missing second call.
        let r = CachedResolver::with_ttl(inner.clone(), Duration::ZERO);
        r.lookup("a.example").unwrap();
        r.lookup("a.example").unwrap();
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    /// The table is shared by clones - which is how a warm-up instance reaches the
    /// later compile.
    ///
    /// (Private tables only: other tests resolve names in parallel, so anything
    /// measured against the process-wide table would be flaky.)
    #[test]
    fn the_cache_is_shared_between_clones() {
        let inner = Counting::new(vec![addr(7), addr(8), addr(9)], Duration::from_millis(2));
        let a = CachedResolver::with_ttl(inner.clone(), Duration::from_secs(60));
        let b = a.clone();
        assert_eq!(a.lookup("pool.example").unwrap().len(), 3);
        assert_eq!(
            b.len(),
            1,
            "a clone shares the table, it does not start over"
        );
        assert_eq!(
            b.lookup("pool.example").unwrap(),
            vec![addr(7), addr(8), addr(9)]
        );
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1, "and it is free");
        a.clear();
        assert!(b.is_empty(), "clear() is visible to clones");
    }

    /// A failed lookup must not be memoised as "empty", or a transient resolver
    /// failure would poison a name for the whole TTL.
    #[test]
    fn a_failed_lookup_is_not_cached() {
        struct AlwaysFails;
        impl Resolver for AlwaysFails {
            fn lookup(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
                Err(std::io::Error::other("no answer"))
            }
        }
        let r = CachedResolver::with_ttl(AlwaysFails, Duration::from_secs(60));
        assert!(r.lookup("nowhere.example").is_err());
        assert!(r.is_empty(), "a failure must not populate the table");
        assert!(
            r.lookup("nowhere.example").is_err(),
            "and it must be retried"
        );
    }

    /// The production entry point (`bpf::parse`) goes through the shared cache, so
    /// pre-warming a filter really does mean the later compile resolves nothing.
    #[test]
    fn prewarming_resolves_what_the_compile_needs() {
        use super::super::{compile, parser::parse};
        let expr = "not host localhost";
        let ast = parse(expr).expect("first parse resolves the name");
        let after_first = name_cache_len();
        let warm = compile(expr).expect("compile with the names already known");
        assert_eq!(
            name_cache_len(),
            after_first,
            "the second compile must not resolve anything new"
        );
        // Caching must not narrow the expansion to the first answer (P2-8/P5-08).
        let expected = ("localhost", 0u16)
            .to_socket_addrs()
            .map(|i| i.collect::<Vec<_>>().len())
            .unwrap_or(0);
        assert!(
            hosts_len(&ast) >= expected.max(1),
            "host <name> must cover every answer, got {} for {expected}",
            hosts_len(&ast)
        );
        assert!(!warm.is_empty());
    }

    fn hosts_len(ast: &super::super::Ast) -> usize {
        use super::super::Ast;
        match ast {
            Ast::Or(a, b) | Ast::And(a, b) => hosts_len(a) + hosts_len(b),
            Ast::Not(a) => hosts_len(a),
            Ast::Host { .. } => 1,
            _ => 0,
        }
    }
}
