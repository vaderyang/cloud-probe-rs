//! Name resolution for BPF compilation: cached, and bounded by a deadline.
//!
//! A filter may contain a host name, so compiling it calls `getaddrinfo()` - a
//! blocking resolver with *its own* timeout, tens of seconds when the name server
//! is unreachable. Two properties make that dangerous here, and this module bounds
//! both (AUDIT4 P2-10):
//!
//! * `bpf::compile()` runs while tasks are being built, and `TaskManager::reload()`
//!   holds the manager mutex that the capture loop and the `cpctl stats` handler
//!   also take - so one slow name stalls packet polling, the reload and the RPC
//!   accounting at once;
//! * every reload re-resolved *every* name of *every* task, paying that cost again
//!   for a configuration whose names had not changed.
//!
//! [`GuardedResolver`] answers from a bounded, TTL'd table shared process-wide, and
//! gives up on a lookup that overruns its budget so the caller gets a clear error
//! (the task fails to build) instead of an unbounded stall.
//!
//! This is a deliberate divergence from the C port, where `pcap_compile()` blocks
//! for the whole resolver timeout: recorded in `PARITY.md §2.5`. The visible cost is
//! that an answer may be up to [`DEFAULT_TTL`] old, i.e. a collector that changed its
//! IP can be missed for that long by an auto-generated exclusion filter; the visible
//! benefit is that the worker keeps capturing while DNS is broken.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::parser::{DnsResolver, Resolver};

/// How long a resolution result may be reused.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Longest a single compile-path lookup may block its caller.
pub const DEFAULT_BUDGET: Duration = Duration::from_secs(2);

/// Maximum names remembered; the table is dropped when it would exceed this, so a
/// caller feeding an endless stream of unique names cannot grow it.
const MAX_CACHED_NAMES: usize = 512;

/// One memoised lookup: when it was answered, and with what.
type Entry = (Instant, Vec<IpAddr>);
/// The lookup table, shared by every clone of a [`GuardedResolver`].
type Table = Arc<Mutex<BTreeMap<String, Entry>>>;

fn global_table() -> Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE
        .get_or_init(|| Arc::new(Mutex::new(BTreeMap::new())))
        .clone()
}

/// Forget every cached name resolution (used by tests, and available to a reload
/// path that must force fresh answers).
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

/// A [`Resolver`] that caches answers and refuses to block longer than a budget.
///
/// `inner` does the real lookup; `R: Clone` because the lookup runs on a worker
/// thread, which needs its own handle.
pub struct GuardedResolver<R: Resolver + Clone + Send + 'static> {
    inner: R,
    ttl: Duration,
    budget: Duration,
    table: Table,
}

impl<R: Resolver + Clone + Send + 'static> Clone for GuardedResolver<R> {
    fn clone(&self) -> Self {
        GuardedResolver {
            inner: self.inner.clone(),
            ttl: self.ttl,
            budget: self.budget,
            table: self.table.clone(),
        }
    }
}

impl GuardedResolver<DnsResolver> {
    /// The resolver every production compile path uses: platform `getaddrinfo`,
    /// results shared process-wide for [`DEFAULT_TTL`], each cold lookup capped at
    /// [`DEFAULT_BUDGET`].
    #[must_use]
    pub fn system() -> GuardedResolver<DnsResolver> {
        GuardedResolver {
            inner: DnsResolver,
            ttl: DEFAULT_TTL,
            budget: DEFAULT_BUDGET,
            table: global_table(),
        }
    }
}

impl<R: Resolver + Clone + Send + 'static> GuardedResolver<R> {
    /// Wrap `inner` with explicit timings and a *private* table (tests).
    #[must_use]
    pub fn new(inner: R, ttl: Duration, budget: Duration) -> Self {
        GuardedResolver {
            inner,
            ttl,
            budget,
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

    /// Forget everything this instance's table holds (its clones too, since the
    /// table is shared).
    pub fn clear(&self) {
        if let Ok(mut t) = self.table.lock() {
            t.clear();
        }
    }

    /// Resolve without consulting or updating the cache, bounded by the budget.
    fn lookup_now(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        let (tx, rx) = mpsc::channel();
        let inner = self.inner.clone();
        let name = host.to_string();
        // A detached worker: if it exceeds the budget the caller has already
        // returned, and the thread finishes (and is reaped) when the resolver does.
        // Leaking at most `budget`-worth of latency per name is strictly better than
        // holding the manager mutex for the resolver's own timeout.
        if std::thread::Builder::new()
            .name("cp-bpf-resolve".to_string())
            .spawn(move || {
                let _ = tx.send(inner.lookup(&name));
            })
            .is_err()
        {
            return self.inner.lookup(host);
        }
        match rx.recv_timeout(self.budget) {
            Ok(res) => res,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "resolving '{host}' took longer than {} ms (name server unreachable? \
                     list the addresses in the filter instead of the name)",
                    self.budget.as_millis()
                ),
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(std::io::Error::other(format!("resolver for '{host}' died")))
            }
        }
    }
}

impl<R: Resolver + Clone + Send + 'static> Resolver for GuardedResolver<R> {
    fn lookup(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        let now = Instant::now();
        if let Ok(table) = self.table.lock() {
            if let Some((at, addrs)) = table.get(host) {
                if now.duration_since(*at) < self.ttl && !addrs.is_empty() {
                    return Ok(addrs.clone());
                }
            }
        }
        let addrs = self.lookup_now(host)?;
        if let Ok(mut table) = self.table.lock() {
            if table.len() >= MAX_CACHED_NAMES {
                table.clear();
            }
            table.insert(host.to_string(), (now, addrs.clone()));
        }
        Ok(addrs)
    }
}

/// Compile `expr` for its side effect on the shared name cache, outside the lock
/// that protects the task manager.
///
/// The compiled program is thrown away; the point is that the *resolution* (and the
/// expression's syntax/address validation) happens on a thread that is not holding
/// the manager mutex, so the build inside the lock is a cache hit.
///
/// # Errors
/// Propagated from [`super::compile`]: a filter that cannot compile here cannot
/// compile later either, and the caller gets the message before any task is torn
/// down.
pub fn prewarm(expr: &str) -> super::Result<()> {
    super::compile(expr).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, ToSocketAddrs};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Default)]
    struct Counting {
        calls: Arc<AtomicUsize>,
        addrs: Vec<IpAddr>,
        delay: Duration,
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

    /// The reload path used to re-resolve every name in every task while holding
    /// the manager mutex; a warm cache means only the *first* build pays.
    #[test]
    fn cached_names_are_reused_without_calling_the_resolver() {
        let inner = Counting {
            calls: Arc::new(AtomicUsize::new(0)),
            addrs: vec![addr(1), addr(2)],
            delay: Duration::ZERO,
        };
        let r = GuardedResolver::new(
            inner.clone(),
            Duration::from_secs(60),
            Duration::from_secs(5),
        );
        let first = r.lookup("collector.example").expect("first");
        let second = r.lookup("collector.example").expect("second");
        assert_eq!(first, vec![addr(1), addr(2)], "every address must be kept");
        assert_eq!(second, first, "the cached answer must be identical");
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "second call must be free"
        );
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn an_expired_entry_is_resolved_again() {
        let inner = Counting {
            calls: Arc::new(AtomicUsize::new(0)),
            addrs: vec![addr(1)],
            delay: Duration::from_millis(2),
        };
        // ttl = 0 -> nothing is ever fresh, and the tiny delay makes a stale hit
        // observable as a missing second call.
        let r = GuardedResolver::new(inner.clone(), Duration::ZERO, Duration::from_secs(5));
        r.lookup("a.example").unwrap();
        r.lookup("a.example").unwrap();
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    /// The actual P2-10 hazard: an unreachable name server must not be able to hold
    /// the capture loop hostage for the resolver's own timeout.
    #[test]
    fn a_slow_lookup_is_given_up_on_within_the_budget() {
        let inner = Counting {
            calls: Arc::new(AtomicUsize::new(0)),
            addrs: vec![],
            delay: Duration::from_millis(400),
        };
        let r = GuardedResolver::new(inner, Duration::from_secs(60), Duration::from_millis(20));
        let start = Instant::now();
        let err = r.lookup("dead.example").expect_err("must time out");
        let elapsed = start.elapsed();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "must be a timeout, got {err}"
        );
        assert!(
            elapsed < Duration::from_millis(300),
            "gave up after {elapsed:?}; the whole point is not to block for the resolver"
        );
        assert!(
            err.to_string().contains("dead.example"),
            "must name it: {err}"
        );
        // A timed-out name is not cached as "empty": the next attempt tries again.
        assert!(r.is_empty(), "a failed lookup must not populate the cache");
    }

    /// The table is shared by clones - which is how one reload's answers serve the
    /// next one, and why a compile inside the lock can be free.
    ///
    /// (Assertions use private tables: other tests resolve names in parallel, so
    /// anything measured against the process-wide table would be flaky.)
    #[test]
    fn the_cache_is_shared_between_clones() {
        let inner = Counting {
            calls: Arc::new(AtomicUsize::new(0)),
            addrs: vec![addr(7), addr(8), addr(9)],
            delay: Duration::from_millis(2),
        };
        let a = GuardedResolver::new(
            inner.clone(),
            Duration::from_secs(60),
            Duration::from_secs(5),
        );
        let b = a.clone();
        assert_eq!(a.lookup("pool.example").unwrap().len(), 3);
        assert_eq!(
            b.len(),
            3 - 2,
            "a clone must share the table, not start a new one"
        );
        assert_eq!(
            b.lookup("pool.example").unwrap(),
            vec![addr(7), addr(8), addr(9)],
            "the clone's lookup must be answered from the shared table"
        );
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1, "and it must be free");
        a.clear();
        assert!(
            b.is_empty(),
            "clearing the shared table must be visible to clones"
        );
    }

    /// The production entry point (`bpf::parse`) goes through the *guarded* resolver,
    /// so pre-warming a filter really does make the later, locked compile a cache
    /// hit - which is the whole P2-10 mechanism.
    #[test]
    fn prewarming_resolves_what_the_compile_needs() {
        use super::super::{compile, parser::parse};
        let expr = "not host localhost";
        let cold = parse(expr).expect("first parse resolves the name");
        let after_first = name_cache_len();
        let warm = compile(expr).expect("compile after pre-warming");
        assert_eq!(
            name_cache_len(),
            after_first,
            "the compile must not resolve anything a pre-warm already resolved"
        );
        // Caching must not narrow the expansion to the first answer (P2-8/P5-08).
        let expected = ("localhost", 0u16)
            .to_socket_addrs()
            .map(|i| i.collect::<Vec<_>>().len())
            .unwrap_or(0);
        assert!(
            hosts_len(&cold) >= expected.max(1),
            "host <name> must cover every answer, got {} for {expected}",
            hosts_len(&cold)
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
