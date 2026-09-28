//! Shared helpers for the `cpdaemon` end-to-end tests.
//!
//! Two things live here:
//!
//! * [`cpworker_binary`], which locates the real `cpworker` executable so the
//!   daemon tests exercise the actual worker process instead of a stub.
//! * [`MockCpm`], a tiny axum server that speaks the CPM HTTP API and records
//!   every request, so the client/syncer tests can assert on the wire contract.
//!
//! This module is compiled once per integration-test binary, and each binary
//! uses only a subset of it (e.g. the worker-supervision test never touches the
//! mock), so a module-wide `dead_code` allow is deliberate here - it is not
//! hiding rot, it is the cost of sharing a helper across binaries with different
//! needs.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

/// Absolute path to the `cpworker` binary built alongside the test binary.
///
/// The supported invocation is `cargo test --workspace` (the gate), which builds
/// `target/<profile>/cpworker`. The test binary lives in `target/<profile>/deps/`,
/// so going up one or two levels finds it in both the workspace and the
/// `-p cpdaemon` case. A missing binary is a hard error (AUDIT4 P2-2: never let
/// an end-to-end test pass by silently skipping).
///
/// Caveat: `cargo test -p cpdaemon` alone neither builds nor refreshes the
/// worker, so use `--workspace` (or `cargo build -p cpworker`) after touching
/// `crates/cpworker`, else this drives a stale binary.
pub fn cpworker_binary() -> PathBuf {
    let mut dir = std::env::current_exe().expect("current_exe");
    dir.pop(); // the test binary file name
    if dir.file_name().and_then(|n| n.to_str()) == Some("deps") {
        dir.pop();
    }
    let bin = dir.join("cpworker");
    assert!(
        bin.is_file(),
        "cpworker binary not found at {}; build it first (e.g. `cargo build -p cpworker` or run `cargo test --workspace`)",
        bin.display()
    );
    bin
}

/// Poll `f` every 20ms until it returns `true` or `timeout` elapses.
pub fn wait_until(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if f() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Everything the mock CPM saw, in arrival order.
#[derive(Debug, Default)]
pub struct Recorded {
    pub register_bodies: Vec<Value>,
    pub strategy_versions: Vec<String>,
    /// The `{id}` path segment of each strategy request (the CPM daemon id).
    pub strategy_ids: Vec<i64>,
    pub metrics_bodies: Vec<Value>,
    /// The `{id}` path segment of each metrics request.
    pub metrics_ids: Vec<i64>,
}

/// A minimal CPM HTTP API server.
///
/// Routes: `POST /api/v1/daemons`, `GET /api/v1/daemons/{id}/sync/strategy`,
/// `POST /api/v1/daemons/{id}/sync/metrics`. Every handler records its request
/// and replies with the configured canned body/status.
#[derive(Clone)]
pub struct MockCpm {
    rec: Arc<Mutex<Recorded>>,
    register_status: u16,
    register_body: Value,
    strategy_status: u16,
    strategy_body: Value,
    strategy_not_modified_version: Option<String>,
    metrics_status: u16,
    metrics_body: Value,
}

impl Default for MockCpm {
    fn default() -> Self {
        Self::new()
    }
}

impl MockCpm {
    #[must_use]
    pub fn new() -> Self {
        MockCpm {
            rec: Arc::new(Mutex::new(Recorded::default())),
            register_status: 200,
            register_body: json!({"id": 1, "paUUID": "pa-1", "syncInterval": 1}),
            strategy_status: 200,
            strategy_body: json!({"id": 1, "daemonId": 1, "version": 1, "syncInterval": 1, "strategy": []}),
            strategy_not_modified_version: None,
            metrics_status: 200,
            metrics_body: json!({}),
        }
    }

    #[must_use]
    pub fn register_body(mut self, body: Value) -> Self {
        self.register_body = body;
        self
    }

    #[must_use]
    pub fn register_status(mut self, status: u16) -> Self {
        self.register_status = status;
        self
    }

    #[must_use]
    pub fn strategy_body(mut self, body: Value) -> Self {
        self.strategy_body = body;
        self
    }

    #[must_use]
    pub fn strategy_status(mut self, status: u16) -> Self {
        self.strategy_status = status;
        self
    }

    /// Return `304 Not Modified` when the request's `version` equals `version`.
    #[must_use]
    pub fn strategy_not_modified_at(mut self, version: &str) -> Self {
        self.strategy_not_modified_version = Some(version.to_string());
        self
    }

    #[must_use]
    pub fn metrics_status(mut self, status: u16) -> Self {
        self.metrics_status = status;
        self
    }

    #[must_use]
    pub fn metrics_body(mut self, body: Value) -> Self {
        self.metrics_body = body;
        self
    }

    /// Handle to the recorded requests (shared with the spawned server).
    #[must_use]
    pub fn recorded(&self) -> Arc<Mutex<Recorded>> {
        self.rec.clone()
    }

    /// Bind to an ephemeral port and serve in the background.
    ///
    /// Returns the `base_url` to hand to `HttpClient::new` and the recorded-state
    /// handle.
    pub async fn spawn(self) -> (String, Arc<Mutex<Recorded>>) {
        let rec = self.rec.clone();
        let app = Router::new()
            .route("/api/v1/daemons", post(register_handler))
            .route("/api/v1/daemons/{id}/sync/strategy", get(strategy_handler))
            .route("/api/v1/daemons/{id}/sync/metrics", post(metrics_handler))
            .with_state(self);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock cpm");
        let addr = listener.local_addr().expect("mock cpm addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}/"), rec)
    }
}

async fn register_handler(State(st): State<MockCpm>, Json(body): Json<Value>) -> Response {
    st.rec.lock().unwrap().register_bodies.push(body);
    let code = StatusCode::from_u16(st.register_status).expect("valid status");
    (code, Json(st.register_body.clone())).into_response()
}

async fn strategy_handler(
    State(st): State<MockCpm>,
    Path(id): Path<i64>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let version = q.get("version").cloned().unwrap_or_default();
    {
        let mut rec = st.rec.lock().unwrap();
        rec.strategy_versions.push(version.clone());
        rec.strategy_ids.push(id);
    }
    if st.strategy_not_modified_version.as_deref() == Some(version.as_str()) {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    let code = StatusCode::from_u16(st.strategy_status).expect("valid status");
    (code, Json(st.strategy_body.clone())).into_response()
}

async fn metrics_handler(
    State(st): State<MockCpm>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> Response {
    {
        let mut rec = st.rec.lock().unwrap();
        rec.metrics_bodies.push(body);
        rec.metrics_ids.push(id);
    }
    let code = StatusCode::from_u16(st.metrics_status).expect("valid status");
    (code, Json(st.metrics_body.clone())).into_response()
}
