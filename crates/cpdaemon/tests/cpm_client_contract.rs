//! CPM HTTP contract tests.
//!
//! The daemon's only coupling to the control plane is `cpm/client.rs`. These
//! tests pin the wire contract against a mock CPM: request shapes, response
//! parsing, `304` handling and the two distinct error paths (HTTP status vs a
//! `200 OK` body carrying `{"code": >= 400}`).

mod common;

use cpdaemon::cpm::client::{ClientConfig, HttpClient};
use cpdaemon::cpm::models::{RegisterRequest, SyncMetricsRequest};
use serde_json::json;

use common::MockCpm;

fn register_req(name: &str) -> RegisterRequest {
    serde_json::from_value(json!({
        "name": name,
        "apiVersion": "v1",
        "supportApiVersions": ["v1"],
        "clientVersion": "0.9.0",
    }))
    .expect("register request")
}

fn client(base_url: &str) -> HttpClient {
    HttpClient::new(base_url, ClientConfig::default()).expect("http client")
}

#[tokio::test]
async fn register_sends_the_request_and_parses_the_response() {
    let mock = MockCpm::new().register_body(json!({
        "id": 42, "paUUID": "pa-42", "name": "probe-a", "syncInterval": 15,
    }));
    let rec = mock.recorded();
    let (url, _rec) = mock.spawn().await;

    let resp = client(&url)
        .register(register_req("probe-a"))
        .await
        .expect("register");

    assert_eq!(resp.id, 42);
    assert_eq!(resp.pa_uuid, "pa-42");
    assert_eq!(resp.sync_interval, 15);

    let sent = rec.lock().unwrap().register_bodies.clone();
    assert_eq!(sent.len(), 1, "exactly one register request");
    assert_eq!(sent[0]["name"], "probe-a");
    assert_eq!(sent[0]["apiVersion"], "v1");
    assert_eq!(sent[0]["supportApiVersions"], json!(["v1"]));
}

#[tokio::test]
async fn sync_strategy_parses_a_changed_strategy() {
    let mock = MockCpm::new().strategy_body(json!({
        "id": 5, "daemonId": 42, "version": 7, "syncInterval": 15,
        "strategy": [{
            "interfaceNames": ["lo"],
            "packetChannelType": "FILE",
            "dumpDir": "/tmp/probe",
            "dumpInterval": 60,
        }],
    }));
    let rec = mock.recorded();
    let (url, _rec) = mock.spawn().await;

    let result = client(&url)
        .sync_strategy(42, -1)
        .await
        .expect("sync strategy");

    assert!(result.changed);
    let resp = result.response.expect("response");
    assert_eq!(resp.version, 7);
    assert_eq!(resp.sync_interval, 15);
    assert_eq!(resp.strategy.len(), 1);
    assert_eq!(resp.strategy[0].interface_names, vec!["lo"]);
    assert_eq!(resp.strategy[0].dump_dir.as_deref(), Some("/tmp/probe"));

    assert_eq!(
        rec.lock().unwrap().strategy_versions,
        vec!["-1".to_string()]
    );
}

#[tokio::test]
async fn sync_strategy_304_reports_not_changed() {
    let mock = MockCpm::new().strategy_not_modified_at("9");
    let (url, _rec) = mock.spawn().await;

    let result = client(&url)
        .sync_strategy(42, 9)
        .await
        .expect("304 is not an error");

    assert!(!result.changed, "304 must yield changed=false");
    assert!(result.response.is_none());
}

/// A `200 OK` whose body carries `{"code": >= 400}` is still an error: the Go
/// client validates the envelope, not just the HTTP status.
#[tokio::test]
async fn register_body_error_code_is_rejected() {
    let mock = MockCpm::new().register_body(json!({"code": 500, "msg": "boom"}));
    let (url, _rec) = mock.spawn().await;

    let err = client(&url)
        .register(register_req("probe-a"))
        .await
        .expect_err("body code >= 400 must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("boom"),
        "message must carry the body msg: {msg}"
    );
    assert!(msg.contains("500"), "message must carry the code: {msg}");
}

/// An HTTP-level failure is reported with the status and the raw body.
#[tokio::test]
async fn http_error_is_reported_with_status_and_body() {
    let mock = MockCpm::new()
        .register_status(503)
        .register_body(json!({"error": "unavailable"}));
    let (url, _rec) = mock.spawn().await;

    let err = client(&url)
        .register(register_req("probe-a"))
        .await
        .expect_err("503 must fail");
    let msg = err.to_string();
    assert!(msg.contains("status_code: 503"), "{msg}");
    assert!(msg.contains("unavailable"), "{msg}");
}

#[tokio::test]
async fn sync_metrics_posts_the_metrics_body() {
    let mock = MockCpm::new();
    let rec = mock.recorded();
    let (url, _rec) = mock.spawn().await;

    let req = SyncMetricsRequest {
        pid: Some(1234),
        metrics: Some(Default::default()),
        ..Default::default()
    };

    client(&url)
        .sync_metrics(42, req)
        .await
        .expect("sync metrics");

    let sent = rec.lock().unwrap().metrics_bodies.clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["pid"], 1234);
    assert!(sent[0]["metrics"].is_object(), "metrics must be sent");
}
