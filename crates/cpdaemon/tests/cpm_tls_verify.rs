//! Upstream #232: the CPM HTTP client must **verify** the server certificate by
//! default, and only skip verification when
//! `cpm.client.tls.insecure_skip_verify = true` is set explicitly.
//!
//! These tests stand up a real TLS server with a self-signed certificate and
//! drive the production `HttpClient` against it:
//!
//! * the default (`insecure_skip_verify = false`) must fail the TLS handshake,
//!   so the server never sees a completed connection;
//! * the explicit opt-out must complete the same request.
//!
//! Running both against the *same* server setup is what makes the result
//! meaningful: the only difference between pass and fail is the client's
//! certificate-verification decision.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cpdaemon::cpm::client::{ClientConfig, HttpClient};
use cpdaemon::cpm::models::RegisterRequest;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

fn register_req() -> RegisterRequest {
    serde_json::from_value(json!({
        "name": "probe-tls",
        "apiVersion": "v1",
        "supportApiVersions": ["v1"],
        "clientVersion": "0.9.0",
    }))
    .expect("register request")
}

/// Generate a fresh self-signed certificate for `localhost`.
fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed cert");
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    (cert, key)
}

/// Start a TLS server on an ephemeral loopback port that answers every request
/// with a canned CPM register response.
///
/// Returns `(base_url, handshake_completed)`. The flag flips to `true` only
/// after a client completes the TLS handshake, so a rejected handshake leaves it
/// `false` - which is exactly what the default-verify test asserts.
async fn spawn_self_signed_tls_cpm() -> (String, Arc<AtomicBool>) {
    let (cert, key) = self_signed();
    let config = ServerConfig::builder_with_provider(ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tls mock cpm");
    let addr = listener.local_addr().expect("tls mock cpm addr");
    let handshake_completed = Arc::new(AtomicBool::new(false));
    let flag = handshake_completed.clone();

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let flag = flag.clone();
            tokio::spawn(async move {
                // A verification failure aborts the handshake here.
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                flag.store(true, Ordering::SeqCst);

                // Drain the request (we only need the response to be well formed).
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;

                let body = r#"{"id":1,"paUUID":"pa-1","syncInterval":15}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    (
        format!("https://localhost:{}/", addr.port()),
        handshake_completed,
    )
}

fn client(base_url: &str, insecure_skip_verify: bool) -> HttpClient {
    HttpClient::new(
        base_url,
        ClientConfig {
            timeout: Duration::from_secs(5),
            insecure_skip_verify,
        },
    )
    .expect("http client")
}

/// The regression this guards (upstream #232): a self-signed certificate used to
/// be accepted unconditionally. It must now be rejected by default.
#[tokio::test]
async fn self_signed_certificate_is_rejected_by_default() {
    let (url, handshake_completed) = spawn_self_signed_tls_cpm().await;

    let err = client(&url, false)
        .register(register_req())
        .await
        .expect_err("default client must reject an untrusted self-signed certificate");

    let msg = err.to_string();
    assert!(
        msg.contains("register request failed"),
        "failure must come from the HTTP transport, not the CPM envelope: {msg}"
    );
    assert!(
        !handshake_completed.load(Ordering::SeqCst),
        "the TLS handshake must not complete when verification is on"
    );
}

/// The escape hatch must still work, and must be what causes acceptance: the
/// same self-signed server is reachable once verification is off.
#[tokio::test]
async fn self_signed_certificate_is_accepted_when_verification_is_skipped() {
    let (url, handshake_completed) = spawn_self_signed_tls_cpm().await;

    let resp = client(&url, true)
        .register(register_req())
        .await
        .expect("insecure_skip_verify=true must accept the self-signed certificate");

    assert_eq!(resp.id, 1);
    assert_eq!(resp.pa_uuid, "pa-1");
    assert!(
        handshake_completed.load(Ordering::SeqCst),
        "the TLS handshake must complete once verification is skipped"
    );
}
