//! mTLS: when `cpm.client.tls.pkcs12_cert_file` is set, the CPM client must
//! present the enclosed certificate as its TLS client identity
//! (`cloud-probe-rs-ryg.2`).
//!
//! These tests stand up a real rustls server that **requires** client
//! authentication (its trust root is a test CA that signs the client cert) and
//! drive the production `HttpClient` against it:
//!
//! * with the PKCS#12 identity configured, the handshake completes and the
//!   server observes exactly the client leaf certificate;
//! * with no identity configured, the same server rejects the handshake.
//!
//! Running both against the same server setup is what makes the result
//! meaningful: the only difference is whether the client was given a PKCS#12
//! archive.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use cpdaemon::cpm::client::{ClientConfig, HttpClient};
use cpdaemon::cpm::models::RegisterRequest;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

const P12_PASSWORD: &str = "s3cret";

fn register_req() -> RegisterRequest {
    serde_json::from_value(json!({
        "name": "probe-mtls",
        "apiVersion": "v1",
        "supportApiVersions": ["v1"],
        "clientVersion": "0.9.0",
    }))
    .expect("register request")
}

/// A test CA plus one client certificate signed by it.
///
/// Returns `(ca_der, client_cert_der, client_key_pkcs8)`. The same CA must be
/// used for the server's trust root and the PKCS#12 archive.
fn client_chain() -> (Vec<u8>, CertificateDer<'static>, Vec<u8>) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "cpdaemon test client CA");
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let mut client_params =
        CertificateParams::new(vec!["client.example".to_string()]).expect("client params");
    client_params
        .distinguished_name
        .push(DnType::CommonName, "cpdaemon test client");
    let client_key = KeyPair::generate().expect("client key");
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("client cert");

    (
        ca_cert.der().to_vec(),
        CertificateDer::from(client_cert.der().to_vec()),
        client_key.serialize_der(),
    )
}

/// Write a PKCS#12 archive containing the client leaf + key + CA to a temp file.
fn write_client_p12(
    client_cert: &[u8],
    client_key: &[u8],
    ca_der: &[u8],
) -> (tempfile::TempDir, String) {
    let pfx = p12::PFX::new(
        client_cert,
        client_key,
        Some(ca_der),
        P12_PASSWORD,
        "client",
    )
    .expect("build pfx")
    .to_der();

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("client.p12");
    std::fs::write(&path, &pfx).expect("write p12");
    (dir, path.to_string_lossy().into_owned())
}

/// Start a TLS server on an ephemeral loopback port that requires client auth
/// and answers every request with a canned CPM register response.
///
/// Returns `(base_url, presented_leaf)`. `presented_leaf` is set to the DER of
/// the first peer certificate the server sees, so a test can prove the client
/// actually presented its identity.
async fn spawn_mtls_cpm(ca_der: Vec<u8>) -> (String, Arc<Mutex<Option<Vec<u8>>>>) {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der))
        .expect("add client CA");
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier");

    let server_ck =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("server cert");
    let server_cert = CertificateDer::from(server_ck.cert.der().to_vec());
    let server_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_ck.key_pair.serialize_der()));

    let config = ServerConfig::builder_with_provider(ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server_cert], server_key)
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mtls mock cpm");
    let addr = listener.local_addr().expect("mtls mock cpm addr");
    let presented: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let presented_srv = presented.clone();

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let presented = presented_srv.clone();
            tokio::spawn(async move {
                // No client certificate => the verifier aborts the handshake.
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                if let Some(leaf) = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                {
                    *presented.lock().expect("presented lock") = Some(leaf.as_ref().to_vec());
                }

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

    (format!("https://localhost:{}/", addr.port()), presented)
}

/// A PKCS#12 client identity must be loaded and presented: the server, which
/// requires a client certificate, completes the handshake and sees the leaf.
#[tokio::test]
async fn pkcs12_client_identity_is_presented_to_a_mtls_server() {
    let (ca_der, client_cert, client_key) = client_chain();
    let (url, presented) = spawn_mtls_cpm(ca_der.clone()).await;
    let (_dir, p12_path) = write_client_p12(client_cert.as_ref(), &client_key, &ca_der);

    let client = HttpClient::new(
        &url,
        ClientConfig {
            timeout: Duration::from_secs(5),
            // The server is self-signed; this test is about client auth, not
            // server verification (covered by `cpm_tls_verify.rs`).
            insecure_skip_verify: true,
            pkcs12_cert_file: p12_path,
            pkcs12_cert_password: P12_PASSWORD.to_string(),
        },
    )
    .expect("http client");

    let resp = client
        .register(register_req())
        .await
        .expect("mTLS client with a PKCS#12 identity must complete the handshake");
    assert_eq!(resp.id, 1);
    assert_eq!(resp.pa_uuid, "pa-1");

    let seen = presented
        .lock()
        .expect("presented lock")
        .clone()
        .expect("server must observe a client certificate");
    assert_eq!(
        seen,
        client_cert.as_ref(),
        "the presented leaf must be the one from the PKCS#12 archive"
    );
}

/// Without an identity the same server rejects the handshake, so a passing
/// positive test above really is about the client certificate.
#[tokio::test]
async fn missing_client_identity_is_rejected_by_a_mtls_server() {
    let (ca_der, _client_cert, _client_key) = client_chain();
    let (url, presented) = spawn_mtls_cpm(ca_der).await;

    let client = HttpClient::new(
        &url,
        ClientConfig {
            timeout: Duration::from_secs(5),
            insecure_skip_verify: true,
            ..ClientConfig::default()
        },
    )
    .expect("http client");

    let err = client
        .register(register_req())
        .await
        .expect_err("a client without an identity must fail the mTLS handshake");
    assert!(
        err.to_string().contains("register request failed"),
        "failure must come from the HTTP transport, not the CPM envelope: {err}"
    );
    assert!(
        presented.lock().expect("presented lock").is_none(),
        "the server must not observe a client certificate"
    );
}
