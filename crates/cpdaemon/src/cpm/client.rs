//! HTTP client for the CPM API. Port of `cpdaemon/pkg/cpm/client.go`.
//!
//! Server TLS verification is **on by default** and can only be disabled
//! explicitly via `cpm.client.tls.insecure_skip_verify` (upstream #232). When
//! `cpm.client.tls.pkcs12_cert_file` is set, the PKCS#12 archive is decoded with
//! `pkcs12_cert_password` and presented as the client identity (mTLS), matching
//! the Go oracle's `provider.go` key set (`cloud-probe-rs-ryg.2`).

use reqwest::Url;
use serde::Deserialize;

use super::models::*;
use crate::config::{CpmClient, DaemonConfig};
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub timeout: std::time::Duration,
    pub insecure_skip_verify: bool,
    /// PKCS#12 archive (`.p12`/`.pfx`) used as the mTLS client identity.
    /// Empty means "no client certificate", which is the default.
    pub pkcs12_cert_file: String,
    /// Password for `pkcs12_cert_file`.
    pub pkcs12_cert_password: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            timeout: std::time::Duration::from_secs(15),
            // Safe by default: verify the server certificate. The Go oracle
            // hard-codes `InsecureSkipVerify: true`; that is upstream #232.
            insecure_skip_verify: false,
            // No client certificate by default (client auth stays opt-in).
            pkcs12_cert_file: String::new(),
            pkcs12_cert_password: String::new(),
        }
    }
}

impl ClientConfig {
    /// Map the parsed `cpm.client` configuration onto the HTTP client's config.
    ///
    /// This is the single place where
    /// `cpm.client.tls.insecure_skip_verify` reaches the client, so the
    /// security decision is a pure function that can be tested without a
    /// network (and it keeps `main.rs` from re-deriving it). The PKCS#12 key
    /// set is carried through verbatim; the archive is only read in
    /// [`HttpClient::new`].
    pub fn from_cpm_client(c: &CpmClient) -> Self {
        ClientConfig {
            timeout: DaemonConfig::parse_duration(&c.timeout, std::time::Duration::from_secs(15)),
            insecure_skip_verify: c.tls.insecure_skip_verify,
            pkcs12_cert_file: c.tls.pkcs12_cert_file.clone(),
            pkcs12_cert_password: c.tls.pkcs12_cert_password.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct BodyError {
    #[serde(default)]
    code: i32,
    #[serde(default)]
    msg: String,
}

pub struct HttpClient {
    base_url: Url,
    client: reqwest::Client,
}

impl HttpClient {
    pub fn new(base_url: &str, cfg: ClientConfig) -> Result<Self> {
        let base_url =
            Url::parse(base_url).map_err(|e| Error::new(format!("parse cpm.base_url: {e}")))?;
        let mut builder = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .danger_accept_invalid_certs(cfg.insecure_skip_verify);
        if !cfg.pkcs12_cert_file.is_empty() {
            let identity = load_client_identity(&cfg.pkcs12_cert_file, &cfg.pkcs12_cert_password)?;
            builder = builder.identity(identity);
        }
        let client = builder
            .build()
            .map_err(|e| Error::new(format!("build http client: {e}")))?;
        Ok(HttpClient { base_url, client })
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        self.base_url
            .join(path.trim_start_matches('/'))
            .map_err(|e| Error::new(format!("build endpoint {path}: {e}")))
    }

    pub async fn register(&self, mut req: RegisterRequest) -> Result<RegisterResponse> {
        req.fix_zero();
        let url = self.endpoint("/api/v1/daemons")?;
        let resp = self
            .client
            .post(url)
            .json(&req)
            .send()
            .await
            .map_err(|e| Error::new(format!("register request failed: {e}")))?;
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::new(format!("read register body: {e}")))?;
        if !status.is_success() {
            return Err(Error::new(format!(
                "http resp error: status_code: {}, body: {}",
                status.as_u16(),
                String::from_utf8_lossy(&body)
            )));
        }
        check_body_error(status.as_u16(), &body)?;
        serde_json::from_slice(&body)
            .map_err(|e| Error::new(format!("unmarshal register body: {e}")))
    }

    pub async fn sync_strategy(&self, daemon_id: i64, version: i32) -> Result<SyncStrategyResult> {
        let mut url = self.endpoint(&format!("/api/v1/daemons/{daemon_id}/sync/strategy"))?;
        url.query_pairs_mut()
            .append_pair("version", &version.to_string());

        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::new(format!("sync strategy request failed: {e}")))?;
        let status = resp.status();
        if status.as_u16() == 304 {
            return Ok(SyncStrategyResult {
                changed: false,
                response: None,
            });
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::new(format!("read strategy body: {e}")))?;
        if !status.is_success() {
            return Err(Error::new(format!(
                "http resp error: status_code: {}, body: {}",
                status.as_u16(),
                String::from_utf8_lossy(&body)
            )));
        }
        check_body_error(status.as_u16(), &body)?;
        let response: SyncStrategyResponse = serde_json::from_slice(&body)
            .map_err(|e| Error::new(format!("unmarshal strategy body: {e}")))?;
        Ok(SyncStrategyResult {
            changed: true,
            response: Some(response),
        })
    }

    pub async fn sync_metrics(&self, daemon_id: i64, req: SyncMetricsRequest) -> Result<()> {
        let url = self.endpoint(&format!("/api/v1/daemons/{daemon_id}/sync/metrics"))?;
        let resp = self
            .client
            .post(url)
            .json(&req)
            .send()
            .await
            .map_err(|e| Error::new(format!("sync metrics request failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.bytes().await.unwrap_or_default();
            return Err(Error::new(format!(
                "http resp error: status_code: {}, body: {}",
                status.as_u16(),
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(())
    }
}

fn check_body_error(status_code: u16, body: &[u8]) -> Result<()> {
    let Ok(res) = serde_json::from_slice::<BodyError>(body) else {
        return Ok(());
    };
    if res.code >= 400 {
        return Err(Error::new(format!(
            "http body error: status_code: {status_code}, code: {}, msg: {}",
            res.code, res.msg
        )));
    }
    Ok(())
}

/// Read and decode a PKCS#12 archive into an mTLS client identity.
///
/// Called from [`HttpClient::new`] only when `cpm.client.tls.pkcs12_cert_file`
/// is non-empty, so the default client is unchanged.
pub fn load_client_identity(path: &str, password: &str) -> Result<reqwest::Identity> {
    let data = std::fs::read(path)
        .map_err(|e| Error::new(format!("read pkcs12 cert file {path}: {e}")))?;
    pkcs12_to_identity(&data, password)
        .map_err(|e| Error::new(format!("load pkcs12 cert file {path}: {e}")))
}

/// Decode PKCS#12 bytes into a `reqwest::Identity`.
///
/// Mirrors the Go oracle: verify the archive's MAC, decrypt the certificate
/// bags and the shrouded private key with the configured password, then build
/// the identity. `p12` supports exactly the legacy PBE schemes
/// (`PBE-SHA1-RC2-40`, `PBE-SHA1-3DES`) that `golang.org/x/crypto/pkcs12`
/// supports; a modern PBES2/AES archive is rejected rather than silently
/// mis-decrypted, matching the oracle's inability to read it.
fn pkcs12_to_identity(data: &[u8], password: &str) -> Result<reqwest::Identity> {
    let pfx = p12::PFX::parse(data).map_err(|e| Error::new(format!("parse pkcs12: {e}")))?;
    if !pfx.verify_mac(password) {
        return Err(Error::new(
            "pkcs12 MAC verification failed (wrong password or corrupt archive)",
        ));
    }
    let certs = pfx
        .cert_x509_bags(password)
        .map_err(|e| Error::new(format!("decode pkcs12 certificate bags: {e}")))?;
    if certs.is_empty() {
        return Err(Error::new("pkcs12 archive contains no X.509 certificate"));
    }
    let key = pfx
        .key_bags(password)
        .map_err(|e| Error::new(format!("decode pkcs12 key bags: {e}")))?
        .into_iter()
        .next()
        .ok_or_else(|| Error::new("pkcs12 archive contains no private key"))?;

    // `reqwest::Identity::from_pem` is the only constructor available with the
    // rustls backend, so re-wrap the DER the decoder produced as PEM.
    let pem = encode_identity_pem(&certs, &key);
    reqwest::Identity::from_pem(&pem).map_err(|e| Error::new(format!("build pkcs12 identity: {e}")))
}

/// PEM-encode a certificate chain (leaf first) and PKCS#8 private key.
fn encode_identity_pem(certs: &[Vec<u8>], key: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut pem = Vec::new();
    for cert in certs {
        push_pem_block(&mut pem, "CERTIFICATE", b64.encode(cert).as_bytes());
    }
    push_pem_block(&mut pem, "PRIVATE KEY", b64.encode(key).as_bytes());
    pem
}

fn push_pem_block(out: &mut Vec<u8>, label: &str, body: &[u8]) {
    out.extend_from_slice(format!("-----BEGIN {label}-----\n").as_bytes());
    for chunk in body.chunks(64) {
        out.extend_from_slice(chunk);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpm_client(json: &str) -> CpmClient {
        serde_json::from_str(json).expect("parse cpm.client")
    }

    /// Upstream #232: the default client config must verify certificates.
    #[test]
    fn default_client_config_verifies_certificates() {
        assert!(!ClientConfig::default().insecure_skip_verify);
    }

    /// The config -> ClientConfig mapping is a pure function; pin its decision
    /// on both the default and the explicit opt-out.
    #[test]
    fn cpm_client_tls_switch_maps_to_client_config() {
        let cfg = ClientConfig::from_cpm_client(&cpm_client("{\"timeout\":\"7s\"}"));
        assert!(
            !cfg.insecure_skip_verify,
            "absent switch must verify the server certificate"
        );
        assert_eq!(cfg.timeout, std::time::Duration::from_secs(7));

        let cfg = ClientConfig::from_cpm_client(&cpm_client(
            "{\"timeout\":\"7s\",\"tls\":{\"insecure_skip_verify\":true}}",
        ));
        assert!(
            cfg.insecure_skip_verify,
            "explicit opt-out must be honoured"
        );
        assert_eq!(cfg.timeout, std::time::Duration::from_secs(7));
    }

    /// The PKCS#12 key set is carried from config into the client config so that
    /// `HttpClient::new` can build the identity. Nothing is read here.
    #[test]
    fn cpm_client_pkcs12_fields_map_to_client_config() {
        let cfg = ClientConfig::from_cpm_client(&cpm_client(
            "{\"tls\":{\"pkcs12_cert_file\":\"/c.p12\",\"pkcs12_cert_password\":\"pw\"}}",
        ));
        assert_eq!(cfg.pkcs12_cert_file, "/c.p12");
        assert_eq!(cfg.pkcs12_cert_password, "pw");

        let cfg = ClientConfig::from_cpm_client(&cpm_client("{}"));
        assert!(cfg.pkcs12_cert_file.is_empty());
        assert!(cfg.pkcs12_cert_password.is_empty());
    }

    /// A fresh self-signed certificate + PKCS#8 key, packed into an in-memory
    /// PKCS#12 archive the same way `openssl pkcs12 -export` would.
    fn self_signed_pkcs12(password: &str) -> Vec<u8> {
        let ck = rcgen::generate_simple_self_signed(vec!["client.example".to_string()])
            .expect("self-signed cert");
        let cert_der = ck.cert.der().to_vec();
        let key_der = ck.key_pair.serialize_der();
        p12::PFX::new(&cert_der, &key_der, None, password, "client")
            .expect("build pfx")
            .to_der()
    }

    /// Minimum contract: a well-formed PKCS#12 archive with the right password
    /// decodes into a reqwest identity (mTLS client certificate).
    #[test]
    fn pkcs12_archive_builds_client_identity() {
        let pfx = self_signed_pkcs12("s3cret");
        pkcs12_to_identity(&pfx, "s3cret").expect("valid p12 + password must build an identity");
    }

    /// A wrong password must be rejected at the MAC check, not silently
    /// produce a broken identity.
    #[test]
    fn pkcs12_wrong_password_is_rejected() {
        let pfx = self_signed_pkcs12("s3cret");
        let err = pkcs12_to_identity(&pfx, "wrong").expect_err("wrong password must fail");
        assert!(
            err.to_string().contains("MAC verification failed"),
            "unexpected error: {err}"
        );
    }

    /// `load_client_identity` names the file in its error so an operator can
    /// see which path failed, and refuses a missing file before decoding.
    #[test]
    fn load_client_identity_reports_missing_file() {
        let err = load_client_identity("/nonexistent/client.p12", "pw")
            .expect_err("missing file must error");
        assert!(
            err.to_string().contains("read pkcs12 cert file"),
            "unexpected error: {err}"
        );
    }

    /// The generated PEM keeps the certificate label and the PKCS#8 key label
    /// that `reqwest::Identity::from_pem` dispatches on.
    #[test]
    fn identity_pem_has_certificate_and_private_key_sections() {
        let pem = encode_identity_pem(&[vec![1, 2, 3]], &[4, 5, 6]);
        let text = String::from_utf8(pem).expect("pem is utf-8");
        assert!(text.contains("-----BEGIN CERTIFICATE-----\n"));
        assert!(text.contains("-----END CERTIFICATE-----\n"));
        assert!(text.contains("-----BEGIN PRIVATE KEY-----\n"));
        assert!(text.contains("-----END PRIVATE KEY-----\n"));
    }
}
