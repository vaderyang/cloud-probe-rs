//! HTTP client for the CPM API. Port of `cpdaemon/pkg/cpm/client.go`.
//!
//! Note: PKCS#12 client-certificate loading is not ported (reqwest/rustls has
//! no built-in PKCS#12 decoder without extra crates). Server TLS verification
//! can be disabled via configuration, matching the Go default.

use serde::Deserialize;
use reqwest::Url;

use super::models::*;
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub timeout: std::time::Duration,
    pub insecure_skip_verify: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            timeout: std::time::Duration::from_secs(15),
            insecure_skip_verify: true,
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
        let base_url = Url::parse(base_url)
            .map_err(|e| Error::new(format!("parse cpm.base_url: {e}")))?;
        let client = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .danger_accept_invalid_certs(cfg.insecure_skip_verify)
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

    pub async fn sync_strategy(
        &self,
        daemon_id: i64,
        version: i32,
    ) -> Result<SyncStrategyResult> {
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
