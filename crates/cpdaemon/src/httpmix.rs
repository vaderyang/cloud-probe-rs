//! HTTP response helpers. Port of `cpdaemon/pkg/httpmix/helper.go`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub message: String,
}

impl ErrorInfo {
    pub fn new(err: &dyn std::error::Error) -> Self {
        ErrorInfo {
            message: err.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorInfo,
}

pub fn error_response(status: StatusCode, err: &dyn std::error::Error) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: ErrorInfo::new(err),
        }),
    )
        .into_response()
}

pub fn bad_request(err: &dyn std::error::Error) -> Response {
    error_response(StatusCode::BAD_REQUEST, err)
}

pub fn not_found(err: &dyn std::error::Error) -> Response {
    error_response(StatusCode::NOT_FOUND, err)
}

pub fn abort(err: &dyn std::error::Error) -> Response {
    log::error!("abort: {err}");
    error_response(StatusCode::INTERNAL_SERVER_ERROR, err)
}

pub fn json_ok<T: Serialize>(value: &T) -> Response {
    (StatusCode::OK, Json(value)).into_response()
}

pub fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}
