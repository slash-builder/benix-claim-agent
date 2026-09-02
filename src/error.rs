//! The one error body shape every 4xx/5xx on this service uses:
//! `{"error": "<snake_case_code>", "message": "<human-readable>"}`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: &'static str,
    pub message: String,
}

/// One handler-level error type covering every documented failure mode of
/// `POST /v1/onboard/claim`. Deliberately flat (no nested `From` chains
/// beyond what's below) — this handler's error surface is small and fully
/// enumerated in the finalized contract.
#[derive(Debug)]
pub enum AppError {
    /// 429 — rate-limit budget exhausted for this source IP.
    RateLimited,
    /// 403 — source IP is not RFC1918/ULA/link-local.
    NonLanSource,
    /// 409 — box is already claimed. Every box this endpoint sees is
    /// supposed to be a clean install, so this is logged as an anomaly by
    /// the caller before this variant is even constructed — this variant
    /// only carries the HTTP-shape half of that.
    AlreadyClaimed,
    /// 400 — `qr_payload` failed to parse per the exact hub grammar.
    InvalidQrPayload(String),
    /// 400 — the request body was not valid JSON, or was valid JSON but
    /// missing/mistyped the one expected field. Axum's own `Json`
    /// extractor rejection is folded into this rather than given a
    /// separate variant, since the response shape is identical.
    MalformedRequest(String),
    /// 502 — `fabric_kit::FabricClient::pair_claim` itself failed (could
    /// not reach the hub, or the hub rejected the claim outright). No
    /// local state change happens on this path — the box remains
    /// unclaimed.
    HubUnreachable(String),
    /// 500 — anything this handler cannot attribute to caller input or the
    /// hub (e.g. a state-directory I/O failure). Kept generic and
    /// non-leaky in the response body; the real detail goes to the log.
    /// Not currently constructed anywhere: the request-handling path's
    /// only fallible I/O (`state::is_claimed`) degrades to "not claimed"
    /// rather than erroring, and every other failure mode already has its
    /// own variant. Kept as a documented, reserved catch-all — the
    /// finalized contract's error-body table names `5xx` as a real
    /// possibility for "all 4xx/5xx" — rather than removed and re-added
    /// the first time something actually needs it.
    #[allow(dead_code)]
    Internal(String),
}

impl AppError {
    fn status(&self) -> StatusCode {
        match self {
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::NonLanSource => StatusCode::FORBIDDEN,
            Self::AlreadyClaimed => StatusCode::CONFLICT,
            Self::InvalidQrPayload(_) | Self::MalformedRequest(_) => StatusCode::BAD_REQUEST,
            Self::HubUnreachable(_) => StatusCode::BAD_GATEWAY,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::RateLimited => "rate_limited",
            Self::NonLanSource => "non_lan_source",
            Self::AlreadyClaimed => "already_claimed",
            Self::InvalidQrPayload(_) => "invalid_qr_payload",
            Self::MalformedRequest(_) => "malformed_request",
            Self::HubUnreachable(_) => "hub_unreachable",
            Self::Internal(_) => "internal_error",
        }
    }

    fn message(&self) -> String {
        match self {
            Self::RateLimited => "rate limit exceeded for this source IP".to_string(),
            Self::NonLanSource => "source IP is not RFC1918/ULA/link-local".to_string(),
            Self::AlreadyClaimed => "this box is already claimed".to_string(),
            Self::InvalidQrPayload(m)
            | Self::MalformedRequest(m)
            | Self::HubUnreachable(m)
            | Self::Internal(m) => m.clone(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = ErrorBody {
            error: self.code(),
            message: self.message(),
        };
        (status, Json(body)).into_response()
    }
}
