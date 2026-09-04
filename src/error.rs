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
    /// Now real and constructed: `src/local_claim.rs`'s `finish` handler
    /// returns this if a post-verification disk write (mark-claimed,
    /// delete-secret, persist-binding) fails.
    Internal(String),
    /// 410 — the local-claim protocol's `challenge_id` is unknown or has
    /// expired (§9hh Item 2's ~120s TTL, enforced on a monotonic clock per
    /// §9ii R3 — never wall-clock). The caller must restart the handshake
    /// from `POST /v1/onboard/local-claim/challenge`.
    ChallengeNotFound,
    /// 401 — the local-claim protocol's `client_proof` did not match this
    /// box's own recomputed HMAC, or `client_sig` did not verify against
    /// `client_pubkey`. Deliberately does NOT consume the box's persisted
    /// secret or invalidate the pending challenge (§9hh: "a legit typo
    /// must not burn onboarding" — the 128-bit secret makes online
    /// guessing infeasible regardless of retry budget, which the rate
    /// limiter already bounds; §9ii's ratified judgment call: no hard
    /// lockout, visibility via logging instead).
    InvalidProof,
    /// 403 — `POST /v1/onboard/claim` (the hub-mediated path, demoted by
    /// §9gg to the deferred Hearth-join step, §9hh Item 5) may only run on
    /// a box that has already completed the local-only claim protocol.
    /// §9ii R4, binding: this box has no local owner to authorize a hub
    /// join on behalf of until a local claim exists, and this must be a
    /// by-construction gate — not merely an accident of the hub being
    /// unreachable on an offline first boot.
    NotLocallyClaimed,
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
            Self::ChallengeNotFound => StatusCode::GONE,
            Self::InvalidProof => StatusCode::UNAUTHORIZED,
            Self::NotLocallyClaimed => StatusCode::FORBIDDEN,
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
            Self::ChallengeNotFound => "challenge_not_found",
            Self::InvalidProof => "invalid_proof",
            Self::NotLocallyClaimed => "not_locally_claimed",
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
            Self::ChallengeNotFound => {
                "challenge_id is unknown or has expired; restart the local-claim handshake"
                    .to_string()
            }
            Self::InvalidProof => "client_proof or client_sig did not verify".to_string(),
            Self::NotLocallyClaimed => {
                "this box must complete the local-only claim protocol before joining a \
                 hub-mediated account"
                    .to_string()
            }
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
