//! `POST /v1/onboard/claim` and `GET /healthz`.
//!
//! Handler sequence for the claim route, in the exact order the finalized
//! contract specifies (`context/projects/benixos.md` §9j):
//! 1. rate-limit check (429) — before touching any other state;
//! 2. fail-closed guard (409 if already claimed, logged `warn`, no side
//!    effects);
//! 3. parse `qr_payload` (400 on any grammar deviation);
//! 4. first-run identity — see the note on `AppState::keypair` below for
//!    why this crate does that at process startup rather than inline
//!    here, and why that's equivalent;
//! 5. call `fabric_kit::FabricClient::pair_claim` (502 on outright
//!    failure, no local state change); on success, respond `202`
//!    immediately;
//! 6. spawn `wait_for_result` as a background task — only
//!    `PairOutcome::Approved` flips local state to `claimed`.
//!
//! Step 1 is checked against the connection's source IP before the
//! request body is read at all — this handler takes the raw
//! [`axum::extract::Request`] rather than a `Json<ClaimRequest>`
//! extractor parameter specifically so body-reading cannot happen ahead of
//! the rate-limit check in the extractor-evaluation order axum would
//! otherwise impose.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use fabric_kit::PairOutcome;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::local_account_binding::LocalAccountBinding;
use crate::qr_payload;
use crate::state;
use crate::AppState;

/// Body cap for the claim route — a `qr_payload` string is at most a few
/// hundred bytes; this is generous headroom, not a real size budget.
const MAX_CLAIM_BODY_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    qr_payload: String,
}

#[derive(Debug, Serialize)]
struct ClaimInitiatedResponse {
    status: &'static str,
    pair_session_id: String,
    expires_at_ms: i64,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub async fn onboard_claim(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, AppError> {
    // --- Step 1: rate-limit check, before touching anything else. ---
    if !state.rate_limiter.allow(addr.ip()) {
        return Err(AppError::RateLimited);
    }

    // --- Step 2 (redefined by §9gg/§9hh, made a binding gate by §9ii R4):
    // this endpoint is no longer BenixOS's initial-ownership path — DJ's
    // ruling (§9gg) moved that to the local-only claim protocol
    // (`src/local_claim.rs`). This endpoint is *demoted but not deleted*:
    // it is now the deferred Hearth-join step (§9hh Item 5), reachable
    // only once a box has already completed a LOCAL claim. An unclaimed
    // box has no local `owner_pubkey` to authorize a hub join on behalf
    // of, so this must fail closed by construction — not merely because
    // the hub happens to be unreachable on an offline first boot (§9ii's
    // own finding: "should, because it can't reach the hub" is not a
    // gate). See `handlers::tests::unclaimed_box_returns_403_and_never_
    // reaches_pair_claim` for the real regression test §9ii R4 requires.
    //
    // **Known gap, named not built (§9hh Item 5 / §9ii R4's own
    // deferral):** this only checks that *a* local claim happened; it does
    // NOT verify the caller is authenticated as the recorded owner via a
    // signature challenge. That "owner-signature auth" mechanism does not
    // exist in this crate yet and is explicitly out of scope for this pass
    // (a messaging-architect + data-architect + software-developer item,
    // per §9hh Item 5's own text) — flagged in README.md, not silently
    // left implicit.
    if !state::is_claimed(&state.state_dir) {
        tracing::warn!(
            source_ip = %addr.ip(),
            "hub-mediated claim POST received on a box that has not completed the \
             local-only claim protocol — refusing by construction (§9ii R4)"
        );
        return Err(AppError::NotLocallyClaimed);
    }

    // --- Content-Type + body parsing (ahead of the qr_payload grammar
    // check itself, but after both stateful guards above). ---
    let content_type_ok = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim() == "application/json")
        .unwrap_or(false);
    if !content_type_ok {
        return Err(AppError::MalformedRequest(
            "Content-Type: application/json is required".to_string(),
        ));
    }

    let body_bytes: Bytes = axum::body::to_bytes(request.into_body(), MAX_CLAIM_BODY_BYTES)
        .await
        .map_err(|e| AppError::MalformedRequest(format!("could not read request body: {e}")))?;
    let claim_request: ClaimRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError::MalformedRequest(format!("invalid JSON body: {e}")))?;

    // --- Step 3: parse qr_payload per the exact hub grammar. ---
    let parsed = qr_payload::parse(&claim_request.qr_payload)
        .map_err(|e| AppError::InvalidQrPayload(e.to_string()))?;

    // --- Step 4: first-run identity. Already resolved by the time this
    // handler runs: `AppState::keypair` is loaded-or-created once at
    // process startup (`main.rs`, mirroring `benix-mdns-advertiser`'s own
    // `id::load_or_create` idiom), not lazily inline here. This is the
    // same local-identity-creation-is-not-a-claimed-state-mutation
    // operation the contract describes for this step — doing it once at
    // startup rather than on every unclaimed-box's first POST is
    // observably identical (idempotent either way) and avoids a
    // request-path disk write on every retry before the first success.
    // See README.md's "Deviations from the contract" section.

    // --- Step 5: call fabric_kit::FabricClient::pair_claim. ---
    let claim_result = state
        .pair_claimer
        .pair_claim(
            &parsed.endpoint,
            &parsed.pair_session_id,
            &state.keypair,
            &state.device_name,
        )
        .await;

    let (ack, pending) = match claim_result {
        Ok(pair) => pair,
        Err(e) => {
            // No local state change on this path — the box remains
            // unclaimed.
            return Err(AppError::HubUnreachable(e.to_string()));
        }
    };

    let response_body = ClaimInitiatedResponse {
        status: "claim_initiated",
        pair_session_id: ack.pair_session_id.clone(),
        expires_at_ms: ack.expires_at_ms,
    };

    // --- Step 6: background wait, NOT awaited by this request. ---
    let expires_at_ms = ack.expires_at_ms;
    let timeout = Duration::from_millis((expires_at_ms - now_ms()).max(0) as u64);
    let background_state = Arc::clone(&state);
    let pair_session_id = ack.pair_session_id.clone();
    tokio::spawn(async move {
        run_wait_for_result(background_state, pending, timeout, pair_session_id).await;
    });

    Ok((StatusCode::ACCEPTED, Json(response_body)).into_response())
}

/// The background task body (Step 6). Split out from the handler so it can
/// be exercised directly in tests without going through the whole HTTP
/// stack.
async fn run_wait_for_result(
    state: Arc<AppState>,
    pending: Box<dyn crate::pairing::PendingPairingHandle>,
    timeout: Duration,
    pair_session_id: String,
) {
    match pending.wait_for_result(timeout).await {
        Ok(PairOutcome::Approved(creds)) => {
            tracing::info!(
                pair_session_id = %pair_session_id,
                credentials = %state::redacted_debug(&creds),
                "pairing approved — flipping local state to claimed"
            );

            if let Err(e) = state::mark_claimed(
                &state.state_dir,
                &creds.device_id,
                &creds.account_id,
                now_ms(),
            ) {
                tracing::error!(error = %e, "failed to persist claimed marker after approval");
                return;
            }
            if let Err(e) = state::persist_pair_credentials(&state.state_dir, &creds) {
                tracing::error!(error = %e, "failed to persist pair credentials after approval");
                return;
            }

            let binding = LocalAccountBinding::new_active(
                state.host_id.clone(),
                creds.device_id.clone(),
                state.device_name.clone(),
                now_ms(),
            );
            if let Err(e) = state::persist_local_account_binding(&state.state_dir, &binding) {
                tracing::error!(error = %e, "failed to persist local account binding after approval");
            }
        }
        Ok(PairOutcome::Rejected) => {
            tracing::info!(pair_session_id = %pair_session_id, "pairing rejected — remaining unclaimed");
        }
        Ok(PairOutcome::Timeout) => {
            tracing::info!(pair_session_id = %pair_session_id, "pairing timed out — remaining unclaimed");
        }
        Err(e) => {
            tracing::warn!(
                pair_session_id = %pair_session_id,
                error = %e,
                "wait_for_result failed — remaining unclaimed"
            );
        }
    }
}

/// `GET /healthz` — process-alive only, no claim-state disclosure.
pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::is_lan_source;
    use crate::pairing::MockPairClaimer;
    use crate::ratelimit::RateLimiter;
    use fabric_kit::{
        ClaimAcknowledged, DeviceKeypair, FabricError, PairCredentials, SealingKeypair,
    };
    use std::path::PathBuf;
    use tempfile_state_dir::temp_state_dir;

    // Small local helper module so this test file doesn't need a
    // dev-dependency on a real tempfile crate just for one pattern used
    // throughout this crate's tests.
    mod tempfile_state_dir {
        use std::path::PathBuf;
        use uuid::Uuid;

        pub fn temp_state_dir() -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "benix-claim-agent-handlers-test-{}",
                Uuid::new_v4()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }
    }

    fn test_state(dir: PathBuf, pair_claimer: MockPairClaimer) -> Arc<AppState> {
        Arc::new(AppState {
            keypair: DeviceKeypair::generate(),
            device_name: "test-box".to_string(),
            host_id: "test-host".to_string(),
            secret: crate::secret::load_or_create_secret(&dir).expect("test secret"),
            pending_challenges: crate::local_claim::PendingChallengeStore::new(),
            claim_commit_lock: std::sync::Mutex::new(()),
            state_dir: dir,
            rate_limiter: RateLimiter::new(10),
            pair_claimer: Box::new(pair_claimer),
        })
    }

    /// Every test below that exercises `onboard_claim` past its §9ii R4
    /// gate needs the box to already be locally claimed (that gate is the
    /// whole point of this PR — see `handlers::onboard_claim`'s own doc
    /// comment). This helper marks a box as locally claimed the same way
    /// `local_claim::local_claim_finish` would, without going through the
    /// full HTTP handshake (that handshake has its own dedicated test
    /// suite in `local_claim.rs`).
    fn mark_locally_claimed_for_test(dir: &std::path::Path) {
        state::mark_claimed_local(dir, "test-owner-pubkey-base64", now_ms())
            .expect("mark_claimed_local for test setup");
    }

    fn credentials() -> PairCredentials {
        PairCredentials {
            device_id: "device-42".to_string(),
            account_id: "account-42".to_string(),
            bearer_token: "secret".to_string(),
            resume_token: vec![1, 2, 3],
            sealing_keypair: SealingKeypair::generate(),
        }
    }

    fn ack() -> ClaimAcknowledged {
        ClaimAcknowledged {
            pair_session_id: "sess-42".to_string(),
            expires_at_ms: now_ms() + 60_000,
        }
    }

    #[tokio::test]
    async fn background_task_marks_claimed_only_on_approved() {
        let dir = temp_state_dir();
        let state = test_state(
            dir.clone(),
            MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Approved(credentials()))),
        );
        let (_, pending) = state
            .pair_claimer
            .pair_claim("wss://hub/v1", "sess-42", &state.keypair, "test-box")
            .await
            .unwrap();

        assert!(!state::is_claimed(&dir));
        run_wait_for_result(
            Arc::clone(&state),
            pending,
            Duration::from_secs(1),
            "sess-42".to_string(),
        )
        .await;
        assert!(state::is_claimed(&dir));
        assert!(state::pair_credentials_path(&dir).exists());
        assert!(state::local_account_binding_path(&dir).exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn background_task_stays_unclaimed_on_rejected() {
        let dir = temp_state_dir();
        let state = test_state(
            dir.clone(),
            MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Rejected)),
        );
        let (_, pending) = state
            .pair_claimer
            .pair_claim("wss://hub/v1", "sess-42", &state.keypair, "test-box")
            .await
            .unwrap();

        run_wait_for_result(
            Arc::clone(&state),
            pending,
            Duration::from_secs(1),
            "sess-42".to_string(),
        )
        .await;
        assert!(!state::is_claimed(&dir));
        assert!(!state::pair_credentials_path(&dir).exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn background_task_stays_unclaimed_on_timeout() {
        let dir = temp_state_dir();
        let state = test_state(
            dir.clone(),
            MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Timeout)),
        );
        let (_, pending) = state
            .pair_claimer
            .pair_claim("wss://hub/v1", "sess-42", &state.keypair, "test-box")
            .await
            .unwrap();

        run_wait_for_result(
            Arc::clone(&state),
            pending,
            Duration::from_secs(1),
            "sess-42".to_string(),
        )
        .await;
        assert!(!state::is_claimed(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn background_task_stays_unclaimed_on_wait_error() {
        let dir = temp_state_dir();
        let state = test_state(
            dir.clone(),
            MockPairClaimer::claim_ok_then(ack(), Err(FabricError::NotConnected)),
        );
        let (_, pending) = state
            .pair_claimer
            .pair_claim("wss://hub/v1", "sess-42", &state.keypair, "test-box")
            .await
            .unwrap();

        run_wait_for_result(
            Arc::clone(&state),
            pending,
            Duration::from_secs(1),
            "sess-42".to_string(),
        )
        .await;
        assert!(!state::is_claimed(&dir));

        std::fs::remove_dir_all(&dir).ok();
    }

    fn app(state: Arc<AppState>) -> axum::Router {
        crate::build_router(state)
    }

    /// `into_make_service_with_connect_info` is what supplies
    /// `ConnectInfo<SocketAddr>` to a real handler in production
    /// (`main.rs`), but it builds a `MakeService`, which `oneshot` cannot
    /// drive directly. Injecting `ConnectInfo` as a request extension is
    /// exactly what that wrapper does per-request under the hood, so this
    /// reproduces the same extractor input without standing up a real
    /// listener.
    async fn oneshot_with_addr(
        router: axum::Router,
        mut request: axum::http::Request<axum::body::Body>,
        addr: SocketAddr,
    ) -> axum::http::Response<axum::body::Body> {
        use tower::ServiceExt;
        request.extensions_mut().insert(ConnectInfo(addr));
        axum::Router::oneshot(router, request).await.unwrap()
    }

    fn lan_addr() -> SocketAddr {
        "192.168.1.50:5000".parse().unwrap()
    }

    fn wan_addr() -> SocketAddr {
        "8.8.8.8:5000".parse().unwrap()
    }

    #[test]
    fn lan_and_wan_test_fixtures_classify_as_expected() {
        assert!(is_lan_source(lan_addr().ip()));
        assert!(!is_lan_source(wan_addr().ip()));
    }

    /// **§9ii R4's own required regression test**, verbatim per its text:
    /// "assert and test that the demoted endpoint cannot record local
    /// ownership on an unclaimed box... prove it with a test that hits the
    /// old endpoint on an unclaimed, offline box." This box is genuinely
    /// unclaimed (no local claim, no hub credentials) and the mock
    /// `PairClaimer` would happily hand back an `Approved` outcome if ever
    /// invoked — the assertion that matters is that `pair_claim` is never
    /// even reached, proven the same way `already_claimed_returns_409...`
    /// used to prove its own analogous claim: the mock has no assertion
    /// wired against being called a *second* time here, but the response
    /// itself proves the handler returned before Step 5 (see
    /// `onboard_claim`'s own doc comment) — a `403` before any `202`/`502`
    /// could ever be produced.
    #[tokio::test]
    async fn unclaimed_box_returns_403_and_never_reaches_pair_claim() {
        let dir = temp_state_dir();
        // Deliberately NOT locally claimed, NOT hub-joined — the exact
        // "genuinely offline, first-boot box" scenario §9ii names.
        let state = test_state(
            dir.clone(),
            MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Approved(credentials()))),
        );
        let router = app(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/onboard/claim")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"qr_payload": "quickring://pair?session=s&endpoint=ws%3A%2F%2Fh%2Fv1"})
                    .to_string(),
            ))
            .unwrap();
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            !state::pair_credentials_path(&dir).exists(),
            "an unclaimed box must not be able to record hub-join credentials, by construction"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn non_lan_source_is_rejected_403() {
        let dir = temp_state_dir();
        let state = test_state(
            dir.clone(),
            MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Approved(credentials()))),
        );
        let router = app(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/onboard/claim")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"qr_payload": "quickring://pair?session=s&endpoint=ws%3A%2F%2Fh%2Fv1"})
                    .to_string(),
            ))
            .unwrap();
        let response = oneshot_with_addr(router, request, wan_addr()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn invalid_qr_payload_returns_400() {
        let dir = temp_state_dir();
        mark_locally_claimed_for_test(&dir);
        let state = test_state(
            dir.clone(),
            MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Approved(credentials()))),
        );
        let router = app(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/onboard/claim")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"qr_payload": "not-a-valid-payload"}).to_string(),
            ))
            .unwrap();
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn successful_claim_returns_202_immediately() {
        let dir = temp_state_dir();
        mark_locally_claimed_for_test(&dir);
        let state = test_state(
            dir.clone(),
            MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Approved(credentials()))),
        );
        let router = app(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/onboard/claim")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"qr_payload": "quickring://pair?session=s&endpoint=ws%3A%2F%2Fh%2Fv1"})
                    .to_string(),
            ))
            .unwrap();
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn hub_unreachable_returns_502_and_does_not_claim() {
        let dir = temp_state_dir();
        mark_locally_claimed_for_test(&dir);
        let state = test_state(
            dir.clone(),
            MockPairClaimer::claim_err(FabricError::Transport("refused".to_string())),
        );
        let router = app(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/onboard/claim")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"qr_payload": "quickring://pair?session=s&endpoint=ws%3A%2F%2Fh%2Fv1"})
                    .to_string(),
            ))
            .unwrap();
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        // The box was already (locally) claimed before this request, per
        // the new §9ii R4 precondition — `is_claimed()` stays `true`
        // throughout regardless of the hub outcome. The meaningful
        // postcondition here is that the hub-join itself did not succeed:
        // no `pair-credentials` were ever persisted.
        assert!(!state::pair_credentials_path(&dir).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn missing_content_type_returns_400() {
        let dir = temp_state_dir();
        mark_locally_claimed_for_test(&dir);
        let state = test_state(
            dir.clone(),
            MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Approved(credentials()))),
        );
        let router = app(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/onboard/claim")
            .body(axum::body::Body::from(
                serde_json::json!({"qr_payload": "quickring://pair?session=s&endpoint=ws%3A%2F%2Fh%2Fv1"})
                    .to_string(),
            ))
            .unwrap();
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn unknown_field_in_body_is_rejected() {
        let dir = temp_state_dir();
        mark_locally_claimed_for_test(&dir);
        let state = test_state(
            dir.clone(),
            MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Approved(credentials()))),
        );
        let router = app(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/onboard/claim")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "qr_payload": "quickring://pair?session=s&endpoint=ws%3A%2F%2Fh%2Fv1",
                    "extra": "nope"
                })
                .to_string(),
            ))
            .unwrap();
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn healthz_returns_200_and_no_claim_state() {
        let dir = temp_state_dir();
        let state = test_state(
            dir.clone(),
            MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Approved(credentials()))),
        );
        let router = app(state);
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = oneshot_with_addr(router, request, wan_addr()).await;
        assert_eq!(response.status(), StatusCode::OK);
        std::fs::remove_dir_all(&dir).ok();
    }
}
