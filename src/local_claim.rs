//! `POST /v1/onboard/local-claim/challenge` and
//! `POST /v1/onboard/local-claim/finish` — the local-only claim protocol
//! (`context/projects/benixos.md` §9hh, answering §9gg's DJ ruling that
//! BenixOS onboarding must work fully local, zero hub/cloud dependency;
//! binding adversarial review §9ii, VERDICT: RATIFIED WITH NAMED REQUIRED
//! CHANGES — R1-R5 below, folded in, not left as follow-up).
//!
//! A two-message mutual proof-of-possession handshake: the box's own
//! displayed secret (`src/secret.rs`) is *proven* via HMAC-SHA256, never
//! transmitted, and the owner credential recorded is Courier's Ed25519
//! public key, not a bearer token. Distinct from `POST /v1/onboard/claim`
//! (`src/handlers.rs`), the hub-mediated path (§9j), which §9gg/§9hh demote
//! to the deferred Hearth-join step (Item 5) — see that module's own R4
//! gate.
//!
//! ## Wire contract
//!
//! **Step 1 — `POST /v1/onboard/local-claim/challenge`**
//! Request: `{"client_pubkey": "<base64, 32-byte Ed25519>"}`.
//! Response: `{"challenge_id", "server_nonce": "<base64, 16 bytes>",
//! "box_pubkey": "<base64, 32 bytes>", "expires_at_ms": <unix ms UTC,
//! ADVISORY DISPLAY ONLY — see R3>}`.
//!
//! **Step 2 — `POST /v1/onboard/local-claim/finish`**
//! Courier computes (m2: **raw decoded bytes**, fixed order, fixed
//! lengths — 16 ‖ 32 ‖ 32 — never base64 text):
//! ```text
//! transcript      = server_nonce ‖ client_pubkey ‖ box_pubkey
//! client_proof    = HMAC-SHA256(key = secret, "benix-claim/client" ‖ transcript)
//! client_sig      = Ed25519-sign(client_privkey, challenge_id ‖ client_proof)
//! ```
//! Request: `{"challenge_id", "client_pubkey", "client_proof": "<base64>",
//! "client_sig": "<base64>"}`.
//! Response (on success): `{"status": "claimed", "box_pubkey", "box_id",
//! "box_proof": "<base64, HMAC-SHA256(secret, "benix-claim/box" ‖
//! transcript)>", "claimed_at_ms"}`. Courier MUST verify `box_proof` before
//! treating the claim as real (T7: a fake/spoofed box cannot produce it).
//!
//! ## §9ii's binding required changes, folded in here
//!
//! - **R1** — the `client_proof` compare is `Mac::verify_slice`, which
//!   performs a constant-time comparison via `subtle::ConstantTimeEq`
//!   internally (RustCrypto's own `digest::Mac` blanket impl) — never a
//!   plain `==` on decoded bytes, which would open a timing oracle that
//!   leaks a directly-replayable `expected_client_proof` byte-by-byte.
//! - **R2** — the `claimed?` re-check and the commit itself
//!   (mark-claimed, delete-secret, persist-binding, invalidate-challenge)
//!   run inside one `AppState::claim_commit_lock`-guarded critical
//!   section, so two concurrent *valid* finishes resolve first-writer-wins
//!   — the loser gets `409`, never a silent overwrite of `owner_pubkey`.
//! - **R3** — the pending-challenge TTL is enforced on [`Instant`]
//!   (monotonic), never wall-clock; `expires_at_ms` in the challenge
//!   response and `claimed_at_ms` in the finish response are advisory
//!   display metadata only (an offline first-boot box has no trustworthy
//!   RTC/NTP-synced clock — §9ii's own finding).
//! - **R4** — see `src/handlers.rs`'s gate on the demoted hub-mediated
//!   endpoint; not this module's own concern, named here for
//!   completeness.
//! - **R5** — see `src/state.rs::write_private_atomic`'s hardening
//!   (0600-from-open, fsync-then-rename-then-fsync-parent-dir), reused
//!   unmodified by `src/secret.rs`.
//! - **m1** — `challenge_id` is CSPRNG-derived ([`Uuid::new_v4`], which
//!   draws from the OS CSPRNG under its `v4` feature), never sequential.
//! - **m2** — see the wire-contract worked example above.
//! - **m3** — the pending-challenge map is capacity-bounded
//!   ([`MAX_PENDING_CHALLENGES`]); when full it evicts the
//!   soonest-to-expire entry rather than rejecting the new request — a
//!   flood is DoS-only (the legit holder gets `410` on `finish` and simply
//!   retries from `/challenge`), never a hard block on new attempts.
//! - **m4** — the transcript is always built from the **finish** request's
//!   `client_pubkey` (the key actually being bound as owner). This crate
//!   does not even persist the step-1 `client_pubkey` — there is nothing
//!   to reconcile it against, by construction.
//! - **m5** — the RFC1918/ULA/link-local source gate (`main.rs`'s
//!   `require_lan_source` middleware, applied to this module's routes the
//!   same as `handlers::onboard_claim`'s) reads `ConnectInfo<SocketAddr>`,
//!   the real socket peer address — never a forwarded header.
//! - **Visibility, not a hard lockout** (§9ii's ratified judgment call): a
//!   failed `client_proof`/`client_sig` is logged (`tracing::warn!`) with
//!   the source IP and `challenge_id`, but does not consume the secret,
//!   invalidate the challenge, or trip any permanent lockout — the
//!   existing per-IP token bucket (`src/ratelimit.rs`) already throttles
//!   online guessing to irrelevance at 128-bit entropy, and a hard lockout
//!   would let an attacker deny the legitimate user their own onboarding.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::error::AppError;
use crate::local_account_binding::LocalAccountBinding;
use crate::state;
use crate::AppState;

type HmacSha256 = Hmac<Sha256>;

/// §9hh Item 2: "short TTL ~120s."
const CHALLENGE_TTL: Duration = Duration::from_secs(120);

/// m3: an overwhelmingly generous bound for a single-household onboarding
/// flow — this exists only to give the eviction policy something concrete
/// to trigger on paper, not because real traffic is expected to approach
/// it.
const MAX_PENDING_CHALLENGES: usize = 256;

/// Generous headroom for these small, fixed-shape JSON bodies (base64 of a
/// handful of 16/32/64-byte fields).
const MAX_BODY_BYTES: usize = 4 * 1024;

const CLIENT_PROOF_LABEL: &[u8] = b"benix-claim/client";
const BOX_PROOF_LABEL: &[u8] = b"benix-claim/box";

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRequest {
    client_pubkey: String,
}

#[derive(Debug, Serialize)]
struct ChallengeResponse {
    challenge_id: String,
    server_nonce: String,
    box_pubkey: String,
    /// R3: advisory display metadata only. Enforcement uses the monotonic
    /// [`Instant`] stored in [`PendingChallengeStore`], never this value.
    expires_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishRequest {
    challenge_id: String,
    client_pubkey: String,
    client_proof: String,
    client_sig: String,
}

#[derive(Debug, Serialize)]
struct FinishResponse {
    status: &'static str,
    box_pubkey: String,
    box_id: String,
    box_proof: String,
    /// R3 corollary: wall-clock, cosmetic only on an offline box with no
    /// trustworthy clock — never used for any security-relevant decision.
    claimed_at_ms: i64,
}

struct PendingChallenge {
    server_nonce: [u8; 16],
    expires_at: Instant,
}

/// The local-claim protocol's bounded, in-memory, lock-guarded pending
/// challenge map (§9hh Item 2, §9ii R2/R3/m3). One instance lives on
/// [`AppState`] for the lifetime of the process — pending challenges do
/// not (and must not) survive a restart, since a restart also means a
/// fresh `server_nonce` is due anyway.
pub struct PendingChallengeStore {
    challenges: Mutex<HashMap<String, PendingChallenge>>,
}

impl PendingChallengeStore {
    pub fn new() -> Self {
        Self {
            challenges: Mutex::new(HashMap::new()),
        }
    }

    /// Insert a fresh pending challenge, first sweeping any expired entries
    /// (opportunistic, not a background reaper — matches `ratelimit.rs`'s
    /// own "small realistic address space for a single-process LAN
    /// service" precedent) and, if still at capacity, evicting the single
    /// soonest-to-expire entry (m3's chosen eviction policy).
    fn insert(&self, challenge_id: String, server_nonce: [u8; 16], now: Instant, ttl: Duration) {
        let mut challenges = self.challenges.lock().expect("pending-challenge lock");
        challenges.retain(|_, c| c.expires_at > now);
        if challenges.len() >= MAX_PENDING_CHALLENGES {
            if let Some(oldest_id) = challenges
                .iter()
                .min_by_key(|(_, c)| c.expires_at)
                .map(|(id, _)| id.clone())
            {
                challenges.remove(&oldest_id);
            }
        }
        challenges.insert(
            challenge_id,
            PendingChallenge {
                server_nonce,
                expires_at: now + ttl,
            },
        );
    }

    /// Look up a pending challenge's `server_nonce` **without** consuming
    /// it — a failed `client_proof` must remain retryable within the TTL
    /// (§9hh: "a legit typo must not burn onboarding"). `None` if absent
    /// or expired (checked against the monotonic `now` passed in — R3).
    fn peek(&self, challenge_id: &str, now: Instant) -> Option<[u8; 16]> {
        let challenges = self.challenges.lock().expect("pending-challenge lock");
        challenges
            .get(challenge_id)
            .filter(|c| c.expires_at > now)
            .map(|c| c.server_nonce)
    }

    /// Consume (invalidate) a pending challenge on a successful claim — the
    /// secret is single-use, and so is the challenge it was proven
    /// against.
    fn invalidate(&self, challenge_id: &str) {
        self.challenges
            .lock()
            .expect("pending-challenge lock")
            .remove(challenge_id);
    }

    /// Test-only: insert a challenge with an explicit (possibly
    /// already-expired) `expires_at`, so the `410` path can be tested
    /// deterministically without depending on real wall-clock sleeps.
    #[cfg(test)]
    fn insert_raw(&self, challenge_id: String, server_nonce: [u8; 16], expires_at: Instant) {
        self.challenges
            .lock()
            .expect("pending-challenge lock")
            .insert(
                challenge_id,
                PendingChallenge {
                    server_nonce,
                    expires_at,
                },
            );
    }
}

impl Default for PendingChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

fn has_json_content_type(request: &Request) -> bool {
    request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim() == "application/json")
        .unwrap_or(false)
}

fn decode_fixed<const N: usize>(field: &'static str, value: &str) -> Result<[u8; N], AppError> {
    let bytes = data_encoding::BASE64
        .decode(value.as_bytes())
        .map_err(|_| AppError::MalformedRequest(format!("{field} is not valid base64")))?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| AppError::MalformedRequest(format!("{field} must decode to {N} bytes")))
}

/// m2: the HMAC input is the *raw decoded bytes* of each field,
/// concatenated in a fixed order at fixed lengths (16 ‖ 32 ‖ 32) — never
/// base64 text. Both this box and Courier MUST build this identically.
fn transcript(server_nonce: &[u8; 16], client_pubkey: &[u8; 32], box_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(16 + 32 + 32);
    t.extend_from_slice(server_nonce);
    t.extend_from_slice(client_pubkey);
    t.extend_from_slice(box_pubkey);
    t
}

fn hmac_with_label(secret: &[u8; 16], label: &[u8], transcript: &[u8]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(label);
    mac.update(transcript);
    mac
}

/// `POST /v1/onboard/local-claim/challenge`. LAN-gated and rate-limited by
/// `main.rs`'s shared middleware, same as `handlers::onboard_claim`.
pub async fn local_claim_challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, AppError> {
    if !state.rate_limiter.allow(addr.ip()) {
        return Err(AppError::RateLimited);
    }
    if state::is_claimed(&state.state_dir) {
        tracing::warn!(
            source_ip = %addr.ip(),
            "local-claim challenge received on an already-claimed box"
        );
        return Err(AppError::AlreadyClaimed);
    }

    if !has_json_content_type(&request) {
        return Err(AppError::MalformedRequest(
            "Content-Type: application/json is required".to_string(),
        ));
    }
    let body_bytes: Bytes = axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|e| AppError::MalformedRequest(format!("could not read request body: {e}")))?;
    let req: ChallengeRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError::MalformedRequest(format!("invalid JSON body: {e}")))?;

    // Shape-validate only (m4: this value is never persisted or bound into
    // anything here — the FINISH request's own `client_pubkey` is what
    // actually gets used, below).
    let _client_pubkey_shape: [u8; 32] = decode_fixed("client_pubkey", &req.client_pubkey)?;

    let mut server_nonce = [0u8; 16];
    OsRng.fill_bytes(&mut server_nonce);
    // m1: CSPRNG-derived, never sequential/guessable.
    let challenge_id = Uuid::new_v4().to_string();
    let now = Instant::now();
    state
        .pending_challenges
        .insert(challenge_id.clone(), server_nonce, now, CHALLENGE_TTL);

    let response = ChallengeResponse {
        challenge_id,
        server_nonce: data_encoding::BASE64.encode(&server_nonce),
        box_pubkey: data_encoding::BASE64.encode(&state.keypair.public_key_bytes()),
        expires_at_ms: now_ms() + CHALLENGE_TTL.as_millis() as i64,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// `POST /v1/onboard/local-claim/finish`. LAN-gated and rate-limited by
/// `main.rs`'s shared middleware.
pub async fn local_claim_finish(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, AppError> {
    if !state.rate_limiter.allow(addr.ip()) {
        return Err(AppError::RateLimited);
    }
    // Fast, unlocked pre-check — a cheap early exit for the common case,
    // avoiding a full HMAC + Ed25519 verification on a box already known
    // to be claimed. The AUTHORITATIVE check is the re-check under
    // `state.claim_commit_lock` immediately before the commit, below
    // (§9ii R2) — this one is allowed to be stale.
    if state::is_claimed(&state.state_dir) {
        tracing::warn!(
            source_ip = %addr.ip(),
            "local-claim finish received on an already-claimed box"
        );
        return Err(AppError::AlreadyClaimed);
    }

    if !has_json_content_type(&request) {
        return Err(AppError::MalformedRequest(
            "Content-Type: application/json is required".to_string(),
        ));
    }
    let body_bytes: Bytes = axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|e| AppError::MalformedRequest(format!("could not read request body: {e}")))?;
    let req: FinishRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError::MalformedRequest(format!("invalid JSON body: {e}")))?;

    // R3: expiry is checked against a monotonic Instant, never wall-clock.
    let now = Instant::now();
    let server_nonce = state
        .pending_challenges
        .peek(&req.challenge_id, now)
        .ok_or(AppError::ChallengeNotFound)?;

    // m4: transcript is built from THIS (finish) request's client_pubkey.
    let client_pubkey_bytes: [u8; 32] = decode_fixed("client_pubkey", &req.client_pubkey)?;
    let box_pubkey_bytes = state.keypair.public_key_bytes();
    let transcript_bytes = transcript(&server_nonce, &client_pubkey_bytes, &box_pubkey_bytes);

    let client_proof_bytes = data_encoding::BASE64
        .decode(req.client_proof.as_bytes())
        .map_err(|_| AppError::MalformedRequest("client_proof is not valid base64".to_string()))?;

    // §9ii R1, binding: `Mac::verify_slice` compares via
    // `subtle::ConstantTimeEq` internally — never a plain `==` on decoded
    // bytes (see this module's own doc comment for why that distinction is
    // load-bearing here, not stylistic).
    let client_mac = hmac_with_label(&state.secret, CLIENT_PROOF_LABEL, &transcript_bytes);
    if client_mac.verify_slice(&client_proof_bytes).is_err() {
        tracing::warn!(
            source_ip = %addr.ip(),
            challenge_id = %req.challenge_id,
            "local-claim finish: client_proof did not verify"
        );
        return Err(AppError::InvalidProof);
    }

    let client_sig_bytes: [u8; 64] = decode_fixed("client_sig", &req.client_sig)?;
    let verifying_key = VerifyingKey::from_bytes(&client_pubkey_bytes).map_err(|_| {
        AppError::MalformedRequest("client_pubkey is not a valid Ed25519 public key".to_string())
    })?;
    let signature = Signature::from_bytes(&client_sig_bytes);
    let mut signed_message = Vec::with_capacity(req.challenge_id.len() + client_proof_bytes.len());
    signed_message.extend_from_slice(req.challenge_id.as_bytes());
    signed_message.extend_from_slice(&client_proof_bytes);
    if verifying_key.verify(&signed_message, &signature).is_err() {
        tracing::warn!(
            source_ip = %addr.ip(),
            challenge_id = %req.challenge_id,
            "local-claim finish: client_sig did not verify"
        );
        return Err(AppError::InvalidProof);
    }

    // §9ii R2, binding: the `claimed?` re-check and the commit are one
    // mutex-guarded critical section. No `.await` happens anywhere in this
    // block, so holding a std `Mutex` guard across it is safe — there is
    // no suspension point where another task could observe a half-held
    // lock or interleave with it.
    let guard = state.claim_commit_lock.lock().expect("claim-commit lock");
    if state::is_claimed(&state.state_dir) {
        drop(guard);
        tracing::warn!(
            source_ip = %addr.ip(),
            challenge_id = %req.challenge_id,
            "local-claim finish: lost the commit race to a concurrent finish (first-writer-wins)"
        );
        return Err(AppError::AlreadyClaimed);
    }

    let owner_pubkey_b64 = data_encoding::BASE64.encode(&client_pubkey_bytes);
    let claimed_at_ms = now_ms();

    if let Err(e) = state::mark_claimed_local(&state.state_dir, &owner_pubkey_b64, claimed_at_ms) {
        drop(guard);
        tracing::error!(error = %e, "failed to persist the claimed marker after a verified local claim");
        return Err(AppError::Internal(e.to_string()));
    }
    if let Err(e) = state::delete_claim_secret(&state.state_dir) {
        // The box is already claimed (marker written) — a leftover secret
        // file is inert from here on (is_claimed() gates every future
        // attempt) and gets cleaned up on an eventual factory-reset wipe.
        // Log, don't fail an otherwise-successful response for it.
        tracing::warn!(error = %e, "claimed, but failed to delete the now-consumed claim secret");
    }
    let binding = LocalAccountBinding::new_active_local(
        state.host_id.clone(),
        owner_pubkey_b64.clone(),
        state.device_name.clone(),
        claimed_at_ms,
    );
    if let Err(e) = state::persist_local_account_binding(&state.state_dir, &binding) {
        tracing::error!(error = %e, "claimed, but failed to persist the local account binding");
    }
    state.pending_challenges.invalidate(&req.challenge_id);
    drop(guard);

    let box_mac = hmac_with_label(&state.secret, BOX_PROOF_LABEL, &transcript_bytes);
    let box_proof = box_mac.finalize().into_bytes();

    let response = FinishResponse {
        status: "claimed",
        box_pubkey: data_encoding::BASE64.encode(&box_pubkey_bytes),
        // Stand-in, same as `LocalAccountBinding::host_id` (data-architect's
        // Task #29 real box identity is still unresolved) — not a new
        // identity concept invented here, just this box's existing
        // hostname-derived `host_id` reused under a different response
        // field name.
        box_id: state.host_id.clone(),
        box_proof: data_encoding::BASE64.encode(&box_proof),
        claimed_at_ms,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::MockPairClaimer;
    use crate::ratelimit::RateLimiter;
    use fabric_kit::{DeviceKeypair, FabricError};
    use serde_json::Value;
    use std::path::PathBuf;
    use tower::ServiceExt;

    fn temp_state_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "benix-claim-agent-local-claim-test-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Builds a real `AppState`, including a **real, on-disk**
    /// `claim-secret` file via `secret::load_or_create_secret` (not a
    /// secret value only held in memory) — several tests below assert on
    /// that file's presence/absence, so it has to genuinely exist on disk
    /// the same way it would in production, not just live in
    /// `AppState::secret`.
    fn test_state(dir: PathBuf, rate_limit: u32) -> Arc<AppState> {
        let secret = crate::secret::load_or_create_secret(&dir).expect("test secret");
        Arc::new(AppState {
            keypair: DeviceKeypair::generate(),
            device_name: "test-box".to_string(),
            host_id: "test-host".to_string(),
            secret,
            pending_challenges: PendingChallengeStore::new(),
            claim_commit_lock: Mutex::new(()),
            state_dir: dir,
            rate_limiter: RateLimiter::new(rate_limit),
            pair_claimer: Box::new(MockPairClaimer::claim_err(FabricError::NotConnected)),
        })
    }

    fn app(state: Arc<AppState>) -> axum::Router {
        crate::build_router(state)
    }

    /// See `handlers.rs::tests::oneshot_with_addr`'s own doc comment for
    /// why this is the right way to inject `ConnectInfo` without a real
    /// listener — duplicated here rather than shared, matching this
    /// crate's existing per-module test-helper convention (see
    /// `handlers.rs`'s own inline `tempfile_state_dir` module).
    async fn oneshot_with_addr(
        router: axum::Router,
        mut request: axum::http::Request<axum::body::Body>,
        addr: SocketAddr,
    ) -> axum::http::Response<axum::body::Body> {
        request.extensions_mut().insert(ConnectInfo(addr));
        axum::Router::oneshot(router, request).await.unwrap()
    }

    fn lan_addr() -> SocketAddr {
        "192.168.1.60:5000".parse().unwrap()
    }

    fn wan_addr() -> SocketAddr {
        "8.8.8.8:5000".parse().unwrap()
    }

    fn json_request(uri: &str, body: Value) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    async fn json_body(response: axum::http::Response<axum::body::Body>) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// A full, real challenge round trip against `state`'s own router,
    /// returning the parsed `(challenge_id, server_nonce, box_pubkey)` —
    /// every finish-side test builds on this rather than hand-minting a
    /// challenge, so it stays realistic (the only tests that bypass it are
    /// the ones specifically testing the "unknown/expired challenge_id"
    /// case, which use [`PendingChallengeStore::insert_raw`] instead).
    async fn real_challenge(
        state: &Arc<AppState>,
        client_pubkey: &[u8; 32],
    ) -> (String, [u8; 16], [u8; 32]) {
        let router = app(Arc::clone(state));
        let request = json_request(
            "/v1/onboard/local-claim/challenge",
            serde_json::json!({ "client_pubkey": data_encoding::BASE64.encode(client_pubkey) }),
        );
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let challenge_id = body["challenge_id"].as_str().unwrap().to_string();
        let server_nonce: [u8; 16] = data_encoding::BASE64
            .decode(body["server_nonce"].as_str().unwrap().as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let box_pubkey: [u8; 32] = data_encoding::BASE64
            .decode(body["box_pubkey"].as_str().unwrap().as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        (challenge_id, server_nonce, box_pubkey)
    }

    /// Computes a genuinely valid `(client_proof, client_sig)` pair for
    /// `courier`'s keypair against `secret`/`server_nonce`/`box_pubkey` —
    /// the exact computation `src/local_claim.rs`'s own module doc comment
    /// specifies for Courier's side of the handshake.
    fn compute_valid_finish(
        secret: &[u8; 16],
        courier: &DeviceKeypair,
        challenge_id: &str,
        server_nonce: &[u8; 16],
        box_pubkey: &[u8; 32],
    ) -> (String, String) {
        let client_pubkey = courier.public_key_bytes();
        let t = transcript(server_nonce, &client_pubkey, box_pubkey);
        let client_proof = hmac_with_label(secret, CLIENT_PROOF_LABEL, &t)
            .finalize()
            .into_bytes();
        let mut signed_message = Vec::with_capacity(challenge_id.len() + client_proof.len());
        signed_message.extend_from_slice(challenge_id.as_bytes());
        signed_message.extend_from_slice(&client_proof);
        let client_sig = courier.sign(&signed_message);
        (
            data_encoding::BASE64.encode(&client_proof),
            data_encoding::BASE64.encode(&client_sig),
        )
    }

    #[tokio::test]
    async fn happy_path_round_trip_records_owner_and_returns_verifiable_box_proof() {
        let dir = temp_state_dir();
        let state = test_state(dir.clone(), 100);
        let secret = state.secret;
        let courier = DeviceKeypair::generate();
        let client_pubkey = courier.public_key_bytes();

        let (challenge_id, server_nonce, box_pubkey) = real_challenge(&state, &client_pubkey).await;
        let (client_proof, client_sig) =
            compute_valid_finish(&secret, &courier, &challenge_id, &server_nonce, &box_pubkey);

        let router = app(Arc::clone(&state));
        let request = json_request(
            "/v1/onboard/local-claim/finish",
            serde_json::json!({
                "challenge_id": challenge_id,
                "client_pubkey": data_encoding::BASE64.encode(&client_pubkey),
                "client_proof": client_proof,
                "client_sig": client_sig,
            }),
        );
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["status"], "claimed");
        assert_eq!(
            body["box_pubkey"].as_str().unwrap(),
            data_encoding::BASE64.encode(&box_pubkey)
        );

        // Courier's own side of T7: verify box_proof before trusting the
        // claim. Recompute independently and compare.
        let expected_box_proof = {
            let t = transcript(&server_nonce, &client_pubkey, &box_pubkey);
            hmac_with_label(&secret, BOX_PROOF_LABEL, &t)
                .finalize()
                .into_bytes()
        };
        assert_eq!(
            body["box_proof"].as_str().unwrap(),
            data_encoding::BASE64.encode(&expected_box_proof)
        );

        // The box is now claimed, and the secret is gone.
        assert!(state::is_claimed(&dir));
        assert!(!dir.join(crate::secret::CLAIM_SECRET_FILENAME).exists());

        // owner_pubkey landed in LocalAccountBinding.
        let raw = std::fs::read_to_string(state::local_account_binding_path(&dir)).unwrap();
        let binding: LocalAccountBinding = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            binding.owner_pubkey.as_deref(),
            Some(data_encoding::BASE64.encode(&client_pubkey).as_str())
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn wrong_client_proof_returns_401_and_does_not_consume_the_secret() {
        let dir = temp_state_dir();
        let state = test_state(dir.clone(), 100);
        let courier = DeviceKeypair::generate();
        let client_pubkey = courier.public_key_bytes();

        let (challenge_id, _server_nonce, _box_pubkey) =
            real_challenge(&state, &client_pubkey).await;

        // A bogus client_proof (32 zero bytes) with an otherwise-valid
        // signature over it — the signature alone is not enough, the HMAC
        // itself must be wrong here.
        let bogus_proof = [0u8; 32];
        let mut signed_message = Vec::with_capacity(challenge_id.len() + bogus_proof.len());
        signed_message.extend_from_slice(challenge_id.as_bytes());
        signed_message.extend_from_slice(&bogus_proof);
        let client_sig = courier.sign(&signed_message);

        let router = app(Arc::clone(&state));
        let request = json_request(
            "/v1/onboard/local-claim/finish",
            serde_json::json!({
                "challenge_id": challenge_id,
                "client_pubkey": data_encoding::BASE64.encode(&client_pubkey),
                "client_proof": data_encoding::BASE64.encode(&bogus_proof),
                "client_sig": data_encoding::BASE64.encode(&client_sig),
            }),
        );
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        assert!(
            !state::is_claimed(&dir),
            "a wrong proof must not claim the box"
        );
        assert!(
            dir.join(crate::secret::CLAIM_SECRET_FILENAME).exists(),
            "a wrong proof (a legit typo) must not consume the secret"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn unknown_challenge_id_returns_410() {
        let dir = temp_state_dir();
        let state = test_state(dir.clone(), 100);
        let secret = state.secret;
        let courier = DeviceKeypair::generate();
        let client_pubkey = courier.public_key_bytes();

        // Never obtained from a real /challenge call.
        let fake_challenge_id = Uuid::new_v4().to_string();
        let fake_server_nonce = [0u8; 16];
        let fake_box_pubkey = [0u8; 32];
        let (client_proof, client_sig) = compute_valid_finish(
            &secret,
            &courier,
            &fake_challenge_id,
            &fake_server_nonce,
            &fake_box_pubkey,
        );

        let router = app(Arc::clone(&state));
        let request = json_request(
            "/v1/onboard/local-claim/finish",
            serde_json::json!({
                "challenge_id": fake_challenge_id,
                "client_pubkey": data_encoding::BASE64.encode(&client_pubkey),
                "client_proof": client_proof,
                "client_sig": client_sig,
            }),
        );
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::GONE);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn expired_challenge_id_returns_410() {
        let dir = temp_state_dir();
        let state = test_state(dir.clone(), 100);
        let secret = state.secret;
        let courier = DeviceKeypair::generate();
        let client_pubkey = courier.public_key_bytes();

        let challenge_id = Uuid::new_v4().to_string();
        let server_nonce = [0x44; 16];
        // R3: expiry is monotonic-clock-based — insert one already in the
        // past relative to `Instant::now()`, no real sleep needed.
        state.pending_challenges.insert_raw(
            challenge_id.clone(),
            server_nonce,
            Instant::now() - Duration::from_secs(1),
        );
        let box_pubkey = state.keypair.public_key_bytes();
        let (client_proof, client_sig) =
            compute_valid_finish(&secret, &courier, &challenge_id, &server_nonce, &box_pubkey);

        let router = app(Arc::clone(&state));
        let request = json_request(
            "/v1/onboard/local-claim/finish",
            serde_json::json!({
                "challenge_id": challenge_id,
                "client_pubkey": data_encoding::BASE64.encode(&client_pubkey),
                "client_proof": client_proof,
                "client_sig": client_sig,
            }),
        );
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::GONE);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn challenge_returns_409_when_already_claimed() {
        let dir = temp_state_dir();
        state::mark_claimed_local(&dir, "already-owner", now_ms()).unwrap();
        let state = test_state(dir.clone(), 100);
        let router = app(state);
        let request = json_request(
            "/v1/onboard/local-claim/challenge",
            serde_json::json!({ "client_pubkey": data_encoding::BASE64.encode(&[0u8; 32]) }),
        );
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn finish_returns_409_when_already_claimed() {
        let dir = temp_state_dir();
        let state = test_state(dir.clone(), 100);
        let secret = state.secret;
        let courier = DeviceKeypair::generate();
        let client_pubkey = courier.public_key_bytes();
        let (challenge_id, server_nonce, box_pubkey) = real_challenge(&state, &client_pubkey).await;
        let (client_proof, client_sig) =
            compute_valid_finish(&secret, &courier, &challenge_id, &server_nonce, &box_pubkey);

        // The box becomes claimed by some other means between challenge
        // and finish (e.g. a concurrent finish that already committed).
        state::mark_claimed_local(&dir, "someone-else", now_ms()).unwrap();

        let router = app(Arc::clone(&state));
        let request = json_request(
            "/v1/onboard/local-claim/finish",
            serde_json::json!({
                "challenge_id": challenge_id,
                "client_pubkey": data_encoding::BASE64.encode(&client_pubkey),
                "client_proof": client_proof,
                "client_sig": client_sig,
            }),
        );
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn non_lan_source_is_rejected_403_on_both_routes() {
        let dir = temp_state_dir();
        let state = test_state(dir.clone(), 100);

        let router = app(Arc::clone(&state));
        let request = json_request(
            "/v1/onboard/local-claim/challenge",
            serde_json::json!({ "client_pubkey": data_encoding::BASE64.encode(&[0u8; 32]) }),
        );
        let response = oneshot_with_addr(router, request, wan_addr()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let router = app(Arc::clone(&state));
        let request = json_request(
            "/v1/onboard/local-claim/finish",
            serde_json::json!({
                "challenge_id": "whatever",
                "client_pubkey": data_encoding::BASE64.encode(&[0u8; 32]),
                "client_proof": data_encoding::BASE64.encode(&[0u8; 32]),
                "client_sig": data_encoding::BASE64.encode(&[0u8; 64]),
            }),
        );
        let response = oneshot_with_addr(router, request, wan_addr()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn rate_limited_after_budget_exhausted() {
        let dir = temp_state_dir();
        // Capacity 1: the second request from the same source IP must 429.
        let state = test_state(dir.clone(), 1);
        let router = app(Arc::clone(&state));
        let request = json_request(
            "/v1/onboard/local-claim/challenge",
            serde_json::json!({ "client_pubkey": data_encoding::BASE64.encode(&[0u8; 32]) }),
        );
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::OK);

        let router = app(Arc::clone(&state));
        let request = json_request(
            "/v1/onboard/local-claim/challenge",
            serde_json::json!({ "client_pubkey": data_encoding::BASE64.encode(&[0u8; 32]) }),
        );
        let response = oneshot_with_addr(router, request, lan_addr()).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// §9ii R2's own required proof: two genuinely concurrent, both
    /// cryptographically *valid* `finish` calls (e.g. T6 — a photographed
    /// secret two Couriers both know) for the SAME challenge, racing to
    /// become owner with two DIFFERENT pubkeys. Real OS-thread parallelism
    /// via a multi-worker tokio runtime and `tokio::spawn` (not a timing
    /// hack) — the `claim_commit_lock` must resolve this first-writer-wins,
    /// never a torn/overwritten `owner_pubkey`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_valid_finishes_resolve_first_writer_wins() {
        let dir = temp_state_dir();
        let state = test_state(dir.clone(), 1000);
        let secret = state.secret;

        let courier_a = DeviceKeypair::generate();
        let courier_b = DeviceKeypair::generate();
        // Both know the secret and the box's real challenge (T6's exact
        // shape) — the box only ever hands out one challenge_id here,
        // reused by both racers, matching "sniffed/shared, not secret."
        let (challenge_id, server_nonce, box_pubkey) =
            real_challenge(&state, &courier_a.public_key_bytes()).await;

        let (proof_a, sig_a) = compute_valid_finish(
            &secret,
            &courier_a,
            &challenge_id,
            &server_nonce,
            &box_pubkey,
        );
        let (proof_b, sig_b) = compute_valid_finish(
            &secret,
            &courier_b,
            &challenge_id,
            &server_nonce,
            &box_pubkey,
        );

        let make_request = |pubkey: [u8; 32], proof: String, sig: String| {
            json_request(
                "/v1/onboard/local-claim/finish",
                serde_json::json!({
                    "challenge_id": challenge_id,
                    "client_pubkey": data_encoding::BASE64.encode(&pubkey),
                    "client_proof": proof,
                    "client_sig": sig,
                }),
            )
        };

        let router_a = app(Arc::clone(&state));
        let request_a = make_request(courier_a.public_key_bytes(), proof_a, sig_a);
        let handle_a =
            tokio::spawn(async move { oneshot_with_addr(router_a, request_a, lan_addr()).await });

        let router_b = app(Arc::clone(&state));
        let request_b = make_request(courier_b.public_key_bytes(), proof_b, sig_b);
        let handle_b =
            tokio::spawn(async move { oneshot_with_addr(router_b, request_b, lan_addr()).await });

        let (response_a, response_b) = tokio::join!(handle_a, handle_b);
        let response_a = response_a.unwrap();
        let response_b = response_b.unwrap();

        let statuses = [response_a.status(), response_b.status()];
        let ok_count = statuses.iter().filter(|s| **s == StatusCode::OK).count();
        let conflict_count = statuses
            .iter()
            .filter(|s| **s == StatusCode::CONFLICT)
            .count();
        assert_eq!(
            ok_count, 1,
            "exactly one of the two concurrent valid finishes must win"
        );
        assert_eq!(
            conflict_count, 1,
            "the loser must get 409, never a silent second success"
        );

        // Whichever one actually won, the persisted owner_pubkey must
        // match THAT winner's pubkey — never a mix, never the loser's.
        let winner_pubkey = if response_a.status() == StatusCode::OK {
            courier_a.public_key_bytes()
        } else {
            courier_b.public_key_bytes()
        };
        let raw = std::fs::read_to_string(state::local_account_binding_path(&dir)).unwrap();
        let binding: LocalAccountBinding = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            binding.owner_pubkey.as_deref(),
            Some(data_encoding::BASE64.encode(&winner_pubkey).as_str())
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
