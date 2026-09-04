//! BenixOS box-side claim agent.
//!
//! One dinit-supervised binary, no subcommands: the box's identity/
//! state-machine core (an `Ed25519` `DeviceKeypair`, persisted to disk,
//! generated on first run; a persisted `claimed`/`unclaimed` flag) AND the
//! HTTP listener Courier POSTs a hub-issued `qr_payload` to
//! (`POST /v1/onboard/claim`). Deliberately one process, not two talking
//! over IPC — there is no IPC bus available yet (Message Kit: `status:
//! design`, zero code), so this doesn't invent one to satisfy a separation
//! of concerns this project doesn't have the plumbing for yet.
//!
//! This is the box-side onboarding endpoint QR-37 Story 3 (Courier
//! delivering a hub-issued `qr_payload` to a headless BenixOS box over the
//! LAN) is blocked on — Task #23's first real code, per the finalized
//! contract at `context/projects/benixos.md` §9j.
//!
//! Depends on `fabric-kit` as a library for the actual `TPair(CLAIM)` wire
//! primitive (`FabricClient::pair_claim`/`PendingPairing::wait_for_result`)
//! — this crate does not hand-roll pairing or wire-encoding logic. See
//! `src/pairing.rs`.
//!
//! **Explicitly out of scope, per security-engineer's binding R1 ruling**
//! (`context/projects/benixos.md` §9i): this agent MUST NOT hold the
//! household content key, and MUST NOT issue `/keys/request`. Its scope is
//! pairing (identity + sealing keys) and `LocalAccountBinding` only —
//! nothing content-key-adjacent lives in this crate.
//!
//! Env vars, all optional (see `src/config.rs`):
//! - `BENIX_MDNS_PORT` — listen port (default `8420`). Shared name with
//!   `benix-mdns-advertiser`'s own SRV-record port var, deliberately — see
//!   `config.rs`'s doc comment.
//! - `BENIX_CLAIM_STATE_DIR` — state directory (default `/var/lib/benixos`).
//! - `BENIX_CLAIM_RATE_LIMIT_PER_MIN` — per-source-IP token bucket budget
//!   (default `10`).
//! - `BENIX_CLAIM_DEVICE_NAME` — the name proposed to the hub at claim time
//!   (default: this box's hostname).
//! - `RUST_LOG` — standard `tracing-subscriber` env filter (default `info`).

mod config;
mod error;
mod handlers;
mod local_account_binding;
mod local_claim;
mod net;
mod pairing;
mod qr_payload;
mod ratelimit;
mod render;
mod secret;
mod state;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use fabric_kit::DeviceKeypair;
use tracing_subscriber::EnvFilter;

use config::Config;
use error::AppError;
use local_claim::PendingChallengeStore;
use pairing::{FabricKitPairClaimer, PairClaimer};
use ratelimit::RateLimiter;

/// Shared application state, one instance per process, handed to every
/// handler behind an `Arc`.
pub struct AppState {
    /// This box's Ed25519 identity keypair. Loaded-or-created once at
    /// process startup (see `main()` below) rather than lazily inside the
    /// handler — see `handlers.rs`'s doc comment on Step 4 for why that's
    /// the equivalent, cleaner choice here.
    pub keypair: DeviceKeypair,
    pub device_name: String,
    /// This box's own host identifier, used only for
    /// `LocalAccountBinding::host_id` — see `local_account_binding.rs` for
    /// why this is a stand-in (this box's hostname) rather than a real,
    /// stable box identity.
    pub host_id: String,
    pub state_dir: std::path::PathBuf,
    pub rate_limiter: RateLimiter,
    pub pair_claimer: Box<dyn PairClaimer>,
    /// The local-only claim protocol's (§9hh) 128-bit secret, loaded once
    /// at startup exactly like `keypair` above — never re-read from disk
    /// per-request. Remains valid in memory even after
    /// `state::delete_claim_secret` removes the on-disk copy on a
    /// successful claim; harmless, since `state::is_claimed` gates every
    /// future request before this value could ever be used again.
    pub secret: [u8; 16],
    /// The local-claim protocol's bounded, in-memory pending-challenge map
    /// (`src/local_claim.rs`).
    pub pending_challenges: PendingChallengeStore,
    /// §9ii R2, binding: serializes the "is this box already claimed?"
    /// re-check against the actual claim-commit write in
    /// `local_claim::local_claim_finish`, so two concurrent valid finishes
    /// resolve first-writer-wins rather than racing on a plain
    /// check-then-write.
    pub claim_commit_lock: Mutex<()>,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Defense-in-depth gate on `POST /v1/onboard/claim`: reject (403) any
/// source IP that is not RFC1918/ULA/link-local. Bind-scoping (never
/// `0.0.0.0`, see `run()` below) should already make a non-LAN source
/// unreachable by construction — this is the second, independent layer,
/// per the finalized contract's explicit hardening requirement. Applied
/// only to the claim route, not `/healthz` (which discloses nothing
/// sensitive and exists purely as a liveness probe).
async fn require_lan_source(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    if net::is_lan_source(addr.ip()) {
        Ok(next.run(request).await)
    } else {
        Err(AppError::NonLanSource)
    }
}

/// Build the router. Split out from `run()` so tests can build one against
/// a fully-controlled `AppState` (real or mock `PairClaimer`) without
/// starting a real listener — see `handlers.rs`'s test module.
pub fn build_router(state: Arc<AppState>) -> Router {
    let claim_routes = Router::new()
        .route("/v1/onboard/claim", post(handlers::onboard_claim))
        .route(
            "/v1/onboard/local-claim/challenge",
            post(local_claim::local_claim_challenge),
        )
        .route(
            "/v1/onboard/local-claim/finish",
            post(local_claim::local_claim_finish),
        )
        .route_layer(middleware::from_fn(require_lan_source));

    Router::new()
        .merge(claim_routes)
        .route("/healthz", get(handlers::healthz))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    init_tracing();

    let config = Config::from_env();

    let keypair = match state::load_or_create_keypair(&config.state_dir) {
        Ok(kp) => kp,
        Err(e) => {
            tracing::error!(
                error = %e,
                state_dir = %config.state_dir.display(),
                "failed to load/create the device keypair, refusing to start"
            );
            std::process::exit(1);
        }
    };

    let host_id = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "benixos".to_string());

    let already_claimed = state::is_claimed(&config.state_dir);

    // The local-only claim protocol's secret (§9hh) is loaded-or-created
    // unconditionally at startup — same generate-once-then-reload-forever
    // posture as `keypair` above — even on an already-claimed box, so a
    // leftover (already-inert, since `is_claimed()` gates everything ahead
    // of it) secret file doesn't turn into a startup failure. Only an
    // UNCLAIMED box actually displays it (see below).
    let secret = match secret::load_or_create_secret(&config.state_dir) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                error = %e,
                state_dir = %config.state_dir.display(),
                "failed to load/create the local-claim secret, refusing to start"
            );
            std::process::exit(1);
        }
    };

    tracing::info!(
        port = config.port,
        state_dir = %config.state_dir.display(),
        device_name = %config.device_name,
        rate_limit_per_min = config.rate_limit_per_min,
        already_claimed,
        "starting benix-claim-agent"
    );

    // §9gg/§9hh: a factory-fresh, unclaimed box shows its secret on
    // startup — the `render` seam (see `src/render.rs`), not the final
    // display renderer. A claimed box has nothing left to display.
    if !already_claimed {
        render::display_claim_code(&secret::encode_display(&secret));
    }

    let app_state = Arc::new(AppState {
        keypair,
        device_name: config.device_name.clone(),
        host_id,
        state_dir: config.state_dir.clone(),
        rate_limiter: RateLimiter::new(config.rate_limit_per_min),
        pair_claimer: Box::new(FabricKitPairClaimer),
        secret,
        pending_challenges: PendingChallengeStore::new(),
        claim_commit_lock: Mutex::new(()),
    });

    let router = build_router(app_state);

    let bind_addrs = match net::non_loopback_addrs() {
        Ok(addrs) if !addrs.is_empty() => addrs,
        Ok(_) => {
            tracing::error!(
                "no non-loopback LAN interface addresses found — refusing to bind 0.0.0.0, \
                 exiting for dinit to restart us once the network is up"
            );
            std::process::exit(1);
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to enumerate network interfaces");
            std::process::exit(1);
        }
    };

    let mut listeners = Vec::with_capacity(bind_addrs.len());
    for ip in &bind_addrs {
        let socket_addr = SocketAddr::new(*ip, config.port);
        match tokio::net::TcpListener::bind(socket_addr).await {
            Ok(listener) => {
                tracing::info!(addr = %socket_addr, "listening");
                listeners.push(listener);
            }
            Err(e) => {
                tracing::error!(error = %e, addr = %socket_addr, "failed to bind");
            }
        }
    }

    if listeners.is_empty() {
        tracing::error!(
            "failed to bind any LAN interface address, exiting for dinit to restart us"
        );
        std::process::exit(1);
    }

    // One task per bound interface, all serving the same router/state —
    // matches "bind explicitly to the box's own LAN interface address(es)"
    // (plural) in the finalized contract, without inventing a
    // multi-listener abstraction axum doesn't already provide.
    let mut tasks = Vec::with_capacity(listeners.len());
    for listener in listeners {
        let router = router.clone();
        tasks.push(tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        }));
    }

    // If any listener task ends (it shouldn't, under normal operation —
    // axum::serve runs until an I/O error), exit non-zero so dinit's
    // `restart = true` / `smooth-recovery = true` brings the whole process
    // back, same posture as benix-mdns-advertiser's main loop.
    let (result, _index, _remaining) = futures_util::future::select_all(tasks).await;
    match result {
        Ok(Ok(())) => tracing::error!("a listener task ended cleanly (unexpected), exiting"),
        Ok(Err(e)) => tracing::error!(error = %e, "a listener task failed"),
        Err(e) => tracing::error!(error = %e, "a listener task panicked"),
    }
    std::process::exit(1);
}
