# benix-claim-agent

BenixOS's box-side claim agent: the identity/state-machine core (an
Ed25519 `DeviceKeypair`, persisted to disk; a persisted `claimed`/
`unclaimed` flag) plus the LAN onboarding endpoint
(`POST /v1/onboard/claim`) Courier delivers a hub-issued `qr_payload` to.
This is the box-side half of QR-37 Story 3 (Courier delivering a
hub-issued `qr_payload` to a headless BenixOS box over the LAN, instead of
rendering it as a QR code for camera scan — a headless box has no screen)
and the first real code toward Task #23, per the finalized contract in
`context/projects/benixos.md` §9j (`dlockamy/vault` workspace),
dispatched by `benixos-pm` 2026-09-02.

## Why this exists, and why here

Full ruling and reasoning: `context/projects/benixos.md` §9j (contract),
cross-checked against §9i (security-engineer's content-key-parity ruling,
whose R1 rider scopes this agent — see below). Short version: a box first
boots unclaimed and fail-closed. `benix-mdns-advertiser` (real, shipped,
CI-green) already broadcasts `_benixos._tcp` so Courier can discover the
box; Courier then runs its normal hub-mediated pairing flow
(`TPair(INITIATE)`), gets back a `qr_payload` string, and POSTs it
byte-identical to this endpoint instead of rendering a QR code. This agent
then opens its own outbound `TPair(CLAIM)` connection to the hub — the one
pre-Hello wire path in the whole protocol — via `fabric-kit`. The hub
eventually responds; Courier (separately, already subscribed for this)
sees the claim happen on its own hub connection, shows the human a
fingerprint to compare, and sends `TPair(APPROVE)`. Only after that does
this agent's claim actually complete.

**Placement**: its own repo, following `benix-mdns-advertiser`'s Tier-2
precedent exactly (`devicenix-legacy/docs/build-model.md`'s two-tier
model), not vendored into `slash-builder/core`'s `meta-benixos`:

- This crate's dependency graph (`axum`, `tokio`, `fabric-kit`) is pure
  Rust with no C-lib/D-Bus dependency — the same shape that put the
  advertiser and `qr-gateway`/`qr-cli` in their own repos rather than an
  in-tree Yocto recipe.
- Unlike the advertiser (already proven musl-clean) and `qr-web` (also
  already proven), `fabric-kit`'s musl-buildability had never been
  checked before this pass — it is heavier than the advertiser's
  dependency set (`ed25519-dalek`, `hpke` (which pulls in `x25519-dalek`
  transitively — **not** a direct `fabric-kit` dependency, correcting the
  dispatch brief's phrasing), `tokio-tungstenite` with
  `rustls-tls-webpki-roots`). **Spiked first, before writing any of this
  crate's own code** — see "What was actually verified" below. Result:
  clean pass.
- Conclusion: build a musl release artifact in this repo's own CI;
  `meta-benixos` gets a thin recipe that fetches the prebuilt binary + a
  dinit unit later — **that recipe does not exist yet**, deliberately out
  of scope for this pass (see "Explicitly out of scope" below).

## What it does

One dinit-supervised binary, no subcommands, no config file. Deliberately
**one process, not two talking over IPC** — there is no IPC bus available
yet (Message Kit: `status: design`, zero code), so this doesn't invent one
to satisfy a separation-of-concerns preference the project doesn't have
the plumbing for yet.

1. Loads (or creates, on first run) this box's `DeviceKeypair`
   (`fabric_kit::pairing::DeviceKeypair`), persisted to
   `<state dir>/device-key`.
2. Binds an HTTP/1.1 listener (axum, no TLS — see "Transport & bind"
   below) to the box's own non-loopback LAN interface address(es), port
   `8420` by default.
3. Serves `POST /v1/onboard/claim`, the one real route (plus an optional
   `GET /healthz`), following the handler sequence in `src/handlers.rs`'s
   own doc comment exactly: rate-limit check → fail-closed guard → parse
   `qr_payload` → call `fabric_kit::FabricClient::pair_claim` → respond
   `202` immediately → background `wait_for_result` → only
   `PairOutcome::Approved` flips local state to `claimed`.
4. Depends on `fabric-kit` as a library for the actual `TPair(CLAIM)` wire
   primitive — **this crate does not hand-roll pairing or wire-encoding
   logic.** See `src/pairing.rs`'s module doc for the seam this crate mocks
   in tests instead.

### The `qr_payload` grammar, verified against real hub source

`quickring/hub/src/pairing.rs::create_session` produces:

```
quickring://pair?session=<pair_session_id>&endpoint=<percent-encoded-ws-url>
```

`src/qr_payload.rs` parses exactly this and nothing more lenient: wrong
scheme, wrong authority, missing/empty `session` or `endpoint`, or
unparseable percent-encoding is a hard `400 invalid_qr_payload`, never a
best-effort partial parse. `pair_session_id` is treated as an opaque
non-empty string, not validated as a UUID beyond that — the hub is the
source of truth for its shape.

### The route

`POST /v1/onboard/claim`, body `{"qr_payload": "<string>"}`
(`Content-Type: application/json` required, no other fields accepted).

| Response | When |
|---|---|
| `429 rate_limited` | token-bucket budget exhausted for this source IP |
| `403 non_lan_source` | source IP is not RFC1918/ULA/link-local |
| `409 already_claimed` | box already claimed (anomaly, logged `warn`, no side effects) |
| `400 invalid_qr_payload` / `malformed_request` | grammar deviation or bad JSON body |
| `502 hub_unreachable` | `pair_claim` itself failed; no local state change |
| `202 claim_initiated` | claim started; `{"status", "pair_session_id", "expires_at_ms"}` |

Every 4xx/5xx uses the same shape: `{"error": "<snake_case_code>",
"message": "<human-readable>"}`.

`GET /healthz` — process-alive only (`200 {"status": "ok"}`), no
claim-state disclosure, no LAN-source restriction (nothing sensitive to
protect there).

### Rate limiting

A hand-rolled per-source-IP token bucket (`src/ratelimit.rs`) — default
10 requests/minute, overridable via `BENIX_CLAIM_RATE_LIMIT_PER_MIN`.
Hand-rolled rather than pulling in `governor`, per the finalized
contract's own "don't over-engineer distributed rate limiting for a
single-process LAN service" note; keeps the dependency surface (and the
musl-cleanliness question) smaller.

### `LocalAccountBinding` — a stand-in, not a locked schema

`src/local_account_binding.rs` implements the minimum viable version of
the shape data-architect settled conceptually in `kits.yaml` (keyed
`(host_id, principal_id)`; `local_uid`, `local_username`, `account_class`,
`status`, `created_at`/`revoked_at`). Checked before writing it: neither
`slash-builder/identity-kit` nor `slash-builder/substrate-kit` has a
concrete struct or migration for this — `grep -rn LocalAccountBinding`
against both, zero hits in either. **This is a stand-in, flagged the same
way `benix-mdns-advertiser`'s own `src/id.rs` flags its placeholder `id`
field** — not this crate unilaterally deciding data-architect's call.
This agent creates no real POSIX user account (out of scope), so
`local_uid` is always `None` here.

## Transport & bind

Plain HTTP/1.1, no TLS — no cert story exists on a fresh unclaimed box,
and this hop carries no secret material (the session id is single-use and
short-lived; the real security boundary is Hearth's own `TPair`/
fingerprint-approval flow downstream of this, not this LAN hop). Binds
explicitly to the box's own non-loopback interface address(es) via
`if-addrs` — **never `0.0.0.0`**. As defense-in-depth, the claim route
also rejects (403) any inbound request whose source IP is not
RFC1918/ULA/link-local, even though bind-scoping should already prevent
WAN reachability by construction.

## Configuration (env vars, all optional)

| Var | Default | Meaning |
|---|---|---|
| `BENIX_MDNS_PORT` | `8420` | Listen port. **Shared name with `benix-mdns-advertiser`'s own SRV-record port var — deliberately.** Its SRV record and this endpoint's actual listen port must always agree; reusing the identical name is the cheapest way to keep them from silently drifting apart. **Known integration risk** (flagged in the finalized contract): there is no single shared environment source yet for the two binaries — a `meta-benixos` dinit-unit pass needs to land one. Not this repo's job to solve; just don't make it worse. |
| `BENIX_CLAIM_STATE_DIR` | `/var/lib/benixos` | State directory. Distinct var name from the advertiser's `BENIX_MDNS_STATE_DIR`; same default path is fine — different filenames underneath (`device-key`, `claimed`, `pair-credentials`, `local-account-binding`). |
| `BENIX_CLAIM_RATE_LIMIT_PER_MIN` | `10` | Per-source-IP token-bucket budget on the claim route. |
| `BENIX_CLAIM_DEVICE_NAME` | this box's hostname | The `proposed_device_name` sent to the hub at claim time. |
| `RUST_LOG` | `info` | Standard `tracing-subscriber` env filter. |

## Explicitly out of scope for this pass

- **No content-key / `/keys/request` logic of any kind.**
  security-engineer's binding R1 ruling (`context/projects/benixos.md`
  §9i, landed the same day as the onboarding contract): this agent MUST
  NOT hold the household content key and MUST NOT issue `/keys/request`.
  Its scope is pairing (identity + sealing keys) and `LocalAccountBinding`
  only. Nothing content-key-adjacent lives in this crate.
- **No fingerprint rendering, no QR rendering, no UI of any kind.**
  Headless backend service; the human fingerprint-compare step happens
  entirely on Courier's side against the hub.
- **No `meta-benixos` dinit unit or BitBake recipe.** Separate,
  sequenced-after work once this binary and its musl release artifact
  exist, same two-step sequence `qr-gateway` and the mDNS advertiser both
  went through.
- **No fix to `quickring/hub/src/ratelimit.rs`/`conn.rs:236`** (a known
  hub-side gap where pre-Hello `TPair(CLAIM)` isn't rate-limited) — routed
  to different work. This agent's own outbound `TPair(CLAIM)` calls land
  on that under-protected hub-side path today; not addressed here.
- **No re-claim / factory-reset flow.** Every box this endpoint sees is
  assumed to be a clean install; an already-claimed box hitting this route
  is an anomaly (409, logged), not a case to build a flow for.
- **No real LAN broadcast-and-connect verification.** No live hub, no
  real Courier POST, no on-target dinit run — see "What was actually
  verified" below for the honest line between what ran and what's
  claimed.

## Deviations from the finalized contract, with reasoning

- **First-run identity (contract step 4) happens at process startup, not
  inline inside the request handler.** The contract's handler sequence
  lists keypair generation as step 4, between parsing `qr_payload` and
  calling `pair_claim`. This binary instead loads-or-creates the
  `DeviceKeypair` once in `main()`, mirroring `benix-mdns-advertiser`'s
  own `id::load_or_create` idiom, and hands the already-resolved keypair
  into `AppState`. The two are observably identical (idempotent either
  way — a fresh box only ever generates the key once, on whichever run
  first touches the state dir) and startup-time loading avoids a
  request-path disk write on every retry before the first successful
  claim attempt. See `src/handlers.rs`'s doc comment on Step 4 for the
  same note in the code.
- **`PairClaimer`/`PendingPairingHandle` (`src/pairing.rs`) mock fabric-kit
  at the call-site boundary, not at the wire-frame level.** The contract
  points at `fabric-kit`'s own `MockTx`/`MockRx` test-module pattern as a
  reusable mock; those types are private to `fabric-kit`'s own test module
  and not importable from here. Reused pattern, not reused code: this
  crate defines its own trait boundary around exactly the two calls the
  handler makes (`pair_claim`, then `wait_for_result` on what it returns),
  with a real implementation that's a direct pass-through to
  `fabric_kit::FabricClient` and a mock that returns canned
  `PairOutcome`s. This is real dependency inversion (the production binary
  wires the real implementation the same way tests wire the mock), and it
  tests the state-transition logic without a live or mock-transport-level
  hub connection, same requirement the contract states — just at a
  narrower seam than wire-frame mocking would be.

## What was actually verified, and how

This environment is a real Linux host with cargo/rustc, Docker, and a
working `lockamy` Nexus registry token — a stronger position than
`benix-mdns-advertiser`'s own README describes (that repo's checks ran
from a macOS/Darwin host with no Linux musl linker available locally).
What was actually run here, not just claimed:

- **The musl spike, run first, before writing this crate's own code.** A
  throwaway crate depending on `fabric-kit` via a path dependency was
  built with `cargo build --release --target x86_64-unknown-linux-musl`
  inside a `rust:1.90-trixie` Docker container (`musl-tools` installed,
  target added, `lockamy` registry credentials supplied for
  `fabric-kit`'s own `message-kit` dependency). **Result: clean pass.**
  `file(1)` classified the resulting binary `ELF 64-bit LSB pie
  executable, x86-64, ... static-pie linked` — real static-PIE, not just a
  successful compile. `ed25519-dalek`, `hpke` (and its transitive
  `x25519-dalek`), `chacha20poly1305`, `tokio-tungstenite` with
  `rustls-tls-webpki-roots` (pure-Rust TLS, no system OpenSSL), and
  `message-kit` itself all resolved and linked clean to musl in this
  spike. This is the load-bearing finding the finalized contract asked to
  be spiked and reported honestly either way — it came back positive.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` (49 unit/integration-style tests — see the coverage list
  below), and `cargo build --release` all ran clean against the **host**
  target (`x86_64-unknown-linux-gnu`), directly on this machine (not just
  in a container).
- **The same four checks, plus the real musl target build, re-run inside a
  `rust:1.90-trixie` container against this crate's actual committed
  source** (not the throwaway spike crate) — `cargo build --release
  --target x86_64-unknown-linux-musl` followed by the same `file(1)`
  static-PIE classification check the GitHub Actions workflow below
  encodes. This is the same container image and command sequence the
  `musl` CI job runs, executed once here to confirm the workflow as
  written actually passes before it was ever pushed.
- The GitHub Actions CI in this repo (`.github/workflows/ci.yml`) mirrors
  all of the above as two jobs (`build`, `musl`) — **not yet confirmed
  green on GitHub's own runners** as of this writing (the repo was just
  created; the first push's Actions run is the actual confirmation, same
  as any new repo's first CI run — check the Actions tab, don't take this
  README's word for it if they disagree, same caveat the advertiser's own
  README states for itself).

**Not verified, not claimed as done:**

- No real LAN broadcast/connect test — no live hub, no real Courier POST,
  no on-target dinit run. Everything above is host- and container-level
  proof that the binary builds, is internally correct against mocked
  boundaries, and links statically for musl; none of it is a live-network
  claim-and-approve round trip against a real `quickring/hub`.
- No `meta-benixos` recipe or dinit-unit integration — this binary is not
  on any image yet, deliberately (see "Explicitly out of scope").
- No musl release artifact has been published anywhere (GitHub Releases
  or otherwise) — only built and classified, not tagged/packaged.
- `LocalAccountBinding`'s schema is a stand-in (see above), not a locked
  design.

## Test coverage

`cargo test` — 49 tests, all passing as of this writing:

- `qr_payload`: the exact hub grammar (real-shaped payload, `wss://`
  production-style, param-order independence, extra-field tolerance) and
  every named malformed case (not a URL, empty string, wrong scheme, wrong
  authority, missing/empty `session`, missing/empty `endpoint`, malformed
  percent-encoding, reserved-character round-trip) → each maps to the
  correct `Err` variant.
- `net`: RFC1918/link-local/ULA acceptance and boundary rejection
  (including the deliberate loopback rejection — see `net.rs`'s doc
  comment on why loopback is not on the allow-list).
- `ratelimit`: capacity enforcement, per-IP bucket independence, refill
  over simulated time, and the no-overflow-after-a-long-idle-period case.
- `state`: keypair generate-then-reload stability, `0600` file
  permissions, the `claimed` marker's presence/absence, `PairCredentials`
  persistence shape, and `redacted_debug` never leaking the bearer token.
- `pairing`: the `MockPairClaimer`/`MockPendingPairingHandle` seam itself,
  each `PairOutcome` variant round-tripping through it.
- `handlers` (router-level, via `tower::ServiceExt::oneshot` — see
  `src/handlers.rs`'s `oneshot_with_addr` helper for how `ConnectInfo` is
  injected without a real listener):
  - fail-closed guard: an already-claimed box returns `409` and never
    reaches `pair_claim` (the mock has no canned answer configured — if
    the guard were broken, the mock would panic rather than silently
    succeed);
  - non-LAN source → `403`;
  - malformed `qr_payload` → `400`;
  - missing `Content-Type` → `400`;
  - unknown JSON field → `400` (`deny_unknown_fields`);
  - successful claim → `202` immediately, without waiting on
    `wait_for_result`;
  - hub-unreachable → `502`, no state change;
  - `/healthz` → `200`, independent of LAN-source restriction.
  - the background task (`run_wait_for_result`, exercised directly, not
    only through the route) marks `claimed` and persists
    `pair-credentials`/`local-account-binding` **only** on
    `PairOutcome::Approved`, and leaves the box unclaimed on `Rejected`,
    `Timeout`, and a `wait_for_result` `Err`.

## Build & CI

Stack: Rust (2021 edition), `axum` 0.7, `tokio`, `fabric-kit` (registry
dependency on the `lockamy` Nexus registry — see `.cargo/config.toml`).

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
cargo build --release --target x86_64-unknown-linux-musl   # requires musl-tools + the musl target
```

GitHub Actions (`.github/workflows/ci.yml`) mirrors the studio's primary
Jenkins pipeline (`Jenkinsfile`) — see both files' own comments for the
`CARGO_REGISTRIES_LOCKAMY_TOKEN` / Jenkins-credential wiring the private
registry dependency requires that `benix-mdns-advertiser`'s CI didn't need.

## Open, routed rather than decided here

- `benixos-pm` — sequencing this into the headless backlog, the
  `meta-benixos` dinit-unit + BitBake recipe work, and real LAN
  broadcast-and-connect verification (deferred items 2 and 3 of the
  finalized contract's ticket).
- `data-architect` — `LocalAccountBinding`'s real, locked schema (this
  crate's version is an explicit stand-in — see above).
- `devops-engineer` — the dinit unit itself, its ordering against network
  bring-up, the `BENIX_MDNS_PORT` shared-env-var drift risk, and wiring a
  real `CARGO_REGISTRIES_LOCKAMY_TOKEN` secret into this repo's GitHub
  Actions.
- `messaging-architect` + `benixos-pm` — whether `resource_advert`
  publishing eventually lands on this agent (expanded) or a separate
  post-claim daemon; if it's this agent, R1 (keyless) must be revisited
  before that expansion, per §9i.
