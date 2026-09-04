# benix-claim-agent

BenixOS's box-side claim agent. Two claim paths now live here:

- **The local-only claim protocol** (`POST /v1/onboard/local-claim/{challenge,finish}`,
  `src/local_claim.rs`) — the box's **default and only path for initial
  ownership**, per DJ's ruling (`context/projects/benixos.md` §9gg) that
  onboarding must work fully local, zero hub/cloud dependency. A 128-bit
  secret the box generates and displays itself (`src/secret.rs`), proven
  via a mutual-HMAC handshake and **never transmitted**; the owner
  credential recorded is Courier's Ed25519 public key, not a bearer token.
  Designed by messaging-architect (§9hh) and ratified with binding required
  changes by security-engineer's adversarial review (§9ii) — see "Local-only
  claim protocol" below.
- **The hub-mediated path** (`POST /v1/onboard/claim`, `src/handlers.rs`) —
  the identity/state-machine core this repo originally shipped (an Ed25519
  `DeviceKeypair`; Courier delivers a hub-issued `qr_payload`). §9gg/§9hh
  **demote** this to the deferred Hearth-join step (join an existing hub
  account *after* a local claim already exists) — it is retained, not
  deleted, but **can no longer establish initial ownership on an unclaimed
  box** (§9ii R4, enforced — see below). Originally the first real code
  toward Task #23, per the finalized contract in
  `context/projects/benixos.md` §9j, dispatched by `benixos-pm`
  2026-09-02.

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

## Local-only claim protocol (default path for initial ownership)

Full design: `context/projects/benixos.md` §9hh (messaging-architect's
protocol/wire-contract) and §9ii (security-engineer's binding adversarial
review — **VERDICT: RATIFIED WITH NAMED REQUIRED CHANGES**, R1-R5, all
folded into this implementation, not left as follow-up).

**The one load-bearing property**: the secret is *proven*, never
*transmitted*, and the owner credential is a *public key*, not a bearer
token — so there is no value on the wire, in either direction, whose
observation grants takeover. This is what makes the plain-HTTP (no TLS)
call defensible on its own merits (§9ii affirmed this, with one binding
invariant — see "Transport & bind" below).

### The secret (`src/secret.rs`)

128 bits of CSPRNG entropy (`rand::rngs::OsRng`, the exact source
`fabric_kit::DeviceKeypair::generate` already uses), generated once on
first boot of an unclaimed box and persisted to `<state_dir>/claim-secret`
(mode `0600`, hardened write-then-rename — see §9ii R5 below). **Not
regenerated on restart** while unclaimed, and **no wall-clock expiry** —
both deliberate (§9hh Item 1, reaffirmed by §9ii: an offline first-boot box
has no trustworthy clock, so a wall-clock expiry could not even be
implemented honestly on the target hardware). Displayed as unpadded
Crockford Base32, grouped `XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX` (26 chars) —
case-insensitive, `I`/`L`/`O` collision-free by construction, and tolerant
of `O`→`0`/`I`,`L`→`1` substitution on decode (Crockford's own documented
leniency). On startup, an **unclaimed** box prints the full claim screen
(see below) to stdout (`src/render.rs`'s `display_claim_code` — a `render`
seam, not the final display renderer; dinit already routes stdout to
console/serial today, per §9h and §9pp's real 160x50 framebuffer capture —
a production unit's physical LCD is later, separate work that only needs to
implement this same seam differently).

### The claim screen: QR + text code (`src/render.rs`, `src/qr.rs`, §9rr)

An unclaimed box's console shows a header, a scannable QR code, the same
secret as grouped Crockford Base32 text, and a one-line instruction —
[`render::build_claim_screen`] is a **pure function of the display code
string** (no I/O, no protocol state), so the composition is unit-tested
without a console; `render::display_claim_code` is the thin `println!`
wrapper that actually reaches stdout.

The QR itself is rendered as Unicode half-block text (`▀`/`▄`/`█`, 2 QR
modules packed per character row — the standard terminal-QR technique) by
`src/qr.rs`, using the `qrcode` crate (`default-features = false`) — a real
`cargo tree` spike confirmed this adds **zero** transitive dependencies
with `image`/`svg`/`pic` disabled, so it does not enlarge this crate's
musl-risk surface at all. `fast_qr` was the named fallback if `qrcode` had
turned out to be heavy; it isn't, so there was no reason to reach for it.
For this crate's actual payload length the QR renders as a 37×19-character
block — comfortably inside the 160×50 console §9pp's real capture
confirmed.

**QR payload format — invented here, not specified by §9hh, NEEDS
MESSAGING-ARCHITECT RATIFICATION before any Courier-side consumer treats it
as settled:**

```
benix-claim://v1?s=<26-character-Crockford-Base32-secret, ungrouped>
```

§9hh's own design text scopes "QR bitmap rendering" as a *display* concern
and specifies no QR wire format for the local-only claim flow — this format
is this implementation's own choice, versioned (`v1`) so it's cheap to
change later, carrying only the secret (nothing about `challenge_id`,
`box_pubkey`, or the transcript rides the QR; that's all negotiated over
the existing two-message handshake exactly as it would be for a
manually-typed code). The *old*, superseded hub-mediated flow's
`quickring://pair?session=...&endpoint=...` grammar (`src/qr_payload.rs`)
was read for format convention only, per this task's explicit instruction
not to couple to a flow §9gg demoted — it carries a hub session id, not a
claim secret, and is a different shape for a different purpose. See
`src/render.rs`'s own doc comment for the full rationale; the same callout
is in this PR's description.

**Gating**: the claim screen is built and printed exactly once, at process
startup, only when `state::is_claimed()` is false — the same gate the
plain-text code already used. A claimed box never renders it (the secret
is deleted from disk on claim anyway — `state::delete_claim_secret`). If
QR rendering itself ever fails (not expected for this crate's short,
fixed-shape payload), the screen degrades gracefully to text-only rather
than losing the whole screen.

**Named follow-up, NOT built in this repo (`slash-builder/core`'s
concern): tty ownership.** DJ's own VM 260 screenshot (§9pp) shows a getty
already running on tty1 — a `println!` from this dinit-supervised service
and the login prompt will interleave on the same console today. The real
fix is a dinit-level decision in `slash-builder/core`'s
`dinit-benixos-services`, not a change to this crate: for example, a
`benix-claim-screen` dinit service that owns tty1 gated on unclaimed state
(with `getty` moved to tty2, or started on tty1 only after claim). This PR
implements the render + startup print; it does not attempt to fix tty
ownership from here.

### The wire contract (`src/local_claim.rs`)

**Step 1 — `POST /v1/onboard/local-claim/challenge`**
Request: `{"client_pubkey": "<base64, 32-byte Ed25519>"}` (Courier's own
keypair — its public half is the identity being bound as owner).
Response: `{"challenge_id", "server_nonce": "<base64, 16 bytes>",
"box_pubkey": "<base64, 32 bytes>", "expires_at_ms"}`.

**Step 2 — `POST /v1/onboard/local-claim/finish`**
Courier computes (raw decoded bytes, fixed order/length — never base64
text):
```
transcript   = server_nonce ‖ client_pubkey ‖ box_pubkey      (16‖32‖32 bytes)
client_proof = HMAC-SHA256(key=secret, "benix-claim/client" ‖ transcript)
client_sig   = Ed25519-sign(client_privkey, challenge_id ‖ client_proof)
```
Request: `{"challenge_id", "client_pubkey", "client_proof": "<base64>",
"client_sig": "<base64>"}`.
On success, response: `{"status": "claimed", "box_pubkey", "box_id",
"box_proof": "<base64, HMAC-SHA256(secret, "benix-claim/box" ‖ transcript)>",
"claimed_at_ms"}`. **Courier MUST verify `box_proof` before trusting the
claim** — a spoofed/fake box cannot produce it (defeats mDNS-spoof T7).

| Response | When |
|---|---|
| `429 rate_limited` | token-bucket budget exhausted for this source IP |
| `403 non_lan_source` | source IP is not RFC1918/ULA/link-local |
| `409 already_claimed` | box already (locally) claimed |
| `410 challenge_not_found` | `challenge_id` unknown or expired (~120s TTL, monotonic clock — §9ii R3) |
| `401 invalid_proof` | `client_proof` or `client_sig` did not verify — secret and challenge NOT consumed (a typo must not burn onboarding) |
| `400 malformed_request` | bad JSON / bad base64 / wrong field length |
| `200` | see the two response shapes above |

### §9ii's binding required changes (R1-R5), as implemented

- **R1 — constant-time compare.** `hmac::Mac::verify_slice` (uses
  `subtle::ConstantTimeEq` internally, confirmed against that crate's own
  source before relying on it) — never a plain `==` on decoded bytes, which
  would open a timing oracle leaking a directly-replayable proof.
- **R2 — atomic claim commit.** The `claimed?` re-check and the actual
  commit (mark-claimed, delete-secret, persist-binding,
  invalidate-challenge) run inside one `AppState::claim_commit_lock`-guarded
  critical section. Proven with a real concurrency test
  (`local_claim::tests::concurrent_valid_finishes_resolve_first_writer_wins`)
  using genuine OS-thread parallelism (`#[tokio::test(flavor =
  "multi_thread")]` + `tokio::spawn`, not a timing hack): two
  simultaneously-valid finishes for two different owner keys resolve
  first-writer-wins, the loser gets `409`, and the persisted `owner_pubkey`
  always matches the actual winner, never a mix.
- **R3 — monotonic challenge TTL.** `Instant`-based, never wall-clock;
  `expires_at_ms`/`claimed_at_ms` in responses are advisory display
  metadata only.
- **R4 — the demoted `/v1/onboard/claim` cannot establish initial
  ownership on an unclaimed box, by construction.** See "Deviations" below
  — this is a real, tested behavior change to that endpoint, not an
  accident of hub-unreachability.
- **R5 — persistence hardening.** `state::write_private_atomic` (reused by
  `secret.rs`, and now every other caller in `state.rs` too) creates the
  temp file mode `0600` from the `open` call itself (never
  create-then-`chmod` — the exact QR-117 race class), `fsync`s the temp
  file before rename and the parent directory after, and sets the state
  directory itself to `0700`.

Also folded in: **m1** (`challenge_id` is CSPRNG via `Uuid::new_v4`, never
sequential), **m2** (the transcript's byte framing is nailed down and
worked-example'd above), **m3** (the pending-challenge map is
capacity-bounded at 256 entries, evict-soonest-to-expire when full), **m4**
(the transcript always uses the *finish* request's `client_pubkey`; the
step-1 value is never even persisted), **m5** (the LAN gate reads
`ConnectInfo<SocketAddr>`, the real socket peer address, never a header).
**Visibility over lockout** (§9ii's ratified judgment call): failed proofs
are logged (`tracing::warn!` with source IP + `challenge_id`) but do not
trip any hard lockout — the existing rate limiter already makes online
guessing infeasible at 128 bits, and a lockout would let an attacker deny
the legitimate user their own onboarding.

**Known gap, named not built**: `m6` (Courier-side recovery on a
crash-between-commit-and-response) and `m7` (a future owner-signature-gated
unclaim/factory-reset endpoint) are both out of scope for this pass —
`m6` is Courier's own logic in a different repo; `m7` has no unclaim
endpoint to gate yet.

### `POST /v1/onboard/claim` — the route (demoted, deferred Hearth-join)

`POST /v1/onboard/claim`, body `{"qr_payload": "<string>"}`
(`Content-Type: application/json` required, no other fields accepted).

| Response | When |
|---|---|
| `429 rate_limited` | token-bucket budget exhausted for this source IP |
| `403 non_lan_source` | source IP is not RFC1918/ULA/link-local |
| `403 not_locally_claimed` | **new (§9ii R4):** box has not completed the local-only claim protocol yet — this endpoint refuses by construction, not because the hub happens to be unreachable |
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

Plain HTTP/1.1, no TLS. For the local-only claim protocol this is a real,
engaged security-engineer call (§9ii), not a default: TLS would buy
confidentiality (nothing to hide — no wire secret), tamper-integrity (a
MITM can only DoS, which it can do anyway), and server-authentication —
and only the last is real value, which `box_proof` + `box_pubkey`
TOFU-pinning already provide; a from-scratch offline first boot has no
reachable CA anyway, so TLS would collapse to self-signed TOFU regardless.
**Binding invariant (§9ii): this call is contingent on the secret-off-wire
property** — any future change that puts a secret or bearer on the wire
re-opens the TLS question. For the demoted `/v1/onboard/claim` route, the
original reasoning stands unchanged: no cert story on a fresh box, and (now)
that route only runs post-local-claim anyway. Binds explicitly to the
box's own non-loopback interface address(es) via `if-addrs` — **never
`0.0.0.0`**. As defense-in-depth, every claim route also rejects (403) any
inbound request whose source IP is not RFC1918/ULA/link-local (checked
against the real socket peer address, never a forwarded header — §9ii m5),
even though bind-scoping should already prevent WAN reachability by
construction.

## Configuration (env vars, all optional)

| Var | Default | Meaning |
|---|---|---|
| `BENIX_MDNS_PORT` | `8420` | Listen port. **Shared name with `benix-mdns-advertiser`'s own SRV-record port var — deliberately.** Its SRV record and this endpoint's actual listen port must always agree; reusing the identical name is the cheapest way to keep them from silently drifting apart. **Known integration risk** (flagged in the finalized contract): there is no single shared environment source yet for the two binaries — a `meta-benixos` dinit-unit pass needs to land one. Not this repo's job to solve; just don't make it worse. |
| `BENIX_CLAIM_STATE_DIR` | `/var/lib/benixos` | State directory (now created `0700`, per §9ii R5). Distinct var name from the advertiser's `BENIX_MDNS_STATE_DIR`; same default path is fine — different filenames underneath (`device-key`, `claimed`, `pair-credentials`, `local-account-binding`, and now `claim-secret` — the local-only claim protocol's secret, wiped on claim). |
| `BENIX_CLAIM_RATE_LIMIT_PER_MIN` | `10` | Per-source-IP token-bucket budget, shared by every claim route (local-claim and the demoted hub-mediated one alike). |
| `BENIX_CLAIM_DEVICE_NAME` | this box's hostname | The `proposed_device_name` sent to the hub at claim time (hub-mediated path only). |
| `RUST_LOG` | `info` | Standard `tracing-subscriber` env filter. |

## Explicitly out of scope for this pass

- **No content-key / `/keys/request` logic of any kind.**
  security-engineer's binding R1 ruling (`context/projects/benixos.md`
  §9i, landed the same day as the onboarding contract): this agent MUST
  NOT hold the household content key and MUST NOT issue `/keys/request`.
  Its scope is pairing (identity + sealing keys) and `LocalAccountBinding`
  only. Nothing content-key-adjacent lives in this crate.
- **No fingerprint rendering.** Text-mode QR rendering now exists (§9rr,
  see "The claim screen" above) — a physical-LCD renderer for production
  hardware, or a fingerprint-comparison display for the deferred Hearth-join
  step, is separate, later display-layer work that implements the same
  `render` seam differently, not a protocol change.
- **No tty-ownership fix.** The claim screen prints to stdout at startup;
  it does not arbitrate against a getty already on the same console tty.
  Named explicitly as `slash-builder/core`'s follow-up — see "The claim
  screen" above.
- **No owner-signature authentication mechanism.** §9ii R4 requires — and
  this PR implements — that the demoted `/v1/onboard/claim` cannot
  establish ownership on an *unclaimed* box. It does NOT yet verify the
  caller is authenticated as the box's recorded `owner_pubkey` via a
  signature challenge once the box *is* claimed — that mechanism doesn't
  exist in this crate yet and is explicitly deferred (§9hh Item 5: a
  messaging-architect + data-architect + software-developer item for a
  later pass, alongside the real conditional-write-ordering work that step
  needs against the hub's own last-write-wins key registration).
- **No `meta-benixos` dinit unit or BitBake recipe.** Separate,
  sequenced-after work once this binary and its musl release artifact
  exist, same two-step sequence `qr-gateway` and the mDNS advertiser both
  went through.
- **No fix to `quickring/hub/src/ratelimit.rs`/`conn.rs:236`** (a known
  hub-side gap where pre-Hello `TPair(CLAIM)` isn't rate-limited) — routed
  to different work. This agent's own outbound `TPair(CLAIM)` calls land
  on that under-protected hub-side path today; not addressed here.
- **No unclaim / factory-reset endpoint.** §9hh names the contract it must
  satisfy when built (wipe `claim-secret` alongside `mdns-id`,
  owner-signature-gated, fail-closed — §9ii m7) — not built here; there is
  nothing to unclaim from in this pass's own test matrix.
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
- **`POST /v1/onboard/claim`'s fail-closed gate flips from "already
  claimed → 409" to "not yet locally claimed → 403" (§9ii R4).** This is a
  real, tested behavior change to a previously-shipped route, not an
  addition: on an unclaimed box this endpoint now refuses (403
  `not_locally_claimed`) before even parsing its body, where it previously
  proceeded to attempt a hub pairing. Required because §9gg/§9hh moved
  initial-ownership establishment to the local-only claim protocol, and
  §9ii found that this route's old "should fail because the hub is
  unreachable" posture was an accident of connectivity, not a real gate.
  The six existing tests that exercised this route against a genuinely
  unclaimed box were updated to first locally-claim the box (matching its
  new precondition as the deferred Hearth-join step) rather than left
  passing-but-testing-a-retired-contract; one of them
  (`already_claimed_returns_409...`) is retired and replaced by
  `unclaimed_box_returns_403_and_never_reaches_pair_claim` — §9ii R4's own
  required regression test, verbatim.

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
  all of the above as two jobs (`build`, `musl`) — **currently RED on
  GitHub's own runners, and not this crate's own code's fault.** Real
  finding, checked rather than assumed: both jobs fail identically at
  dependency resolution —
  `error: failed to get 'fabric-kit' as a dependency ... unable to update
  registry 'lockamy' ... download of config.json failed ... transfer too
  slow: failed to transfer more than 10 bytes in 30s` — i.e.
  `nexus.softsurve.com` is not reachably fast (effectively unreachable)
  from GitHub-hosted `ubuntu-latest` runners' public IPs, most likely a
  Sol-side firewall/security-group scoped to known LAN/VPN source ranges
  (`softsurve/sol/docs/NETWORK.md` documents `nexus.softsurve.com` as a
  single-ingress `sol-nginx` proxy on `io`, not obviously open to
  arbitrary public internet source IPs). **This is not new, and not
  specific to this repo**: `slash-builder/fabric-kit`'s own GitHub Actions
  history shows every run failing this exact same way from the moment
  QR-220 gave that repo its own first `lockamy`-registry dependency
  (`message-kit`) onward (2026-08-29 21:04 UTC through the latest run
  checked) — every run before that (when fabric-kit vendored its own
  proto and touched no private registry) was green. In other words: any
  repo's GitHub Actions workflow that resolves a `lockamy`-registry crate
  hits this wall today, including the repo this crate's own dependency
  comes from. Retried once here (`gh run rerun`) to rule out one-off
  flakiness — failed identically both times, ruling out a transient
  blip.
  **Does not affect the studio's authoritative CI**: Jenkins agents run
  on Sol's own network (`agent { label 'linux-build' }`) and reach
  `nexus.softsurve.com` the same way any other on-network Sol service
  does — this repo's `Jenkinsfile` needs no workaround and should pass
  there. Routed rather than silently worked around (no vendoring, no
  disabling the job, no path-dependency substitution): `sol-pm`/
  `devops-engineer` own whether GitHub's runner IP ranges should be
  allow-listed on Sol's ingress, or whether this is an accepted,
  Jenkins-is-authoritative gap for every `lockamy`-registry-consuming
  repo's GitHub Actions mirror. Every check this crate's own code is
  responsible for — fmt, clippy, tests, host build, and the musl build's
  `file(1)` static-PIE classification — is independently proven above,
  against this crate's actual committed source, in a real container with
  working registry access; the CI-red status is a network-reachability
  fact about the runner, not a code defect.

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

### This pass's own verification (local-only claim protocol, §9hh/§9ii)

Same discipline as above — real, checked, not claimed on faith. Run inside
a `rust:1.90-trixie` container (host + registry access, this crate's own
established verification environment):

- `cargo fmt --check` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean, zero warnings.
- `cargo test` — **68/68 passing** (up from 49; 19 new tests: 2 in
  `secret`'s round-trip/case-insensitivity suite beyond the two the spec
  asked for, plus a display-shape test; 2 in `local_account_binding`; 1 in
  `handlers` — the retired-and-replaced R4 regression test; 13 in
  `local_claim` — see "Test coverage" below).
- `cargo build --release` — clean.
- **`cargo build --release --target x86_64-unknown-linux-musl` — attempted,
  did NOT succeed in this session's container, and this is disclosed
  rather than hidden or silently worked around.** The failure is `ring`
  (an existing transitive TLS dependency, not anything this PR adds)
  failing to compile its C sources: `musl-gcc`'s `cc1` in this pull of
  `rust:1.90-trixie` rejects `-m64` outright. **Confirmed NOT a regression
  this PR introduced**: the identical failure reproduces byte-for-byte
  against the pre-existing baseline commit (`da7a035`, before any change in
  this PR), checked via `git stash` before concluding anything. This
  contradicts the musl spike this repo's own README already claims as a
  clean pass under the same image tag — most likely explained by
  `rust:1.90-trixie` being a floating tag whose underlying Debian
  trixie/musl-cross-toolchain packages have moved since that original
  session, not by anything code-side. Not chased further: this crate's own
  code has zero new C-compilation surface (`hmac`/`sha2`/`ed25519-dalek`/
  `rand`/`data-encoding` are all pure Rust), and the studio's authoritative
  CI is Jenkins (`agent { label 'linux-build' }`), a different, real
  environment this session cannot reach to cross-check — not this local
  ad hoc Docker pull. Flagged for whoever next touches this crate's musl
  job, not fixed here.

### This pass's own verification (claim screen QR, §9rr)

Same discipline, same environment (`rust:1.90-trixie` container via local
Docker, matching the Jenkinsfile's `Build & Test`/`musl cross-compile`
stages exactly, including the `-u root:root` fix from PR #2 for the
`apt-get` stage):

- **Dependency spike, run before adding `qrcode` to `Cargo.toml`**: a
  throwaway crate depending on `qrcode = { version = "0.14",
  default-features = false }` was built with `cargo tree` — confirmed
  **zero** additional transitive dependencies (the default `image`/`svg`/
  `pic` features are the only feature-gated parts of that crate; the
  `render::unicode` module used here is not gated). Checked, not assumed.
- `cargo fmt --check` — clean (one formatting fix applied after the first
  run).
- `cargo clippy --all-targets -- -D warnings` — clean, zero warnings (one
  unused-import fixed after the first run).
- `cargo test` — **79/79 passing (up from 68; 11 new tests)**: 5 in `qr.rs`
  (determinism, distinct payloads render distinctly, the 160×50 console fit
  with a pinned 37×19 regression size, glyph-set restriction, an empty-
  payload edge case) and 6 in `render.rs` (the claim-URI's versioned
  scheme/separator-stripping, a round trip through `secret::decode`,
  distinct secrets producing distinct URIs, the full claim screen
  containing the header/code/QR, the screen composer being a pure function
  of its input, and distinct codes producing distinct screens). Zero
  regressions in the existing 68.
- `cargo build --release` — clean.
- **`cargo build --release --target x86_64-unknown-linux-musl` — attempted,
  did NOT succeed in this session's container, for the exact same
  pre-existing, already-disclosed reason as the §9hh/§9ii pass above:**
  `ring` (an existing transitive TLS dependency this PR does not touch)
  fails to compile its C sources because this pull of `rust:1.90-trixie`'s
  `musl-gcc`/`cc1` rejects `-m64`. **Confirmed NOT a regression this PR
  introduces**: re-ran the identical build against the untouched baseline
  commit (`21bae64`, via a separate `git worktree`, before concluding
  anything) and got the byte-identical failure. This crate's own new
  dependency (`qrcode`) is pure Rust with zero C-compilation surface, so it
  cannot be the cause. Same disposition as before: not chased further here
  (a floating-Docker-tag toolchain issue, not code-side), flagged for
  whoever next touches this crate's musl job, and not blocking on the
  studio's authoritative Jenkins, which this session cannot reach to
  cross-check directly (`jenkins.softsurve.com` returns an auth-required
  page from this environment).
- GitHub Actions (`ci.yml`): this repo's own CI history shows every run on
  `main` red since before this PR, for the already-documented,
  unrelated-to-code reason above ("What was actually verified" —
  `nexus.softsurve.com` unreachable from GitHub-hosted runners). Checked
  via `gh run list` before assuming this PR's own run would be any
  different; it is not expected to turn the mirror green, and a red run on
  this PR should be cross-checked against that pre-existing pattern before
  being read as a regression.

## Test coverage

`cargo test` — 79 tests, all passing as of this writing:

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
- `secret`: `load_or_create_secret` generate-then-reload stability (a
  restart shows the same code), `0600` file permissions, the 5-groups/26-char
  display shape, round-trip encode→decode across 20 varied byte patterns,
  case-insensitivity (upper/lower/mixed), separator/whitespace tolerance,
  Crockford's own `O`/`I`/`L` decode leniency, and rejection of both
  wrong-length and out-of-alphabet input.
- `local_account_binding`: the existing hub-mediated `new_active` round
  trip (now also asserting `owner_pubkey` is `None` there), plus
  `new_active_local` recording `owner_pubkey` as both that field and
  `principal_id`.
- `local_claim` (router-level, same `tower::ServiceExt::oneshot` pattern as
  `handlers`'s own test module):
  - happy-path round trip: `challenge` → `finish` → `200 claimed`,
    `owner_pubkey` actually persisted in `LocalAccountBinding`, the
    returned `box_proof` independently recomputed and matched, the secret
    file gone, `is_claimed()` true;
  - wrong `client_proof` → `401`, and — explicitly asserted, not assumed —
    the secret file **still exists** afterward (a typo does not burn
    onboarding);
  - unknown `challenge_id` → `410`; an expired one (inserted already-past
    a monotonic `Instant`, no real sleep needed) → `410` too (§9ii R3);
  - already-claimed → `409` on both `challenge` and `finish`;
  - non-LAN source → `403` on both routes;
  - rate-limit budget exhausted → `429`;
  - **§9ii R2's own required proof**: two genuinely concurrent (real
    multi-threaded-runtime, real `tokio::spawn`) valid finishes for two
    different owner keys against the same challenge resolve
    first-writer-wins — exactly one `200`, exactly one `409`, and the
    persisted `owner_pubkey` matches whichever one actually won, never a
    torn or overwritten value.
- `handlers` (router-level, via `tower::ServiceExt::oneshot` — see
  `src/handlers.rs`'s `oneshot_with_addr` helper for how `ConnectInfo` is
  injected without a real listener):
  - **§9ii R4's own required regression test**: a genuinely unclaimed,
    offline box hitting the demoted `/v1/onboard/claim` gets `403
    not_locally_claimed` and never reaches `pair_claim`, proven by the
    response itself (a `403` precludes the `202`/`502` `pair_claim` would
    otherwise produce) — replacing the old "already claimed → 409" test,
    whose own precondition is no longer the anomaly under the new model;
  - non-LAN source → `403`;
  - malformed `qr_payload` → `400`;
  - missing `Content-Type` → `400`;
  - unknown JSON field → `400` (`deny_unknown_fields`);
  - successful claim → `202` immediately, without waiting on
    `wait_for_result` (now run against a box pre-claimed locally, per the
    new R4 precondition);
  - hub-unreachable → `502`, no `pair-credentials` ever persisted (the box
    was already locally claimed going in, per the new R4 precondition —
    `is_claimed()` itself doesn't change on this path, hub-join simply
    never completes);
  - `/healthz` → `200`, independent of LAN-source restriction.
  - the background task (`run_wait_for_result`, exercised directly, not
    only through the route) marks `claimed` and persists
    `pair-credentials`/`local-account-binding` **only** on
    `PairOutcome::Approved`, and leaves the box unclaimed on `Rejected`,
    `Timeout`, and a `wait_for_result` `Err`.
- `qr` (§9rr, the text-mode QR primitive): the same payload renders
  identically every time (determinism, not eyeballed), two different
  payloads render differently, the rendered block's glyph set is restricted
  to exactly the four expected characters (`▀`/`▄`/`█`/space), an empty
  payload still encodes without panicking, and — a pinned regression, not
  just a bound — this crate's actual claim-URI length renders to exactly
  37×19 characters, comfortably inside the 160×50 console §9pp confirmed.
- `render` (§9rr, the claim-screen composer): the claim URI carries the
  versioned `benix-claim://v1?s=` prefix and strips the display code's `-`
  group separators; the embedded compact secret round-trips through
  `secret::decode` to the exact same bytes the grouped display string does;
  different secrets produce different URIs; the full composed screen
  contains the header, the grouped code, the word "Courier", and at least
  one real QR glyph (proving the QR is genuinely embedded, not silently
  skipped); the composer is a pure function (same input twice → identical
  output); and different codes produce different screens.

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
Jenkins pipeline (`Jenkinsfile`). Unlike `benix-mdns-advertiser`, this
crate resolves a private-registry dependency (`fabric-kit`, via the
`lockamy` Nexus registry) — but that needs no secret/credential wiring in
either CI system: checked before assuming otherwise, the `cargo-group`
registry's index and crate downloads are unauthenticated reads (confirmed
with a bare `curl` against both the sparse-index JSON and a crate
`.crate` download, no `Authorization` header sent, both `200`). A token is
only needed for `cargo publish`, which this repo doesn't do.
`slash-builder/fabric-kit`'s own CI confirms the same shape — no
`secrets.*`/`credentialsId` reference anywhere in its workflow or
Jenkinsfile either.

## Open, routed rather than decided here

- `benixos-pm` — sequencing this into the headless backlog, the
  `meta-benixos` dinit-unit + BitBake recipe work, and real LAN
  broadcast-and-connect verification (deferred items 2 and 3 of the
  finalized contract's ticket) — now including the local-only claim
  protocol's own on-target verification (no real Courier client exists yet
  to drive it end-to-end).
- `data-architect` — `LocalAccountBinding`'s real, locked schema (this
  crate's version is an explicit stand-in — see above), including whether
  `owner_pubkey` (new in this pass) is the field's final shape.
- `devops-engineer` — the dinit unit itself, its ordering against network
  bring-up, the `BENIX_MDNS_PORT` shared-env-var drift risk, the state
  directory's ownership (§9ii R5 sets its *mode* to `0700` from inside this
  crate; *which user* the dinit unit runs as, so that mode is actually
  meaningful, is a deployment decision this crate cannot and should not
  force via `chown`), and this session's own unresolved local musl-build
  toolchain finding (see "What was actually verified" above) if it turns
  out to also affect a real Jenkins/GitHub Actions run.
- `messaging-architect` + `benixos-pm` — whether `resource_advert`
  publishing eventually lands on this agent (expanded) or a separate
  post-claim daemon; if it's this agent, R1 (keyless) must be revisited
  before that expansion, per §9i.
- `messaging-architect` + `data-architect` + `software-developer` — §9hh
  Item 5 (join Hearth after a local claim): owner-signature
  authentication for the demoted `/v1/onboard/claim`, and the
  conditional-write-ordering discipline named in
  `context/projects/benixos.md`'s own record (the ADR-0004 device-0
  provisioning lesson) for registering against both local state and the
  hub without a last-write-wins race.
- `qa-engineer` — a full concurrency/race-condition test harness beyond
  this PR's own single hand-written R2 regression test (§9ii's own
  framing: "that harness is qa-engineer's to build; this section says what
  must be proven").
- **Courier-side** (different repo, `quickring/courier` or similar,
  `quickring-pm`/`software-developer`) — the actual UI flow that reads the
  box's displayed code, runs this two-step handshake, verifies `box_proof`,
  and stores the box as an owned peer keyed by `box_pubkey`. Scoped under
  QR-37 in §9hh's own text; nothing in this repo builds it.
