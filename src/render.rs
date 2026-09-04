//! The claim-code display seam — deliberately named "a `render` seam, not
//! the final display renderer" in §9hh's own implementation spec
//! (`context/projects/benixos.md`). A production unit's physical LCD is a
//! *display* concern, not a *protocol* concern (§9gg item 1) — swapping
//! one in later means giving [`display_claim_code`] a different body (or
//! adding a second implementation this module dispatches to), not
//! touching `secret.rs` or `local_claim.rs` at all.
//!
//! ## tty1 visibility (§9rr follow-up, closed here)
//!
//! §9rr shipped this screen as a plain `println!` to stdout, reasoning
//! that "dinit already routes this process's stdout to the box's
//! console/serial output". That reasoning does not survive contact with
//! VM 260's real kernel cmdline (`console=tty0,115200n8
//! console=ttyS0,115200n8`, PR #28): userspace writes to `/dev/console`
//! are a real Linux kernel behavior, not a dinit or BenixOS quirk — they
//! only ever reach the kernel's one "preferred console" device, which is
//! the *last* `console=` entry (`ttyS0`, the serial port), regardless of
//! how many earlier entries also receive kernel `printk` output. Whatever
//! dinit's own `benix-claim-agent` service unit does with this process's
//! stdout (today, nothing — no `logfile`/`log-type` directive is set on
//! that unit, and dinit's own documented default is `log-type = none`,
//! i.e. the output is silently discarded; see
//! `slash-builder/core`'s `dinit-benixos-services/services/dockerd` for
//! the identical, already-diagnosed default-discard behavior on a
//! different service), a bare `println!` was never going to reach the
//! framebuffer VT (`tty1`) DJ's own §9pp/§9qq screenshots confirm is the
//! screen an operator actually looks at.
//!
//! The fix: [`display_claim_code`] now writes directly to a configurable
//! tty device node (`BENIX_CLAIM_TTY`, default [`DEFAULT_CLAIM_TTY`]) via
//! a plain `OpenOptions::write` — bypassing dinit's stdout routing (or
//! lack thereof) and the kernel's `/dev/console` last-entry-wins
//! resolution entirely. If that open/write fails for any reason (the
//! device doesn't exist — every non-BenixOS dev machine and this crate's
//! own CI containers, permission denied, etc.), it falls back to the
//! original `println!` to stdout, so nothing here can turn a missing
//! `/dev/tty1` into a startup failure or a lost test run.
//!
//! **Named, not solved here**: dinit's own `tty1` unit
//! (`slash-builder/core`'s `dinit-benixos-services/services/tty1`) starts
//! an `agetty` login prompt on the same device independently of this
//! process, and nothing coordinates the two — this round's fix is
//! deliberately pragmatic coexistence (see [`crate::config::Config::
//! claim_screen_delay_ms`]'s doc comment: a short startup delay so the
//! claim screen lands *after* agetty's own prompt rather than racing it,
//! not proper ownership arbitration), matching the scope this task
//! explicitly set. The clean fix — a dinit-level `benix-claim-screen`
//! service that owns `tty1` while unclaimed, with `getty` moved to
//! `tty2` — is `slash-builder/core`'s follow-up, tracked as task #64, not
//! attempted from this repo.
//!
//! ## §9rr: the claim screen (QR + text code)
//!
//! [`build_claim_screen`] composes the full unclaimed-box screen — header,
//! QR block, grouped Base32 code, one-line instruction — as a **pure
//! function of the display code string**, so it's unit-testable without a
//! console, a running process, or any protocol state. [`display_claim_code`]
//! is the thin `println!` wrapper around it that actually reaches the
//! console, kept separate for exactly the same "pure function vs. I/O"
//! split `secret.rs`/`local_claim.rs` already draw elsewhere in this crate.
//!
//! ### QR payload format — RATIFIED, §9ss
//!
//! §9hh's own design text scopes "QR bitmap rendering" as a *display*
//! concern, explicitly out of the protocol it defines, and specifies no QR
//! wire format for the local-only claim flow (the *old*, superseded
//! hub-mediated flow's `quickring://pair?session=...&endpoint=...` grammar
//! in `src/qr_payload.rs` is a different flow entirely — read for format
//! *convention*, deliberately not reused or coupled to here, since §9gg
//! demoted that flow and it carries a hub session id, not a claim secret).
//!
//! In that absence, this module defined one:
//!
//! ```text
//! benix-claim://v1?s=<26-character-Crockford-Base32-secret>
//! ```
//!
//! - `benix-claim` scheme, `v1` authority — versioned so a future wire
//!   change (e.g. adding a discovery hint) doesn't silently break an older
//!   Courier build parsing an older box's QR.
//! - `s` is the *ungrouped* 26-character encoding from
//!   [`crate::secret::encode_display`] with its `-` group separators
//!   stripped (shorter payload, smaller/simpler QR; `secret::decode` is
//!   already separator-tolerant, so a Courier-side parser can feed the
//!   captured `s` value through the exact same decode path whether it came
//!   from a scanned QR or a typed, grouped code).
//! - No other fields. Nothing about this claim's `challenge_id`,
//!   `box_pubkey`, or transcript rides the QR — the secret is the only
//!   value a QR needs to carry; everything else is negotiated over the
//!   two-message handshake in `src/local_claim.rs` exactly as it would be
//!   for a manually-typed code.
//!
//! **messaging-architect's binding ratification** (`context/projects/
//! benixos.md` §9ss, verdict: RATIFIED WITH NAMED BINDING ADDITIONS): the
//! emitted string above is unchanged — every addition is a parser-side
//! rule, nothing this crate emits is affected. The two binding rules a
//! Courier-side parser MUST follow, so this format stays cheap to evolve
//! without a version bump for every addition:
//!
//! 1. **Unknown query params MUST be ignored.** Mirrors
//!    `qr_payload.rs`'s own existing "additive/unknown field" tolerance —
//!    makes an optional future field (e.g. an mDNS-`id` correlation hint,
//!    named in §9ss Q2 as the only acceptable shape for one, advisory
//!    only, never a raw IP) an additive, non-breaking change.
//! 2. **Additive fields need no version bump; breaking changes go to a new
//!    `v2` authority.** `v1` stays reserved for this exact shape.

/// The QR payload scheme/version prefix — see this module's own doc comment
/// for why this exists and its ratification status.
const CLAIM_URI_PREFIX: &str = "benix-claim://v1?s=";

/// Overrides which device [`display_claim_code`] writes the claim screen
/// to — see this module's "tty1 visibility" doc section above. Tests
/// point this at a throwaway regular file rather than a real tty device;
/// `OpenOptions::write` has no tty-specific behavior, so a regular file
/// exercises the exact same code path a real `/dev/tty1` open would.
const CLAIM_TTY_ENV_VAR: &str = "BENIX_CLAIM_TTY";

/// Default target: the local framebuffer VT — the screen §9pp/§9qq's
/// framebuffer-console work made real and DJ's own screenshot confirms is
/// what an operator actually looks at. Deliberately NOT `/dev/console`
/// (see this module's doc comment for why that resolves to the serial
/// port on this box's real kernel cmdline) and NOT a `BENIX_CLAIM_STATE_DIR`-relative
/// path (this is a device node, not persisted state).
const DEFAULT_CLAIM_TTY: &str = "/dev/tty1";

/// Resolve the tty device path to write the claim screen to, honoring
/// [`CLAIM_TTY_ENV_VAR`] with a documented default — same env-var-with-
/// default idiom `config.rs` uses everywhere else in this crate.
fn claim_tty_path() -> std::path::PathBuf {
    std::env::var(CLAIM_TTY_ENV_VAR)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(DEFAULT_CLAIM_TTY))
}

/// Open `path` for writing and write `screen` to it — no tty-specific
/// logic at all, just a plain, unbuffered write-and-flush. Split out from
/// [`display_claim_code`] so the open/write/fallback decision is a single,
/// pure `Result`-returning step, independent of the `println!` fallback
/// that decision drives.
fn write_screen_to_device(path: &std::path::Path, screen: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut device = std::fs::OpenOptions::new().write(true).open(path)?;
    device.write_all(screen.as_bytes())?;
    device.flush()
}

/// Build this box's claim URI from its human-readable display code (the
/// grouped, 26-character Crockford Base32 string from
/// [`crate::secret::encode_display`]). Strips the display grouping's `-`
/// separators before embedding — the QR carries the compact form; see this
/// module's doc comment for the full format rationale and its
/// not-yet-ratified status.
fn claim_uri(display_code: &str) -> String {
    let compact: String = display_code.chars().filter(|c| *c != '-').collect();
    format!("{CLAIM_URI_PREFIX}{compact}")
}

/// Compose the full unclaimed-box claim screen: a short factual header, the
/// QR block encoding [`claim_uri`], the same code as grouped human-readable
/// text beneath it, and a one-line instruction — as a single `String`, so
/// this is testable independent of any console/stdout.
///
/// `display_code` is expected to be the output of
/// [`crate::secret::encode_display`] (grouped, 26 characters); this function
/// doesn't validate that shape itself — `secret.rs` owns the encoding, this
/// module only composes around it.
///
/// If QR rendering fails (see [`crate::qr::render_unicode`]'s doc comment —
/// not expected for this crate's short, fixed-shape payload, but not
/// assumed impossible either), the screen degrades gracefully: it still
/// shows the human-readable code and instruction, just without the QR
/// block, rather than losing the whole claim screen over a QR-rendering
/// failure.
pub fn build_claim_screen(display_code: &str) -> String {
    let uri = claim_uri(display_code);
    let qr_block = crate::qr::render_unicode(uri.as_bytes());

    let mut out = String::new();
    out.push_str(
        "\n================================================================\n\
         BenixOS box is UNCLAIMED.\n\n",
    );

    match qr_block {
        Some(block) => {
            out.push_str("Scan this code with Courier to claim it:\n\n");
            for line in block.lines() {
                out.push_str("    ");
                out.push_str(line);
                out.push('\n');
            }
            out.push_str("\nOr enter this code in Courier if you can't scan:\n\n");
        }
        None => {
            out.push_str("To claim it, open Courier and enter this code when prompted:\n\n");
        }
    }

    out.push_str(&format!("    {display_code}\n\n"));
    out.push_str("This code stays valid until the box is claimed.\n");
    out.push_str("================================================================\n");
    out
}

/// Show `code` (the Crockford-Base32, grouped display string from
/// [`crate::secret::encode_display`]) to whoever can see this box's
/// console. Called exactly once, at startup, only while the box is
/// unclaimed (see `main.rs`) — a claimed box has nothing left to display.
///
/// Writes directly to the configured tty device
/// ([`CLAIM_TTY_ENV_VAR`]/[`DEFAULT_CLAIM_TTY`] — see this module's "tty1
/// visibility" doc section) rather than relying on this process's stdout
/// being routed anywhere useful. Falls back to a plain `println!` if that
/// open/write fails for any reason (device absent, permission denied,
/// not a BenixOS box at all) — this function can never turn a missing tty
/// device into a startup failure, and the fallback preserves this crate's
/// original §9kk/§9rr behavior for tests and non-BenixOS environments.
/// Either way this is a user-facing instruction, not a diagnostic log
/// line: it must reach its destination regardless of `RUST_LOG`'s
/// configured level, so it never goes through `tracing::info!` — only the
/// *decision* of which path was taken is logged, via `tracing`, at
/// whichever level fits (`info` on success, `warn` on fallback).
///
/// A thin wrapper around [`build_claim_screen`] — see that function for the
/// actual, unit-tested composition; this one only exists to perform the
/// I/O.
pub fn display_claim_code(code: &str) {
    let screen = build_claim_screen(code);
    let tty_path = claim_tty_path();
    match write_screen_to_device(&tty_path, &screen) {
        Ok(()) => {
            tracing::info!(tty = %tty_path.display(), "wrote claim screen to console device");
        }
        Err(error) => {
            tracing::warn!(
                tty = %tty_path.display(),
                %error,
                "failed to write claim screen to configured tty device, falling back to stdout"
            );
            println!("{screen}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::encode_display;

    const SAMPLE_SECRET: [u8; 16] = [0xAB; 16];

    #[test]
    fn claim_uri_has_versioned_scheme_and_strips_separators() {
        let display = encode_display(&SAMPLE_SECRET);
        assert!(display.contains('-'), "sanity: display code is grouped");
        let uri = claim_uri(&display);
        assert!(uri.starts_with("benix-claim://v1?s="));
        let s_value = uri.strip_prefix("benix-claim://v1?s=").unwrap();
        assert!(!s_value.contains('-'));
        assert_eq!(s_value.len(), 26);
    }

    #[test]
    fn claim_uri_round_trips_through_secret_decode() {
        use crate::secret::decode;
        let display = encode_display(&SAMPLE_SECRET);
        let uri = claim_uri(&display);
        let s_value = uri.strip_prefix(CLAIM_URI_PREFIX).unwrap();
        // secret::decode is separator/case tolerant, so the compact QR
        // payload value decodes back to the exact same secret bytes as the
        // grouped display string does.
        assert_eq!(decode(s_value), Some(SAMPLE_SECRET));
        assert_eq!(decode(&display), Some(SAMPLE_SECRET));
    }

    #[test]
    fn different_secrets_produce_different_claim_uris() {
        let a = claim_uri(&encode_display(&[0x11; 16]));
        let b = claim_uri(&encode_display(&[0x22; 16]));
        assert_ne!(a, b);
    }

    #[test]
    fn claim_screen_contains_header_qr_code_and_instruction() {
        let display = encode_display(&SAMPLE_SECRET);
        let screen = build_claim_screen(&display);
        assert!(screen.contains("UNCLAIMED"));
        assert!(screen.contains(&display), "the grouped code must be shown");
        assert!(screen.contains("Courier"));
        // The QR block: at least one half-block glyph must be present for
        // a real payload (this isn't asserting exact geometry — src/qr.rs
        // already pins that — just that a QR is genuinely embedded here,
        // not silently skipped).
        assert!(
            screen
                .chars()
                .any(|c| matches!(c, '\u{2580}' | '\u{2584}' | '\u{2588}')),
            "claim screen must embed a rendered QR block"
        );
    }

    #[test]
    fn claim_screen_is_a_pure_function_of_the_display_code() {
        let display = encode_display(&SAMPLE_SECRET);
        let a = build_claim_screen(&display);
        let b = build_claim_screen(&display);
        assert_eq!(a, b);
    }

    #[test]
    fn claim_screen_differs_for_different_codes() {
        let a = build_claim_screen(&encode_display(&[0x11; 16]));
        let b = build_claim_screen(&encode_display(&[0x22; 16]));
        assert_ne!(a, b);
    }

    /// Both the success path (a writable stand-in device) and the
    /// fallback path (an unwritable one) in a single test function,
    /// deliberately — `BENIX_CLAIM_TTY` is process-global state, and
    /// `cargo test` runs tests in parallel by default, so two separate
    /// tests each setting/clearing the same env var would race each other
    /// (the same isolation concern `config.rs`'s own env-var test already
    /// names for its own vars).
    #[test]
    fn display_claim_code_writes_to_configured_tty_and_falls_back_on_failure() {
        // Default: unset entirely resolves to /dev/tty1 — checked first,
        // before this test touches the env var at all, so it can't race
        // any other test that might also read/clear BENIX_CLAIM_TTY.
        std::env::remove_var(CLAIM_TTY_ENV_VAR);
        assert_eq!(claim_tty_path(), std::path::PathBuf::from("/dev/tty1"));

        // Success: OpenOptions::write has no tty-specific behavior, so a
        // plain regular file exercises the exact same open/write/flush
        // path a real /dev/tty1 would.
        let stand_in = std::env::temp_dir().join(format!(
            "benix-claim-agent-test-tty-{}-{}",
            std::process::id(),
            "success"
        ));
        std::fs::write(&stand_in, b"").expect("create stand-in tty file");
        std::env::set_var(CLAIM_TTY_ENV_VAR, &stand_in);

        let display = encode_display(&SAMPLE_SECRET);
        display_claim_code(&display);

        let written = std::fs::read_to_string(&stand_in).expect("read stand-in tty file");
        assert!(
            written.contains(&display),
            "claim screen must have been written to the configured tty path"
        );
        let _ = std::fs::remove_file(&stand_in);

        // Fallback: a path whose parent directory doesn't exist can never
        // be opened for writing — must not panic, must silently fall back
        // to println! instead (this crate's original §9kk/§9rr behavior,
        // and the default posture for every non-BenixOS environment,
        // including this very test run, when BENIX_CLAIM_TTY is unset).
        std::env::set_var(
            CLAIM_TTY_ENV_VAR,
            "/nonexistent-dir-benix-claim-agent-test-should-never-exist/tty1",
        );
        display_claim_code(&display);

        std::env::remove_var(CLAIM_TTY_ENV_VAR);
    }
}
