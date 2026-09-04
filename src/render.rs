//! The claim-code display seam — deliberately named "a `render` seam, not
//! the final display renderer" in §9hh's own implementation spec
//! (`context/projects/benixos.md`). Today this is exactly one function that
//! prints to stdout, because dinit already routes this process's stdout to
//! the box's console/serial output (§9h; VM 260's own `qm terminal`/
//! `-serial` side-channel already proves this text path works, no new
//! engineering needed for the dev/VM case, and §9pp's real framebuffer
//! capture confirms a genuine 160x50 text console on the actual VGA path).
//! A production unit's physical LCD is a *display* concern, not a
//! *protocol* concern (§9gg item 1) — swapping one in later means giving
//! [`display_claim_code`] a different body (or adding a second
//! implementation this module dispatches to), not touching `secret.rs` or
//! `local_claim.rs` at all.
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
//! ### QR payload format — INVENTED HERE, NOT SPECIFIED BY §9hh, NEEDS
//! MESSAGING-ARCHITECT RATIFICATION
//!
//! §9hh's own design text scopes "QR bitmap rendering" as a *display*
//! concern, explicitly out of the protocol it defines, and specifies no QR
//! wire format for the local-only claim flow (the *old*, superseded
//! hub-mediated flow's `quickring://pair?session=...&endpoint=...` grammar
//! in `src/qr_payload.rs` is a different flow entirely — read for format
//! *convention*, deliberately not reused or coupled to here, since §9gg
//! demoted that flow and it carries a hub session id, not a claim secret).
//!
//! In the absence of a specified format, this module defines one:
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
//! **This format is this implementation's own choice, not a ratified
//! contract.** It is deliberately simple and versioned so it's cheap to
//! change. Flagging explicitly, per this project's own discipline (§9hh/
//! §9ii's design-then-review precedent): **a Courier-side implementer
//! should not treat this scheme as settled until messaging-architect signs
//! off on it** — see the PR this lands in for the same callout.

/// The QR payload scheme/version prefix — see this module's own doc comment
/// for why this exists and its ratification status.
const CLAIM_URI_PREFIX: &str = "benix-claim://v1?s=";

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
/// Uses `println!` rather than `tracing::info!` deliberately: this is a
/// user-facing instruction, not a diagnostic log line, and must reach the
/// console regardless of `RUST_LOG`'s configured level.
///
/// A thin wrapper around [`build_claim_screen`] — see that function for the
/// actual, unit-tested composition; this one only exists to perform the
/// `println!` I/O.
pub fn display_claim_code(code: &str) {
    println!("{}", build_claim_screen(code));
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
}
