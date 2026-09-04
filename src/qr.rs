//! Text-mode QR rendering: turn an arbitrary byte payload into a Unicode
//! half-block (`▀`/`▄`/`█`) text block a terminal/framebuffer console can
//! display directly, no bitmap/image support required.
//!
//! This module owns exactly one concern — bytes in, QR text block out — and
//! knows nothing about the claim protocol, the secret, or the screen layout
//! around it. `src/render.rs` is the seam that decides *what* payload to
//! encode and *how* to compose the full claim screen; this module is purely
//! the QR-rendering primitive it calls, kept separate so it stays
//! unit-testable against fixed inputs without any of that context.
//!
//! ## Why `qrcode`, and why this doesn't add musl/dependency risk
//!
//! `qrcode = { version = "0.14", default-features = false }` — confirmed via
//! a real `cargo tree` spike (not assumed) to add **zero** transitive
//! dependencies with the default `image`/`svg`/`pic` features disabled; the
//! `render::unicode` module used here is not itself feature-gated. Pure
//! Rust, no C deps, confirmed to build for `x86_64-unknown-linux-musl`
//! before being committed (see `Cargo.toml`'s own comment on this
//! dependency and the PR/README record). `fast_qr` was the named fallback
//! if `qrcode` had turned out to be heavy; the spike showed it isn't, so
//! there was no reason to reach for it.
//!
//! ## Sizing
//!
//! The two-round-trip QR payload this crate encodes today (see
//! `render::claim_uri`) is short enough to fit QR version 1-3 (21-29
//! modules per side) at error-correction level M (the `qrcode` crate's own
//! default). With the standard 4-module quiet zone and the `Dense1x2`
//! Unicode renderer (2 QR modules packed per output character row), that's
//! well within the 160x50 text console §9pp's real capture confirmed
//! (`Console: switching to colour frame buffer device 160x50`) — a version-3
//! QR renders at 37 characters wide by 19 lines tall, confirmed by this
//! module's own tests.

use qrcode::render::unicode;
use qrcode::QrCode;

/// Render `payload` as a Unicode half-block QR code, including the standard
/// quiet zone, one QR module per output column and two QR modules per
/// output row (`▀`/`▄`/`█`/space).
///
/// Returns `None` only if the payload is too large to encode as a QR code
/// at all (`qrcode`'s own hard ceiling is version 40, ~2900 bytes at the
/// lowest error-correction level) — never expected in this crate's actual
/// use (a claim URI built from a 26-character secret is a few dozen bytes),
/// but surfaced as `Option` rather than panicking so a caller can degrade
/// gracefully (still show the human-readable code) instead of taking the
/// whole claim screen down over a QR-rendering failure.
pub fn render_unicode(payload: &[u8]) -> Option<String> {
    let code = QrCode::new(payload).ok()?;
    Some(
        code.render::<unicode::Dense1x2>()
            .quiet_zone(true)
            .module_dimensions(1, 1)
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_short_payload_deterministically() {
        let a = render_unicode(b"benix-claim://v1?s=8HXTGJ2K913MZQPVDCRWN4B6ES").unwrap();
        let b = render_unicode(b"benix-claim://v1?s=8HXTGJ2K913MZQPVDCRWN4B6ES").unwrap();
        assert_eq!(a, b, "same payload must render identically every time");
    }

    #[test]
    fn different_payloads_render_differently() {
        let a = render_unicode(b"benix-claim://v1?s=AAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let b = render_unicode(b"benix-claim://v1?s=ZZZZZZZZZZZZZZZZZZZZZZZZZZ").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn fits_comfortably_within_the_160x50_console() {
        // The real claim-uri length this crate actually produces (§9rr):
        // "benix-claim://v1?s=" (20 bytes) + a 26-character Crockford
        // secret, unpadded.
        let payload = b"benix-claim://v1?s=8HXTGJ2K913MZQPVDCRWN4B6ES";
        let block = render_unicode(payload).unwrap();
        let lines: Vec<&str> = block.lines().collect();
        assert!(!lines.is_empty());
        let width = lines[0].chars().count();
        // Every line must be the same width — a ragged block is a bug.
        assert!(lines.iter().all(|l| l.chars().count() == width));
        assert!(
            width <= 160,
            "QR block width {width} must fit the 160-column console"
        );
        assert!(
            lines.len() <= 50,
            "QR block height {} must fit the 50-row console",
            lines.len()
        );
        // Named as a concrete regression pin, not just a bound: a version-3
        // QR (the size this exact payload length produces at EC level M)
        // renders to 37x19 with this renderer's quiet-zone/module settings.
        assert_eq!(width, 37);
        assert_eq!(lines.len(), 19);
    }

    #[test]
    fn contains_only_expected_qr_glyphs_and_spaces() {
        let block = render_unicode(b"benix-claim://v1?s=8HXTGJ2K913MZQPVDCRWN4B6ES").unwrap();
        for c in block.chars() {
            assert!(
                matches!(c, ' ' | '\n' | '\u{2580}' | '\u{2584}' | '\u{2588}'),
                "unexpected glyph {c:?} in rendered QR block"
            );
        }
    }

    #[test]
    fn empty_payload_still_renders_a_qr_code() {
        // Degenerate but valid input — the qrcode crate happily encodes an
        // empty byte string. Asserting this doesn't panic, not asserting
        // any particular shape.
        assert!(render_unicode(b"").is_some());
    }
}
