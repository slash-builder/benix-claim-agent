//! The claim-code display seam — deliberately named "a `render` seam, not
//! the final display renderer" in §9hh's own implementation spec
//! (`context/projects/benixos.md`). Today this is exactly one function that
//! prints to stdout, because dinit already routes this process's stdout to
//! the box's console/serial output (§9h; VM 260's own `qm terminal`/
//! `-serial` side-channel already proves this text path works, no new
//! engineering needed for the dev/VM case). A production unit's physical
//! LCD, or a QR/framebuffer renderer for hardware with a screen, is a
//! *display* concern, not a *protocol* concern (§9gg item 1) — swapping
//! either in later means giving [`display_claim_code`] a different body (or
//! adding a second implementation this module dispatches to), not touching
//! `secret.rs` or `local_claim.rs` at all.

/// Show `code` (the Crockford-Base32, grouped display string from
/// [`crate::secret::encode_display`]) to whoever can see this box's
/// console. Called exactly once, at startup, only while the box is
/// unclaimed (see `main.rs`) — a claimed box has nothing left to display.
///
/// Uses `println!` rather than `tracing::info!` deliberately: this is a
/// user-facing instruction, not a diagnostic log line, and must reach the
/// console regardless of `RUST_LOG`'s configured level.
pub fn display_claim_code(code: &str) {
    println!(
        "\n================================================================\n\
         BenixOS box is UNCLAIMED.\n\
         \n\
         To claim it, open Courier and enter this code when prompted:\n\
         \n\
         \x20   {code}\n\
         \n\
         This code stays valid until the box is claimed.\n\
         ================================================================\n"
    );
}
