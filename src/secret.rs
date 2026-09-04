//! The local-only claim protocol's box-minted secret
//! (`context/projects/benixos.md` §9hh Item 1): 128 bits of CSPRNG entropy,
//! generated once and persisted until claimed, displayed to a human via
//! Crockford Base32 so an operator can read it off the box's screen/console
//! and type it into Courier. This secret is the *only* thing DJ's §9gg
//! ruling requires the box to show — it is never transmitted over the wire
//! in either direction (see `src/local_claim.rs`'s mutual-HMAC handshake,
//! which *proves* possession of these bytes instead of sending them).
//!
//! ## Entropy source
//!
//! `rand::rngs::OsRng` — the OS CSPRNG (`getrandom(2)`/`/dev/urandom`
//! equivalent), the exact same source `fabric_kit::DeviceKeypair::generate`
//! already uses (see that type's own source: `SigningKey::generate(&mut
//! rand::rngs::OsRng)`). `rand` 0.8 is therefore already resolved and
//! musl-proven in this crate's dependency tree (§9r's spike, `state.rs`'s
//! own `load_or_create_keypair` exercises the same transitive path) — this
//! module adds it as a *direct* dependency (Cargo requires that to `use` it
//! at all) but not a *new* one in the tree.
//!
//! ## Lifecycle
//!
//! Generated once on first run of an unclaimed box, persisted to
//! `<state_dir>/claim-secret` (mode `0600`, the exact write-then-rename
//! idiom `state.rs::write_private_atomic` already implements — reused here,
//! not reimplemented), reloaded on every subsequent start. **Deliberately
//! NOT regenerated on restart** while unclaimed: dinit's `restart = true`
//! crash-recovery, a boot loop, or an operator restart must keep displaying
//! and accepting the exact same code the user is looking at (§9hh's own
//! explicit requirement, answering §9gg's "a restart mid-onboarding
//! shouldn't silently invalidate a secret the user is looking at"). Deleted
//! by `state::delete_claim_secret` the instant a claim succeeds
//! (`src/local_claim.rs`) — single-use, by construction of the caller, not
//! by any expiry logic in this module. **No wall-clock expiry** — a
//! deliberate decision, not an omission; see §9hh Item 1's full reasoning
//! (a timer would silently kill a code a human is actively staring at on a
//! static serial-LCD/console display, which cannot be live-rotated).

use std::fs;
use std::io;
use std::path::Path;

use rand::rngs::OsRng;
use rand::RngCore;

use crate::state::write_private_atomic;

/// Filename under `<state_dir>`. `pub(crate)` so `state::
/// delete_claim_secret` (the consume-on-success / unclaim path) can name
/// the same file without this module needing to expose a delete operation
/// of its own — deletion is a claimed-state mutation, and `state.rs` is
/// where every other claimed-state mutation already lives.
pub(crate) const CLAIM_SECRET_FILENAME: &str = "claim-secret";

/// 128 bits, per §9hh Item 1: the *floor* data-architect set for the
/// non-secret mDNS `id` (§9w) applied to an actual credential, which must
/// not be weaker than the discovery handle it sits alongside.
const SECRET_LEN: usize = 16;

/// Crockford's own alphabet: excludes `I`/`L`/`O`/`U` to avoid `1`/`0`
/// visual ambiguity and accidental words — chosen in §9hh specifically for
/// a human retyping a code off a serial LCD or console, where hex's `0`/`O`
/// and `1`/`I`/`l` ambiguity is a real transcription hazard.
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// `ceil(128 bits / 5 bits-per-symbol)` — the last symbol carries 3 real
/// bits and 2 zero-padding bits.
const ENCODED_LEN: usize = 26;

/// Load the box's persisted 128-bit local-claim secret, generating and
/// persisting a fresh one on first run if absent — the same
/// generate-once-then-reload-forever posture as
/// [`crate::state::load_or_create_keypair`], and for the same "treat an
/// empty/invalid file as missing" recovery posture on a corrupt read.
pub fn load_or_create_secret(state_dir: &Path) -> io::Result<[u8; SECRET_LEN]> {
    let path = state_dir.join(CLAIM_SECRET_FILENAME);
    if let Ok(bytes) = fs::read(&path) {
        if let Ok(secret) = <[u8; SECRET_LEN]>::try_from(bytes.as_slice()) {
            return Ok(secret);
        }
        // Wrong length: fall through and regenerate, same posture
        // `load_or_create_keypair` takes on a corrupt device-key file.
    }

    let mut secret = [0u8; SECRET_LEN];
    OsRng.fill_bytes(&mut secret);
    write_private_atomic(&path, &secret)?;
    Ok(secret)
}

/// Render `secret` for a human to read: unpadded Crockford Base32, grouped
/// `XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX` (26 characters total, in 4 groups of 5
/// plus a final group of 6). One encoding serves both the plain-text
/// console/serial-LCD path and a future QR bitmap (the QR carries the same
/// 26-character string; QR rendering itself is a display concern, not a
/// protocol concern — see `src/render.rs`).
pub fn encode_display(secret: &[u8; SECRET_LEN]) -> String {
    let raw = encode_crockford(secret);
    debug_assert_eq!(raw.len(), ENCODED_LEN);
    format!(
        "{}-{}-{}-{}-{}",
        &raw[0..5],
        &raw[5..10],
        &raw[10..15],
        &raw[15..20],
        &raw[20..26]
    )
}

/// Parse a human-typed code back to its raw 16 secret bytes.
/// Case-insensitive; tolerant of the display's own `-` group separators and
/// incidental whitespace, so `XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`,
/// `xxxxxxxxxxxxxxxxxxxxxxxxxx` (no separators), and a version with stray
/// spaces all decode identically. Also tolerates Crockford's own documented
/// decode leniency (`O` reads as `0`; `I`/`L` read as `1`) — the exact
/// ambiguity the encode alphabet was chosen to avoid *producing*, forgiven
/// on the way back in for a human who transcribes one anyway. `None` on any
/// other malformed input (wrong length after stripping separators, or a
/// character outside the Crockford alphabet).
///
/// Not called anywhere in *this* binary's own production path today — this
/// box only ever `encode_display`s its own secret; the party that ever
/// needs to `decode` one back is Courier, in a different repo. Kept here
/// (rather than deleted as "unused") as the documented, tested reference
/// implementation of `encode_display`'s exact inverse, so a Courier-side
/// implementer has a real, round-trip-tested algorithm to match — see this
/// module's own test suite below.
#[allow(dead_code)]
pub fn decode(input: &str) -> Option<[u8; SECRET_LEN]> {
    let cleaned: Vec<char> = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if cleaned.len() != ENCODED_LEN {
        return None;
    }

    let mut buffer: u32 = 0;
    let mut bits_in_buffer: u32 = 0;
    let mut out = Vec::with_capacity(SECRET_LEN);
    for c in cleaned {
        let value = crockford_value(c)? as u32;
        buffer = (buffer << 5) | value;
        bits_in_buffer += 5;
        if bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            out.push(((buffer >> bits_in_buffer) & 0xFF) as u8);
        }
    }

    if out.len() != SECRET_LEN {
        return None;
    }
    let mut secret = [0u8; SECRET_LEN];
    secret.copy_from_slice(&out);
    Some(secret)
}

/// The encode half of Crockford Base32: a plain 5-bits-per-symbol bit-stream
/// chunker, zero-padded on the final partial group (there is no `=`
/// padding character in Crockford — the padding is implicit zero bits
/// absorbed into the last symbol).
fn encode_crockford(bytes: &[u8; SECRET_LEN]) -> String {
    let mut output = String::with_capacity(ENCODED_LEN);
    let mut buffer: u32 = 0;
    let mut bits_in_buffer: u32 = 0;
    for &byte in bytes.iter() {
        buffer = (buffer << 8) | byte as u32;
        bits_in_buffer += 8;
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = (buffer >> bits_in_buffer) & 0x1F;
            output.push(CROCKFORD_ALPHABET[index as usize] as char);
        }
    }
    if bits_in_buffer > 0 {
        let index = (buffer << (5 - bits_in_buffer)) & 0x1F;
        output.push(CROCKFORD_ALPHABET[index as usize] as char);
    }
    output
}

/// `decode`'s own helper — dead in this binary's production path for
/// exactly the same reason `decode` itself is; see that function's doc
/// comment.
#[allow(dead_code)]
fn crockford_value(c: char) -> Option<u8> {
    let upper = c.to_ascii_uppercase();
    match upper {
        'O' => Some(0),
        'I' | 'L' => Some(1),
        other => CROCKFORD_ALPHABET
            .iter()
            .position(|&b| b as char == other)
            .map(|i| i as u8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("benix-claim-agent-secret-test-{}", Uuid::new_v4()))
    }

    #[test]
    fn generates_and_persists_secret_on_first_run() {
        let dir = temp_dir();
        let s1 = load_or_create_secret(&dir).expect("first load creates a secret");
        let s2 = load_or_create_secret(&dir).expect("second load reads the persisted secret");
        assert_eq!(
            s1, s2,
            "a restart must not silently rotate the displayed code"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn secret_file_is_owner_only() {
        let dir = temp_dir();
        load_or_create_secret(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(dir.join(CLAIM_SECRET_FILENAME)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn display_encoding_is_five_groups_twenty_six_chars() {
        let secret = [0xAB; SECRET_LEN];
        let display = encode_display(&secret);
        let groups: Vec<&str> = display.split('-').collect();
        assert_eq!(groups.len(), 5);
        assert_eq!(groups[0].len(), 5);
        assert_eq!(groups[1].len(), 5);
        assert_eq!(groups[2].len(), 5);
        assert_eq!(groups[3].len(), 5);
        assert_eq!(groups[4].len(), 6);
        assert_eq!(display.chars().filter(|c| *c != '-').count(), 26);
    }

    #[test]
    fn round_trips_through_encode_and_decode() {
        for seed in 0u8..20 {
            let mut secret = [0u8; SECRET_LEN];
            for (i, b) in secret.iter_mut().enumerate() {
                *b = seed.wrapping_mul(7).wrapping_add(i as u8);
            }
            let display = encode_display(&secret);
            let decoded = decode(&display).expect("a freshly encoded code must decode");
            assert_eq!(decoded, secret);
        }
    }

    #[test]
    fn decode_is_case_insensitive() {
        let secret = [0x42; SECRET_LEN];
        let display = encode_display(&secret);
        assert_eq!(decode(&display.to_lowercase()), Some(secret));
        assert_eq!(decode(&display.to_uppercase()), Some(secret));
        // Mixed case, human-typo-shaped.
        let mixed: String = display
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_lowercase()
                } else {
                    c
                }
            })
            .collect();
        assert_eq!(decode(&mixed), Some(secret));
    }

    #[test]
    fn decode_tolerates_missing_or_extra_separators_and_whitespace() {
        let secret = [0x99; SECRET_LEN];
        let display = encode_display(&secret);
        let no_dashes: String = display.chars().filter(|c| *c != '-').collect();
        assert_eq!(decode(&no_dashes), Some(secret));

        let spaced = display.replace('-', " ");
        assert_eq!(decode(&spaced), Some(secret));
    }

    #[test]
    fn decode_tolerates_crockford_o_i_l_substitution() {
        // Build a code, then swap in an occurrence of a substitutable
        // character if the alphabet ever produces one adjacent to our
        // test byte pattern — deterministic regardless via direct
        // construction: an all-zero-index-0 symbol is '0', which a human
        // might type as 'O'/'o'.
        let secret = [0x00; SECRET_LEN];
        let display = encode_display(&secret); // all '0' symbols
        assert!(display.contains('0'));
        let substituted = display.replace('0', "O");
        assert_eq!(decode(&substituted), Some(secret));
        let substituted_lower = display.replace('0', "o");
        assert_eq!(decode(&substituted_lower), Some(secret));
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(decode("TOO-SHORT"), None);
        assert_eq!(decode(""), None);
    }

    #[test]
    fn decode_rejects_invalid_alphabet_characters() {
        // 26 chars, but with a '$' outside the whole alphabet.
        let mut bogus = String::from("$");
        bogus.push_str(&"A".repeat(25));
        assert_eq!(bogus.len(), 26);
        assert_eq!(decode(&bogus), None);
    }
}
