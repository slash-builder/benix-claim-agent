//! On-disk persistence: the box's `DeviceKeypair`, its claimed/unclaimed
//! flag, the `PairCredentials` an approved claim yields, and the
//! `LocalAccountBinding` record. Reuses `benix-mdns-advertiser`'s state-dir
//! convention (default `/var/lib/benixos`, write-then-rename so a crash
//! mid-write never leaves a partial file for the next boot to read back)
//! but under this crate's own `BENIX_CLAIM_STATE_DIR` env var — a distinct
//! variable from the advertiser's `BENIX_MDNS_STATE_DIR`, same default
//! path, different filenames underneath it.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use fabric_kit::{DeviceKeypair, PairCredentials};
use serde::{Deserialize, Serialize};

use crate::local_account_binding::LocalAccountBinding;

const DEVICE_KEY_FILENAME: &str = "device-key";
const CLAIMED_FILENAME: &str = "claimed";
const PAIR_CREDENTIALS_FILENAME: &str = "pair-credentials";
const LOCAL_ACCOUNT_BINDING_FILENAME: &str = "local-account-binding";

/// Write `contents` to `path` via write-then-rename (same crash-safety
/// idiom as `benix-mdns-advertiser`'s `id.rs`), then restrict permissions
/// to owner-read-write-only — every file this module writes carries either
/// key material or claim-adjacent metadata that has no business being
/// world-readable.
fn write_private_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, contents)?;
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Load the box's persisted `DeviceKeypair`, generating and persisting a
/// fresh one on first run if absent. Local identity creation only — never
/// a claimed-state mutation (a box can hold an identity key long before
/// anyone claims it; see `src/handlers.rs`'s fail-closed guard, which is
/// unaffected by whether this file exists).
pub fn load_or_create_keypair(state_dir: &Path) -> io::Result<DeviceKeypair> {
    let path = state_dir.join(DEVICE_KEY_FILENAME);
    if let Ok(bytes) = fs::read(&path) {
        if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(DeviceKeypair::from_bytes(seed));
        }
        // Wrong length: treat like a missing/corrupt file and regenerate,
        // same "empty/invalid is missing" posture as the advertiser's
        // id.rs.
    }

    let keypair = DeviceKeypair::generate();
    write_private_atomic(&path, &keypair.to_bytes())?;
    Ok(keypair)
}

/// `true` if this box's persisted state says `claimed`. The sole
/// authority the fail-closed guard checks — never the mDNS advertiser's
/// own advisory `claimed` TXT field (that field is explicitly documented
/// there as never authoritative).
pub fn is_claimed(state_dir: &Path) -> bool {
    state_dir.join(CLAIMED_FILENAME).exists()
}

#[derive(Serialize, Deserialize)]
struct ClaimedMarker {
    claimed_at_ms: i64,
    device_id: String,
    account_id: String,
}

/// Flip local state to claimed. Called from exactly one place: the
/// background task's handling of `PairOutcome::Approved`, never from the
/// request-handling path itself (see `src/handlers.rs`).
pub fn mark_claimed(
    state_dir: &Path,
    device_id: &str,
    account_id: &str,
    at_ms: i64,
) -> io::Result<()> {
    let marker = ClaimedMarker {
        claimed_at_ms: at_ms,
        device_id: device_id.to_string(),
        account_id: account_id.to_string(),
    };
    let json = serde_json::to_vec_pretty(&marker)?;
    write_private_atomic(&state_dir.join(CLAIMED_FILENAME), &json)
}

/// On-disk shape for `PairCredentials`. Not `fabric_kit::PairCredentials`
/// itself — that type deliberately implements neither `Serialize` nor a
/// plain `Debug` (see its own doc comment: `bearer_token`, `resume_token`,
/// and `sealing_keypair` are redacted in its `Debug` impl by design). This
/// struct is this crate's own persistence boundary, not a workaround of
/// that redaction — the values still have to reach disk somewhere; they
/// just never reach a log line un-redacted (see `redacted_debug` below,
/// reused at every call site that logs a `PairCredentials`-shaped value).
#[derive(Serialize, Deserialize)]
struct PersistedPairCredentials {
    device_id: String,
    account_id: String,
    bearer_token: String,
    resume_token_hex: String,
    sealing_keypair_seed_hex: String,
}

/// Persist `PairCredentials` to `<state_dir>/pair-credentials`, mode 0600.
pub fn persist_pair_credentials(state_dir: &Path, creds: &PairCredentials) -> io::Result<()> {
    let persisted = PersistedPairCredentials {
        device_id: creds.device_id.clone(),
        account_id: creds.account_id.clone(),
        bearer_token: creds.bearer_token.clone(),
        resume_token_hex: hex::encode(&creds.resume_token),
        sealing_keypair_seed_hex: hex::encode(creds.sealing_keypair.to_bytes()),
    };
    let json = serde_json::to_vec_pretty(&persisted)?;
    write_private_atomic(&state_dir.join(PAIR_CREDENTIALS_FILENAME), &json)
}

/// Redacted, log-safe stand-in for `PairCredentials::Debug` (that impl
/// already redacts everything sensitive — this just gives call sites in
/// this crate a name to reach for without re-deriving the redaction
/// policy themselves). Reuses the upstream type's own `Debug`, per the
/// finalized contract's explicit instruction not to roll a second
/// redaction implementation.
pub fn redacted_debug(creds: &PairCredentials) -> String {
    format!("{creds:?}")
}

/// Persist the (stand-in-shaped, see `local_account_binding.rs`)
/// `LocalAccountBinding` record, mode 0600.
pub fn persist_local_account_binding(
    state_dir: &Path,
    binding: &LocalAccountBinding,
) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(binding)?;
    write_private_atomic(&state_dir.join(LOCAL_ACCOUNT_BINDING_FILENAME), &json)
}

/// Test-only accessors for the two on-disk paths this module doesn't
/// otherwise expose outside itself — production code has no reason to
/// know these filenames beyond `is_claimed`/`mark_claimed`'s own API.
#[cfg(test)]
pub fn pair_credentials_path(state_dir: &Path) -> PathBuf {
    state_dir.join(PAIR_CREDENTIALS_FILENAME)
}

#[cfg(test)]
pub fn local_account_binding_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LOCAL_ACCOUNT_BINDING_FILENAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fabric_kit::SealingKeypair;
    use uuid::Uuid;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("benix-claim-agent-state-test-{}", Uuid::new_v4()))
    }

    #[test]
    fn generates_and_persists_keypair_on_first_run() {
        let dir = temp_dir();
        let kp1 = load_or_create_keypair(&dir).expect("first load creates a key");
        let kp2 = load_or_create_keypair(&dir).expect("second load reads the persisted key");
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn device_key_file_is_owner_only() {
        let dir = temp_dir();
        load_or_create_keypair(&dir).unwrap();
        let meta = fs::metadata(dir.join(DEVICE_KEY_FILENAME)).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn is_claimed_false_until_marked() {
        let dir = temp_dir();
        fs::create_dir_all(&dir).unwrap();
        assert!(!is_claimed(&dir));
        mark_claimed(&dir, "device-1", "account-1", 1_700_000_000_000).unwrap();
        assert!(is_claimed(&dir));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pair_credentials_round_trip_via_persisted_shape() {
        let dir = temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let creds = PairCredentials {
            device_id: "device-1".to_string(),
            account_id: "account-1".to_string(),
            bearer_token: "top-secret".to_string(),
            resume_token: vec![9, 9, 9],
            sealing_keypair: SealingKeypair::generate(),
        };
        persist_pair_credentials(&dir, &creds).expect("persist");
        let raw = fs::read_to_string(pair_credentials_path(&dir)).unwrap();
        let persisted: PersistedPairCredentials = serde_json::from_str(&raw).unwrap();
        assert_eq!(persisted.device_id, "device-1");
        assert_eq!(persisted.bearer_token, "top-secret");
        assert_eq!(persisted.resume_token_hex, hex::encode([9, 9, 9]));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn redacted_debug_never_contains_the_bearer_token() {
        let creds = PairCredentials {
            device_id: "device-1".to_string(),
            account_id: "account-1".to_string(),
            bearer_token: "super-secret-value".to_string(),
            resume_token: vec![1, 2, 3],
            sealing_keypair: SealingKeypair::generate(),
        };
        let debug = redacted_debug(&creds);
        assert!(!debug.contains("super-secret-value"));
        assert!(debug.contains("device-1"));
    }
}
