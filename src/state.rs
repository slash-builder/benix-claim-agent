//! On-disk persistence: the box's `DeviceKeypair`, its claimed/unclaimed
//! flag, the `PairCredentials` an approved claim yields, and the
//! `LocalAccountBinding` record. Reuses `benix-mdns-advertiser`'s state-dir
//! convention (default `/var/lib/benixos`, write-then-rename so a crash
//! mid-write never leaves a partial file for the next boot to read back)
//! but under this crate's own `BENIX_CLAIM_STATE_DIR` env var — a distinct
//! variable from the advertiser's `BENIX_MDNS_STATE_DIR`, same default
//! path, different filenames underneath it.

use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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

/// Write `contents` to `path` via write-then-rename, hardened per
/// `context/projects/benixos.md` §9ii R5 (the QR-117 write-before-chmod
/// race class, made explicit and binding for `secret.rs`'s new
/// `claim-secret` file, and fixed here for every existing caller too since
/// they all share this one helper):
///
/// 1. The temp file is created **mode 0600 from the `open` call itself**
///    (`O_CREAT`, explicit `mode(0o600)`) — never
///    create-with-default-mode-then-`chmod`, which leaves a real (if
///    narrow) window where the file exists at a world/group-readable mode
///    before the follow-up `chmod` lands.
/// 2. The temp file lives in the **same directory** as the final path (via
///    [`Path::with_extension`], unchanged from before this hardening pass)
///    so the final [`fs::rename`] is a same-filesystem, atomic rename.
/// 3. The temp file's contents are `fsync`'d (`File::sync_all`) **before**
///    the rename, and the **parent directory** is `fsync`'d **after** —
///    without this, a crash mid-write (or right after an unsynced rename)
///    can leave the target either empty/partial or pointing at a stale
///    directory entry. For `secret.rs`'s caller specifically this is a
///    *correctness* requirement, not just hygiene: an unsynced crash could
///    make the box regenerate a **different** secret on the next boot,
///    silently breaking §9gg's "the same code the user is staring at
///    survives a restart" guarantee.
///
/// `pub(crate)` (not `pub`, not private): `src/secret.rs` reuses this exact
/// idiom for the local-claim secret rather than reimplementing it (§9hh's
/// own explicit instruction) — this module is still the one place that
/// owns "how a private state file gets written," `secret.rs` just also
/// needs to call it.
pub(crate) fn write_private_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "write_private_atomic: path has no parent directory",
        )
    })?;
    fs::create_dir_all(dir)?;
    // §9ii R5(4): the state directory itself is not world/group-traversable
    // — every file under it carries key material or claim-adjacent
    // metadata. (Ownership, i.e. "root-owned," is a deployment/dinit-unit
    // concern — which user this process runs as — not something this
    // in-process call can or should force via `chown`; see README's "Open,
    // routed rather than decided here.")
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

    let tmp_path = path.with_extension("tmp");
    let mut tmp_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)?;
    tmp_file.write_all(contents)?;
    tmp_file.sync_all()?;
    drop(tmp_file);

    fs::rename(&tmp_path, path)?;

    let dir_handle = fs::File::open(dir)?;
    dir_handle.sync_all()?;

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
    /// Hub-assigned identifiers from the hub-mediated claim (`mark_claimed`
    /// / `src/handlers.rs`). `None` for a local claim, which has no hub
    /// identity to record.
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    /// The local-only claim protocol's owner credential (§9hh): the
    /// requester's Ed25519 public key, base64-encoded. `None` for a
    /// hub-mediated claim (`mark_claimed`), whose owner is the hub
    /// `device_id`/`account_id` pair instead. Set only by
    /// `mark_claimed_local`.
    #[serde(default)]
    owner_pubkey: Option<String>,
}

/// Flip local state to claimed via the **hub-mediated** path (§9j). Called
/// from exactly one place: the background task's handling of
/// `PairOutcome::Approved`, never from the request-handling path itself
/// (see `src/handlers.rs`). See [`mark_claimed_local`] for the local-only
/// claim protocol's (§9hh) counterpart — distinct because a local claim has
/// no hub-assigned `device_id`/`account_id` to record.
pub fn mark_claimed(
    state_dir: &Path,
    device_id: &str,
    account_id: &str,
    at_ms: i64,
) -> io::Result<()> {
    let marker = ClaimedMarker {
        claimed_at_ms: at_ms,
        device_id: Some(device_id.to_string()),
        account_id: Some(account_id.to_string()),
        owner_pubkey: None,
    };
    let json = serde_json::to_vec_pretty(&marker)?;
    write_private_atomic(&state_dir.join(CLAIMED_FILENAME), &json)
}

/// Flip local state to claimed via the **local-only** claim protocol
/// (§9hh): `owner_pubkey` (base64 Ed25519 public key) is recorded in place
/// of a hub `device_id`/`account_id` pair. Called from exactly one place:
/// `src/local_claim.rs`'s `finish` handler, on a verified mutual-HMAC
/// handshake — never speculatively, and never before `client_sig` has been
/// checked. Same on-disk marker file as [`mark_claimed`]; `is_claimed`
/// doesn't care which of the two wrote it.
pub fn mark_claimed_local(state_dir: &Path, owner_pubkey: &str, at_ms: i64) -> io::Result<()> {
    let marker = ClaimedMarker {
        claimed_at_ms: at_ms,
        device_id: None,
        account_id: None,
        owner_pubkey: Some(owner_pubkey.to_string()),
    };
    let json = serde_json::to_vec_pretty(&marker)?;
    write_private_atomic(&state_dir.join(CLAIMED_FILENAME), &json)
}

/// Delete `<state_dir>/claim-secret`. Called from exactly two places: the
/// local-claim `finish` handler's consume-on-success step (§9hh — the
/// secret is single-use), and (in a later pass, not this one — see §9hh
/// Item 1) a factory-reset/unclaim path, which must wipe this file
/// alongside `<state_dir>/mdns-id` per the same ownership-boundary rotation
/// contract §9w binds on the mDNS `id`. Idempotent: a missing file is not
/// an error (the caller may race a retry, or this may run on a box that
/// was never actually unclaimed-with-a-secret in the first place).
pub fn delete_claim_secret(state_dir: &Path) -> io::Result<()> {
    match fs::remove_file(state_dir.join(crate::secret::CLAIM_SECRET_FILENAME)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
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
