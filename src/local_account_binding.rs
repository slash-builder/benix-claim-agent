//! `LocalAccountBinding` — the fabric-principal-to-box-local-identity
//! projection created the moment a claim's `PairOutcome::Approved` lands.
//!
//! **Stand-in, not a locked schema.** Checked before writing this, not
//! invented from nothing: `dlockamy/vault: context/kits.yaml`'s Identity
//! Kit entry records a real data-architect settlement for this record
//! (`kits.yaml`, "NEW RECORD, same settlement: `LocalAccountBinding`"),
//! but that settlement is conceptual — a field list and a key, not a
//! concrete Rust struct or an on-disk migration. Neither
//! `slash-builder/identity-kit` nor `slash-builder/substrate-kit` (the two
//! repos named as the places a concrete shape might already live) has one:
//! checked with `grep -rn LocalAccountBinding` against both before writing
//! this module, zero hits in either.
//!
//! So this module implements the minimum viable version of that settled
//! shape and nothing more, the same self-disclosure style
//! `benix-mdns-advertiser`'s `src/id.rs` uses for its own placeholder
//! `id` field: **do not treat this as the final `LocalAccountBinding`
//! shape.** It exists so `PairOutcome::Approved` has somewhere concrete to
//! land, not as this crate unilaterally deciding data-architect's call.
//! Flagged in this repo's README and PR description for the same reason.
//!
//! ## What's a real settlement here, and what's this crate's own filler
//!
//! From `kits.yaml`, real (not invented here): keyed `(host_id,
//! principal_id)`; fields `local_uid`, `local_username`, `account_class:
//! interactive | system`, `status: active | revoked`,
//! `created_at`/`revoked_at`; deliberately **no** `last_seen_at` or any
//! session/engagement field (vetoed studio-wide, non-engagement lock).
//!
//! This crate's own filler, because nothing upstream defines it yet:
//! - `host_id`: this box's hostname. A real box identity (decoupled from a
//!   mutable hostname) is exactly the kind of question `benix-mdns-
//!   advertiser`'s own `id.rs` flags as pending data-architect's Task #29
//!   — unresolved there, still unresolved here, not re-litigated in this
//!   crate.
//! - `local_uid`/`local_username`: this agent creates no actual POSIX
//!   user account (out of scope — see README "Explicitly out of scope").
//!   `local_uid` is `None` and `local_username` mirrors
//!   `proposed_device_name` until a real box-local-account mechanism
//!   exists to assign either for real.
//! - `schema_version`: not in `kits.yaml` at all; added here defensively
//!   so a future real schema can distinguish this stand-in's on-disk shape
//!   from its own.

use serde::{Deserialize, Serialize};

/// This stand-in's own on-disk schema version — bump if this module's
/// field set changes before a real schema supersedes it entirely.
pub const SCHEMA_VERSION: u32 = 0;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountClass {
    Interactive,
    System,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BindingStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAccountBinding {
    pub schema_version: u32,
    pub host_id: String,
    /// The fabric principal this binding projects — `PairCredentials::
    /// device_id` from the approved claim, per §9i's framing
    /// (`benix-claim-agent` is a principal; the box is a chassis, not a
    /// principal itself).
    pub principal_id: String,
    /// `None`: this crate creates no real POSIX account. See module docs.
    pub local_uid: Option<u32>,
    pub local_username: String,
    pub account_class: AccountClass,
    pub status: BindingStatus,
    pub created_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    /// The local-only claim protocol's owner credential
    /// (`context/projects/benixos.md` §9hh): the Ed25519 public key
    /// Courier proved possession-adjacent trust for during
    /// `POST /v1/onboard/local-claim/finish`, base64-encoded. `None` for a
    /// hub-mediated binding ([`new_active`](Self::new_active)) — that
    /// path's owner is the hub `account_id`/`principal_id` pair instead,
    /// not a bare public key. Routed to data-architect, same as every
    /// other field in this stand-in — not this crate's schema to
    /// finalize.
    #[serde(default)]
    pub owner_pubkey: Option<String>,
}

impl LocalAccountBinding {
    /// Build the binding this agent creates on `PairOutcome::Approved` (the
    /// **hub-mediated** path, §9j) — always fresh, always `Active`, never
    /// revoked at construction. See [`new_active_local`](Self::new_active_local)
    /// for the local-only claim protocol's (§9hh) counterpart.
    pub fn new_active(
        host_id: String,
        principal_id: String,
        local_username: String,
        created_at_ms: i64,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            host_id,
            principal_id,
            local_uid: None,
            local_username,
            account_class: AccountClass::Interactive,
            status: BindingStatus::Active,
            created_at_ms,
            revoked_at_ms: None,
            owner_pubkey: None,
        }
    }

    /// Build the binding the local-only claim protocol (§9hh) creates on a
    /// successful `POST /v1/onboard/local-claim/finish` — the local
    /// counterpart to [`new_active`](Self::new_active). There is no
    /// hub-assigned `principal_id` to project in this path (no hub is
    /// involved at all): `principal_id` is set to `owner_pubkey` itself,
    /// since the owner's public key *is* the principal this claim
    /// establishes (matching the studio's Ed25519-everywhere principal
    /// model — a fabric `device_id` is itself a public key).
    pub fn new_active_local(
        host_id: String,
        owner_pubkey: String,
        local_username: String,
        created_at_ms: i64,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            host_id,
            principal_id: owner_pubkey.clone(),
            local_uid: None,
            local_username,
            account_class: AccountClass::Interactive,
            status: BindingStatus::Active,
            created_at_ms,
            revoked_at_ms: None,
            owner_pubkey: Some(owner_pubkey),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_active_binding_round_trips_through_json() {
        let binding = LocalAccountBinding::new_active(
            "venus".to_string(),
            "device-abc123".to_string(),
            "benix-box".to_string(),
            1_700_000_000_000,
        );
        let json = serde_json::to_string(&binding).expect("serialize");
        let back: LocalAccountBinding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.host_id, "venus");
        assert_eq!(back.principal_id, "device-abc123");
        assert_eq!(back.status, BindingStatus::Active);
        assert!(back.revoked_at_ms.is_none());
        assert!(back.local_uid.is_none());
        assert!(back.owner_pubkey.is_none());
    }

    #[test]
    fn new_active_local_binding_records_owner_pubkey_as_the_principal() {
        let binding = LocalAccountBinding::new_active_local(
            "venus".to_string(),
            "QW5FeGFtcGxlUHVia2V5Qnl0ZXM=".to_string(),
            "benix-box".to_string(),
            1_700_000_000_000,
        );
        let json = serde_json::to_string(&binding).expect("serialize");
        let back: LocalAccountBinding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.host_id, "venus");
        assert_eq!(
            back.owner_pubkey.as_deref(),
            Some("QW5FeGFtcGxlUHVia2V5Qnl0ZXM=")
        );
        assert_eq!(back.principal_id, "QW5FeGFtcGxlUHVia2V5Qnl0ZXM=");
        assert_eq!(back.status, BindingStatus::Active);
    }
}
