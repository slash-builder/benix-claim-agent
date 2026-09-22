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

/// R2 (`context/hot-decisions.md` "Standalone-first identity";
/// `working-memory-poc`'s `findings/W4-G-key-custody.md`): whether this
/// box's TPM 2.0 `lockoutAuth` was randomized and discarded as part of
/// claim completion. Recorded so the state a box actually claimed in is
/// visible later — never a byte of the discarded value itself, which no
/// part of this crate ever holds past `crate::tpm::TpmLockout::
/// discard_lockout_auth`'s own call frame (see that module's doc comment).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TpmCustodyState {
    /// A TPM 2.0 was present at claim time and its `lockoutAuth` was set
    /// to CSPRNG bytes and discarded in the same claim-completion step —
    /// device-root can no longer reset the TPM's dictionary-attack
    /// counter, so it becomes a real (if device-global, not
    /// per-principal — W4-G) hardware attempt limit.
    LockoutDiscarded,
    /// No TPM 2.0 was detected at claim time. This is recorded, not
    /// treated as a claim failure (a box with no TPM is still a valid
    /// claim) — but it means this box has no hardware attempt-limit
    /// backstop: a software key-wrap backend here is `offline_guessable`
    /// (W4-G's `CustodyProperties`) and callers must not treat it as
    /// DA-protected.
    NoTpmPresent,
}

/// R1/R2 (`context/hot-decisions.md` "Standalone-first identity"): a
/// device's owner is always a **person**, never a household — "device-root
/// is a capability grant held by that owner, delegable ... to one
/// household or to individuals." This crate's own owner fields
/// (`principal_id`, `owner_pubkey` below) already carry a person's
/// identity by construction (a hub `account_id`, or the Ed25519 public key
/// Courier proved possession-adjacent trust for — never a household id),
/// so this type isn't a new owner representation; it's the typed hook for
/// the *separate* record R2 requires: delegating some of that ownership to
/// a household.
///
/// **No grant store exists for this crate to write to.** Checked before
/// adding this: `slash-builder/identity-kit` has `family`/`authz` modules
/// with household/grant-shaped concepts (`FamilyClient`,
/// `JoinHouseholdRequest`, `Capabilities`), but this crate has no
/// dependency on `identity-kit` today, and wiring one in is a real
/// cross-Kit dependency decision this scoped pass doesn't make
/// unilaterally. So this stays a typed hook: the shape a household
/// delegation grant would take if/when a real store exists, always `None`
/// today, and never populated by any code in this crate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HouseholdDelegationGrant {
    /// The household this owner has delegated a scoped set of device-root
    /// to. Matches the shared data model's `household.hid` (`retired ids
    /// are never reused`) — a plain string here since this crate has no
    /// household type of its own to borrow.
    pub household_id: String,
    /// The scoped capability set delegated (R2: "install, users, network,
    /// updates"), not full device-root. Free-form strings rather than a
    /// closed enum — this crate doesn't own that vocabulary, and
    /// inventing one here would be exactly the kind of Kit-logic fork the
    /// studio convention forbids.
    pub scope: Vec<String>,
    pub granted_at_ms: i64,
}

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
    /// R2: this box's TPM custody state as of claim completion. `None` for
    /// [`new_active`](Self::new_active) (the hub-mediated path) — that
    /// path never establishes *initial* ownership on an unclaimed box
    /// (§9ii R4), so whatever TPM custody step ran already happened during
    /// the local claim that necessarily preceded it; this binding record
    /// simply doesn't repeat it. Recorded only by
    /// [`new_active_local`](Self::new_active_local), which is where
    /// initial ownership — and the TPM step — actually happens. See
    /// `crate::tpm` for the trait this state comes from.
    #[serde(default)]
    pub tpm_custody: Option<TpmCustodyState>,
    /// R1/R2 typed hook, always `None` today — see
    /// [`HouseholdDelegationGrant`]'s own doc comment for why.
    #[serde(default)]
    pub household_delegation: Option<HouseholdDelegationGrant>,
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
            tpm_custody: None,
            household_delegation: None,
        }
    }

    /// Build the binding the local-only claim protocol (§9hh) creates on a
    /// successful `POST /v1/onboard/local-claim/finish` — the local
    /// counterpart to [`new_active`](Self::new_active). There is no
    /// hub-assigned `principal_id` to project in this path (no hub is
    /// involved at all): `principal_id` is set to `owner_pubkey` itself,
    /// since the owner's public key *is* the principal this claim
    /// establishes (matching the studio's Ed25519-everywhere principal
    /// model — a fabric `device_id` is itself a public key). `tpm_custody`
    /// is required (not optional) here because this is the one path where
    /// initial ownership, and the R2 TPM step, actually happen —
    /// `local_claim.rs`'s claim-completion step has always already decided
    /// it (`TpmCustodyState::LockoutDiscarded` or `NoTpmPresent`) by the
    /// time this constructor runs.
    pub fn new_active_local(
        host_id: String,
        owner_pubkey: String,
        local_username: String,
        created_at_ms: i64,
        tpm_custody: TpmCustodyState,
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
            tpm_custody: Some(tpm_custody),
            household_delegation: None,
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
        assert!(
            back.tpm_custody.is_none(),
            "the hub-mediated path doesn't repeat the local claim's TPM step"
        );
        assert!(back.household_delegation.is_none());
    }

    #[test]
    fn new_active_local_binding_records_owner_pubkey_as_the_principal() {
        let binding = LocalAccountBinding::new_active_local(
            "venus".to_string(),
            "QW5FeGFtcGxlUHVia2V5Qnl0ZXM=".to_string(),
            "benix-box".to_string(),
            1_700_000_000_000,
            TpmCustodyState::LockoutDiscarded,
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
        assert_eq!(back.tpm_custody, Some(TpmCustodyState::LockoutDiscarded));
        // R1: the owner named on the claim record is a person (a bare
        // account/principal id), never a household — and no delegation
        // exists yet, since this crate has no grant store to write one to.
        assert!(back.household_delegation.is_none());
    }

    #[test]
    fn no_tpm_present_is_recorded_not_treated_as_a_failure() {
        let binding = LocalAccountBinding::new_active_local(
            "venus".to_string(),
            "QW5FeGFtcGxlUHVia2V5Qnl0ZXM=".to_string(),
            "benix-box".to_string(),
            1_700_000_000_000,
            TpmCustodyState::NoTpmPresent,
        );
        assert_eq!(binding.status, BindingStatus::Active);
        assert_eq!(binding.tpm_custody, Some(TpmCustodyState::NoTpmPresent));
    }

    #[test]
    fn tpm_custody_serializes_as_a_bare_tag_never_a_byte_payload() {
        // Guards the property `crate::tpm`'s doc comment leans on: there is
        // no field anywhere in this record shaped to hold the discarded
        // lockoutAuth bytes. If a future edit adds one, this test's
        // hardcoded expected JSON breaks loudly.
        let json = serde_json::to_string(&TpmCustodyState::LockoutDiscarded).unwrap();
        assert_eq!(json, "\"lockout_discarded\"");
        let json = serde_json::to_string(&TpmCustodyState::NoTpmPresent).unwrap();
        assert_eq!(json, "\"no_tpm_present\"");
    }
}
