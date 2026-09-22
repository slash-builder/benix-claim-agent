//! TPM 2.0 dictionary-attack (DA) lockout custody: the `lockoutAuth`
//! discard step R2 requires at claim
//! (`context/hot-decisions.md` "Standalone-first identity" —
//! "`benix-claim-agent` sets the TPM `lockoutAuth` to random bytes and
//! discards it at claim"). Full design, the exhaustion-cost math, and the
//! AMD fTPM/faulTPM caveat live in `working-memory-poc`'s
//! `findings/W4-G-key-custody.md`; the concrete `tpm2-tools` recipe this
//! module's [`SystemTpm`] follows is
//! `spikes/key-custody/tpm2/venus-tpm2-sketch.sh`'s T0 (detect)/T1
//! (`tpm2_changeauth -c lockout ...`) steps — **neither was run against
//! real hardware in this pass**: venus's SSH host key isn't pinned yet
//! (W4-G's own escalation to devops-engineer), and this crate must not
//! bypass host-key verification or touch a real device/TPM. `swtpm` is not
//! installed in this environment either (checked: `which swtpm`), so there
//! is no local integration target — see this crate's README for what's
//! still owed on real hardware.
//!
//! ## The one property this module exists to hold
//!
//! The TPM's own DA counter (`failedTries`, incremented on every wrong
//! `authValue`, `TPM_RC_LOCKOUT` at `maxTries`) only protects a member if
//! `lockoutAuth` is neither empty nor known to device-root: otherwise
//! `tpm2_dictionarylockout -c` resets the counter and the limit is void
//! (W4-G, "The one setting that decides everything"). The counter is also
//! **device-global, not per-principal** — one member's typos, or
//! device-root's guessing, locks out every member for up to
//! `recoveryTime`; that doesn't change here, and nothing in this module
//! claims otherwise. This module closes exactly the "root can reset it"
//! hole, once, at claim, by making `lockoutAuth` unknown to anyone,
//! including this process.
//!
//! [`TpmLockout::discard_lockout_auth`] sets `lockoutAuth` to 32 bytes of
//! CSPRNG output and never returns, logs, or persists them: the trait
//! signature itself has no path for the bytes to reach a caller (there is
//! no `-> WrappedKey`/`-> [u8; 32]` return), so `local_claim.rs`'s claim-
//! completion step is structurally unable to leak them, not merely
//! disciplined not to. The trade-off is honest and irreversible — a later
//! `TPM2_Clear` needs the platform/firmware hierarchy (a BIOS-level "clear
//! TPM"), which wipes every sealed key on the device — and that is the
//! point (W4-G: "acceptable, and fail-closed").
//!
//! ## Why a trait
//!
//! Real TPM access means shelling out to `tpm2-tools` against a resource-
//! managed device node. That's neither available nor safe to exercise in
//! this session, so `TpmLockout` is the seam: `local_claim.rs`'s claim-
//! completion step is unit-tested against [`MockTpm`], never against
//! [`SystemTpm`] directly. [`SystemTpm`] is written here so the shape
//! exists and compiles, but its own correctness against a real TPM is
//! explicitly **not verified by this pass** — see this crate's README.

use rand::rngs::OsRng;
use rand::RngCore;

/// Whether a TPM 2.0 was found on this box at claim time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmPresence {
    Present,
    Absent,
}

/// Deliberately generic: never carries the attempted `lockoutAuth` value,
/// a byte count, a hex prefix, or anything else derived from it — every
/// variant's `Display` must stay safe to hand straight to `tracing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmError {
    /// The lockout-hierarchy `TPM2_ChangeAuth` call itself failed (wrong
    /// state, `lockoutAuth` already set and unknown to this process, or a
    /// real hardware/driver error). The caller MUST treat this as a
    /// claim-aborting failure — see `local_claim.rs`'s claim-completion
    /// step, which never marks a box claimed on this path.
    ChangeAuthFailed,
}

impl std::fmt::Display for TpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TpmError::ChangeAuthFailed => write!(f, "tpm lockout changeauth failed"),
        }
    }
}

/// The seam `local_claim.rs`'s claim-completion step calls through.
/// Implemented by [`SystemTpm`] (real hardware, not exercised in this
/// pass) and [`MockTpm`] (tests). `Send` because it lives behind
/// `AppState`'s `Mutex<Box<dyn TpmLockout>>`, shared across the async
/// handlers `Arc<AppState>` reaches.
pub trait TpmLockout: Send {
    /// Cheap and read-only: is a TPM 2.0 present on this box? Must never
    /// mutate any TPM state, and must never touch `lockoutAuth`.
    fn detect(&self) -> TpmPresence;

    /// Set `lockoutAuth` to 32 bytes of CSPRNG output and discard them
    /// within this same call — no implementation may return, log, or
    /// persist the bytes, on success or on failure.
    fn discard_lockout_auth(&mut self) -> Result<(), TpmError>;
}

/// Real backend: shells out to `tpm2-tools` against the resource-managed
/// device node, mirroring `spikes/key-custody/tpm2/venus-tpm2-sketch.sh`'s
/// T0 (detect) and T1 (`tpm2_changeauth -c lockout ...`) steps. **Not run
/// against real hardware in this session** — see this module's own doc
/// comment and this crate's README "Open, routed rather than decided
/// here" for what a real venus run still owes (T0 read-only first, to
/// confirm an fTPM/dTPM and read `lockoutAuthSet`, per W4-G's own
/// escalation to devops-engineer).
///
/// **Known limitation, flagged not fixed in this pass**: the generated
/// bytes exist as a `String` (hex, for the one `tpm2_changeauth` CLI
/// argument they must become) for the duration of the subprocess call.
/// They are zeroed in the `[u8; 32]` source buffer immediately after
/// encoding and the `String` is dropped as soon as the call returns, but
/// Rust gives no guarantee that dropping a `String` actually overwrites
/// its heap allocation (no `zeroize`/`secrecy` dependency is added here to
/// close that gap — this backend is unexercised by this pass, and adding
/// a new dependency for it is a call for whoever next touches this crate's
/// musl job and real-hardware verification, not this pass).
pub struct SystemTpm {
    /// The resource-manager device node [`detect`](TpmLockout::detect)
    /// checks. A field, not a hardcoded constant, so a future `swtpm`-
    /// backed integration test could point this at a chardev without
    /// touching real hardware — unused by this session's own test suite
    /// (no `swtpm` binary available here; `MockTpm` is what exercises the
    /// trait instead).
    device_node: std::path::PathBuf,
}

impl SystemTpm {
    pub fn new() -> Self {
        Self {
            device_node: std::path::PathBuf::from("/dev/tpmrm0"),
        }
    }
}

impl Default for SystemTpm {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmLockout for SystemTpm {
    fn detect(&self) -> TpmPresence {
        if self.device_node.exists() {
            TpmPresence::Present
        } else {
            TpmPresence::Absent
        }
    }

    fn discard_lockout_auth(&mut self) -> Result<(), TpmError> {
        let mut lockout_auth = [0u8; 32];
        OsRng.fill_bytes(&mut lockout_auth);
        let hex_auth = format!("hex:{}", hex::encode(lockout_auth));
        lockout_auth.fill(0);

        // tpm2_dictionarylockout -s -n 10 -t 7200 -l 86400 (the DA policy
        // itself) is provisioning, not claim-time, and is deliberately not
        // run here — this call only ever touches lockoutAuth, the one
        // setting R2 is scoped to. See venus-tpm2-sketch.sh's own T1 for
        // the full provisioning sequence this backend does not replicate.
        let result = std::process::Command::new("tpm2_changeauth")
            .args(["-c", "lockout", &hex_auth])
            .output();
        // Nothing below this line may reference `hex_auth` again.
        drop(hex_auth);

        match result {
            Ok(output) if output.status.success() => Ok(()),
            _ => Err(TpmError::ChangeAuthFailed),
        }
    }
}

/// Test-only backend. Presence and the change-auth outcome are configured
/// up front; `discard_calls` records how many times
/// [`discard_lockout_auth`](TpmLockout::discard_lockout_auth) actually ran
/// — tests use it to prove the TPM step happened (and happened exactly
/// once) as part of claim completion, not that it merely compiled.
///
/// Holds the same discipline the trait requires of a real backend: even
/// though this is test code, `discard_lockout_auth` never stores the bytes
/// it generates anywhere `self` (or a caller) can read back — there is
/// nothing here for a "never logged/persisted" test to accidentally pass
/// by reading a field that shouldn't exist on a real backend either.
#[cfg(test)]
pub struct MockTpm {
    presence: TpmPresence,
    fail_change_auth: bool,
    /// `Arc<AtomicU32>`, not a plain field: once `self` is moved into
    /// `AppState::tpm`'s `Box<dyn TpmLockout>`, a test has no other way to
    /// keep reading the call count — see
    /// [`discard_call_counter`](Self::discard_call_counter).
    discard_calls: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

#[cfg(test)]
impl MockTpm {
    pub fn present() -> Self {
        Self::new(TpmPresence::Present, false)
    }

    /// A TPM is present, but the `TPM2_ChangeAuth` call itself fails
    /// (hardware/driver error, or `lockoutAuth` already set to something
    /// this process doesn't know) — models the claim-aborting failure
    /// path.
    pub fn present_but_failing() -> Self {
        Self::new(TpmPresence::Present, true)
    }

    pub fn absent() -> Self {
        Self::new(TpmPresence::Absent, false)
    }

    fn new(presence: TpmPresence, fail_change_auth: bool) -> Self {
        Self {
            presence,
            fail_change_auth,
            discard_calls: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    /// A cloneable, independently-readable handle to this mock's call
    /// counter — take a clone before handing `self` to `AppState::tpm`
    /// (which erases it behind `Box<dyn TpmLockout>`), then read it after
    /// the claim request completes to prove
    /// [`discard_lockout_auth`](TpmLockout::discard_lockout_auth) actually
    /// ran (and ran exactly once) as part of claim completion.
    pub fn discard_call_counter(&self) -> std::sync::Arc<std::sync::atomic::AtomicU32> {
        self.discard_calls.clone()
    }
}

#[cfg(test)]
impl TpmLockout for MockTpm {
    fn detect(&self) -> TpmPresence {
        self.presence
    }

    fn discard_lockout_auth(&mut self) -> Result<(), TpmError> {
        self.discard_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail_change_auth {
            return Err(TpmError::ChangeAuthFailed);
        }
        // Model the real backend's own shape (generate, then immediately
        // discard) even though nothing here needs real entropy — proves
        // the mock isn't a no-op stand-in for what production code does.
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        bytes.fill(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn mock_present_discard_succeeds_and_counts_the_call() {
        let mut tpm = MockTpm::present();
        let counter = tpm.discard_call_counter();
        assert_eq!(tpm.detect(), TpmPresence::Present);
        assert_eq!(tpm.discard_lockout_auth(), Ok(()));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn mock_absent_reports_absence() {
        let tpm = MockTpm::absent();
        assert_eq!(tpm.detect(), TpmPresence::Absent);
    }

    #[test]
    fn mock_present_but_failing_returns_change_auth_failed() {
        let mut tpm = MockTpm::present_but_failing();
        let counter = tpm.discard_call_counter();
        assert_eq!(tpm.discard_lockout_auth(), Err(TpmError::ChangeAuthFailed));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn tpm_error_display_never_embeds_byte_shaped_content() {
        // A cheap, permanent guard against a future variant regressing this:
        // the error surface must stay a fixed, safe string, never anything
        // built from the attempted lockoutAuth bytes.
        let msg = TpmError::ChangeAuthFailed.to_string();
        assert_eq!(msg, "tpm lockout changeauth failed");
    }

    #[test]
    fn system_tpm_absent_device_node_reports_absence() {
        // SystemTpm::new() always points at /dev/tpmrm0; this environment
        // has no TPM, so detect() must honestly report absence rather than
        // guessing present. Confirms the real backend's read-only detect
        // path is safe to construct and call even off-hardware.
        assert_eq!(SystemTpm::new().detect(), TpmPresence::Absent);
    }
}
