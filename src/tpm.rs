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
//! This module was revised once already, against the Wave C security
//! review of the first version (`wiki/reports/
//! standalone-first-wave-c-security-2026-09-22.md`, "CA-1" through "CA-4"
//! below) — every doc comment citing "CA-N" is that review's finding, not
//! a design choice invented here.
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
//! disciplined not to. **CA-1/CA-2 (Wave C):** a value that reaches argv,
//! or that sits unzeroized in a heap allocation, has not actually been
//! discarded — an audit log or a debugger attached to this process would
//! still see it. [`SystemTpm::discard_lockout_auth`] generates into a
//! `Zeroizing<[u8; 32]>`, never encodes the bytes into a `String`, and
//! hands them to `tpm2_changeauth` over the child process's stdin
//! (`file:-`), never as a command-line argument.
//!
//! The trade-off is honest and irreversible — a later `TPM2_Clear` needs
//! the platform/firmware hierarchy (a BIOS-level "clear TPM"), which wipes
//! every sealed key on the device — and that is the point (W4-G:
//! "acceptable, and fail-closed").
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

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// Whether — and how safely — a TPM 2.0 was found on this box at claim
/// time.
///
/// **CA-4 (Wave C):** the first version of this module collapsed "no TPM
/// hardware" and "a TPM exists but this backend can't reach it" into the
/// same `Absent` outcome. That's a silent downgrade: a box whose resource-
/// manager device is missing, unbound, or permission-denied would record
/// `NoTpmPresent` and proceed with no DA backstop, exactly as if it had no
/// TPM at all. [`PresentButUnavailable`](TpmPresence::PresentButUnavailable)
/// exists so the caller can refuse to proceed instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmPresence {
    /// This backend's resource-managed device node opened successfully —
    /// safe to call [`discard_lockout_auth`](TpmLockout::discard_lockout_auth).
    Present,
    /// No TPM hardware signal was found at all (no sysfs `tpm` class
    /// device, no raw `/dev/tpm*` node). A genuinely TPM-less box — safe to
    /// record [`TpmCustodyState::NoTpmPresent`][ncs] and proceed; there is
    /// nothing this backend could have reached anyway.
    ///
    /// [ncs]: crate::local_account_binding::TpmCustodyState::NoTpmPresent
    Absent,
    /// Hardware-presence signals exist (a sysfs `tpm` class device, or a
    /// raw `/dev/tpm0`), but the resource-managed device node this backend
    /// actually needs is missing or not accessible (e.g. permission
    /// denied). **The caller MUST treat this as a claim-aborting failure,
    /// the same as a `discard_lockout_auth` error** — never fall back to
    /// `Absent`.
    PresentButUnavailable,
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
    /// Cheap and read-only: what TPM state is this box in? Must never
    /// mutate any TPM state, and must never touch `lockoutAuth`. See
    /// [`TpmPresence`]'s own doc comment for the three-way distinction
    /// callers must respect (CA-4).
    fn detect(&self) -> TpmPresence;

    /// Set `lockoutAuth` to 32 bytes of CSPRNG output and discard them
    /// within this same call — no implementation may return, log, or
    /// persist the bytes, on success or on failure, and no implementation
    /// may put them on a command line or in an environment variable
    /// (CA-1) or leave them in an unzeroized heap allocation (CA-2).
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
pub struct SystemTpm {
    /// The resource-manager device node this backend both probes in
    /// [`detect`](TpmLockout::detect) and pins explicitly via `--tcti` in
    /// [`discard_lockout_auth`](TpmLockout::discard_lockout_auth) (CA-3: an
    /// inherited `TPM2TOOLS_TCTI` could be pointed at a spoofed
    /// `swtpm`/software TCTI that returns success unconditionally). A
    /// field, not a hardcoded constant, so a future `swtpm`-backed
    /// integration test could point this at a chardev without touching
    /// real hardware — unused by this session's own test suite (no
    /// `swtpm` binary available here; `MockTpm` is what exercises the
    /// trait instead).
    resource_manager_node: PathBuf,
    /// CA-4: independent hardware-presence signals, consulted only when
    /// `resource_manager_node` itself doesn't open, so "no TPM" and "TPM
    /// present but the resource manager device is unavailable" are never
    /// conflated. The kernel's sysfs `tpm` class device and the raw
    /// (non-resource-managed) `/dev/tpm0` node are both independent of
    /// whether the resource-manager daemon/kernel driver for `tpmrm0`
    /// happens to be bound.
    hardware_signal_nodes: Vec<PathBuf>,
}

/// **Not verified against the real BenixOS image layout — this pass never
/// touched venus.** `tpm2-tools` packages typically install here on a
/// Debian/Yocto-derived rootfs, but confirm the actual installed path
/// before this backend is exercised for real (this crate's README "Open,
/// routed rather than decided here"). An absolute path is load-bearing
/// (CA-3): resolving through an inherited, attacker-influenced `PATH`
/// would let a spoofed binary claim success.
const TPM2_CHANGEAUTH_BIN: &str = "/usr/bin/tpm2_changeauth";

impl SystemTpm {
    pub fn new() -> Self {
        Self {
            resource_manager_node: PathBuf::from("/dev/tpmrm0"),
            hardware_signal_nodes: vec![
                PathBuf::from("/sys/class/tpm/tpm0"),
                PathBuf::from("/dev/tpm0"),
            ],
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
        // CA-4: open (read+write, the same access discard_lockout_auth's
        // subprocess will need), not just `Path::exists`, so a node that
        // exists but is permission-denied is distinguished from one that
        // opens cleanly — `exists()` alone can't tell those apart.
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.resource_manager_node)
        {
            Ok(_handle) => TpmPresence::Present,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if self.hardware_signal_nodes.iter().any(|p| p.exists()) {
                    // The kernel sees TPM hardware, but the resource
                    // manager node isn't there (driver/daemon not bound
                    // yet, or a genuinely broken image) — CA-4, never
                    // `Absent`.
                    TpmPresence::PresentButUnavailable
                } else {
                    TpmPresence::Absent
                }
            }
            // Any other failure to open an *existing* node — permission
            // denied is the expected real-world case — is the same
            // "present but unreachable" outcome, never `Absent`.
            Err(_) => TpmPresence::PresentButUnavailable,
        }
    }

    fn discard_lockout_auth(&mut self) -> Result<(), TpmError> {
        // CA-2: generated straight into a Zeroizing buffer, and never
        // copied into a String/Vec that wouldn't be zeroized on drop —
        // there is no hex encoding step to leave a second heap copy of.
        let mut lockout_auth: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *lockout_auth);

        // tpm2_dictionarylockout -s -n 10 -t 7200 -l 86400 (the DA policy
        // itself) is provisioning, not claim-time, and is deliberately not
        // run here — this call only ever touches lockoutAuth, the one
        // setting R2 is scoped to. See venus-tpm2-sketch.sh's own T1 for
        // the full provisioning sequence this backend does not replicate.
        //
        // CA-1: the new auth value is never a CLI argument. `file:-` tells
        // tpm2_changeauth to read the raw auth bytes from stdin instead —
        // this needs confirming against the tpm2-tools build actually
        // shipped on venus (flagged, not verified here; no real hardware
        // touched).
        // CA-3: an absolute path (never resolved through an inherited
        // `PATH`), `env_clear()` (no inherited `TPM2TOOLS_TCTI` or
        // anything else an attacker-controlled parent environment could
        // set), and `--tcti` pinned explicitly to the exact device node
        // `detect()` itself already checked.
        let tcti = format!("device:{}", self.resource_manager_node.display());
        let mut child = Command::new(TPM2_CHANGEAUTH_BIN)
            .env_clear()
            .args(["--tcti", &tcti, "-c", "lockout", "file:-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| TpmError::ChangeAuthFailed)?;

        let write_result = {
            let Some(mut stdin) = child.stdin.take() else {
                return Err(TpmError::ChangeAuthFailed);
            };
            // The Zeroizing buffer's contents go out over the pipe exactly
            // once, to this one child process's stdin — never to argv,
            // never to an env var, never logged. Dropping `stdin` here
            // closes the write end, so the child sees EOF and proceeds.
            stdin.write_all(&*lockout_auth)
        };
        // `lockout_auth` is zeroized on drop regardless of what happens
        // below (Zeroizing's whole purpose) — nothing past this point
        // needs to reference it again.
        drop(lockout_auth);

        if write_result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(TpmError::ChangeAuthFailed);
        }

        match child.wait() {
            Ok(status) if status.success() => Ok(()),
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

    /// CA-4: hardware detected, but this backend can't reach it (resource
    /// manager device missing/permission-denied). `discard_lockout_auth`
    /// is never expected to be called against this variant — the caller
    /// must abort on `detect()` alone — so it's configured to fail loudly
    /// if it somehow is.
    pub fn present_but_unavailable() -> Self {
        Self::new(TpmPresence::PresentButUnavailable, true)
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
        // Model the real backend's own shape (generate into a Zeroizing
        // buffer, then let it drop) even though nothing here needs real
        // entropy — proves the mock isn't a no-op stand-in for what
        // production code does.
        let bytes: Zeroizing<[u8; 32]> = {
            let mut b = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *b);
            b
        };
        drop(bytes);
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
    fn mock_present_but_unavailable_is_distinct_from_absent() {
        let tpm = MockTpm::present_but_unavailable();
        assert_eq!(tpm.detect(), TpmPresence::PresentButUnavailable);
        assert_ne!(tpm.detect(), TpmPresence::Absent);
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
        // SystemTpm::new() points at /dev/tpmrm0 plus the sysfs/raw
        // hardware-signal nodes; this environment (a Mac, no TPM at all)
        // has none of them, so detect() must honestly report absence
        // rather than guessing present or unavailable. Confirms the real
        // backend's read-only detect path is safe to construct and call
        // even off-hardware.
        assert_eq!(SystemTpm::new().detect(), TpmPresence::Absent);
    }

    #[test]
    fn system_tpm_reports_present_but_unavailable_when_only_hardware_signals_exist() {
        // CA-4's own regression test: a resource-manager node that isn't
        // there, but a hardware-signal node that is, must never collapse
        // to `Absent`. Uses this OS's real filesystem (a tempfile standing
        // in for "/dev/tpm0", not real hardware) rather than adding a
        // dependency-injection seam SystemTpm doesn't otherwise need.
        let dir = std::env::temp_dir().join(format!(
            "benix-claim-agent-tpm-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let hardware_signal = dir.join("tpm0");
        std::fs::write(&hardware_signal, b"").unwrap();

        let tpm = SystemTpm {
            resource_manager_node: dir.join("tpmrm0-does-not-exist"),
            hardware_signal_nodes: vec![hardware_signal],
        };
        assert_eq!(tpm.detect(), TpmPresence::PresentButUnavailable);

        std::fs::remove_dir_all(&dir).ok();
    }
}
