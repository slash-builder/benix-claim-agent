//! The one seam between this crate and `fabric-kit`'s network call.
//!
//! `fabric_kit::FabricClient::pair_claim` opens a real WebSocket to the
//! hub named in the parsed `qr_payload`. The handler must not block on
//! that connection's eventual approval (`PendingPairing::wait_for_result`
//! can take an arbitrary amount of time — a human has to compare a
//! fingerprint on Courier's side), and unit tests for the state
//! transition on `PairOutcome::Approved`/`Rejected`/`Timeout` must not
//! require a live or even mock-transport-level hub connection to run.
//!
//! `fabric-kit`'s own test module (`client.rs`'s `MockTx`/`MockRx`) is
//! private to that crate and drives its mocking at the wire-frame level —
//! not something this crate can import. The boundary this module mocks
//! instead is the same one the handler actually calls through: "start a
//! claim, get back an ack plus something to await the outcome on." That's
//! a narrower, call-site-level seam rather than a wire-level one, but it
//! is real dependency inversion, not a `#[cfg(test)]` bypass of the
//! production code path — `main.rs` wires the real
//! [`FabricKitPairClaimer`] into the handler exactly the way the mock is
//! wired into tests.

use std::time::Duration;

use async_trait::async_trait;
use fabric_kit::{ClaimAcknowledged, DeviceKeypair, FabricError, PairOutcome};

/// Starts a claim and hands back something that can be awaited for the
/// eventual outcome. One implementation talks to a real hub
/// ([`FabricKitPairClaimer`]); tests substitute [`MockPairClaimer`].
#[async_trait]
pub trait PairClaimer: Send + Sync {
    async fn pair_claim(
        &self,
        endpoint: &str,
        pair_session_id: &str,
        keypair: &DeviceKeypair,
        proposed_device_name: &str,
    ) -> Result<(ClaimAcknowledged, Box<dyn PendingPairingHandle>), FabricError>;
}

/// The awaitable half — mirrors `fabric_kit::PendingPairing::
/// wait_for_result`'s signature exactly, so [`FabricKitPairClaimer`] is a
/// direct, no-op-shaped pass-through.
#[async_trait]
pub trait PendingPairingHandle: Send {
    async fn wait_for_result(
        self: Box<Self>,
        timeout: Duration,
    ) -> Result<PairOutcome, FabricError>;
}

/// The real implementation: a thin, direct pass-through to
/// `fabric_kit::FabricClient::pair_claim`. No behavior of its own to
/// unit-test — the wrapping exists solely to give the handler a seam,
/// see module docs.
pub struct FabricKitPairClaimer;

#[async_trait]
impl PairClaimer for FabricKitPairClaimer {
    async fn pair_claim(
        &self,
        endpoint: &str,
        pair_session_id: &str,
        keypair: &DeviceKeypair,
        proposed_device_name: &str,
    ) -> Result<(ClaimAcknowledged, Box<dyn PendingPairingHandle>), FabricError> {
        let (ack, pending) = fabric_kit::FabricClient::pair_claim(
            endpoint,
            pair_session_id,
            keypair,
            proposed_device_name,
        )
        .await?;
        Ok((ack, Box::new(RealPendingPairing(pending))))
    }
}

struct RealPendingPairing(fabric_kit::PendingPairing);

#[async_trait]
impl PendingPairingHandle for RealPendingPairing {
    async fn wait_for_result(
        self: Box<Self>,
        timeout: Duration,
    ) -> Result<PairOutcome, FabricError> {
        let RealPendingPairing(pending) = *self;
        pending.wait_for_result(timeout).await
    }
}

/// Test double: canned answers for both halves of the seam, each
/// consumable exactly once (a real claim attempt is a one-shot sequence
/// too — there is no "claim again on the same handle").
#[cfg(test)]
pub struct MockPairClaimer {
    claim_result: std::sync::Mutex<Option<Result<ClaimAcknowledged, FabricError>>>,
    wait_result: std::sync::Mutex<Option<Result<PairOutcome, FabricError>>>,
}

#[cfg(test)]
impl MockPairClaimer {
    /// `pair_claim` succeeds with `ack`; the resulting handle's
    /// `wait_for_result` later resolves to `outcome`.
    pub fn claim_ok_then(
        ack: ClaimAcknowledged,
        outcome: Result<PairOutcome, FabricError>,
    ) -> Self {
        Self {
            claim_result: std::sync::Mutex::new(Some(Ok(ack))),
            wait_result: std::sync::Mutex::new(Some(outcome)),
        }
    }

    /// `pair_claim` itself fails outright (unreachable hub, etc.) — the
    /// 502 path. No `wait_for_result` ever happens on this path.
    pub fn claim_err(err: FabricError) -> Self {
        Self {
            claim_result: std::sync::Mutex::new(Some(Err(err))),
            wait_result: std::sync::Mutex::new(None),
        }
    }
}

#[cfg(test)]
#[async_trait]
impl PairClaimer for MockPairClaimer {
    async fn pair_claim(
        &self,
        _endpoint: &str,
        _pair_session_id: &str,
        _keypair: &DeviceKeypair,
        _proposed_device_name: &str,
    ) -> Result<(ClaimAcknowledged, Box<dyn PendingPairingHandle>), FabricError> {
        let result = self
            .claim_result
            .lock()
            .expect("mock claim_result lock")
            .take()
            .expect("MockPairClaimer::pair_claim called more than once");
        let ack = result?;
        let wait_result = self
            .wait_result
            .lock()
            .expect("mock wait_result lock")
            .take()
            .expect("no wait_result configured for a successful mock claim");
        Ok((
            ack,
            Box::new(MockPendingPairing {
                result: wait_result,
            }),
        ))
    }
}

#[cfg(test)]
struct MockPendingPairing {
    result: Result<PairOutcome, FabricError>,
}

#[cfg(test)]
#[async_trait]
impl PendingPairingHandle for MockPendingPairing {
    async fn wait_for_result(
        self: Box<Self>,
        _timeout: Duration,
    ) -> Result<PairOutcome, FabricError> {
        self.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fabric_kit::{PairCredentials, SealingKeypair};

    fn ack() -> ClaimAcknowledged {
        ClaimAcknowledged {
            pair_session_id: "sess-1".to_string(),
            expires_at_ms: 1_700_000_060_000,
        }
    }

    fn credentials() -> PairCredentials {
        PairCredentials {
            device_id: "device-1".to_string(),
            account_id: "account-1".to_string(),
            bearer_token: "secret-token".to_string(),
            resume_token: vec![1, 2, 3],
            sealing_keypair: SealingKeypair::generate(),
        }
    }

    #[tokio::test]
    async fn mock_claim_ok_then_approved_round_trips() {
        let mock = MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Approved(credentials())));
        let keypair = DeviceKeypair::generate();
        let (returned_ack, pending) = mock
            .pair_claim("wss://hub.example.com/v1", "sess-1", &keypair, "box")
            .await
            .expect("mock claim should succeed");
        assert_eq!(returned_ack.pair_session_id, "sess-1");
        let outcome = pending
            .wait_for_result(Duration::from_secs(1))
            .await
            .expect("mock wait should succeed");
        assert!(matches!(outcome, PairOutcome::Approved(_)));
    }

    #[tokio::test]
    async fn mock_claim_ok_then_rejected() {
        let mock = MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Rejected));
        let keypair = DeviceKeypair::generate();
        let (_, pending) = mock
            .pair_claim("wss://hub.example.com/v1", "sess-1", &keypair, "box")
            .await
            .unwrap();
        let outcome = pending
            .wait_for_result(Duration::from_secs(1))
            .await
            .unwrap();
        assert!(matches!(outcome, PairOutcome::Rejected));
    }

    #[tokio::test]
    async fn mock_claim_ok_then_timeout() {
        let mock = MockPairClaimer::claim_ok_then(ack(), Ok(PairOutcome::Timeout));
        let keypair = DeviceKeypair::generate();
        let (_, pending) = mock
            .pair_claim("wss://hub.example.com/v1", "sess-1", &keypair, "box")
            .await
            .unwrap();
        let outcome = pending
            .wait_for_result(Duration::from_secs(1))
            .await
            .unwrap();
        assert!(matches!(outcome, PairOutcome::Timeout));
    }

    #[tokio::test]
    async fn mock_claim_err_surfaces_before_any_wait() {
        let mock = MockPairClaimer::claim_err(FabricError::Transport("connection refused".into()));
        let keypair = DeviceKeypair::generate();
        let result = mock
            .pair_claim("wss://hub.example.com/v1", "sess-1", &keypair, "box")
            .await;
        assert!(result.is_err());
    }
}
