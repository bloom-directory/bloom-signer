use std::sync::Arc;

use bloom_signer_api::{BootEpoch, ProtocolError, ProtocolErrorCode, ReadinessState, Token};
use bloom_trusted_time::{MAX_FORWARD_STEP_MS, PlatformTimeReading, PlatformTimeSampler};
use parking_lot::Mutex;

use crate::engine::SignerEngine;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockCondition {
    Healthy,
    ForwardJumpRejected,
    Untrusted,
    RollbackFrozen,
    Repaired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockDecision {
    pub effective_now_ms: u64,
    pub condition: ClockCondition,
    pub observed_utc_ms: Option<u64>,
    pub monotonic_anchor_ns: u64,
    pub boot_epoch: BootEpoch,
}

pub struct SignerClock {
    engine: Arc<SignerEngine>,
    sampler: PlatformTimeSampler,
    boot_epoch: BootEpoch,
    observation_lock: Mutex<()>,
}

impl SignerClock {
    pub fn new(
        engine: Arc<SignerEngine>,
        trusted_time_source: &str,
        boot_epoch: BootEpoch,
    ) -> Result<Self, ProtocolError> {
        let sampler = PlatformTimeSampler::new(trusted_time_source).map_err(|error| {
            ProtocolError::new(ProtocolErrorCode::ClockUntrusted, error.to_string())
        })?;
        let clock = Self {
            engine,
            sampler,
            boot_epoch,
            observation_lock: Mutex::new(()),
        };
        if clock.engine.audit_is_degraded() {
            // A damaged local audit journal must not prevent status/read-only
            // startup. Do not attempt the normal clock-state mutation while
            // the audit latch is closed.
            clock.observe_read_only()?;
        } else {
            clock.observe(false)?;
        }
        Ok(clock)
    }

    pub(crate) fn observe(
        &self,
        rate_limited_mutation: bool,
    ) -> Result<ClockDecision, ProtocolError> {
        let _observation = self.observation_lock.lock();
        let reading = self.sampler.sample().map_err(|error| {
            ProtocolError::new(ProtocolErrorCode::ClockUntrusted, error.to_string())
        })?;
        self.engine.observe_time(
            PlatformTimeReading {
                utc_ms: reading.utc_ms,
                monotonic_elapsed_ms: reading.monotonic_elapsed_ms,
                monotonic_anchor_ns: reading.monotonic_anchor_ns,
            },
            self.boot_epoch.clone(),
            MAX_FORWARD_STEP_MS,
            rate_limited_mutation,
        )
    }

    pub fn now_ms(&self, rate_limited_mutation: bool) -> Result<u64, ProtocolError> {
        Ok(self.observe(rate_limited_mutation)?.effective_now_ms)
    }

    pub fn now_ms_read_only(&self) -> Result<u64, ProtocolError> {
        Ok(self.observe_read_only()?.effective_now_ms)
    }

    fn observe_read_only(&self) -> Result<ClockDecision, ProtocolError> {
        let _observation = self.observation_lock.lock();
        let reading = self.sampler.sample().map_err(|error| {
            ProtocolError::new(ProtocolErrorCode::ClockUntrusted, error.to_string())
        })?;
        self.engine.observe_time_read_only(
            PlatformTimeReading {
                utc_ms: reading.utc_ms,
                monotonic_elapsed_ms: reading.monotonic_elapsed_ms,
                monotonic_anchor_ns: reading.monotonic_anchor_ns,
            },
            self.boot_epoch.clone(),
            MAX_FORWARD_STEP_MS,
        )
    }

    pub fn readiness(&self) -> Result<(ReadinessState, Vec<Token>), ProtocolError> {
        let decision = match self.observe_read_only() {
            Ok(decision) => decision,
            Err(_) => {
                return Ok((
                    ReadinessState::DegradedReadOnly,
                    vec![Token::new("clock_untrusted")?],
                ));
            }
        };
        if self.engine.audit_is_degraded() {
            return Ok((
                ReadinessState::DegradedReadOnly,
                vec![Token::new("audit_degraded")?],
            ));
        }
        let condition = match decision.condition {
            ClockCondition::Healthy | ClockCondition::Repaired => {
                return Ok((ReadinessState::Ready, Vec::new()));
            }
            ClockCondition::ForwardJumpRejected => "clock_forward_jump",
            ClockCondition::Untrusted => "clock_untrusted",
            ClockCondition::RollbackFrozen => "clock_rollback",
        };
        Ok((
            ReadinessState::DegradedReadOnly,
            vec![Token::new(condition)?],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{engine::SignerAuditKeys, registry::BackendRegistry};
    use bloom_signer_api::Token;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    #[test]
    fn degraded_audit_still_constructs_clock_for_readiness() {
        let engine = Arc::new(
            SignerEngine::open_in_memory(
                Token::new("broker-key").unwrap(),
                SigningKey::from_bytes(&[1; 32]).verifying_key(),
                SigningKey::from_bytes(&[2; 32]).verifying_key(),
                Token::new("revocation-key").unwrap(),
                SigningKey::from_bytes(&[3; 32]),
                SignerAuditKeys {
                    current_key_id: Token::new("audit-key").unwrap(),
                    current_signing_key: SigningKey::from_bytes(&[30; 32]),
                    historical_verifying_keys: BTreeMap::new(),
                },
                Arc::new(BackendRegistry::from_compiled(vec![]).unwrap()),
            )
            .unwrap(),
        );
        engine.latch_audit_degraded();
        #[cfg(target_os = "macos")]
        let source = "macos-managed-timed";
        #[cfg(target_os = "linux")]
        let source = "linux-chrony-nts";
        let clock =
            SignerClock::new(engine, source, BootEpoch::new("01".repeat(16)).unwrap()).unwrap();
        assert_eq!(
            clock.readiness().unwrap().0,
            ReadinessState::DegradedReadOnly
        );
    }
}
