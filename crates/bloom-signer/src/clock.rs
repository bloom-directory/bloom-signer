use std::sync::Arc;

use bloom_triad_protocol::{BootEpoch, ProtocolError, ProtocolErrorCode, ReadinessState, Token};
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
        clock.observe(false)?;
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

    pub fn readiness(&self) -> Result<(ReadinessState, Vec<Token>), ProtocolError> {
        let decision = match self.observe(false) {
            Ok(decision) => decision,
            Err(_) => {
                return Ok((
                    ReadinessState::DegradedReadOnly,
                    vec![Token::new("clock_untrusted")?],
                ));
            }
        };
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
