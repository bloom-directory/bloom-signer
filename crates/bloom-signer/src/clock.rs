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

impl ClockCondition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::ForwardJumpRejected => "forward_jump_rejected",
            Self::Untrusted => "untrusted",
            Self::RollbackFrozen => "rollback_frozen",
            Self::Repaired => "repaired",
        }
    }
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
    durable_clock_guard: bool,
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
        let durable_clock_guard = sampler.source().requires_durable_clock_guard();
        let boot_epoch = durable_clock_boot_epoch(durable_clock_guard, boot_epoch)?;
        let clock = Self {
            engine,
            sampler,
            boot_epoch,
            durable_clock_guard,
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
        if !self.durable_clock_guard {
            // macOS administrator/root compromise is outside the service
            // boundary. Its wall clock is authoritative and legacy durable
            // clock state must not latch readiness across a restart.
            return host_wall_clock_decision(reading, self.boot_epoch.clone());
        }
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

    pub const fn uses_durable_clock_guard(&self) -> bool {
        self.durable_clock_guard
    }

    fn observe_read_only(&self) -> Result<ClockDecision, ProtocolError> {
        let _observation = self.observation_lock.lock();
        let reading = self.sampler.sample().map_err(|error| {
            ProtocolError::new(ProtocolErrorCode::ClockUntrusted, error.to_string())
        })?;
        if !self.durable_clock_guard {
            return host_wall_clock_decision(reading, self.boot_epoch.clone());
        }
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

fn durable_clock_boot_epoch(
    durable_clock_guard: bool,
    enrollment_boot_epoch: BootEpoch,
) -> Result<BootEpoch, ProtocolError> {
    if !durable_clock_guard {
        return Ok(enrollment_boot_epoch);
    }
    #[cfg(target_os = "linux")]
    {
        let boot_id_path = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(std::path::PathBuf::from)
            .map(|directory| directory.join("kernel-boot-id"))
            .unwrap_or_else(|| "/proc/sys/kernel/random/boot_id".into());
        let raw = std::fs::read_to_string(&boot_id_path).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::ClockUntrusted,
                format!(
                    "read Linux kernel boot ID from {}: {error}",
                    boot_id_path.display()
                ),
            )
        })?;
        parse_linux_boot_epoch(&raw)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(ProtocolError::new(
            ProtocolErrorCode::ClockUntrusted,
            "durable clock guard requires a reviewed platform boot ID",
        ))
    }
}

#[cfg(target_os = "linux")]
fn parse_linux_boot_epoch(raw: &str) -> Result<BootEpoch, ProtocolError> {
    let mut compact = String::with_capacity(32);
    let mut segments = raw.trim().split('-');
    for expected_len in [8, 4, 4, 4, 12] {
        let segment = segments.next().ok_or_else(malformed_linux_boot_epoch)?;
        if segment.len() != expected_len || !segment.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(malformed_linux_boot_epoch());
        }
        compact.push_str(segment);
    }
    if segments.next().is_some() {
        return Err(malformed_linux_boot_epoch());
    }
    BootEpoch::new(compact.to_ascii_lowercase()).map_err(|_| malformed_linux_boot_epoch())
}

#[cfg(target_os = "linux")]
fn malformed_linux_boot_epoch() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::ClockUntrusted,
        "Linux kernel boot ID is malformed",
    )
}

fn host_wall_clock_decision(
    reading: PlatformTimeReading,
    boot_epoch: BootEpoch,
) -> Result<ClockDecision, ProtocolError> {
    let utc_ms = reading.utc_ms.ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorCode::ClockUntrusted,
            "platform wall clock is unavailable",
        )
    })?;
    Ok(ClockDecision {
        effective_now_ms: utc_ms,
        condition: ClockCondition::Healthy,
        observed_utc_ms: Some(utc_ms),
        monotonic_anchor_ns: reading.monotonic_anchor_ns,
        boot_epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{engine::SignerAuditKeys, registry::BackendRegistry};
    use bloom_signer_api::Token;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    #[test]
    fn host_wall_clock_accepts_forward_and_backward_changes() {
        let boot_epoch = BootEpoch::from_bytes([7; 16]);
        for utc_ms in [10_000, 40_000_000, 5_000] {
            let decision = host_wall_clock_decision(
                PlatformTimeReading {
                    utc_ms: Some(utc_ms),
                    monotonic_anchor_ns: 123,
                    monotonic_elapsed_ms: 0,
                },
                boot_epoch.clone(),
            )
            .unwrap();
            assert_eq!(decision.effective_now_ms, utc_ms);
            assert_eq!(decision.condition, ClockCondition::Healthy);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn durable_clock_uses_kernel_boot_id_instead_of_enrollment_epoch() {
        let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let expected = parse_linux_boot_epoch(&raw).unwrap();
        let selected = durable_clock_boot_epoch(true, BootEpoch::from_bytes([0xff; 16])).unwrap();
        assert_eq!(selected, expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_boot_id_parser_rejects_noncanonical_input() {
        for malformed in [
            "00112233445566778899aabbccddeeff",
            "00112233-4455-6677-8899-aabbccddeef",
            "00112233-4455-6677-8899-aabbccddeefg",
            "00112233-4455-6677-8899-aabbccddeeff-extra",
        ] {
            assert!(parse_linux_boot_epoch(malformed).is_err());
        }
    }

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
        let source = "linux-system-clock";
        let clock =
            SignerClock::new(engine, source, BootEpoch::new("01".repeat(16)).unwrap()).unwrap();
        assert_eq!(
            clock.readiness().unwrap().0,
            ReadinessState::DegradedReadOnly
        );
    }
}
