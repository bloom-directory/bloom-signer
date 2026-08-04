use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Retry contract attached to every protocol error.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    Never,
    SameOperation,
    AfterReconciliation,
    AfterBackoff,
    AfterReread,
    AfterRepair,
    UserAction,
}

/// Whether the failed request may have caused a durable effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableEffect {
    None,
    PriorOperationStands,
    ReservationReleased,
    PossibleProviderEffect,
    UnknownResolveByStatus,
}

/// Closed v1 error-code registry from architecture section 18.1.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolErrorCode {
    UnauthenticatedPeer,
    UnsupportedVersion,
    MalformedFrame,
    LimitExceededFrame,
    UnknownField,
    UnknownMethod,
    OperationIdConflict,
    ApprovalNotFound,
    ApprovalExpired,
    ApprovalRevoked,
    ApprovalRearmRequired,
    RevocationEpochUnreconciled,
    SelectorMismatch,
    SuiteNotAllowed,
    KeyrefMismatch,
    LimitExceededOperations,
    LimitExceededSignatures,
    LimitExceededValue,
    LimitExceededRate,
    SignerRateBackstopDenied,
    ClaimInvalid,
    AssuranceUnavailable,
    ProvenanceMismatch,
    PolicyBaselineStale,
    CeremonyRateLimited,
    CeremonyReplay,
    CeremonyKindMismatch,
    QuotaExceeded,
    ClockUntrusted,
    ClockRollback,
    BackendUnsupported,
    BackendInvalidRequest,
    AmbiguousProviderEffect,
    ServiceUnavailable,
}

impl ProtocolErrorCode {
    pub const ALL: [Self; 34] = [
        Self::UnauthenticatedPeer,
        Self::UnsupportedVersion,
        Self::MalformedFrame,
        Self::LimitExceededFrame,
        Self::UnknownField,
        Self::UnknownMethod,
        Self::OperationIdConflict,
        Self::ApprovalNotFound,
        Self::ApprovalExpired,
        Self::ApprovalRevoked,
        Self::ApprovalRearmRequired,
        Self::RevocationEpochUnreconciled,
        Self::SelectorMismatch,
        Self::SuiteNotAllowed,
        Self::KeyrefMismatch,
        Self::LimitExceededOperations,
        Self::LimitExceededSignatures,
        Self::LimitExceededValue,
        Self::LimitExceededRate,
        Self::SignerRateBackstopDenied,
        Self::ClaimInvalid,
        Self::AssuranceUnavailable,
        Self::ProvenanceMismatch,
        Self::PolicyBaselineStale,
        Self::CeremonyRateLimited,
        Self::CeremonyReplay,
        Self::CeremonyKindMismatch,
        Self::QuotaExceeded,
        Self::ClockUntrusted,
        Self::ClockRollback,
        Self::BackendUnsupported,
        Self::BackendInvalidRequest,
        Self::AmbiguousProviderEffect,
        Self::ServiceUnavailable,
    ];

    pub fn contract(self) -> ErrorContract {
        use DurableEffect as Effect;
        use ProtocolErrorCode as Code;
        use RetryClass as Retry;

        match self {
            Code::OperationIdConflict => {
                ErrorContract::new(Retry::Never, Effect::PriorOperationStands)
            }
            Code::RevocationEpochUnreconciled => {
                ErrorContract::new(Retry::AfterReconciliation, Effect::None)
            }
            Code::ApprovalRearmRequired => ErrorContract::new(Retry::UserAction, Effect::None),
            Code::PolicyBaselineStale => ErrorContract::new(Retry::AfterReread, Effect::None),
            Code::CeremonyRateLimited | Code::QuotaExceeded => {
                ErrorContract::new(Retry::AfterBackoff, Effect::None)
            }
            Code::ClockUntrusted | Code::ClockRollback => {
                ErrorContract::new(Retry::AfterRepair, Effect::None)
            }
            Code::LimitExceededOperations
            | Code::LimitExceededSignatures
            | Code::LimitExceededValue
            | Code::LimitExceededRate
            | Code::SignerRateBackstopDenied => {
                ErrorContract::new(Retry::Never, Effect::ReservationReleased)
            }
            Code::AmbiguousProviderEffect => {
                ErrorContract::new(Retry::Never, Effect::PossibleProviderEffect)
            }
            Code::ServiceUnavailable => {
                ErrorContract::new(Retry::SameOperation, Effect::UnknownResolveByStatus)
            }
            _ => ErrorContract::new(Retry::Never, Effect::None),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnauthenticatedPeer => "UNAUTHENTICATED_PEER",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::MalformedFrame => "MALFORMED_FRAME",
            Self::LimitExceededFrame => "LIMIT_EXCEEDED_FRAME",
            Self::UnknownField => "UNKNOWN_FIELD",
            Self::UnknownMethod => "UNKNOWN_METHOD",
            Self::OperationIdConflict => "OPERATION_ID_CONFLICT",
            Self::ApprovalNotFound => "APPROVAL_NOT_FOUND",
            Self::ApprovalExpired => "APPROVAL_EXPIRED",
            Self::ApprovalRevoked => "APPROVAL_REVOKED",
            Self::ApprovalRearmRequired => "APPROVAL_REARM_REQUIRED",
            Self::RevocationEpochUnreconciled => "REVOCATION_EPOCH_UNRECONCILED",
            Self::SelectorMismatch => "SELECTOR_MISMATCH",
            Self::SuiteNotAllowed => "SUITE_NOT_ALLOWED",
            Self::KeyrefMismatch => "KEYREF_MISMATCH",
            Self::LimitExceededOperations => "LIMIT_EXCEEDED_OPERATIONS",
            Self::LimitExceededSignatures => "LIMIT_EXCEEDED_SIGNATURES",
            Self::LimitExceededValue => "LIMIT_EXCEEDED_VALUE",
            Self::LimitExceededRate => "LIMIT_EXCEEDED_RATE",
            Self::SignerRateBackstopDenied => "SIGNER_RATE_BACKSTOP_DENIED",
            Self::ClaimInvalid => "CLAIM_INVALID",
            Self::AssuranceUnavailable => "ASSURANCE_UNAVAILABLE",
            Self::ProvenanceMismatch => "PROVENANCE_MISMATCH",
            Self::PolicyBaselineStale => "POLICY_BASELINE_STALE",
            Self::CeremonyRateLimited => "CEREMONY_RATE_LIMITED",
            Self::CeremonyReplay => "CEREMONY_REPLAY",
            Self::CeremonyKindMismatch => "CEREMONY_KIND_MISMATCH",
            Self::QuotaExceeded => "QUOTA_EXCEEDED",
            Self::ClockUntrusted => "CLOCK_UNTRUSTED",
            Self::ClockRollback => "CLOCK_ROLLBACK",
            Self::BackendUnsupported => "BACKEND_UNSUPPORTED",
            Self::BackendInvalidRequest => "BACKEND_INVALID_REQUEST",
            Self::AmbiguousProviderEffect => "AMBIGUOUS_PROVIDER_EFFECT",
            Self::ServiceUnavailable => "SERVICE_UNAVAILABLE",
        }
    }
}

impl FromStr for ProtocolErrorCode {
    type Err = UnknownPeerErrorCode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        for code in Self::ALL {
            if code.as_str() == value {
                return Ok(code);
            }
        }
        Err(UnknownPeerErrorCode(value.to_owned()))
    }
}

impl Serialize for ProtocolErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProtocolErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorContract {
    pub retry: RetryClass,
    pub durable_effect: DurableEffect,
}

impl ErrorContract {
    const fn new(retry: RetryClass, durable_effect: DurableEffect) -> Self {
        Self {
            retry,
            durable_effect,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    pub code: ProtocolErrorCode,
    pub retry: RetryClass,
    pub durable_effect: DurableEffect,
    pub message: String,
}

impl<'de> Deserialize<'de> for ProtocolError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireError {
            code: ProtocolErrorCode,
            retry: RetryClass,
            durable_effect: DurableEffect,
            message: String,
        }

        let wire = WireError::deserialize(deserializer)?;
        let contract = wire.code.contract();
        if wire.retry != contract.retry || wire.durable_effect != contract.durable_effect {
            return Err(serde::de::Error::custom(format!(
                "{} carries a forged retry or durable-effect contract",
                wire.code.as_str()
            )));
        }
        Ok(Self {
            code: wire.code,
            retry: wire.retry,
            durable_effect: wire.durable_effect,
            message: wire.message,
        })
    }
}

impl ProtocolError {
    pub fn new(code: ProtocolErrorCode, message: impl Into<String>) -> Self {
        let contract = code.contract();
        Self {
            code,
            retry: contract.retry,
            durable_effect: contract.durable_effect,
            message: message.into(),
        }
    }

    pub fn fatal(code: ProtocolErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, message)
    }

    pub fn has_valid_contract(&self) -> bool {
        self.code.contract()
            == ErrorContract {
                retry: self.retry,
                durable_effect: self.durable_effect,
            }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for ProtocolError {}

impl From<bloom_rpc_wire::WireError> for ProtocolError {
    fn from(error: bloom_rpc_wire::WireError) -> Self {
        use bloom_rpc_wire::WireErrorCode as Wire;
        let code = match error.code {
            Wire::MalformedFrame => ProtocolErrorCode::MalformedFrame,
            Wire::UnknownField => ProtocolErrorCode::UnknownField,
            Wire::LimitExceededFrame => ProtocolErrorCode::LimitExceededFrame,
            Wire::UnauthenticatedPeer => ProtocolErrorCode::UnauthenticatedPeer,
            Wire::UnsupportedVersion => ProtocolErrorCode::UnsupportedVersion,
            Wire::OperationIdConflict => ProtocolErrorCode::OperationIdConflict,
            Wire::QuotaExceeded => ProtocolErrorCode::QuotaExceeded,
            Wire::ServiceUnavailable => ProtocolErrorCode::ServiceUnavailable,
            Wire::ClockRollback => ProtocolErrorCode::ClockRollback,
            Wire::ClockUntrusted => ProtocolErrorCode::ClockUntrusted,
        };
        Self::new(code, error.message)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownPeerErrorCode(pub String);

impl fmt::Display for UnknownPeerErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown peer error code {}; fail closed", self.0)
    }
}

impl std::error::Error for UnknownPeerErrorCode {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_peer_code_fails_closed_and_is_not_retryable() {
        let error = "NEW_AND_UNKNOWN".parse::<ProtocolErrorCode>().unwrap_err();
        assert_eq!(error.0, "NEW_AND_UNKNOWN");
    }

    #[test]
    fn serialized_error_contract_cannot_lie() {
        let mut error = ProtocolError::new(
            ProtocolErrorCode::AmbiguousProviderEffect,
            "provider acceptance unknown",
        );
        assert!(error.has_valid_contract());
        error.retry = RetryClass::SameOperation;
        assert!(!error.has_valid_contract());

        let wire = r#"{
            "code":"AMBIGUOUS_PROVIDER_EFFECT",
            "retry":"same_operation",
            "durable_effect":"possible_provider_effect",
            "message":"forged"
        }"#;
        assert!(serde_json::from_str::<ProtocolError>(wire).is_err());
    }
}
