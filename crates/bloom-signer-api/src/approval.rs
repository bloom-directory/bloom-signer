use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;

use crate::{
    CryptoSuite, DecimalU64, DecimalU256, Digest32, KeyRef, ProtocolError, ProtocolErrorCode,
    RequestNonce, Token,
};

const APPROVAL_DOMAIN: &[u8] = b"bloom-sealed-approval-terms/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalSubject {
    Petal {
        package_hash: Digest32,
        route: String,
        agent_id: Option<String>,
    },
    Cli {
        client_id: Token,
        command_class: Token,
    },
    System {
        component_id: Token,
        operation_class: Token,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimAssuranceLevel {
    MachineAsserted,
    ProofVerified,
    InvariantAttested,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalSelector {
    Exact {
        ordered_payload_digests: Vec<Digest32>,
        ordered_hashes: Vec<Digest32>,
    },
    Petal {
        package_hash: Digest32,
        route: String,
        allowed_operation_classes: Vec<Token>,
        required_claim_assurance: ClaimAssuranceLevel,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlidingWindow {
    pub maximum: DecimalU64,
    pub duration_ms: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetId {
    pub chain: Token,
    pub asset: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValueLimit {
    pub asset: AssetId,
    pub lifetime: DecimalU256,
    pub rolling_windows: Vec<ValueWindow>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValueWindow {
    pub maximum: DecimalU256,
    pub duration_ms: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLimits {
    pub max_operations: DecimalU64,
    pub max_signatures: DecimalU64,
    pub operation_rate_limits: Vec<SlidingWindow>,
    pub signature_rate_limits: Vec<SlidingWindow>,
    pub value_limits: Vec<ValueLimit>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActivationMode {
    BootBound,
    DurableLocal {
        provider_tier: Token,
        maximum_rearm_until_ms: DecimalU64,
    },
    BackendManaged,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedApprovalTerms {
    pub subject: ApprovalSubject,
    pub wallet_id: Token,
    pub key_ref: KeyRef,
    pub allowed_crypto_suites: Vec<CryptoSuite>,
    pub selector: ApprovalSelector,
    pub limits: ApprovalLimits,
    pub activation_mode: ActivationMode,
    pub wallet_revocation_epoch: DecimalU64,
    pub policy_version: DecimalU64,
    pub policy_digest: Digest32,
    pub provenance_digest: Digest32,
    pub request_nonce: RequestNonce,
    pub issued_at_ms: DecimalU64,
    pub not_before_ms: DecimalU64,
    pub expires_at_ms: DecimalU64,
    pub renewal_of: Option<Digest32>,
}

impl SealedApprovalTerms {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.key_ref.validate()?;
        validate_suites(&self.allowed_crypto_suites, self.key_ref.key_spec)?;
        validate_limits(&self.limits)?;

        if self.expires_at_ms.get() <= self.not_before_ms.get()
            || self.issued_at_ms.get() > self.expires_at_ms.get()
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "approval validity interval is invalid",
            ));
        }

        match (&self.subject, &self.selector) {
            (
                ApprovalSubject::Petal {
                    package_hash,
                    route,
                    ..
                },
                ApprovalSelector::Petal {
                    package_hash: selector_hash,
                    route: selector_route,
                    allowed_operation_classes,
                    ..
                },
            ) if package_hash == selector_hash
                && route == selector_route
                && !allowed_operation_classes.is_empty()
                && unique(allowed_operation_classes) => {}
            (
                _,
                ApprovalSelector::Exact {
                    ordered_payload_digests,
                    ordered_hashes,
                },
            ) if !ordered_payload_digests.is_empty()
                && !ordered_hashes.is_empty()
                && self.limits.max_operations.get() == 1
                && self.limits.max_signatures.get() == ordered_hashes.len() as u64 => {}
            _ => {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::SelectorMismatch,
                    "subject, selector, and count constraints are inconsistent",
                ));
            }
        }

        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("approval JCS encoding failed: {error}"),
            )
        })
    }

    pub fn approval_digest(&self) -> Result<Digest32, ProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(APPROVAL_DOMAIN);
        hasher.update(self.canonical_bytes()?);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }

    pub fn approval_id(&self) -> Result<Digest32, ProtocolError> {
        self.approval_digest()
    }
}

fn validate_suites(suites: &[CryptoSuite], key_spec: crate::KeySpec) -> Result<(), ProtocolError> {
    if suites.is_empty()
        || suites.len() > 4
        || !unique(suites)
        || suites.iter().any(|suite| suite.key_spec() != key_spec)
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::SuiteNotAllowed,
            "allowed CryptoSuites must contain 1-4 unique suites compatible with the KeyRef",
        ));
    }
    Ok(())
}

fn validate_limits(limits: &ApprovalLimits) -> Result<(), ProtocolError> {
    if limits.max_operations.get() == 0 || limits.max_signatures.get() == 0 {
        return Err(ProtocolError::new(
            ProtocolErrorCode::LimitExceededOperations,
            "operation and signature limits must be greater than zero",
        ));
    }
    if limits
        .operation_rate_limits
        .iter()
        .chain(&limits.signature_rate_limits)
        .any(|window| window.maximum.get() == 0 || window.duration_ms.get() == 0)
        || limits.value_limits.iter().any(|limit| {
            limit.asset.asset.is_empty()
                || limit
                    .rolling_windows
                    .iter()
                    .any(|window| window.duration_ms.get() == 0)
        })
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::LimitExceededRate,
            "rate limits require positive maxima and durations",
        ));
    }
    Ok(())
}

fn unique<T: Eq + std::hash::Hash>(values: &[T]) -> bool {
    let mut seen = HashSet::with_capacity(values.len());
    values.iter().all(|value| seen.insert(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DerivationRef, KeySpec};

    fn exact_terms(nonce: &str) -> SealedApprovalTerms {
        SealedApprovalTerms {
            subject: ApprovalSubject::Cli {
                client_id: Token::new("bloom-cli").unwrap(),
                command_class: Token::new("wallet.sign").unwrap(),
            },
            wallet_id: Token::new("wallet-1").unwrap(),
            key_ref: KeyRef {
                backend: Token::new("local").unwrap(),
                backend_instance: Token::new("local-default").unwrap(),
                locator: "key-1".into(),
                key_spec: KeySpec::Secp256k1,
                public_key_fingerprint: Digest32::new("11".repeat(32)).unwrap(),
                derivation: Some(DerivationRef::Bip32Secp256k1 {
                    root_key_id: Token::new("root-1").unwrap(),
                    path: "m/44'/60'/0'/0/0".into(),
                }),
            },
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            selector: ApprovalSelector::Exact {
                ordered_payload_digests: vec![Digest32::new("22".repeat(32)).unwrap()],
                ordered_hashes: vec![Digest32::new("33".repeat(32)).unwrap()],
            },
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(1),
                max_signatures: DecimalU64::new(1),
                operation_rate_limits: vec![],
                signature_rate_limits: vec![],
                value_limits: vec![],
            },
            activation_mode: ActivationMode::BootBound,
            wallet_revocation_epoch: DecimalU64::new(7),
            policy_version: DecimalU64::new(3),
            policy_digest: Digest32::new("44".repeat(32)).unwrap(),
            provenance_digest: Digest32::new("55".repeat(32)).unwrap(),
            request_nonce: RequestNonce::new(nonce).unwrap(),
            issued_at_ms: DecimalU64::new(1_900_000_000_000),
            not_before_ms: DecimalU64::new(1_900_000_000_000),
            expires_at_ms: DecimalU64::new(1_900_000_600_000),
            renewal_of: None,
        }
    }

    #[test]
    fn approval_digest_excludes_lifecycle_and_nonce_distinguishes_identical_requests() {
        let first = exact_terms("00".repeat(16).as_str());
        let second = exact_terms("01".repeat(16).as_str());
        assert_ne!(first.approval_id().unwrap(), second.approval_id().unwrap());
    }

    #[test]
    fn exact_selector_count_consistency_is_fail_closed() {
        let mut terms = exact_terms("00".repeat(16).as_str());
        terms.limits.max_signatures = DecimalU64::new(2);
        assert_eq!(
            terms.validate().unwrap_err().code,
            ProtocolErrorCode::SelectorMismatch
        );
    }
}
