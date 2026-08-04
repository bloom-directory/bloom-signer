use serde::{Deserialize, Serialize};

use crate::{
    Base64UrlBytes, CustodyCompleteRequest, CustodyPrepareRequest, CustodyResult, DecimalU64,
    Digest32, OperationId, ProtocolError, ProtocolErrorCode, Token,
};
use sha2::{Digest as _, Sha256};

const POLICY_UPDATE_TERMS_DOMAIN: &[u8] = b"bloom-policy-update-terms/v1";
const POLICY_COMMIT_RECEIPT_DOMAIN: &[u8] = b"bloom-policy-commit-receipt/v1";

/// Canonical wallet-policy document written by Signer and interpreted by
/// Broker. Keeping its closed shape in the protocol package lets registration
/// create a valid initial document without teaching Signer policy semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalWalletPolicy {
    pub wallet_id: Token,
    pub maximum_approval_lifetime_ms: u64,
    pub allowed_petal_packages: Vec<Digest32>,
    pub allowed_destinations: Vec<PolicyDestination>,
    pub required_verifiers: Vec<RequiredVerifier>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDestination {
    pub chain: Token,
    pub destination: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredVerifier {
    pub verifier_id: Token,
    pub verifier_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicySnapshot {
    pub wallet_id: Token,
    pub version: DecimalU64,
    pub canonical_policy: Base64UrlBytes,
    pub policy_digest: Digest32,
    pub policy_signing_key_id: Token,
    pub policy_verifying_key: Base64UrlBytes,
    pub signer_signature: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdateRequest {
    pub operation_id: OperationId,
    pub wallet_id: Token,
    pub baseline_version: DecimalU64,
    pub baseline_digest: Digest32,
    pub proposed_canonical_policy: Base64UrlBytes,
    pub proposed_policy_digest: Digest32,
    pub authority_diff_digest: Digest32,
    pub assurance_level: Token,
}

impl PolicyUpdateRequest {
    pub fn terms_digest(&self) -> Result<Digest32, ProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(POLICY_UPDATE_TERMS_DOMAIN);
        hasher.update(serde_jcs::to_vec(self).map_err(canonical_error)?);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyValidationReceipt {
    pub update_terms_digest: Digest32,
    pub review_manifest_digest: Digest32,
    pub broker_key_id: Token,
    pub broker_signature: Base64UrlBytes,
}

impl PolicyValidationReceipt {
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            update_terms_digest: &'a Digest32,
            review_manifest_digest: &'a Digest32,
            broker_key_id: &'a Token,
        }
        serde_jcs::to_vec(&Unsigned {
            update_terms_digest: &self.update_terms_digest,
            review_manifest_digest: &self.review_manifest_digest,
            broker_key_id: &self.broker_key_id,
        })
        .map_err(canonical_error)
    }

    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        Ok(Digest32::from_bytes(
            Sha256::digest(serde_jcs::to_vec(self).map_err(canonical_error)?).into(),
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCompareAndSwapRequest {
    pub update: PolicyUpdateRequest,
    pub ceremony_receipt: CustodyResult,
    pub broker_validation_receipt: PolicyValidationReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdateCeremonyPrepareRequest {
    pub custody: CustodyPrepareRequest,
    pub update: PolicyUpdateRequest,
    pub broker_validation_receipt: PolicyValidationReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdateCeremonyCompleteRequest {
    pub custody: CustodyCompleteRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCommitReceipt {
    pub operation_id: OperationId,
    pub wallet_id: Token,
    pub previous_version: DecimalU64,
    pub committed: SignedPolicySnapshot,
    pub authority_diff_digest: Digest32,
    pub signer_key_id: Token,
    pub signer_signature: Base64UrlBytes,
}

impl PolicyCommitReceipt {
    pub fn signature_message(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut unsigned = self.clone();
        unsigned.signer_signature = Base64UrlBytes::from_bytes(&[]);
        Ok([
            POLICY_COMMIT_RECEIPT_DOMAIN,
            serde_jcs::to_vec(&unsigned)
                .map_err(canonical_error)?
                .as_slice(),
        ]
        .concat())
    }
}

fn canonical_error(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::MalformedFrame,
        format!("policy canonicalization failed: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> PolicyCommitReceipt {
        PolicyCommitReceipt {
            operation_id: OperationId::from_bytes([0x11; 32]),
            wallet_id: Token::new("wallet-golden").unwrap(),
            previous_version: DecimalU64::new(7),
            committed: SignedPolicySnapshot {
                wallet_id: Token::new("wallet-golden").unwrap(),
                version: DecimalU64::new(8),
                canonical_policy: Base64UrlBytes::from_bytes(b"canonical-policy"),
                policy_digest: Digest32::from_bytes([0x12; 32]),
                policy_signing_key_id: Token::new("policy-key-golden").unwrap(),
                policy_verifying_key: Base64UrlBytes::from_bytes(&[0x13; 32]),
                signer_signature: Base64UrlBytes::from_bytes(&[0x14; 64]),
            },
            authority_diff_digest: Digest32::from_bytes([0x15; 32]),
            signer_key_id: Token::new("policy-key-golden").unwrap(),
            signer_signature: Base64UrlBytes::from_bytes(&[0x16; 64]),
        }
    }

    #[test]
    fn policy_commit_signature_message_is_golden_and_binds_every_unsigned_field() {
        let original = receipt();
        let message = original.signature_message().unwrap();
        assert_eq!(
            Digest32::from_bytes(Sha256::digest(&message).into()).as_str(),
            "afce40bd62aa2ba4ef3a02451583a9cabff4f90f0852274048a30cd750ec01bb"
        );
        let mut changes = Vec::new();
        let mut changed = original.clone();
        changed.operation_id = OperationId::from_bytes([0x21; 32]);
        changes.push(changed);
        let mut changed = original.clone();
        changed.wallet_id = Token::new("wallet-other").unwrap();
        changes.push(changed);
        let mut changed = original.clone();
        changed.previous_version = DecimalU64::new(6);
        changes.push(changed);
        let mut changed = original.clone();
        changed.committed.wallet_id = Token::new("wallet-other").unwrap();
        changes.push(changed);
        let mut changed = original.clone();
        changed.committed.version = DecimalU64::new(9);
        changes.push(changed);
        let mut changed = original.clone();
        changed.committed.canonical_policy = Base64UrlBytes::from_bytes(b"other-policy");
        changes.push(changed);
        let mut changed = original.clone();
        changed.committed.policy_digest = Digest32::from_bytes([0x22; 32]);
        changes.push(changed);
        let mut changed = original.clone();
        changed.committed.policy_signing_key_id = Token::new("policy-key-other").unwrap();
        changes.push(changed);
        let mut changed = original.clone();
        changed.committed.policy_verifying_key = Base64UrlBytes::from_bytes(&[0x23; 32]);
        changes.push(changed);
        let mut changed = original.clone();
        changed.committed.signer_signature = Base64UrlBytes::from_bytes(&[0x24; 64]);
        changes.push(changed);
        let mut changed = original.clone();
        changed.authority_diff_digest = Digest32::from_bytes([0x25; 32]);
        changes.push(changed);
        let mut changed = original.clone();
        changed.signer_key_id = Token::new("policy-key-other").unwrap();
        changes.push(changed);

        for changed in changes {
            assert_ne!(changed.signature_message().unwrap(), message);
        }
        let mut changed_signature_only = original;
        changed_signature_only.signer_signature = Base64UrlBytes::from_bytes(&[0x26; 64]);
        assert_eq!(changed_signature_only.signature_message().unwrap(), message);
    }
}
