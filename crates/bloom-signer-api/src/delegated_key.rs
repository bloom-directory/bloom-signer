use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;

use crate::{
    CryptoSuite, DecimalU64, Digest32, KeyRef, OperationId, ProtocolError, ProtocolErrorCode, Token,
};

const DELEGATED_KEY_SCOPE_DOMAIN: &[u8] = b"bloom-delegated-key-scope/v1";
const DELEGATED_KEY_REQUEST_DOMAIN: &[u8] = b"bloom-delegated-key-request/v1";

/// Immutable owner-attested authority boundary for a Signer-owned delegated key.
///
/// The stable digest excludes the currently active subject so an owner-attested
/// authority may advance that subject without changing the delegated-key identity.
/// The request digest binds every field for one derivation attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedKeyScope {
    pub wallet_id: Token,
    pub parent_key_ref: KeyRef,
    pub authority_id: Digest32,
    pub active_subject_id: Digest32,
    pub delegate_id: Token,
    pub allowed_resource_ids: Vec<Digest32>,
    pub allowed_operation_classes: Vec<Token>,
    pub allowed_crypto_suites: Vec<CryptoSuite>,
    pub maximum_lifetime_ms: DecimalU64,
    pub custody_operation_id: OperationId,
}

impl<'de> Deserialize<'de> for DelegatedKeyScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unchecked {
            wallet_id: Token,
            parent_key_ref: KeyRef,
            authority_id: Digest32,
            active_subject_id: Digest32,
            delegate_id: Token,
            allowed_resource_ids: Vec<Digest32>,
            allowed_operation_classes: Vec<Token>,
            allowed_crypto_suites: Vec<CryptoSuite>,
            maximum_lifetime_ms: DecimalU64,
            custody_operation_id: OperationId,
        }

        let unchecked = Unchecked::deserialize(deserializer)?;
        let scope = Self {
            wallet_id: unchecked.wallet_id,
            parent_key_ref: unchecked.parent_key_ref,
            authority_id: unchecked.authority_id,
            active_subject_id: unchecked.active_subject_id,
            delegate_id: unchecked.delegate_id,
            allowed_resource_ids: unchecked.allowed_resource_ids,
            allowed_operation_classes: unchecked.allowed_operation_classes,
            allowed_crypto_suites: unchecked.allowed_crypto_suites,
            maximum_lifetime_ms: unchecked.maximum_lifetime_ms,
            custody_operation_id: unchecked.custody_operation_id,
        };
        scope.validate().map_err(serde::de::Error::custom)?;
        Ok(scope)
    }
}

impl DelegatedKeyScope {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.parent_key_ref.validate()?;
        let unique_resources: HashSet<_> = self.allowed_resource_ids.iter().collect();
        let unique_classes: HashSet<_> = self.allowed_operation_classes.iter().collect();
        if self.allowed_resource_ids.is_empty()
            || unique_resources.len() != self.allowed_resource_ids.len()
            || self.allowed_operation_classes.is_empty()
            || unique_classes.len() != self.allowed_operation_classes.len()
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "delegated key scope requires unique non-empty resource and operation-class sets",
            ));
        }

        let unique_suites: HashSet<_> = self.allowed_crypto_suites.iter().copied().collect();
        if self.allowed_crypto_suites.is_empty()
            || self.allowed_crypto_suites.len() > CryptoSuite::ALL.len()
            || unique_suites.len() != self.allowed_crypto_suites.len()
            || self
                .allowed_crypto_suites
                .iter()
                .any(|suite| suite.key_spec() != self.parent_key_ref.key_spec)
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SuiteNotAllowed,
                "delegated key scope must contain 1-3 unique suites compatible with its parent KeyRef",
            ));
        }
        if self.maximum_lifetime_ms.get() == 0 {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "delegated key scope maximum_lifetime_ms must be greater than zero",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        #[derive(Serialize)]
        struct StableScope<'a> {
            wallet_id: &'a Token,
            parent_key_ref: &'a KeyRef,
            authority_id: &'a Digest32,
            delegate_id: &'a Token,
            allowed_resource_ids: &'a [Digest32],
            allowed_operation_classes: &'a [Token],
            allowed_crypto_suites: &'a [CryptoSuite],
            maximum_lifetime_ms: &'a DecimalU64,
            custody_operation_id: &'a OperationId,
        }
        serde_jcs::to_vec(&StableScope {
            wallet_id: &self.wallet_id,
            parent_key_ref: &self.parent_key_ref,
            authority_id: &self.authority_id,
            delegate_id: &self.delegate_id,
            allowed_resource_ids: &self.allowed_resource_ids,
            allowed_operation_classes: &self.allowed_operation_classes,
            allowed_crypto_suites: &self.allowed_crypto_suites,
            maximum_lifetime_ms: &self.maximum_lifetime_ms,
            custody_operation_id: &self.custody_operation_id,
        })
        .map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("delegated key scope JCS encoding failed: {error}"),
            )
        })
    }

    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(DELEGATED_KEY_SCOPE_DOMAIN);
        hasher.update(self.canonical_bytes()?);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }

    pub fn request_digest(&self) -> Result<Digest32, ProtocolError> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(DELEGATED_KEY_REQUEST_DOMAIN);
        hasher.update(serde_jcs::to_vec(self).map_err(|error| {
            ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
        })?);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DerivationRef, KeySpec};

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn operation(byte: u8) -> OperationId {
        OperationId::from_bytes([byte; 32])
    }

    fn scope() -> DelegatedKeyScope {
        DelegatedKeyScope {
            wallet_id: Token::new("primary").unwrap(),
            parent_key_ref: KeyRef {
                backend: Token::new("local").unwrap(),
                backend_instance: Token::new("default").unwrap(),
                locator: "wallet/primary/root".into(),
                key_spec: KeySpec::Secp256k1,
                public_key_fingerprint: digest(1),
                derivation: Some(DerivationRef::Bip32Secp256k1 {
                    root_key_id: Token::new("primary-root").unwrap(),
                    path: "m/44'/60'/0'".into(),
                }),
            },
            authority_id: digest(2),
            active_subject_id: digest(3),
            delegate_id: Token::new("desk-a").unwrap(),
            allowed_resource_ids: vec![digest(4), digest(5)],
            allowed_operation_classes: vec![
                Token::new("exchange.order").unwrap(),
                Token::new("exchange.cancel").unwrap(),
            ],
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            maximum_lifetime_ms: DecimalU64::new(86_400_000),
            custody_operation_id: operation(6),
        }
    }

    #[test]
    fn delegated_scope_digest_is_canonical_and_domain_separated() {
        let scope = scope();
        let canonical = scope.canonical_bytes().unwrap();
        let encoded = serde_jcs::to_vec(&scope).unwrap();
        let reparsed: DelegatedKeyScope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(scope, reparsed);
        assert_eq!(scope.digest().unwrap(), reparsed.digest().unwrap());
        assert_eq!(
            scope.digest().unwrap().as_str(),
            "d0278bb6d5af3bb777bd0d9730e0f76c01def33c6d8ed2342304c8249155184d"
        );
        let raw_jcs_digest = Digest32::from_bytes(Sha256::digest(canonical).into());
        assert_ne!(scope.digest().unwrap(), raw_jcs_digest);
    }

    #[test]
    fn delegated_stable_scope_binds_authority_and_bounds_but_not_active_subject() {
        let original = scope();
        let original_digest = original.digest().unwrap();
        let mut variants = Vec::new();

        let mut changed = original.clone();
        changed.wallet_id = Token::new("secondary").unwrap();
        variants.push(changed);
        let mut changed = original.clone();
        changed.parent_key_ref.locator = "wallet/primary/other-root".into();
        variants.push(changed);
        let mut changed = original.clone();
        changed.authority_id = digest(7);
        variants.push(changed);
        let mut changed = original.clone();
        changed.delegate_id = Token::new("desk-b").unwrap();
        variants.push(changed);
        let mut changed = original.clone();
        changed.allowed_resource_ids = vec![digest(8)];
        variants.push(changed);
        let mut changed = original.clone();
        changed.allowed_operation_classes = vec![Token::new("payment.send").unwrap()];
        variants.push(changed);
        let mut changed = original.clone();
        changed.allowed_crypto_suites = vec![CryptoSuite::Secp256k1Sha256Recoverable];
        variants.push(changed);
        let mut changed = original.clone();
        changed.maximum_lifetime_ms = DecimalU64::new(60_000);
        variants.push(changed);
        let mut changed = original.clone();
        changed.custody_operation_id = operation(9);
        variants.push(changed);

        for variant in variants {
            assert_ne!(variant.digest().unwrap(), original_digest);
        }

        let mut successor = original;
        successor.active_subject_id = digest(10);
        assert_eq!(successor.digest().unwrap(), original_digest);
    }

    #[test]
    fn delegated_scope_decode_rejects_duplicate_resources() {
        let mut value = serde_json::to_value(scope()).unwrap();
        value["allowed_resource_ids"] = serde_json::json!([digest(4), digest(4)]);
        assert!(serde_json::from_value::<DelegatedKeyScope>(value).is_err());
    }
}
