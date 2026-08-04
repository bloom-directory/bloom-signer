use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;

use crate::{
    CryptoSuite, DecimalU64, Digest32, KeyRef, OperationId, ProtocolError, ProtocolErrorCode, Token,
};

const PETAL_KEY_SCOPE_DOMAIN: &[u8] = b"bloom-petal-key-scope/v1";
const ROUTE_MAX_BYTES: usize = 2 * 1024;
const AGENT_ID_MAX_BYTES: usize = 256;

/// Immutable installer-pinned authority boundary for a Signer-owned Petal key.
///
/// The scope contains public metadata only. Its digest is the stable identity
/// recorded by Broker and Signer; the child private key remains exclusively in
/// Signer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalKeyScope {
    pub wallet_id: Token,
    pub parent_key_ref: KeyRef,
    pub package_hash: Digest32,
    pub route: String,
    pub agent_id: Option<String>,
    pub purpose: Token,
    pub allowed_crypto_suites: Vec<CryptoSuite>,
    pub maximum_lifetime_ms: DecimalU64,
    pub custody_operation_id: OperationId,
}

impl<'de> Deserialize<'de> for PetalKeyScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unchecked {
            wallet_id: Token,
            parent_key_ref: KeyRef,
            package_hash: Digest32,
            route: String,
            agent_id: Option<String>,
            purpose: Token,
            allowed_crypto_suites: Vec<CryptoSuite>,
            maximum_lifetime_ms: DecimalU64,
            custody_operation_id: OperationId,
        }

        let unchecked = Unchecked::deserialize(deserializer)?;
        let scope = Self {
            wallet_id: unchecked.wallet_id,
            parent_key_ref: unchecked.parent_key_ref,
            package_hash: unchecked.package_hash,
            route: unchecked.route,
            agent_id: unchecked.agent_id,
            purpose: unchecked.purpose,
            allowed_crypto_suites: unchecked.allowed_crypto_suites,
            maximum_lifetime_ms: unchecked.maximum_lifetime_ms,
            custody_operation_id: unchecked.custody_operation_id,
        };
        scope.validate().map_err(serde::de::Error::custom)?;
        Ok(scope)
    }
}

impl PetalKeyScope {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.parent_key_ref.validate()?;
        validate_display_identity("Petal route", &self.route, ROUTE_MAX_BYTES)?;
        if let Some(agent_id) = &self.agent_id {
            validate_display_identity("Petal agent_id", agent_id, AGENT_ID_MAX_BYTES)?;
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
                "Petal key scope must contain 1-3 unique suites compatible with its parent KeyRef",
            ));
        }
        if self.maximum_lifetime_ms.get() == 0 {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "Petal key scope maximum_lifetime_ms must be greater than zero",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("Petal key scope JCS encoding failed: {error}"),
            )
        })
    }

    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(PETAL_KEY_SCOPE_DOMAIN);
        hasher.update(self.canonical_bytes()?);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }
}

fn validate_display_identity(
    field: &str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(ProtocolError::new(
            ProtocolErrorCode::MalformedFrame,
            format!(
                "{field} must contain 1-{maximum_bytes} UTF-8 bytes without control characters"
            ),
        ));
    }
    Ok(())
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

    fn scope() -> PetalKeyScope {
        PetalKeyScope {
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
            package_hash: digest(2),
            route: "/petals/exchange/orders".into(),
            agent_id: Some("desk-a".into()),
            purpose: Token::new("exchange-agent").unwrap(),
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            maximum_lifetime_ms: DecimalU64::new(86_400_000),
            custody_operation_id: operation(3),
        }
    }

    #[test]
    fn scope_digest_is_canonical_and_domain_separated() {
        let scope = scope();
        let canonical = scope.canonical_bytes().unwrap();
        let reparsed: PetalKeyScope = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(scope, reparsed);
        assert_eq!(scope.digest().unwrap(), reparsed.digest().unwrap());
        assert_eq!(
            scope.digest().unwrap().as_str(),
            "f3cffedb85ce0dd3eac9b44f9766fc0056e6af67296be1d97b120afd895c296a"
        );

        let raw_jcs_digest = Digest32::from_bytes(Sha256::digest(canonical).into());
        assert_ne!(scope.digest().unwrap(), raw_jcs_digest);
    }

    #[test]
    fn every_scope_identity_field_is_digest_bound() {
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
        changed.package_hash = digest(4);
        variants.push(changed);
        let mut changed = original.clone();
        changed.route = "/petals/exchange/cancel".into();
        variants.push(changed);
        let mut changed = original.clone();
        changed.agent_id = Some("desk-b".into());
        variants.push(changed);
        let mut changed = original.clone();
        changed.purpose = Token::new("payment-key").unwrap();
        variants.push(changed);
        let mut changed = original.clone();
        changed.allowed_crypto_suites = vec![CryptoSuite::Secp256k1Sha256Recoverable];
        variants.push(changed);
        let mut changed = original.clone();
        changed.maximum_lifetime_ms = DecimalU64::new(60_000);
        variants.push(changed);
        let mut changed = original;
        changed.custody_operation_id = operation(5);
        variants.push(changed);

        for variant in variants {
            assert_ne!(variant.digest().unwrap(), original_digest);
        }
    }

    #[test]
    fn malformed_scope_fails_closed_during_decode() {
        let mut value = serde_json::to_value(scope()).unwrap();
        value["allowed_crypto_suites"] = serde_json::json!([]);
        assert!(serde_json::from_value::<PetalKeyScope>(value).is_err());

        let mut value = serde_json::to_value(scope()).unwrap();
        value["route"] = serde_json::json!("bad\nroute");
        assert!(serde_json::from_value::<PetalKeyScope>(value).is_err());
    }
}
