//! Reusable backend conformance checks used by every backend test suite.

use crate::{
    BackendCapabilities, BackendError, BackendSignRequest, BackendSignature, SignerBackend,
};
use bloom_signer_api::{CryptoInputKind, SignatureEncoding};
use std::collections::HashSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceFailure(pub String);

impl std::fmt::Display for ConformanceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for ConformanceFailure {}

pub fn validate_capabilities(capabilities: &BackendCapabilities) -> Result<(), ConformanceFailure> {
    if capabilities.supported_key_specs.is_empty()
        || capabilities.supported_crypto_suites.is_empty()
        || capabilities.maximum_input_bytes.get() == 0
        || capabilities.maximum_batch_size.get() == 0
    {
        return Err(ConformanceFailure(
            "backend capabilities contain an empty required set or zero maximum".into(),
        ));
    }
    if !all_unique(&capabilities.supported_key_specs)
        || !all_unique(&capabilities.supported_crypto_suites)
        || !all_unique(&capabilities.input_kinds)
        || !all_unique(&capabilities.output_encodings)
    {
        return Err(ConformanceFailure(
            "backend capabilities contain duplicate entries".into(),
        ));
    }
    for suite in &capabilities.supported_crypto_suites {
        if !capabilities.supported_key_specs.contains(&suite.key_spec())
            || !capabilities.input_kinds.contains(&suite.input_kind())
            || !capabilities
                .output_encodings
                .contains(&suite.signature_encoding())
        {
            return Err(ConformanceFailure(format!(
                "capabilities do not fully describe {suite:?}"
            )));
        }
    }
    if capabilities.networked && capabilities.backend_id.as_str() == "local" {
        return Err(ConformanceFailure(
            "local backend must not advertise network access".into(),
        ));
    }
    Ok(())
}

pub fn validate_signature(
    request: &BackendSignRequest,
    signature: &BackendSignature,
) -> Result<(), ConformanceFailure> {
    if !request.input_matches_suite() {
        return Err(ConformanceFailure(
            "backend request input kind does not match CryptoSuite".into(),
        ));
    }
    if signature.crypto_suite != request.crypto_suite
        || signature.encoding != request.crypto_suite.signature_encoding()
    {
        return Err(ConformanceFailure(
            "backend output changed the requested suite or encoding".into(),
        ));
    }
    let expected_length = match signature.encoding {
        SignatureEncoding::Secp256k1Recoverable65 => 65,
        SignatureEncoding::Ed25519Raw64 => 64,
    };
    if signature.bytes.decode().len() != expected_length {
        return Err(ConformanceFailure(format!(
            "normalized signature must contain {expected_length} bytes"
        )));
    }
    Ok(())
}

pub async fn exercise_closed_error_taxonomy<F>(
    factory: F,
    request: BackendSignRequest,
) -> Result<(), ConformanceFailure>
where
    F: Fn(BackendError) -> Box<dyn SignerBackend>,
{
    let outcomes = [
        BackendError::DefinitiveRejected,
        BackendError::RetryableBeforeAcceptance,
        BackendError::Unsupported,
        BackendError::InvalidRequest,
        BackendError::IndeterminateAcceptance,
    ];
    for expected in outcomes {
        let backend = factory(expected);
        let actual = backend
            .sign(request.clone())
            .await
            .expect_err("fault-injection backend must return its selected outcome");
        if actual != expected {
            return Err(ConformanceFailure(format!(
                "fault outcome {expected:?} mapped to {actual:?}"
            )));
        }
    }
    Ok(())
}

fn all_unique<T: Eq + std::hash::Hash>(values: &[T]) -> bool {
    let mut seen = HashSet::with_capacity(values.len());
    values.iter().all(|value| seen.insert(value))
}

pub fn expected_input_kind(capabilities: &BackendCapabilities) -> Vec<CryptoInputKind> {
    capabilities
        .supported_crypto_suites
        .iter()
        .map(|suite| suite.input_kind())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BackendFuture, BackendInput, KeyDescription, ProviderIdempotency};
    use bloom_signer_api::{
        Base64UrlBytes, CryptoSuite, DecimalU64, Digest32, KeyRef, KeySpec, Token,
    };

    struct FaultBackend(BackendError);

    impl SignerBackend for FaultBackend {
        fn backend_id(&self) -> Token {
            Token::new("fault").unwrap()
        }

        fn capabilities(&self) -> BackendCapabilities {
            valid_capabilities()
        }

        fn describe_key<'a>(
            &'a self,
            _key: &'a KeyRef,
        ) -> BackendFuture<'a, Result<KeyDescription, BackendError>> {
            Box::pin(async move { Err(self.0) })
        }

        fn sign<'a>(
            &'a self,
            _request: BackendSignRequest,
        ) -> BackendFuture<'a, Result<BackendSignature, BackendError>> {
            Box::pin(async move { Err(self.0) })
        }
    }

    fn key_ref() -> KeyRef {
        KeyRef {
            backend: Token::new("local").unwrap(),
            backend_instance: Token::new("local-default").unwrap(),
            locator: "key-1".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: Digest32::new("11".repeat(32)).unwrap(),
            derivation: None,
        }
    }

    fn request() -> BackendSignRequest {
        BackendSignRequest {
            provider_attempt_id: Digest32::new("22".repeat(32)).unwrap(),
            key_ref: key_ref(),
            crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
            input: BackendInput::Digest32 {
                digest: Digest32::new("33".repeat(32)).unwrap(),
            },
            deadline_ms: DecimalU64::new(100),
        }
    }

    fn valid_capabilities() -> BackendCapabilities {
        BackendCapabilities {
            backend_id: Token::new("local").unwrap(),
            backend_instance_id: Token::new("local-default").unwrap(),
            supported_key_specs: vec![KeySpec::Secp256k1],
            supported_crypto_suites: vec![CryptoSuite::Secp256k1Sha256Recoverable],
            supported_derivation: vec![],
            input_kinds: vec![CryptoInputKind::Digest32],
            output_encodings: vec![SignatureEncoding::Secp256k1Recoverable65],
            maximum_input_bytes: DecimalU64::new(32),
            maximum_batch_size: DecimalU64::new(1),
            can_generate: true,
            can_import: true,
            can_export_encrypted: true,
            can_delete: true,
            requires_activation: false,
            requires_user_presence: false,
            networked: false,
            provider_idempotency: ProviderIdempotency::NoDeduplication,
        }
    }

    #[test]
    fn capabilities_and_normalized_output_are_checked() {
        let capabilities = valid_capabilities();
        validate_capabilities(&capabilities).unwrap();
        assert_eq!(
            expected_input_kind(&capabilities),
            vec![CryptoInputKind::Digest32]
        );

        let output = BackendSignature {
            crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
            encoding: SignatureEncoding::Secp256k1Recoverable65,
            bytes: Base64UrlBytes::from_bytes(&[0; 65]),
            provider_correlation_id: None,
        };
        validate_signature(&request(), &output).unwrap();

        let mut invalid = capabilities;
        invalid.input_kinds.clear();
        assert!(validate_capabilities(&invalid).is_err());
    }

    #[test]
    fn every_backend_fault_outcome_remains_distinct() {
        futures::executor::block_on(exercise_closed_error_taxonomy(
            |error| Box::new(FaultBackend(error)),
            request(),
        ))
        .unwrap();
    }
}
