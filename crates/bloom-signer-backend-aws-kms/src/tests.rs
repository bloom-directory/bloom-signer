use crate::*;
use bloom_signer_backend_api::{
    BackendError, BackendInput, BackendSignRequest, SecretBytes, SignerBackend,
    SignerBackendDerivation,
    conformance::{validate_capabilities, validate_signature},
};
use bloom_triad_protocol::{CryptoSuite, DecimalU64, Digest32, SignatureEncoding, Token};
use k256::{
    ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner},
    pkcs8::EncodePublicKey,
};
use parking_lot::RwLock;
use sha2::Digest as _;
use std::{
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const ARN: &str = "arn:aws:kms:eu-west-2:123456789012:key/11111111-2222-3333-4444-555555555555";

struct MockProvider {
    signing_key: SigningKey,
    metadata: AwsKmsKeyMetadata,
    public: AwsKmsPublicKey,
    sign_error: RwLock<Option<AwsProviderError>>,
    signature_override: RwLock<Option<Vec<u8>>>,
    sign_request_id: RwLock<String>,
    last_sign: RwLock<Option<AwsKmsSignRequest>>,
    sign_calls: RwLock<u64>,
}

impl MockProvider {
    fn new() -> Self {
        let signing_key = SigningKey::from_slice(&[7; 32]).unwrap();
        let public_key = k256::PublicKey::from_sec1_bytes(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap();
        Self {
            signing_key,
            metadata: AwsKmsKeyMetadata {
                arn: ARN.into(),
                account_id: "123456789012".into(),
                region: "eu-west-2".into(),
                enabled: true,
                key_usage: "SIGN_VERIFY".into(),
                key_spec: "ECC_SECG_P256K1".into(),
                signing_algorithms: vec!["ECDSA_SHA_256".into()],
            },
            public: AwsKmsPublicKey {
                canonical_spki_der: public_key.to_public_key_der().unwrap().as_bytes().to_vec(),
                request_id: "get-public-key-request".into(),
            },
            sign_error: RwLock::new(None),
            signature_override: RwLock::new(None),
            sign_request_id: RwLock::new("sign-request-id".into()),
            last_sign: RwLock::new(None),
            sign_calls: RwLock::new(0),
        }
    }
}

impl AwsKmsProvider for MockProvider {
    fn describe_key<'a>(
        &'a self,
        _immutable_key_arn: &'a str,
        _context: AwsProviderCallContext,
    ) -> bloom_signer_backend_api::BackendFuture<
        'a,
        Result<AwsProviderResponse<AwsKmsKeyMetadata>, AwsProviderError>,
    > {
        Box::pin(async {
            Ok(AwsProviderResponse {
                value: self.metadata.clone(),
                request_id: "describe-key-request".into(),
            })
        })
    }

    fn get_public_key<'a>(
        &'a self,
        _immutable_key_arn: &'a str,
        _context: AwsProviderCallContext,
    ) -> bloom_signer_backend_api::BackendFuture<
        'a,
        Result<AwsProviderResponse<AwsKmsPublicKey>, AwsProviderError>,
    > {
        Box::pin(async {
            Ok(AwsProviderResponse {
                value: self.public.clone(),
                request_id: "get-public-key-request".into(),
            })
        })
    }

    fn sign<'a>(
        &'a self,
        request: AwsKmsSignRequest,
    ) -> bloom_signer_backend_api::BackendFuture<'a, Result<AwsKmsSignResponse, AwsProviderError>>
    {
        Box::pin(async move {
            *self.sign_calls.write() += 1;
            *self.last_sign.write() = Some(request.clone());
            if let Some(error) = self.sign_error.read().clone() {
                return Err(error);
            }
            let signature: Signature =
                self.signing_key
                    .sign_prehash(&request.digest)
                    .map_err(|_| {
                        AwsProviderError::new(AwsProviderErrorKind::DefinitiveRejected, None)
                    })?;
            Ok(AwsKmsSignResponse {
                der_signature: self
                    .signature_override
                    .read()
                    .clone()
                    .unwrap_or_else(|| signature.to_der().as_bytes().to_vec()),
                request_id: self.sign_request_id.read().clone(),
            })
        })
    }
}

fn config(root: &Path) -> AwsKmsInstanceConfig {
    AwsKmsInstanceConfig {
        backend_instance_id: Token::new("aws-production").unwrap(),
        account_id: "123456789012".into(),
        region: "eu-west-2".into(),
        credential_source: CredentialSource::WebIdentity {
            role_arn: "arn:aws:iam::123456789012:role/bloom-signer".into(),
            token_file: root.join("web-identity-token"),
            session_name: Token::new("bloom-signer").unwrap(),
        },
        allowed_key_arns: vec![ARN.into()],
        allowed_egress_hosts: vec![
            "kms.eu-west-2.amazonaws.com".into(),
            "sts.eu-west-2.amazonaws.com".into(),
        ],
        cloudtrail_required: true,
        maximum_calls_per_second: DecimalU64::new(10),
        state_store_path: root.join("aws-kms-state.json"),
    }
}

fn future_deadline() -> DecimalU64 {
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    DecimalU64::new(now + 60_000)
}

fn state_authentication_key() -> SecretBytes {
    SecretBytes::new(vec![0x42; 32])
}

fn test_backend(
    config: AwsKmsInstanceConfig,
    provider: Arc<MockProvider>,
) -> Result<AwsKmsSignerBackend, BackendError> {
    AwsKmsSignerBackend::new(config, provider, state_authentication_key())
}

fn request(key_ref: bloom_triad_protocol::KeyRef) -> BackendSignRequest {
    BackendSignRequest {
        provider_attempt_id: Digest32::new("22".repeat(32)).unwrap(),
        key_ref,
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        input: BackendInput::Digest32 {
            digest: Digest32::new("33".repeat(32)).unwrap(),
        },
        deadline_ms: future_deadline(),
    }
}

#[test]
fn config_requires_explicit_credentials_exact_egress_and_immutable_arns() {
    let directory = tempfile::tempdir().unwrap();
    config(directory.path()).validate().unwrap();

    let mut invalid_egress = config(directory.path());
    invalid_egress
        .allowed_egress_hosts
        .push("sts.amazonaws.com".into());
    assert_eq!(
        invalid_egress.validate().unwrap_err(),
        BackendError::InvalidRequest
    );

    let mut alias = config(directory.path());
    alias.allowed_key_arns = vec!["arn:aws:kms:eu-west-2:123456789012:alias/wallet".into()];
    assert_eq!(alias.validate().unwrap_err(), BackendError::InvalidRequest);
}

#[test]
fn production_constructor_binds_the_explicit_aws_sdk_provider_without_ambient_chain() {
    let directory = tempfile::tempdir().unwrap();
    let backend =
        AwsKmsSignerBackend::from_aws_sdk(config(directory.path()), state_authentication_key())
            .unwrap();
    assert_eq!(backend.backend_id(), Token::new("aws-kms").unwrap());
    assert!(backend.capabilities().networked);
}

#[test]
fn enrollment_pins_metadata_spki_and_normalizes_recoverable_signature() {
    let directory = tempfile::tempdir().unwrap();
    let provider = Arc::new(MockProvider::new());
    let backend = test_backend(config(directory.path()), provider.clone()).unwrap();
    validate_capabilities(&backend.capabilities()).unwrap();
    assert!(backend.supported_derivation_schemes().is_empty());

    let description =
        futures::executor::block_on(backend.enroll_key(ARN, future_deadline())).unwrap();
    assert_eq!(description.key_ref.locator, ARN);
    assert!(backend.key_is_available(&description.key_ref));
    assert_eq!(
        futures::executor::block_on(backend.describe_key(&description.key_ref)).unwrap(),
        description
    );

    let request = request(description.key_ref);
    let signature = futures::executor::block_on(backend.sign(request.clone())).unwrap();
    validate_signature(&request, &signature).unwrap();
    assert_eq!(
        signature.encoding,
        SignatureEncoding::Secp256k1Recoverable65
    );
    assert_eq!(
        signature.provider_correlation_id.as_deref(),
        Some("sign-request-id")
    );
    let sent = provider.last_sign.read().clone().unwrap();
    assert_eq!(sent.key_arn, ARN);
    assert_eq!(sent.algorithm, "ECDSA_SHA_256");
    assert!(sent.message_type_digest);
    assert_eq!(sent.digest, [0x33; 32]);
    assert_eq!(sent.deadline_ms, request.deadline_ms);
    let audit = backend.audit_events();
    assert_eq!(audit.len(), 3);
    assert_eq!(audit[0].request_id.as_deref(), Some("describe-key-request"));
    assert_eq!(
        audit[1].request_id.as_deref(),
        Some("get-public-key-request")
    );
    assert_eq!(audit[2].request_id.as_deref(), Some("sign-request-id"));
}

#[test]
fn durable_enrollment_restores_without_provider_reenrollment() {
    let directory = tempfile::tempdir().unwrap();
    let provider = Arc::new(MockProvider::new());
    let key = {
        let backend = test_backend(config(directory.path()), provider.clone()).unwrap();
        futures::executor::block_on(backend.enroll_key(ARN, future_deadline()))
            .unwrap()
            .key_ref
    };

    let restarted = test_backend(config(directory.path()), provider.clone()).unwrap();
    assert!(restarted.key_is_registered(&key));
    let signature = futures::executor::block_on(restarted.sign(request(key.clone()))).unwrap();
    assert_eq!(
        signature.encoding,
        SignatureEncoding::Secp256k1Recoverable65
    );
    assert_eq!(restarted.audit_events().len(), 3);

    let path = config(directory.path()).state_store_path;
    let original = std::fs::read(&path).unwrap();
    let mut state: AuthenticatedAwsKmsState = serde_json::from_slice(&original).unwrap();
    let substitute = SigningKey::from_slice(&[9; 32]).unwrap();
    let substitute_public = substitute.verifying_key();
    let substitute_spki =
        k256::PublicKey::from_sec1_bytes(substitute_public.to_encoded_point(false).as_bytes())
            .unwrap()
            .to_public_key_der()
            .unwrap();
    state.payload.enrollments[0].canonical_spki_der =
        bloom_triad_protocol::Base64UrlBytes::from_bytes(substitute_spki.as_bytes());
    state.payload.enrollments[0].public_key_fingerprint =
        Digest32::from_bytes(sha2::Sha256::digest(substitute_spki.as_bytes()).into());
    state.payload.enrollments[0].public_key_address = ethereum_address(substitute_public);
    std::fs::write(&path, serde_jcs::to_vec(&state).unwrap()).unwrap();
    assert!(matches!(
        test_backend(config(directory.path()), provider),
        Err(BackendError::DefinitiveRejected)
    ));

    std::fs::write(&path, original).unwrap();
    let mut rebound = config(directory.path());
    rebound.backend_instance_id = Token::new("aws-rebound").unwrap();
    assert!(matches!(
        test_backend(rebound, Arc::new(MockProvider::new())),
        Err(BackendError::DefinitiveRejected)
    ));
    assert!(matches!(
        AwsKmsSignerBackend::new(
            config(directory.path()),
            Arc::new(MockProvider::new()),
            SecretBytes::new(vec![0x43; 32]),
        ),
        Err(BackendError::DefinitiveRejected)
    ));
}

#[test]
fn enrollment_rejects_alias_metadata_drift_and_unpinned_keys() {
    let directory = tempfile::tempdir().unwrap();
    let provider = Arc::new(MockProvider::new());
    let backend = test_backend(config(directory.path()), provider.clone()).unwrap();
    assert_eq!(
        futures::executor::block_on(backend.enroll_key(
            "arn:aws:kms:eu-west-2:123456789012:alias/wallet",
            future_deadline(),
        ))
        .unwrap_err(),
        BackendError::InvalidRequest
    );
    assert_eq!(
        futures::executor::block_on(backend.enroll_key(
            "arn:aws:kms:eu-west-2:123456789012:key/not-allowed",
            future_deadline(),
        ))
        .unwrap_err(),
        BackendError::InvalidRequest
    );

    let mut wrong = provider.metadata.clone();
    wrong.enabled = false;
    let wrong_provider = Arc::new(MockProvider {
        metadata: wrong,
        ..MockProvider::new()
    });
    let wrong_directory = tempfile::tempdir().unwrap();
    let wrong_backend = test_backend(config(wrong_directory.path()), wrong_provider).unwrap();
    assert_eq!(
        futures::executor::block_on(wrong_backend.enroll_key(ARN, future_deadline())).unwrap_err(),
        BackendError::InvalidRequest
    );

    let mut noncanonical = MockProvider::new();
    noncanonical.public.canonical_spki_der.push(0);
    let noncanonical_directory = tempfile::tempdir().unwrap();
    let noncanonical_backend = test_backend(
        config(noncanonical_directory.path()),
        Arc::new(noncanonical),
    )
    .unwrap();
    assert_eq!(
        futures::executor::block_on(noncanonical_backend.enroll_key(ARN, future_deadline()))
            .unwrap_err(),
        BackendError::InvalidRequest
    );
}

#[test]
fn provider_faults_preserve_ambiguity_and_never_invent_retry_safety() {
    let cases = [
        (
            AwsProviderErrorKind::DefinitiveRejected,
            BackendError::DefinitiveRejected,
        ),
        (
            AwsProviderErrorKind::ProvenNotDispatched,
            BackendError::RetryableBeforeAcceptance,
        ),
        (AwsProviderErrorKind::Unsupported, BackendError::Unsupported),
        (
            AwsProviderErrorKind::InvalidRequest,
            BackendError::InvalidRequest,
        ),
        (
            AwsProviderErrorKind::TimeoutAfterDispatch,
            BackendError::IndeterminateAcceptance,
        ),
        (
            AwsProviderErrorKind::Unknown,
            BackendError::IndeterminateAcceptance,
        ),
    ];
    for (index, (provider_error, expected)) in cases.into_iter().enumerate() {
        let directory = tempfile::tempdir().unwrap();
        let provider = Arc::new(MockProvider::new());
        let backend = test_backend(config(directory.path()), provider.clone()).unwrap();
        let key = futures::executor::block_on(backend.enroll_key(ARN, future_deadline()))
            .unwrap()
            .key_ref;
        *provider.sign_error.write() = Some(AwsProviderError::new(
            provider_error,
            Some(format!("failure-request-{index}")),
        ));
        assert_eq!(
            futures::executor::block_on(backend.sign(request(key))).unwrap_err(),
            expected
        );
        let audit = backend.audit_events();
        assert_eq!(
            audit.last().unwrap().request_id.as_deref(),
            Some(format!("failure-request-{index}").as_str())
        );
        assert!(provider.last_sign.read().is_some());
        assert_eq!(*provider.sign_calls.read(), 1);
        drop(backend);
        let restarted = test_backend(config(directory.path()), provider).unwrap();
        assert_eq!(
            restarted
                .audit_events()
                .last()
                .unwrap()
                .request_id
                .as_deref(),
            Some(format!("failure-request-{index}").as_str())
        );
    }
}

#[test]
fn high_s_provider_signature_is_normalized_to_low_s() {
    let directory = tempfile::tempdir().unwrap();
    let provider = Arc::new(MockProvider::new());
    let backend = test_backend(config(directory.path()), provider.clone()).unwrap();
    let key = futures::executor::block_on(backend.enroll_key(ARN, future_deadline()))
        .unwrap()
        .key_ref;
    let low: Signature = provider.signing_key.sign_prehash(&[0x33; 32]).unwrap();
    let high_s = subtract_be(
        [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ],
        low.s().to_bytes().into(),
    );
    let high = Signature::from_scalars(low.r().to_bytes(), high_s).unwrap();
    assert!(high.normalize_s().is_some());
    *provider.signature_override.write() = Some(high.to_der().as_bytes().to_vec());

    let output = futures::executor::block_on(backend.sign(request(key))).unwrap();
    let bytes = output.bytes.decode();
    let normalized = Signature::from_slice(&bytes[..64]).unwrap();
    assert!(normalized.normalize_s().is_none());
}

fn subtract_be(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    let mut borrow = 0_i16;
    for index in (0..32).rev() {
        let value = left[index] as i16 - right[index] as i16 - borrow;
        if value < 0 {
            output[index] = (value + 256) as u8;
            borrow = 1;
        } else {
            output[index] = value as u8;
            borrow = 0;
        }
    }
    assert_eq!(borrow, 0);
    output
}

#[test]
fn expired_deadline_and_quota_reject_before_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let provider = Arc::new(MockProvider::new());
    let mut limited = config(directory.path());
    limited.maximum_calls_per_second = DecimalU64::new(2);
    let backend = test_backend(limited, provider.clone()).unwrap();
    let key = futures::executor::block_on(backend.enroll_key(ARN, future_deadline()))
        .unwrap()
        .key_ref;
    assert_eq!(
        futures::executor::block_on(backend.sign(request(key.clone()))).unwrap_err(),
        BackendError::RetryableBeforeAcceptance
    );
    assert!(provider.last_sign.read().is_none());

    let mut expired = request(key);
    expired.deadline_ms = DecimalU64::new(1);
    assert_eq!(
        futures::executor::block_on(backend.sign(expired)).unwrap_err(),
        BackendError::RetryableBeforeAcceptance
    );
    assert!(provider.last_sign.read().is_none());
}

#[test]
fn malformed_or_wrong_key_provider_signatures_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let provider = Arc::new(MockProvider::new());
    let backend = test_backend(config(directory.path()), provider.clone()).unwrap();
    let key = futures::executor::block_on(backend.enroll_key(ARN, future_deadline()))
        .unwrap()
        .key_ref;

    *provider.signature_override.write() = Some(vec![0x30, 0x00]);
    assert_eq!(
        futures::executor::block_on(backend.sign(request(key.clone()))).unwrap_err(),
        BackendError::DefinitiveRejected
    );

    let wrong_signer = SigningKey::from_slice(&[9; 32]).unwrap();
    let wrong_signature: Signature = wrong_signer.sign_prehash(&[0x33; 32]).unwrap();
    *provider.signature_override.write() = Some(wrong_signature.to_der().as_bytes().to_vec());
    assert_eq!(
        futures::executor::block_on(backend.sign(request(key))).unwrap_err(),
        BackendError::DefinitiveRejected
    );
}

#[test]
fn successful_provider_signature_without_correlation_is_indeterminate_and_charged() {
    let directory = tempfile::tempdir().unwrap();
    let provider = Arc::new(MockProvider::new());
    let backend = test_backend(config(directory.path()), provider.clone()).unwrap();
    let key = futures::executor::block_on(backend.enroll_key(ARN, future_deadline()))
        .unwrap()
        .key_ref;
    provider.sign_request_id.write().clear();
    assert_eq!(
        futures::executor::block_on(backend.sign(request(key))).unwrap_err(),
        BackendError::IndeterminateAcceptance
    );
    assert_eq!(*provider.sign_calls.read(), 1);
    assert_eq!(
        backend.audit_events().last().unwrap().outcome,
        AwsKmsAuditOutcome::Failed(AwsProviderErrorKind::Unknown)
    );
}
