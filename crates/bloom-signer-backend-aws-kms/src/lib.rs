//! Pinned AWS KMS secp256k1 backend.
//!
//! The backend owns validation, immutable key enrollment, normalized
//! signatures, and fail-closed provider error mapping. Transport and AWS
//! credential acquisition are injected through [`AwsKmsProvider`]; production
//! packaging must supply the reviewed provider implementation and enforce the
//! declared egress profile.

mod sdk;

pub use sdk::AwsSdkKmsProvider;

#[cfg(test)]
mod tests;

use bloom_signer_backend_api::{
    BackendCapabilities, BackendError, BackendFuture, BackendInput, BackendSignRequest,
    BackendSignature, DerivationCapability, KeyDescription, ProviderIdempotency, SecretBytes,
    SignerBackend, SignerBackendDerivation,
};
use bloom_triad_protocol::{
    Base64UrlBytes, CryptoInputKind, CryptoSuite, DecimalU64, Digest32, KeyRef, KeySpec,
    SignatureEncoding, Token,
};
use hmac::{Hmac, Mac as _};
use k256::{
    PublicKey,
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const KMS_KEY_SPEC: &str = "ECC_SECG_P256K1";
const KMS_KEY_USAGE: &str = "SIGN_VERIFY";
const KMS_SIGNING_ALGORITHM: &str = "ECDSA_SHA_256";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    WebIdentity {
        role_arn: String,
        token_file: PathBuf,
        session_name: Token,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AwsKmsInstanceConfig {
    pub backend_instance_id: Token,
    pub account_id: String,
    pub region: String,
    pub credential_source: CredentialSource,
    pub allowed_key_arns: Vec<String>,
    pub allowed_egress_hosts: Vec<String>,
    pub cloudtrail_required: bool,
    pub maximum_calls_per_second: DecimalU64,
    pub state_store_path: PathBuf,
}

impl AwsKmsInstanceConfig {
    pub fn validate(&self) -> Result<(), BackendError> {
        let expected_hosts = [
            format!("kms.{}.amazonaws.com", self.region),
            format!("sts.{}.amazonaws.com", self.region),
        ];
        if self.account_id.len() != 12
            || !self.account_id.bytes().all(|byte| byte.is_ascii_digit())
            || self.region.is_empty()
            || self.allowed_key_arns.is_empty()
            || self.allowed_egress_hosts != expected_hosts
            || !self.cloudtrail_required
            || self.maximum_calls_per_second.get() == 0
            || !self.state_store_path.is_absolute()
            || self
                .allowed_key_arns
                .iter()
                .any(|arn| parse_key_arn(arn, &self.region, &self.account_id).is_err())
        {
            return Err(BackendError::InvalidRequest);
        }
        match &self.credential_source {
            CredentialSource::WebIdentity {
                role_arn,
                token_file,
                session_name,
            } if role_arn.starts_with(&format!("arn:aws:iam::{}:role/", self.account_id))
                && token_file.is_absolute()
                && !session_name.as_str().is_empty() => {}
            _ => return Err(BackendError::InvalidRequest),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AwsKmsKeyMetadata {
    pub arn: String,
    pub account_id: String,
    pub region: String,
    pub enabled: bool,
    pub key_usage: String,
    pub key_spec: String,
    pub signing_algorithms: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsKmsPublicKey {
    pub canonical_spki_der: Vec<u8>,
    pub request_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsKmsSignRequest {
    pub key_arn: String,
    pub digest: [u8; 32],
    pub algorithm: String,
    pub message_type_digest: bool,
    pub provider_attempt_id: Digest32,
    pub deadline_ms: DecimalU64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsKmsSignResponse {
    pub der_signature: Vec<u8>,
    pub request_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsProviderErrorKind {
    DefinitiveRejected,
    ProvenNotDispatched,
    Unsupported,
    InvalidRequest,
    TimeoutAfterDispatch,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("AWS provider failure: {kind:?}")]
pub struct AwsProviderError {
    pub kind: AwsProviderErrorKind,
    pub request_id: Option<String>,
}

impl AwsProviderError {
    pub fn new(kind: AwsProviderErrorKind, request_id: Option<String>) -> Self {
        Self { kind, request_id }
    }

    pub const fn into_backend(&self) -> BackendError {
        match self.kind {
            AwsProviderErrorKind::DefinitiveRejected => BackendError::DefinitiveRejected,
            AwsProviderErrorKind::ProvenNotDispatched => BackendError::RetryableBeforeAcceptance,
            AwsProviderErrorKind::Unsupported => BackendError::Unsupported,
            AwsProviderErrorKind::InvalidRequest => BackendError::InvalidRequest,
            AwsProviderErrorKind::TimeoutAfterDispatch | AwsProviderErrorKind::Unknown => {
                BackendError::IndeterminateAcceptance
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsProviderCallContext {
    pub deadline_ms: DecimalU64,
    pub provider_attempt_id: Option<Digest32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsProviderResponse<T> {
    pub value: T,
    pub request_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AwsKmsEnrollmentRecord {
    pub metadata: AwsKmsKeyMetadata,
    pub canonical_spki_der: Base64UrlBytes,
    pub public_key_fingerprint: Digest32,
    pub public_key_address: String,
    pub describe_request_id: String,
    pub get_public_key_request_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AwsKmsAuditEvent {
    pub operation: AwsKmsAuditOperation,
    pub provider_attempt_id: Option<Digest32>,
    pub request_id: Option<String>,
    pub outcome: AwsKmsAuditOutcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsKmsAuditOperation {
    DescribeKey,
    GetPublicKey,
    Sign,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AwsKmsAuditOutcome {
    Succeeded,
    Failed(AwsProviderErrorKind),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AwsKmsDurablePayload {
    config_digest: Digest32,
    enrollments: Vec<AwsKmsEnrollmentRecord>,
    audit_events: Vec<AwsKmsAuditEvent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedAwsKmsState {
    payload: AwsKmsDurablePayload,
    authentication_tag: Digest32,
}

pub trait AwsKmsProvider: Send + Sync {
    fn describe_key<'a>(
        &'a self,
        immutable_key_arn: &'a str,
        context: AwsProviderCallContext,
    ) -> BackendFuture<'a, Result<AwsProviderResponse<AwsKmsKeyMetadata>, AwsProviderError>>;

    fn get_public_key<'a>(
        &'a self,
        immutable_key_arn: &'a str,
        context: AwsProviderCallContext,
    ) -> BackendFuture<'a, Result<AwsProviderResponse<AwsKmsPublicKey>, AwsProviderError>>;

    fn sign<'a>(
        &'a self,
        request: AwsKmsSignRequest,
    ) -> BackendFuture<'a, Result<AwsKmsSignResponse, AwsProviderError>>;
}

#[derive(Clone)]
struct EnrolledKey {
    description: KeyDescription,
    verifying_key: VerifyingKey,
    record: AwsKmsEnrollmentRecord,
}

pub struct AwsKmsSignerBackend {
    config: AwsKmsInstanceConfig,
    provider: Arc<dyn AwsKmsProvider>,
    state_authentication_key: SecretBytes,
    enrolled: RwLock<BTreeMap<String, EnrolledKey>>,
    recent_provider_calls_ms: Mutex<VecDeque<u64>>,
    durable: Mutex<AwsKmsDurablePayload>,
}

impl AwsKmsSignerBackend {
    /// Constructs the production SDK backend. `state_authentication_key` is a
    /// 32-byte secret owned by trusted Signer state and must remain stable
    /// across restarts; it authenticates the enrollment and provider-audit
    /// journal against coherent substitution and configuration rebinding.
    pub fn from_aws_sdk(
        config: AwsKmsInstanceConfig,
        state_authentication_key: SecretBytes,
    ) -> Result<Self, BackendError> {
        let provider =
            Arc::new(AwsSdkKmsProvider::new(&config).map_err(|error| error.into_backend())?);
        Self::new(config, provider, state_authentication_key)
    }

    fn new(
        config: AwsKmsInstanceConfig,
        provider: Arc<dyn AwsKmsProvider>,
        state_authentication_key: SecretBytes,
    ) -> Result<Self, BackendError> {
        config.validate()?;
        if state_authentication_key.expose_to_backend().len() != 32 {
            return Err(BackendError::InvalidRequest);
        }
        let config_digest = config_digest(&config)?;
        let durable = load_authenticated_state(
            &config.state_store_path,
            &state_authentication_key,
            &config_digest,
        )?;
        let backend = Self {
            config,
            provider,
            state_authentication_key,
            enrolled: RwLock::new(BTreeMap::new()),
            recent_provider_calls_ms: Mutex::new(VecDeque::new()),
            durable: Mutex::new(durable),
        };
        for record in backend.durable.lock().enrollments.clone() {
            let key = backend.validate_enrollment_record(record)?;
            backend
                .enrolled
                .write()
                .insert(key.description.key_ref.locator.clone(), key);
        }
        Ok(backend)
    }

    pub async fn enroll_key(
        &self,
        immutable_key_arn: &str,
        deadline_ms: DecimalU64,
    ) -> Result<KeyDescription, BackendError> {
        parse_key_arn(
            immutable_key_arn,
            &self.config.region,
            &self.config.account_id,
        )?;
        if !self
            .config
            .allowed_key_arns
            .iter()
            .any(|allowed| allowed == immutable_key_arn)
        {
            return Err(BackendError::InvalidRequest);
        }
        let context = AwsProviderCallContext {
            deadline_ms: deadline_ms.clone(),
            provider_attempt_id: None,
        };
        self.admit_provider_call(&deadline_ms)?;
        let metadata = match self
            .provider
            .describe_key(immutable_key_arn, context.clone())
            .await
        {
            Ok(response) => {
                if response.request_id.is_empty() {
                    self.record_audit(
                        AwsKmsAuditOperation::DescribeKey,
                        context.clone(),
                        None,
                        AwsKmsAuditOutcome::Failed(AwsProviderErrorKind::Unknown),
                    )?;
                    return Err(BackendError::DefinitiveRejected);
                }
                self.record_audit(
                    AwsKmsAuditOperation::DescribeKey,
                    context.clone(),
                    Some(response.request_id.clone()),
                    AwsKmsAuditOutcome::Succeeded,
                )?;
                response
            }
            Err(error) => {
                self.record_audit(
                    AwsKmsAuditOperation::DescribeKey,
                    context.clone(),
                    error.request_id.clone(),
                    AwsKmsAuditOutcome::Failed(error.kind),
                )?;
                return Err(error.into_backend());
            }
        };
        validate_metadata(&metadata.value, immutable_key_arn, &self.config)?;
        self.admit_provider_call(&deadline_ms)?;
        let response = match self
            .provider
            .get_public_key(immutable_key_arn, context.clone())
            .await
        {
            Ok(response) => {
                if response.request_id.is_empty() {
                    self.record_audit(
                        AwsKmsAuditOperation::GetPublicKey,
                        context.clone(),
                        None,
                        AwsKmsAuditOutcome::Failed(AwsProviderErrorKind::Unknown),
                    )?;
                    return Err(BackendError::DefinitiveRejected);
                }
                self.record_audit(
                    AwsKmsAuditOperation::GetPublicKey,
                    context.clone(),
                    Some(response.request_id.clone()),
                    AwsKmsAuditOutcome::Succeeded,
                )?;
                response
            }
            Err(error) => {
                self.record_audit(
                    AwsKmsAuditOperation::GetPublicKey,
                    context.clone(),
                    error.request_id.clone(),
                    AwsKmsAuditOutcome::Failed(error.kind),
                )?;
                return Err(error.into_backend());
            }
        };
        let public_key = PublicKey::from_public_key_der(&response.value.canonical_spki_der)
            .map_err(|_| BackendError::InvalidRequest)?;
        let canonical_spki_der = public_key
            .to_public_key_der()
            .map_err(|_| BackendError::InvalidRequest)?;
        if canonical_spki_der.as_bytes() != response.value.canonical_spki_der {
            return Err(BackendError::InvalidRequest);
        }
        let verifying_key = VerifyingKey::from(public_key);
        let fingerprint =
            Digest32::from_bytes(Sha256::digest(canonical_spki_der.as_bytes()).into());
        let key_ref = KeyRef {
            backend: Token::new("aws-kms").expect("static token"),
            backend_instance: self.config.backend_instance_id.clone(),
            locator: immutable_key_arn.to_owned(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: fingerprint.clone(),
            derivation: None,
        };
        key_ref
            .validate()
            .map_err(|_| BackendError::InvalidRequest)?;
        let description = KeyDescription {
            key_ref: key_ref.clone(),
            canonical_spki_der: Base64UrlBytes::from_bytes(canonical_spki_der.as_bytes()),
            public_key_fingerprint: fingerprint.clone(),
            supported_crypto_suites: vec![
                CryptoSuite::Secp256k1Keccak256Recoverable,
                CryptoSuite::Secp256k1Sha256Recoverable,
            ],
        };
        let record = AwsKmsEnrollmentRecord {
            metadata: metadata.value,
            canonical_spki_der: description.canonical_spki_der.clone(),
            public_key_fingerprint: fingerprint,
            public_key_address: ethereum_address(&verifying_key),
            describe_request_id: metadata.request_id,
            get_public_key_request_id: response.request_id,
        };
        let mut enrolled = self.enrolled.write();
        if let Some(existing) = enrolled.get(immutable_key_arn) {
            if existing.description == description && existing.record == record {
                return Ok(description);
            }
            return Err(BackendError::DefinitiveRejected);
        }
        let key = EnrolledKey {
            description: description.clone(),
            verifying_key,
            record,
        };
        let mut durable = self.durable.lock();
        durable.enrollments.push(key.record.clone());
        if let Err(error) = persist_authenticated_state(
            &self.config.state_store_path,
            &durable,
            &self.state_authentication_key,
        ) {
            durable.enrollments.pop();
            return Err(error);
        }
        enrolled.insert(immutable_key_arn.to_owned(), key);
        Ok(description)
    }

    pub fn enrollment_records(&self) -> Vec<AwsKmsEnrollmentRecord> {
        self.durable.lock().enrollments.clone()
    }

    pub fn audit_events(&self) -> Vec<AwsKmsAuditEvent> {
        self.durable.lock().audit_events.clone()
    }

    pub fn key_is_registered(&self, key_ref: &KeyRef) -> bool {
        self.enrolled
            .read()
            .get(&key_ref.locator)
            .is_some_and(|key| key.description.key_ref == *key_ref)
    }

    pub fn key_is_available(&self, key_ref: &KeyRef) -> bool {
        self.key_is_registered(key_ref)
    }

    fn enrolled_key(&self, key_ref: &KeyRef) -> Result<EnrolledKey, BackendError> {
        self.enrolled
            .read()
            .get(&key_ref.locator)
            .filter(|key| key.description.key_ref == *key_ref)
            .cloned()
            .ok_or(BackendError::InvalidRequest)
    }

    fn validate_enrollment_record(
        &self,
        record: AwsKmsEnrollmentRecord,
    ) -> Result<EnrolledKey, BackendError> {
        let arn = record.metadata.arn.clone();
        parse_key_arn(&arn, &self.config.region, &self.config.account_id)?;
        if !self.config.allowed_key_arns.contains(&arn) {
            return Err(BackendError::DefinitiveRejected);
        }
        validate_metadata(&record.metadata, &arn, &self.config)?;
        let spki = record.canonical_spki_der.decode();
        let public_key =
            PublicKey::from_public_key_der(&spki).map_err(|_| BackendError::DefinitiveRejected)?;
        let canonical = public_key
            .to_public_key_der()
            .map_err(|_| BackendError::DefinitiveRejected)?;
        if canonical.as_bytes() != spki {
            return Err(BackendError::DefinitiveRejected);
        }
        let fingerprint = Digest32::from_bytes(Sha256::digest(&spki).into());
        if fingerprint != record.public_key_fingerprint {
            return Err(BackendError::DefinitiveRejected);
        }
        if record.describe_request_id.is_empty() || record.get_public_key_request_id.is_empty() {
            return Err(BackendError::DefinitiveRejected);
        }
        let key_ref = KeyRef {
            backend: Token::new("aws-kms").expect("static token"),
            backend_instance: self.config.backend_instance_id.clone(),
            locator: arn,
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: fingerprint.clone(),
            derivation: None,
        };
        let verifying_key = VerifyingKey::from(public_key);
        if record.public_key_address != ethereum_address(&verifying_key) {
            return Err(BackendError::DefinitiveRejected);
        }
        Ok(EnrolledKey {
            description: KeyDescription {
                key_ref,
                canonical_spki_der: record.canonical_spki_der.clone(),
                public_key_fingerprint: fingerprint,
                supported_crypto_suites: vec![
                    CryptoSuite::Secp256k1Keccak256Recoverable,
                    CryptoSuite::Secp256k1Sha256Recoverable,
                ],
            },
            verifying_key,
            record,
        })
    }

    fn admit_provider_call(&self, deadline_ms: &DecimalU64) -> Result<(), BackendError> {
        let now = unix_time_ms()?;
        if deadline_ms.get() <= now {
            return Err(BackendError::RetryableBeforeAcceptance);
        }
        let mut calls = self.recent_provider_calls_ms.lock();
        while calls
            .front()
            .is_some_and(|time| time.saturating_add(1_000) <= now)
        {
            calls.pop_front();
        }
        if calls.len() as u64 >= self.config.maximum_calls_per_second.get() {
            return Err(BackendError::RetryableBeforeAcceptance);
        }
        calls.push_back(now);
        Ok(())
    }

    fn record_audit(
        &self,
        operation: AwsKmsAuditOperation,
        context: AwsProviderCallContext,
        request_id: Option<String>,
        outcome: AwsKmsAuditOutcome,
    ) -> Result<(), BackendError> {
        let mut durable = self.durable.lock();
        durable.audit_events.push(AwsKmsAuditEvent {
            operation,
            provider_attempt_id: context.provider_attempt_id,
            request_id,
            outcome,
        });
        if let Err(error) = persist_authenticated_state(
            &self.config.state_store_path,
            &durable,
            &self.state_authentication_key,
        ) {
            durable.audit_events.pop();
            return Err(error);
        }
        Ok(())
    }
}

impl SignerBackend for AwsKmsSignerBackend {
    fn backend_id(&self) -> Token {
        Token::new("aws-kms").expect("static token")
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend_id: self.backend_id(),
            backend_instance_id: self.config.backend_instance_id.clone(),
            supported_key_specs: vec![KeySpec::Secp256k1],
            supported_crypto_suites: vec![
                CryptoSuite::Secp256k1Keccak256Recoverable,
                CryptoSuite::Secp256k1Sha256Recoverable,
            ],
            supported_derivation: vec![],
            input_kinds: vec![CryptoInputKind::Digest32],
            output_encodings: vec![SignatureEncoding::Secp256k1Recoverable65],
            maximum_input_bytes: DecimalU64::new(32),
            maximum_batch_size: DecimalU64::new(1),
            can_generate: false,
            can_import: false,
            can_export_encrypted: false,
            can_delete: false,
            requires_activation: false,
            requires_user_presence: true,
            networked: true,
            provider_idempotency: ProviderIdempotency::NoDeduplication,
        }
    }

    fn describe_key<'a>(
        &'a self,
        key: &'a KeyRef,
    ) -> BackendFuture<'a, Result<KeyDescription, BackendError>> {
        Box::pin(async move { Ok(self.enrolled_key(key)?.description) })
    }

    fn sign<'a>(
        &'a self,
        request: BackendSignRequest,
    ) -> BackendFuture<'a, Result<BackendSignature, BackendError>> {
        Box::pin(async move {
            if !request.input_matches_suite()
                || !self
                    .capabilities()
                    .supported_crypto_suites
                    .contains(&request.crypto_suite)
            {
                return Err(BackendError::Unsupported);
            }
            let BackendInput::Digest32 { digest } = &request.input else {
                return Err(BackendError::InvalidRequest);
            };
            let digest_bytes: [u8; 32] = hex::decode(digest.as_str())
                .map_err(|_| BackendError::InvalidRequest)?
                .try_into()
                .map_err(|_| BackendError::InvalidRequest)?;
            let enrolled = self.enrolled_key(&request.key_ref)?;
            self.admit_provider_call(&request.deadline_ms)?;
            let context = AwsProviderCallContext {
                deadline_ms: request.deadline_ms.clone(),
                provider_attempt_id: Some(request.provider_attempt_id.clone()),
            };
            let provider = match self
                .provider
                .sign(AwsKmsSignRequest {
                    key_arn: request.key_ref.locator.clone(),
                    digest: digest_bytes,
                    algorithm: KMS_SIGNING_ALGORITHM.to_owned(),
                    message_type_digest: true,
                    provider_attempt_id: request.provider_attempt_id,
                    deadline_ms: request.deadline_ms,
                })
                .await
            {
                Ok(response) => {
                    if response.request_id.is_empty() {
                        self.record_audit(
                            AwsKmsAuditOperation::Sign,
                            context,
                            None,
                            AwsKmsAuditOutcome::Failed(AwsProviderErrorKind::Unknown),
                        )
                        .map_err(|_| BackendError::IndeterminateAcceptance)?;
                        return Err(BackendError::IndeterminateAcceptance);
                    }
                    self.record_audit(
                        AwsKmsAuditOperation::Sign,
                        context.clone(),
                        Some(response.request_id.clone()),
                        AwsKmsAuditOutcome::Succeeded,
                    )
                    .map_err(|_| BackendError::IndeterminateAcceptance)?;
                    response
                }
                Err(error) => {
                    self.record_audit(
                        AwsKmsAuditOperation::Sign,
                        context,
                        error.request_id.clone(),
                        AwsKmsAuditOutcome::Failed(error.kind),
                    )
                    .map_err(|_| BackendError::IndeterminateAcceptance)?;
                    return Err(error.into_backend());
                }
            };
            let normalized = normalize_recoverable_signature(
                &provider.der_signature,
                &digest_bytes,
                &enrolled.verifying_key,
            )?;
            Ok(BackendSignature {
                crypto_suite: request.crypto_suite,
                encoding: SignatureEncoding::Secp256k1Recoverable65,
                bytes: Base64UrlBytes::from_bytes(&normalized),
                provider_correlation_id: Some(provider.request_id),
            })
        })
    }
}

impl SignerBackendDerivation for AwsKmsSignerBackend {
    fn supported_derivation_schemes(&self) -> Vec<DerivationCapability> {
        Vec::new()
    }

    fn derive_public<'a>(
        &'a self,
        _root: &'a KeyRef,
        _canonical_path: &'a str,
    ) -> BackendFuture<'a, Result<KeyDescription, BackendError>> {
        Box::pin(async { Err(BackendError::Unsupported) })
    }

    fn register_derived_key<'a>(
        &'a self,
        _root: &'a KeyRef,
        _canonical_path: &'a str,
    ) -> BackendFuture<'a, Result<KeyDescription, BackendError>> {
        Box::pin(async { Err(BackendError::Unsupported) })
    }
}

fn parse_key_arn(arn: &str, region: &str, account_id: &str) -> Result<(), BackendError> {
    let prefix = format!("arn:aws:kms:{region}:{account_id}:key/");
    let key_id = arn
        .strip_prefix(&prefix)
        .filter(|value| !value.is_empty())
        .ok_or(BackendError::InvalidRequest)?;
    if key_id.contains('/') || key_id.contains(':') || arn.contains(":alias/") {
        return Err(BackendError::InvalidRequest);
    }
    Ok(())
}

fn validate_metadata(
    metadata: &AwsKmsKeyMetadata,
    immutable_key_arn: &str,
    config: &AwsKmsInstanceConfig,
) -> Result<(), BackendError> {
    if metadata.arn != immutable_key_arn
        || metadata.account_id != config.account_id
        || metadata.region != config.region
        || !metadata.enabled
        || metadata.key_usage != KMS_KEY_USAGE
        || metadata.key_spec != KMS_KEY_SPEC
        || metadata.signing_algorithms != [KMS_SIGNING_ALGORITHM]
    {
        return Err(BackendError::InvalidRequest);
    }
    Ok(())
}

fn normalize_recoverable_signature(
    der: &[u8],
    digest: &[u8; 32],
    expected_key: &VerifyingKey,
) -> Result<[u8; 65], BackendError> {
    let signature = Signature::from_der(der).map_err(|_| BackendError::DefinitiveRejected)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    let recovery_id = (0_u8..=3)
        .filter_map(RecoveryId::from_byte)
        .find(|recovery_id| {
            VerifyingKey::recover_from_prehash(digest, &signature, *recovery_id)
                .is_ok_and(|recovered| recovered == *expected_key)
        })
        .ok_or(BackendError::DefinitiveRejected)?;
    let mut output = [0_u8; 65];
    output[..64].copy_from_slice(&signature.to_bytes());
    output[64] = recovery_id.to_byte();
    Ok(output)
}

fn ethereum_address(verifying_key: &VerifyingKey) -> String {
    let encoded = verifying_key.to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    format!("0x{}", hex::encode(&digest[12..]))
}

fn unix_time_ms() -> Result<u64, BackendError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BackendError::RetryableBeforeAcceptance)?
        .as_millis();
    millis
        .try_into()
        .map_err(|_| BackendError::RetryableBeforeAcceptance)
}

fn config_digest(config: &AwsKmsInstanceConfig) -> Result<Digest32, BackendError> {
    let bytes = serde_jcs::to_vec(config).map_err(|_| BackendError::InvalidRequest)?;
    Ok(Digest32::from_bytes(Sha256::digest(bytes).into()))
}

fn load_authenticated_state(
    path: &Path,
    authentication_key: &SecretBytes,
    expected_config_digest: &Digest32,
) -> Result<AwsKmsDurablePayload, BackendError> {
    match fs::read(path) {
        Ok(bytes) => {
            let state: AuthenticatedAwsKmsState =
                serde_json::from_slice(&bytes).map_err(|_| BackendError::DefinitiveRejected)?;
            if state.payload.config_digest != *expected_config_digest {
                return Err(BackendError::DefinitiveRejected);
            }
            let payload =
                serde_jcs::to_vec(&state.payload).map_err(|_| BackendError::DefinitiveRejected)?;
            let mut mac = Hmac::<Sha256>::new_from_slice(authentication_key.expose_to_backend())
                .map_err(|_| BackendError::DefinitiveRejected)?;
            mac.update(&payload);
            let tag = hex::decode(state.authentication_tag.as_str())
                .map_err(|_| BackendError::DefinitiveRejected)?;
            mac.verify_slice(&tag)
                .map_err(|_| BackendError::DefinitiveRejected)?;
            Ok(state.payload)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(AwsKmsDurablePayload {
            config_digest: expected_config_digest.clone(),
            enrollments: Vec::new(),
            audit_events: Vec::new(),
        }),
        Err(_) => Err(BackendError::DefinitiveRejected),
    }
}

fn persist_authenticated_state(
    path: &Path,
    payload: &AwsKmsDurablePayload,
    authentication_key: &SecretBytes,
) -> Result<(), BackendError> {
    let parent = path.parent().ok_or(BackendError::InvalidRequest)?;
    fs::create_dir_all(parent).map_err(|_| BackendError::DefinitiveRejected)?;
    let temporary = path.with_extension("tmp");
    let payload_bytes = serde_jcs::to_vec(payload).map_err(|_| BackendError::DefinitiveRejected)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(authentication_key.expose_to_backend())
        .map_err(|_| BackendError::DefinitiveRejected)?;
    mac.update(&payload_bytes);
    let state = AuthenticatedAwsKmsState {
        payload: payload.clone(),
        authentication_tag: Digest32::from_bytes(mac.finalize().into_bytes().into()),
    };
    let bytes = serde_jcs::to_vec(&state).map_err(|_| BackendError::DefinitiveRejected)?;
    {
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| BackendError::DefinitiveRejected)?;
        file.write_all(&bytes)
            .map_err(|_| BackendError::DefinitiveRejected)?;
        file.sync_all()
            .map_err(|_| BackendError::DefinitiveRejected)?;
    }
    fs::rename(&temporary, path).map_err(|_| BackendError::DefinitiveRejected)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| BackendError::DefinitiveRejected)
}
