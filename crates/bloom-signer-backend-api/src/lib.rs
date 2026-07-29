//! Compile-time Signer backend contract.
//!
//! Backends implement this object-safe seam inside the Signer process. The
//! types here contain no Sealed Approval, Petal, policy, asset, or budget
//! concepts.

pub mod conformance;

use bloom_triad_protocol::{
    Base64UrlBytes, CryptoInputKind, CryptoSuite, DecimalU64, Digest32, KeyRef, KeySpec,
    SignatureEncoding, Token,
};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderIdempotency {
    NativeOperationKey,
    NoDeduplication,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationCapability {
    pub scheme: Token,
    pub maximum_depth: u8,
    pub maximum_index: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendCapabilities {
    pub backend_id: Token,
    pub backend_instance_id: Token,
    pub supported_key_specs: Vec<KeySpec>,
    pub supported_crypto_suites: Vec<CryptoSuite>,
    pub supported_derivation: Vec<DerivationCapability>,
    pub input_kinds: Vec<CryptoInputKind>,
    pub output_encodings: Vec<SignatureEncoding>,
    pub maximum_input_bytes: DecimalU64,
    pub maximum_batch_size: DecimalU64,
    pub can_generate: bool,
    pub can_import: bool,
    pub can_export_encrypted: bool,
    pub can_delete: bool,
    pub requires_activation: bool,
    pub requires_user_presence: bool,
    pub networked: bool,
    pub provider_idempotency: ProviderIdempotency,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyDescription {
    pub key_ref: KeyRef,
    pub canonical_spki_der: Base64UrlBytes,
    pub public_key_fingerprint: Digest32,
    pub supported_crypto_suites: Vec<CryptoSuite>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackendInput {
    Digest32 { digest: Digest32 },
    Message { message: Base64UrlBytes },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendSignRequest {
    pub provider_attempt_id: Digest32,
    pub key_ref: KeyRef,
    pub crypto_suite: CryptoSuite,
    pub input: BackendInput,
    pub deadline_ms: DecimalU64,
}

impl BackendSignRequest {
    pub fn input_matches_suite(&self) -> bool {
        matches!(
            (self.crypto_suite.input_kind(), &self.input),
            (CryptoInputKind::Digest32, BackendInput::Digest32 { .. })
                | (CryptoInputKind::Message, BackendInput::Message { .. })
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendSignature {
    pub crypto_suite: CryptoSuite,
    pub encoding: SignatureEncoding,
    pub bytes: Base64UrlBytes,
    pub provider_correlation_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BackendError {
    #[error("backend definitively rejected the operation")]
    DefinitiveRejected,
    #[error("backend proved it had not accepted the operation")]
    RetryableBeforeAcceptance,
    #[error("backend does not support the request")]
    Unsupported,
    #[error("backend request is invalid")]
    InvalidRequest,
    #[error("backend acceptance is indeterminate")]
    IndeterminateAcceptance,
}

impl BackendError {
    /// Fail-closed mapping for an unrecognized provider failure.
    pub const fn from_unknown_provider_error() -> Self {
        Self::IndeterminateAcceptance
    }
}

pub trait SignerBackend: Send + Sync {
    fn backend_id(&self) -> Token;

    fn capabilities(&self) -> BackendCapabilities;

    fn describe_key<'a>(
        &'a self,
        key: &'a KeyRef,
    ) -> BackendFuture<'a, Result<KeyDescription, BackendError>>;

    fn sign<'a>(
        &'a self,
        request: BackendSignRequest,
    ) -> BackendFuture<'a, Result<BackendSignature, BackendError>>;
}

#[derive(Clone, Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose_to_backend(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct ProvisionedSecret {
    pub private_material: SecretBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedExport {
    pub format: Token,
    pub ciphertext: Base64UrlBytes,
}

pub trait SignerBackendProvisioning: Send + Sync {
    fn generate<'a>(
        &'a self,
        key_spec: KeySpec,
    ) -> BackendFuture<'a, Result<KeyDescription, BackendError>>;

    fn import<'a>(
        &'a self,
        key_spec: KeySpec,
        secret: SecretBytes,
    ) -> BackendFuture<'a, Result<KeyDescription, BackendError>>;

    fn delete<'a>(&'a self, key: &'a KeyRef) -> BackendFuture<'a, Result<(), BackendError>>;

    fn export_encrypted<'a>(
        &'a self,
        key: &'a KeyRef,
    ) -> BackendFuture<'a, Result<EncryptedExport, BackendError>>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStatus {
    Inactive,
    Active,
}

pub trait SignerBackendActivation: Send + Sync {
    fn prepare<'a>(&'a self, key: &'a KeyRef) -> BackendFuture<'a, Result<Token, BackendError>>;

    fn activate<'a>(
        &'a self,
        key: &'a KeyRef,
        secret: SecretBytes,
    ) -> BackendFuture<'a, Result<(), BackendError>>;

    fn deactivate<'a>(&'a self, key: &'a KeyRef) -> BackendFuture<'a, Result<(), BackendError>>;

    fn activation_status<'a>(
        &'a self,
        key: &'a KeyRef,
    ) -> BackendFuture<'a, Result<ActivationStatus, BackendError>>;
}

pub trait SignerBackendDerivation: Send + Sync {
    fn supported_derivation_schemes(&self) -> Vec<DerivationCapability>;

    fn derive_public<'a>(
        &'a self,
        root: &'a KeyRef,
        canonical_path: &'a str,
    ) -> BackendFuture<'a, Result<KeyDescription, BackendError>>;

    fn register_derived_key<'a>(
        &'a self,
        root: &'a KeyRef,
        canonical_path: &'a str,
    ) -> BackendFuture<'a, Result<KeyDescription, BackendError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_backend_errors_are_indeterminate() {
        assert_eq!(
            BackendError::from_unknown_provider_error(),
            BackendError::IndeterminateAcceptance
        );
    }

    #[test]
    fn suite_controls_input_kind() {
        let request = BackendSignRequest {
            provider_attempt_id: Digest32::new("11".repeat(32)).unwrap(),
            key_ref: KeyRef {
                backend: Token::new("local").unwrap(),
                backend_instance: Token::new("local-default").unwrap(),
                locator: "key-1".into(),
                key_spec: KeySpec::Secp256k1,
                public_key_fingerprint: Digest32::new("22".repeat(32)).unwrap(),
                derivation: None,
            },
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            input: BackendInput::Message {
                message: Base64UrlBytes::from_bytes(b"wrong input kind"),
            },
            deadline_ms: DecimalU64::new(10),
        };
        assert!(!request.input_matches_suite());
    }
}
