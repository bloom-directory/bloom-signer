use serde::{Deserialize, Serialize};

use crate::{
    ActivationMode, Base64UrlBytes, CeremonyState, CryptoSuite, DecimalU64, Digest32, HpkeEnvelope,
    KeyRef, OperationId, PetalKeyScope, ProtocolError, ProtocolErrorCode, SealedApprovalTerms,
    Token,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyKind {
    SealedApproval,
    WalletRegistration,
    WalletImport,
    WalletExport,
    WalletDelete,
    WalletRecovery,
    CredentialAdd,
    CredentialReplace,
    CredentialRemove,
    BackendEnrollment,
    KeyDerive,
    PolicyUpdate,
}

impl CeremonyKind {
    /// Normative successful terminal state from §13.6. Registration completes
    /// only after its recovery-output acknowledgement; every other custody
    /// workflow uses the generic/credential `SUCCEEDED` terminal.
    pub const fn successful_terminal_state(self) -> Option<crate::CeremonyState> {
        match self {
            Self::SealedApproval => None,
            Self::WalletRegistration => Some(crate::CeremonyState::Completed),
            Self::WalletImport
            | Self::WalletExport
            | Self::WalletDelete
            | Self::WalletRecovery
            | Self::CredentialAdd
            | Self::CredentialReplace
            | Self::CredentialRemove
            | Self::BackendEnrollment
            | Self::KeyDerive
            | Self::PolicyUpdate => Some(crate::CeremonyState::Succeeded),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyPrepareRequest {
    pub activation_operation_id: OperationId,
    pub terms: SealedApprovalTerms,
    pub review_manifest_digest: Digest32,
    pub exact_ordered_payload_digests: Vec<Digest32>,
    pub exact_ordered_hashes: Vec<Digest32>,
    pub replacement_approval_id: Option<Digest32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerCeremonyContribution {
    pub ceremony_id: Digest32,
    pub signer_nonce: Digest32,
    pub approval_digest: Digest32,
    pub review_manifest_digest: Digest32,
    pub key_ref: KeyRef,
    pub allowed_crypto_suites: Vec<CryptoSuite>,
    pub activation_mode: ActivationMode,
    pub wallet_revocation_epoch: DecimalU64,
    pub required_user_verification: bool,
    pub ephemeral_encryption_public_key: Option<Base64UrlBytes>,
    pub expires_at_ms: DecimalU64,
    pub signer_key_id: Token,
    pub signer_signature: Base64UrlBytes,
}

/// Complete Signer-owned material needed for Broker to render and verify an
/// approval ceremony. The signed contribution alone is insufficient because
/// WebAuthn challenge bytes and credential options are also Signer-derived.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerPreparedApproval {
    pub contribution: SignerCeremonyContribution,
    pub challenges: Vec<CeremonyChallenge>,
    pub webauthn_options: CeremonyWebAuthnOptions,
    pub verification_credentials: Vec<WebAuthnCredential>,
}

impl SignerCeremonyContribution {
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, crate::ProtocolError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            ceremony_id: &'a Digest32,
            signer_nonce: &'a Digest32,
            approval_digest: &'a Digest32,
            review_manifest_digest: &'a Digest32,
            key_ref: &'a KeyRef,
            allowed_crypto_suites: &'a [CryptoSuite],
            activation_mode: ActivationMode,
            wallet_revocation_epoch: &'a DecimalU64,
            required_user_verification: bool,
            ephemeral_encryption_public_key: &'a Option<Base64UrlBytes>,
            expires_at_ms: &'a DecimalU64,
            signer_key_id: &'a Token,
        }
        serde_jcs::to_vec(&Unsigned {
            ceremony_id: &self.ceremony_id,
            signer_nonce: &self.signer_nonce,
            approval_digest: &self.approval_digest,
            review_manifest_digest: &self.review_manifest_digest,
            key_ref: &self.key_ref,
            allowed_crypto_suites: &self.allowed_crypto_suites,
            activation_mode: self.activation_mode.clone(),
            wallet_revocation_epoch: &self.wallet_revocation_epoch,
            required_user_verification: self.required_user_verification,
            ephemeral_encryption_public_key: &self.ephemeral_encryption_public_key,
            expires_at_ms: &self.expires_at_ms,
            signer_key_id: &self.signer_key_id,
        })
        .map_err(canonical_error)
    }

    pub fn digest(&self) -> Result<Digest32, crate::ProtocolError> {
        digest_canonical(serde_jcs::to_vec(self).map_err(canonical_error)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebAuthnAssertion {
    pub credential_id: Base64UrlBytes,
    pub authenticator_data: Base64UrlBytes,
    pub client_data_json: Base64UrlBytes,
    pub signature: Base64UrlBytes,
    pub user_handle: Option<Base64UrlBytes>,
}

/// Raw WebAuthn credential-creation response.
///
/// Broker and Signer each verify these bytes. The protocol deliberately does
/// not carry a Broker-produced "verified" boolean or parsed public key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebAuthnAttestation {
    pub credential_id: Base64UrlBytes,
    pub client_data_json: Base64UrlBytes,
    pub attestation_object: Base64UrlBytes,
    pub transports: Vec<Token>,
}

/// Public credential metadata owned by Signer after successful attestation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebAuthnCredential {
    pub credential_id: Base64UrlBytes,
    pub cose_public_key: Base64UrlBytes,
    pub user_handle: Base64UrlBytes,
    pub rp_id: Token,
    pub prf_salt: Base64UrlBytes,
    pub sign_count: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialPrfInput {
    pub credential_id: Base64UrlBytes,
    pub prf_salt: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyWebAuthnOptions {
    pub allowed_credentials: Vec<CredentialPrfInput>,
    pub registration_user_handle: Option<Base64UrlBytes>,
    pub registration_prf_salt: Option<Base64UrlBytes>,
}

/// The exact browser proof phases permitted for a ceremony.
///
/// Registration needs a creation attestation. Credential changes additionally
/// need an assertion from existing root authority. Recovery authenticates with
/// encrypted recovery input instead of pretending an old passkey is present.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebAuthnCeremonyProof {
    Assertion {
        assertion: WebAuthnAssertion,
    },
    Registration {
        attestation: WebAuthnAttestation,
        prf_assertion: Option<WebAuthnAssertion>,
    },
    AuthorityCredentialChange {
        authority_assertion: WebAuthnAssertion,
        new_credential_attestation: WebAuthnAttestation,
        new_credential_prf_assertion: Option<WebAuthnAssertion>,
    },
    RecoveryCredentialChange {
        new_credential_attestation: WebAuthnAttestation,
        new_credential_prf_assertion: Option<WebAuthnAssertion>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyCompleteRequest {
    pub activation_operation_id: OperationId,
    pub proof: WebAuthnCeremonyProof,
    pub contribution: SignerCeremonyContribution,
    pub encrypted_local_prf: Option<HpkeEnvelope>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerActivationReceipt {
    pub activation_operation_id: OperationId,
    pub ceremony_id: Digest32,
    pub approval_id: Digest32,
    pub approval_digest: Digest32,
    pub review_manifest_digest: Digest32,
    pub key_ref: KeyRef,
    pub allowed_crypto_suites: Vec<CryptoSuite>,
    pub activation_mode: ActivationMode,
    pub wallet_revocation_epoch: DecimalU64,
    pub replaced_approval_id: Option<Digest32>,
    pub activated_at_ms: DecimalU64,
    pub expires_at_ms: DecimalU64,
    pub signer_key_id: Token,
    pub signer_signature: Base64UrlBytes,
}

impl SignerActivationReceipt {
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, crate::ProtocolError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            activation_operation_id: &'a OperationId,
            ceremony_id: &'a Digest32,
            approval_id: &'a Digest32,
            approval_digest: &'a Digest32,
            review_manifest_digest: &'a Digest32,
            key_ref: &'a KeyRef,
            allowed_crypto_suites: &'a [CryptoSuite],
            activation_mode: ActivationMode,
            wallet_revocation_epoch: &'a DecimalU64,
            replaced_approval_id: &'a Option<Digest32>,
            activated_at_ms: &'a DecimalU64,
            expires_at_ms: &'a DecimalU64,
            signer_key_id: &'a Token,
        }
        serde_jcs::to_vec(&Unsigned {
            activation_operation_id: &self.activation_operation_id,
            ceremony_id: &self.ceremony_id,
            approval_id: &self.approval_id,
            approval_digest: &self.approval_digest,
            review_manifest_digest: &self.review_manifest_digest,
            key_ref: &self.key_ref,
            allowed_crypto_suites: &self.allowed_crypto_suites,
            activation_mode: self.activation_mode.clone(),
            wallet_revocation_epoch: &self.wallet_revocation_epoch,
            replaced_approval_id: &self.replaced_approval_id,
            activated_at_ms: &self.activated_at_ms,
            expires_at_ms: &self.expires_at_ms,
            signer_key_id: &self.signer_key_id,
        })
        .map_err(canonical_error)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyPasskeyMigrationPublic {
    pub schema: Token,
    pub wallet_name: Token,
    pub address: String,
    pub public_key_fingerprint: Digest32,
    pub credential_id_fingerprint: Digest32,
    pub legacy_format_version: u8,
    pub bundle_digest: Digest32,
    pub policy_mode: Token,
}

impl LegacyPasskeyMigrationPublic {
    pub fn terms_digest(&self, operation_id: &OperationId) -> Result<Digest32, ProtocolError> {
        #[derive(Serialize)]
        struct Terms<'a> {
            schema: &'a Token,
            operation_id: &'a OperationId,
            wallet_name: &'a Token,
            address: &'a str,
            public_key_fingerprint: &'a Digest32,
            credential_id_fingerprint: &'a Digest32,
            legacy_format_version: u8,
            bundle_digest: &'a Digest32,
            policy_mode: &'a Token,
        }
        digest_canonical(
            serde_jcs::to_vec(&Terms {
                schema: &self.schema,
                operation_id,
                wallet_name: &self.wallet_name,
                address: &self.address,
                public_key_fingerprint: &self.public_key_fingerprint,
                credential_id_fingerprint: &self.credential_id_fingerprint,
                legacy_format_version: self.legacy_format_version,
                bundle_digest: &self.bundle_digest,
                policy_mode: &self.policy_mode,
            })
            .map_err(canonical_error)?,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyPrepareRequest {
    pub ceremony_kind: CeremonyKind,
    pub custody_operation_id: OperationId,
    /// The authoritative wallet ID. New registrations and ordinary imports
    /// require the caller-selected ID; legacy migration derives it from the
    /// authenticated migration receipt instead.
    pub wallet_id: Option<Token>,
    pub key_ref: Option<KeyRef>,
    pub exact_terms_digest: Digest32,
    pub expected_input_class: Token,
    pub browser_output_recipient_key: Option<Base64UrlBytes>,
    #[serde(default)]
    pub petal_key_scope: Option<PetalKeyScope>,
    #[serde(default)]
    pub legacy_passkey_migration: Option<LegacyPasskeyMigrationPublic>,
}

impl CustodyPrepareRequest {
    pub fn validate_wallet_creation_binding(&self) -> Result<(), ProtocolError> {
        if !matches!(
            self.ceremony_kind,
            CeremonyKind::WalletRegistration | CeremonyKind::WalletImport
        ) {
            return Ok(());
        }
        if self.key_ref.is_some() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "wallet creation derives its root KeyRef inside Signer",
            ));
        }
        let legacy_import = self.ceremony_kind == CeremonyKind::WalletImport
            && self.legacy_passkey_migration.is_some();
        if self.wallet_id.is_none() && !legacy_import {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "wallet registration and ordinary import require an authoritative wallet ID",
            ));
        }
        if self.wallet_id.is_some() && legacy_import {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "legacy migration wallet ID must come from its authenticated receipt",
            ));
        }
        Ok(())
    }

    pub fn validate_legacy_passkey_migration_binding(&self) -> Result<(), ProtocolError> {
        let Some(migration) = &self.legacy_passkey_migration else {
            if self.expected_input_class.as_str() == "legacy_passkey_v1_prf" {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::MalformedFrame,
                    "legacy passkey input class requires public migration terms",
                ));
            }
            return Ok(());
        };
        if self.ceremony_kind != CeremonyKind::WalletImport
            || self.expected_input_class.as_str() != "legacy_passkey_v1_prf"
            || self.wallet_id.is_some()
            || self.key_ref.is_some()
            || self.petal_key_scope.is_some()
            || migration.schema.as_str() != "bloom.legacy_passkey_migration_receipt.v1"
            || migration.policy_mode.as_str() != "restrictive_current_policy"
            || migration.legacy_format_version != 1
            || self.exact_terms_digest != migration.terms_digest(&self.custody_operation_id)?
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "legacy passkey migration terms do not match the custody request",
            ));
        }
        Ok(())
    }

    /// Validate the full Petal scope carried by the existing key-derivation
    /// surface. Broker and Signer both call this before accepting the scope.
    pub fn validate_petal_key_scope_binding(&self) -> Result<(), ProtocolError> {
        let Some(scope) = &self.petal_key_scope else {
            return Ok(());
        };

        if self.ceremony_kind != CeremonyKind::KeyDerive {
            return Err(ProtocolError::new(
                ProtocolErrorCode::CeremonyKindMismatch,
                "Petal key scope is valid only for key-derive custody",
            ));
        }
        scope.validate()?;
        if scope.custody_operation_id != self.custody_operation_id {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "Petal key scope custody operation does not match the request",
            ));
        }
        if self.wallet_id.as_ref() != Some(&scope.wallet_id) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "Petal key scope wallet does not match the custody request",
            ));
        }
        if self.key_ref.as_ref() != Some(&scope.parent_key_ref) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "Petal key scope parent KeyRef does not match the custody request",
            ));
        }
        if self.exact_terms_digest != scope.request_digest()? {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "key-derive exact terms digest does not match the Petal key scope",
            ));
        }
        if self.browser_output_recipient_key.is_some() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "Petal key derivation cannot return Browser-provided key material",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodySignerContribution {
    pub ceremony_id: Digest32,
    pub ceremony_kind: CeremonyKind,
    pub custody_operation_id: OperationId,
    pub signer_nonce: Digest32,
    pub review_manifest_digest: Digest32,
    pub wallet_id: Option<Token>,
    pub key_ref: Option<KeyRef>,
    pub expected_input_class: Token,
    pub required_user_verification: bool,
    pub hpke_recipient_key: Base64UrlBytes,
    pub browser_output_recipient_key: Option<Base64UrlBytes>,
    #[serde(default)]
    pub petal_key_scope: Option<PetalKeyScope>,
    pub expires_at_ms: DecimalU64,
    pub signer_key_id: Token,
    pub signer_signature: Base64UrlBytes,
}

/// Complete Signer-owned material needed for Broker to render and verify a
/// custody ceremony.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerPreparedCustody {
    pub contribution: CustodySignerContribution,
    pub challenges: Vec<CeremonyChallenge>,
    pub webauthn_options: CeremonyWebAuthnOptions,
    pub verification_credentials: Vec<WebAuthnCredential>,
}

/// Restart-safe Broker-facing ceremony status. Terminal receipts are returned
/// verbatim so Broker can reconcile without replaying a browser proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", content = "result", rename_all = "snake_case")]
pub enum SignerCeremonyStatus {
    Pending,
    CompletedApproval(Box<SignerActivationReceipt>),
    CompletedCustody(Box<CustodyResult>),
    CompletedOwnerAttestation(Box<crate::OwnerAttestationReceipt>),
    /// A durable non-successful terminal ceremony state, distinct from an
    /// operation unknown to Signer.
    Terminal(CeremonyState),
    Missing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum SignerCeremonyCancelResponse {
    Public(crate::CeremonyPublicStatus),
    OwnerAttestation(SignerCeremonyStatus),
}

/// The generic `ceremony.prepare` body. Policy update is the sole custody kind
/// whose semantic review is originated by Broker and therefore shares this
/// method with sealed-approval preparation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "ceremony_kind", content = "request", rename_all = "snake_case")]
pub enum SignerCeremonyPrepareRequest {
    SealedApproval(Box<CeremonyPrepareRequest>),
    PolicyUpdate(Box<crate::PolicyUpdateCeremonyPrepareRequest>),
    OwnerAttestationPrepare(Box<crate::OwnerAttestationPrepareRequest>),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "ceremony_kind", content = "prepared", rename_all = "snake_case")]
// The variant sizes are frozen by the v1 typed wire contract. Boxing the
// larger variant would needlessly change the public Rust API during extraction.
#[allow(clippy::large_enum_variant)]
pub enum SignerCeremonyPrepareResponse {
    SealedApproval(SignerPreparedApproval),
    PolicyUpdate(SignerPreparedCustody),
    OwnerAttestationPrepare(crate::PreparedOwnerAttestation),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "ceremony_kind", content = "request", rename_all = "snake_case")]
pub enum SignerCeremonyCompleteRequest {
    SealedApproval(Box<CeremonyCompleteRequest>),
    PolicyUpdate(Box<crate::PolicyUpdateCeremonyCompleteRequest>),
    OwnerAttestationComplete(Box<crate::OwnerAttestationCompleteRequest>),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "ceremony_kind", content = "result", rename_all = "snake_case")]
pub enum SignerCeremonyCompleteResponse {
    SealedApproval(Box<SignerActivationReceipt>),
    PolicyUpdate(Box<CustodyResult>),
    OwnerAttestationComplete(Box<crate::OwnerAttestationReceipt>),
}

impl CustodySignerContribution {
    /// Verify that the Signer-signed contribution carries exactly the Petal
    /// scope accepted on the corresponding Broker-to-Signer request.
    pub fn validate_petal_key_scope_binding(
        &self,
        request: &CustodyPrepareRequest,
    ) -> Result<(), ProtocolError> {
        request.validate_petal_key_scope_binding()?;
        if request.petal_key_scope.is_none() {
            if self.petal_key_scope.is_some() {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "Signer introduced a Petal key scope on an unscoped custody request",
                ));
            }
            return Ok(());
        }
        if self.ceremony_kind != request.ceremony_kind
            || self.custody_operation_id != request.custody_operation_id
            || self.wallet_id != request.wallet_id
            || self.key_ref != request.key_ref
            || self.petal_key_scope != request.petal_key_scope
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "Signer custody contribution does not match the requested Petal key scope",
            ));
        }
        Ok(())
    }

    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, crate::ProtocolError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            ceremony_id: &'a Digest32,
            ceremony_kind: CeremonyKind,
            custody_operation_id: &'a OperationId,
            signer_nonce: &'a Digest32,
            review_manifest_digest: &'a Digest32,
            wallet_id: &'a Option<Token>,
            key_ref: &'a Option<KeyRef>,
            expected_input_class: &'a Token,
            required_user_verification: bool,
            hpke_recipient_key: &'a Base64UrlBytes,
            browser_output_recipient_key: &'a Option<Base64UrlBytes>,
            petal_key_scope: &'a Option<PetalKeyScope>,
            expires_at_ms: &'a DecimalU64,
            signer_key_id: &'a Token,
        }
        serde_jcs::to_vec(&Unsigned {
            ceremony_id: &self.ceremony_id,
            ceremony_kind: self.ceremony_kind,
            custody_operation_id: &self.custody_operation_id,
            signer_nonce: &self.signer_nonce,
            review_manifest_digest: &self.review_manifest_digest,
            wallet_id: &self.wallet_id,
            key_ref: &self.key_ref,
            expected_input_class: &self.expected_input_class,
            required_user_verification: self.required_user_verification,
            hpke_recipient_key: &self.hpke_recipient_key,
            browser_output_recipient_key: &self.browser_output_recipient_key,
            petal_key_scope: &self.petal_key_scope,
            expires_at_ms: &self.expires_at_ms,
            signer_key_id: &self.signer_key_id,
        })
        .map_err(canonical_error)
    }

    pub fn digest(&self) -> Result<Digest32, crate::ProtocolError> {
        digest_canonical(serde_jcs::to_vec(self).map_err(canonical_error)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyCompleteRequest {
    pub ceremony_kind: CeremonyKind,
    pub custody_operation_id: OperationId,
    pub ceremony_id: Digest32,
    pub proof: WebAuthnCeremonyProof,
    pub encrypted_input: Option<HpkeEnvelope>,
    pub public_binding_digest: Digest32,
}

/// Canonical challenge payload embedded as the WebAuthn challenge bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyChallenge {
    pub schema: Token,
    pub ceremony_id: Digest32,
    pub ceremony_kind: CeremonyKind,
    pub operation_id: OperationId,
    pub signer_nonce: Digest32,
    pub review_manifest_digest: Digest32,
    pub signer_contribution_digest: Digest32,
    pub exact_terms_digest: Digest32,
    pub phase: CeremonyPhase,
}

impl CeremonyChallenge {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, crate::ProtocolError> {
        serde_jcs::to_vec(self).map_err(|error| {
            crate::ProtocolError::new(crate::ProtocolErrorCode::MalformedFrame, error.to_string())
        })
    }

    pub fn webauthn_challenge(&self) -> Result<Base64UrlBytes, crate::ProtocolError> {
        Ok(Base64UrlBytes::from_bytes(&self.canonical_bytes()?))
    }

    pub fn digest(&self) -> Result<Digest32, crate::ProtocolError> {
        use sha2::{Digest as _, Sha256};
        Ok(Digest32::from_bytes(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyPhase {
    Approve,
    RegisterCredential,
    ConfirmPrf,
}

/// RFC 9180 associated data for local passkey PRF delivery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPrfHpkeAad {
    pub ceremony_id: Digest32,
    pub signer_nonce: Digest32,
    pub approval_id: Digest32,
    pub approval_digest: Digest32,
    pub review_manifest_digest: Digest32,
    pub key_ref: KeyRef,
    pub allowed_crypto_suites: Vec<CryptoSuite>,
    pub credential_id: Base64UrlBytes,
    pub activation_mode: ActivationMode,
    pub wallet_revocation_epoch: DecimalU64,
}

impl LocalPrfHpkeAad {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, crate::ProtocolError> {
        serde_jcs::to_vec(self).map_err(|error| {
            crate::ProtocolError::new(crate::ProtocolErrorCode::MalformedFrame, error.to_string())
        })
    }
}

/// RFC 9180 associated data for a custody input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyHpkeAad {
    pub ceremony_id: Digest32,
    pub ceremony_kind: CeremonyKind,
    pub custody_operation_id: OperationId,
    pub signer_nonce: Digest32,
    pub signer_contribution_digest: Digest32,
    pub wallet_id: Option<Token>,
    pub key_ref: Option<KeyRef>,
    pub credential_id: Option<Base64UrlBytes>,
    pub expected_input_class: Token,
}

impl CustodyHpkeAad {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, crate::ProtocolError> {
        serde_jcs::to_vec(self).map_err(|error| {
            crate::ProtocolError::new(crate::ProtocolErrorCode::MalformedFrame, error.to_string())
        })
    }
}

/// RFC 9180 associated data for a sensitive custody result returned directly
/// from Signer to a Browser-owned one-use recipient key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyOutputHpkeAad {
    pub ceremony_id: Digest32,
    pub ceremony_kind: CeremonyKind,
    pub custody_operation_id: OperationId,
    pub signer_contribution_digest: Digest32,
    pub public_binding_digest: Digest32,
}

impl CustodyOutputHpkeAad {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, crate::ProtocolError> {
        serde_jcs::to_vec(self).map_err(canonical_error)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyResult {
    pub ceremony_kind: CeremonyKind,
    pub custody_operation_id: OperationId,
    pub public_status: crate::CeremonyState,
    pub wallet_id: Option<Token>,
    pub public_key_refs: Vec<KeyRef>,
    pub credential_summaries: Vec<CredentialSummary>,
    pub initial_policy: Option<crate::SignedPolicySnapshot>,
    pub receipt_digest: Digest32,
    pub encrypted_browser_result: Option<HpkeEnvelope>,
    pub signer_key_id: Token,
    pub signer_signature: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSummary {
    pub credential_id: Base64UrlBytes,
    pub rp_id: Token,
    pub active: bool,
}

impl CustodyResult {
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, crate::ProtocolError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            ceremony_kind: CeremonyKind,
            custody_operation_id: &'a OperationId,
            public_status: crate::CeremonyState,
            wallet_id: &'a Option<Token>,
            public_key_refs: &'a [KeyRef],
            credential_summaries: &'a [CredentialSummary],
            initial_policy: &'a Option<crate::SignedPolicySnapshot>,
            receipt_digest: &'a Digest32,
            encrypted_browser_result: &'a Option<HpkeEnvelope>,
            signer_key_id: &'a Token,
        }
        serde_jcs::to_vec(&Unsigned {
            ceremony_kind: self.ceremony_kind,
            custody_operation_id: &self.custody_operation_id,
            public_status: self.public_status,
            wallet_id: &self.wallet_id,
            public_key_refs: &self.public_key_refs,
            credential_summaries: &self.credential_summaries,
            initial_policy: &self.initial_policy,
            receipt_digest: &self.receipt_digest,
            encrypted_browser_result: &self.encrypted_browser_result,
            signer_key_id: &self.signer_key_id,
        })
        .map_err(canonical_error)
    }
}

fn digest_canonical(bytes: Vec<u8>) -> Result<Digest32, crate::ProtocolError> {
    use sha2::{Digest as _, Sha256};
    Ok(Digest32::from_bytes(Sha256::digest(bytes).into()))
}

fn canonical_error(error: impl std::fmt::Display) -> crate::ProtocolError {
    crate::ProtocolError::new(crate::ProtocolErrorCode::MalformedFrame, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CeremonyState, DerivationRef, KeySpec};

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn operation(byte: u8) -> OperationId {
        OperationId::from_bytes([byte; 32])
    }

    fn petal_scope() -> PetalKeyScope {
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
            lineage_id: "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            key_slot: Token::new("desk-a").unwrap(),
            allowed_routes: vec!["/petals/exchange/orders".into()],
            allowed_operation_classes: vec![Token::new("exchange-agent").unwrap()],
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            maximum_lifetime_ms: DecimalU64::new(86_400_000),
            custody_operation_id: operation(3),
        }
    }

    fn scoped_prepare() -> CustodyPrepareRequest {
        let scope = petal_scope();
        CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::KeyDerive,
            custody_operation_id: scope.custody_operation_id.clone(),
            wallet_id: Some(scope.wallet_id.clone()),
            key_ref: Some(scope.parent_key_ref.clone()),
            exact_terms_digest: scope.request_digest().unwrap(),
            expected_input_class: Token::new("petal-key-scope-v1").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: Some(scope),
            legacy_passkey_migration: None,
        }
    }

    fn registration_prepare(wallet_id: Option<Token>) -> CustodyPrepareRequest {
        CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::WalletRegistration,
            custody_operation_id: operation(4),
            wallet_id,
            key_ref: None,
            exact_terms_digest: digest(5),
            expected_input_class: Token::new("passkey-prf").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: None,
            legacy_passkey_migration: None,
        }
    }

    #[test]
    fn new_wallet_creation_requires_its_authoritative_id() {
        assert!(
            registration_prepare(Some(Token::new("quiet-lilac").unwrap()))
                .validate_wallet_creation_binding()
                .is_ok()
        );
        assert_eq!(
            registration_prepare(None)
                .validate_wallet_creation_binding()
                .unwrap_err()
                .code,
            ProtocolErrorCode::MalformedFrame
        );
    }

    #[test]
    fn custody_success_states_match_section_13_6() {
        assert_eq!(
            CeremonyKind::WalletRegistration.successful_terminal_state(),
            Some(CeremonyState::Completed)
        );
        for kind in [
            CeremonyKind::WalletImport,
            CeremonyKind::WalletExport,
            CeremonyKind::WalletDelete,
            CeremonyKind::WalletRecovery,
            CeremonyKind::CredentialAdd,
            CeremonyKind::CredentialReplace,
            CeremonyKind::CredentialRemove,
            CeremonyKind::BackendEnrollment,
            CeremonyKind::KeyDerive,
            CeremonyKind::PolicyUpdate,
        ] {
            assert_eq!(
                kind.successful_terminal_state(),
                Some(CeremonyState::Succeeded),
                "{kind:?}"
            );
        }
        assert_eq!(
            CeremonyKind::SealedApproval.successful_terminal_state(),
            None
        );
    }

    #[test]
    fn petal_key_scope_is_exactly_bound_to_key_derive_request() {
        assert!(scoped_prepare().validate_petal_key_scope_binding().is_ok());

        let mut request = scoped_prepare();
        request.petal_key_scope.as_mut().unwrap().route = "/petals/exchange/cancel".into();
        assert_eq!(
            request.validate_petal_key_scope_binding().unwrap_err().code,
            ProtocolErrorCode::OperationIdConflict
        );
    }

    #[test]
    fn petal_scope_rejects_cross_operation_and_non_derivation_reuse() {
        let mut request = scoped_prepare();
        request.custody_operation_id = operation(9);
        assert_eq!(
            request.validate_petal_key_scope_binding().unwrap_err().code,
            ProtocolErrorCode::OperationIdConflict
        );

        let mut request = scoped_prepare();
        request.ceremony_kind = CeremonyKind::WalletImport;
        assert_eq!(
            request.validate_petal_key_scope_binding().unwrap_err().code,
            ProtocolErrorCode::CeremonyKindMismatch
        );
    }

    #[test]
    fn signed_custody_contribution_binds_full_petal_scope() {
        let scope = petal_scope();
        let contribution = CustodySignerContribution {
            ceremony_id: digest(4),
            ceremony_kind: CeremonyKind::KeyDerive,
            custody_operation_id: scope.custody_operation_id.clone(),
            signer_nonce: digest(5),
            review_manifest_digest: digest(6),
            wallet_id: Some(scope.wallet_id.clone()),
            key_ref: Some(scope.parent_key_ref.clone()),
            expected_input_class: Token::new("petal-key-scope-v1").unwrap(),
            required_user_verification: true,
            hpke_recipient_key: Base64UrlBytes::from_bytes(&[7; 32]),
            browser_output_recipient_key: None,
            petal_key_scope: Some(scope),
            expires_at_ms: DecimalU64::new(1000),
            signer_key_id: Token::new("signer-identity").unwrap(),
            signer_signature: Base64UrlBytes::from_bytes(&[8; 64]),
        };
        assert!(
            contribution
                .validate_petal_key_scope_binding(&scoped_prepare())
                .is_ok()
        );
        let original = contribution.unsigned_canonical_bytes().unwrap();
        let mut tampered = contribution;
        tampered
            .petal_key_scope
            .as_mut()
            .unwrap()
            .allowed_operation_classes = vec![Token::new("payment-key").unwrap()];
        assert_ne!(original, tampered.unsigned_canonical_bytes().unwrap());
        assert_eq!(
            tampered
                .validate_petal_key_scope_binding(&scoped_prepare())
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );
    }
}
