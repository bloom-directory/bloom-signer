use bloom_signer_api::{
    ActivationMode, Base64UrlBytes, CeremonyChallenge, CeremonyCompleteRequest, CeremonyKind,
    CeremonyPhase, CeremonyPrepareRequest, CeremonyPublicStatus, CeremonyState,
    CeremonyWebAuthnOptions, CredentialPrfInput, CredentialSummary, CryptoSuite,
    CustodyCompleteRequest, CustodyHpkeAad, CustodyOutputHpkeAad, CustodyPrepareRequest,
    CustodyResult, CustodySignerContribution, DecimalU64, Digest32, LocalPrfHpkeAad, OperationId,
    OwnerAttestationChallenge, OwnerAttestationCompleteRequest, OwnerAttestationPrepareRequest,
    OwnerAttestationReceipt, OwnerAttestationSignerContribution, OwnerAttestationTerms,
    PetalKeyScope, PolicyUpdateCeremonyCompleteRequest, PolicyUpdateCeremonyPrepareRequest,
    PreparedOwnerAttestation, ProtocolError, ProtocolErrorCode, SignerActivationReceipt,
    SignerCeremonyContribution, Token, WebAuthnCeremonyProof, WebAuthnCredential,
};
use bloom_signer_backend_api::SecretBytes;
use ed25519_dalek::{Signer as _, SigningKey};
use futures::lock::Mutex as AsyncMutex;
use hkdf::Hkdf;
use parking_lot::Mutex;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use crate::{
    custody::{UnlockedWallet, WalletCustody, WalletCustodyBackup},
    engine::{CeremonyDatabaseEffect, SignerEngine},
    hpke::{
        CUSTODY_INPUT_INFO, CUSTODY_OUTPUT_INFO, HpkeRecipient, LOCAL_PRF_INFO, seal_to_recipient,
    },
    legacy_passkey::{LEGACY_PASSKEY_INPUT_CLASS, LegacyMigrationStore, PreparedLegacyMigration},
    webauthn::{verify_webauthn_assertion, verify_webauthn_attestation},
};

fn ceremony_state_name(state: CeremonyState) -> &'static str {
    match state {
        CeremonyState::Prepared => "prepared",
        CeremonyState::AwaitingUser => "awaiting_user",
        CeremonyState::Verifying => "verifying",
        CeremonyState::WalletCommitted => "wallet_committed",
        CeremonyState::AwaitingRecoveryAck => "awaiting_recovery_ack",
        CeremonyState::Completed => "completed",
        CeremonyState::ApprovingRootChange => "approving_root_change",
        CeremonyState::CreatingCredential => "creating_credential",
        CeremonyState::Committing => "committing",
        CeremonyState::Succeeded => "succeeded",
        CeremonyState::Cancelled => "cancelled",
        CeremonyState::Expired => "expired",
        CeremonyState::Failed => "failed",
    }
}

fn ceremony_kind_name(kind: CeremonyKind) -> &'static str {
    match kind {
        CeremonyKind::SealedApproval => "sealed_approval",
        CeremonyKind::WalletRegistration => "wallet_registration",
        CeremonyKind::WalletImport => "wallet_import",
        CeremonyKind::WalletExport => "wallet_export",
        CeremonyKind::WalletDelete => "wallet_delete",
        CeremonyKind::WalletRecovery => "wallet_recovery",
        CeremonyKind::CredentialAdd => "credential_add",
        CeremonyKind::CredentialReplace => "credential_replace",
        CeremonyKind::CredentialRemove => "credential_remove",
        CeremonyKind::BackendEnrollment => "backend_enrollment",
        CeremonyKind::KeyDerive => "key_derive",
        CeremonyKind::PolicyUpdate => "policy_update",
    }
}

const CEREMONY_TTL_MS: u64 = 5 * 60 * 1_000;
const CONTRIBUTION_DOMAIN: &[u8] = b"bloom-signer-ceremony-contribution/v1";
const RECEIPT_DOMAIN: &[u8] = b"bloom-signer-ceremony-receipt/v1";
const WRAP_INFO: &[u8] = b"bloom-passkey-wallet-wrap/v1";
const DERIVATION_AUTHORITY_DOMAIN: &[u8] = b"bloom-key-derive-authority/v1";
const PETAL_SUBKEY_NAMESPACE: &str = "petal-subkeys-v1";
const PETAL_SUBKEY_PREFIX: &str = "m/44'/60'/0'/18735";

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerAttestationPublicBinding<'a> {
    terms_digest: &'a Digest32,
    ceremony_id: &'a Digest32,
    signer_nonce: &'a Digest32,
    expires_at_ms: &'a DecimalU64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerAttestationReceiptPreimage<'a> {
    operation_id: &'a OperationId,
    ceremony_id: &'a Digest32,
    terms_digest: &'a Digest32,
    public_binding_digest: &'a Digest32,
}

#[derive(Clone)]
struct PendingOwnerAttestation {
    request_digest: Digest32,
    terms: OwnerAttestationTerms,
    contribution: OwnerAttestationSignerContribution,
    challenge: OwnerAttestationChallenge,
    signer_nonce: Digest32,
    expires_at_ms: DecimalU64,
}

#[derive(Clone, Debug)]
pub struct PreparedApprovalCeremony {
    pub contribution: SignerCeremonyContribution,
    pub challenges: Vec<CeremonyChallenge>,
    pub webauthn_options: CeremonyWebAuthnOptions,
}

#[derive(Clone, Debug)]
pub struct PreparedCustodyCeremony {
    pub contribution: CustodySignerContribution,
    pub challenges: Vec<CeremonyChallenge>,
    pub webauthn_options: CeremonyWebAuthnOptions,
    pub verification_credentials: Vec<WebAuthnCredential>,
}

enum PendingRequest {
    Approval(Box<CeremonyPrepareRequest>),
    Custody(Box<CustodyPrepareRequest>),
    PolicyUpdate(Box<PolicyUpdateCeremonyPrepareRequest>),
}

#[allow(clippy::large_enum_variant)]
enum PendingContribution {
    Approval(SignerCeremonyContribution),
    Custody(CustodySignerContribution),
}

struct RegistrationSecrets {
    wallet_id: Token,
    user_handle: Base64UrlBytes,
    prf_salt: Base64UrlBytes,
    root: SecretBytes,
    policy_seed: SecretBytes,
    wkek: SecretBytes,
    recovery_id: Token,
    recovery_secret: Base64UrlBytes,
}

struct CredentialCreation {
    user_handle: Base64UrlBytes,
    prf_salt: Base64UrlBytes,
}

struct PendingCeremony {
    request_digest: Digest32,
    request: PendingRequest,
    contribution: PendingContribution,
    challenges: Vec<CeremonyChallenge>,
    hpke_recipient: Option<HpkeRecipient>,
    registration: Option<RegistrationSecrets>,
    credential_creation: Option<CredentialCreation>,
    legacy_migration: Option<PreparedLegacyMigration>,
}

#[derive(Clone)]
struct BoundCredential {
    wallet_id: Token,
    credential: WebAuthnCredential,
}

enum CompletedCeremony {
    Approval(Box<SignerActivationReceipt>),
    Custody {
        result: Box<CustodyResult>,
        ceremony_id: Digest32,
        expires_at_ms: DecimalU64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerCeremonyStatus {
    Pending,
    CompletedApproval(Box<SignerActivationReceipt>),
    CompletedCustody(Box<CustodyResult>),
    CompletedOwnerAttestation(Box<OwnerAttestationReceipt>),
    /// A ceremony that ran and reached a durable non-successful terminal:
    /// failed closed, expired, or cancelled. Distinct from `Missing`, which
    /// means Signer holds no record of the operation at all.
    Terminal(CeremonyState),
    Missing,
}

#[derive(Debug)]
pub enum SignerCeremonyCancellation {
    Public(CeremonyPublicStatus),
    OwnerAttestation(SignerCeremonyStatus),
}

struct CustodyApplyContext {
    recipient: Option<HpkeRecipient>,
    registration: Option<RegistrationSecrets>,
    credential_creation: Option<CredentialCreation>,
    legacy_migration: Option<PreparedLegacyMigration>,
}

struct CustodyApplyOutcome {
    sensitive_output: Option<Vec<u8>>,
    database_effect: CeremonyDatabaseEffect,
    rollback_derived_key: Option<bloom_signer_api::KeyRef>,
    rollback_provisioned_backend: Option<bloom_signer_api::KeyRef>,
    public_key_refs: Vec<bloom_signer_api::KeyRef>,
    consume_legacy_migration: bool,
}

struct GenericCustodyOutcome {
    sensitive_output: Option<Vec<u8>>,
    database_effect: CeremonyDatabaseEffect,
    rollback_derived_key: Option<bloom_signer_api::KeyRef>,
    public_key_refs: Vec<bloom_signer_api::KeyRef>,
}

/// Signer-owned, single-use ceremony state.
///
/// Pending HPKE and registration secrets exist only in this process. Restart
/// destroys them and therefore fails pre-commit ceremonies closed; completed
/// receipts remain the responsibility of the durable RPC host.
pub struct SignerCeremonyService {
    engine: Arc<SignerEngine>,
    signer_key_id: Token,
    signing_key: SigningKey,
    pending: Mutex<HashMap<OperationId, PendingCeremony>>,
    pending_owner_attestations: Mutex<HashMap<OperationId, PendingOwnerAttestation>>,
    completed: Mutex<HashMap<OperationId, CompletedCeremony>>,
    credentials: Mutex<BTreeMap<String, BoundCredential>>,
    wallets: Mutex<BTreeMap<Token, Arc<WalletCustody>>>,
    legacy_migrations: Option<Arc<LegacyMigrationStore>>,
    preparation_barrier: Mutex<()>,
    approval_completion_barrier: AsyncMutex<()>,
    custody_completion_barrier: Mutex<()>,
    owner_attestation_completion_barrier: Mutex<()>,
}

pub(crate) struct VerifiedCeremonyActivation(());

impl SignerCeremonyService {
    pub fn new(
        engine: Arc<SignerEngine>,
        signer_key_id: Token,
        signing_key: SigningKey,
    ) -> Result<Self, ProtocolError> {
        #[cfg(feature = "local")]
        for enrollment in engine.load_ceremony_backend_enrollments()? {
            if enrollment.backend.as_str() != "local" || enrollment.pinned_keys.len() != 1 {
                return Err(protocol(
                    ProtocolErrorCode::KeyrefMismatch,
                    "persisted ceremony backend enrollment is malformed",
                ));
            }
            engine.backend_registry().restore_local_wallet_backend(
                &enrollment.backend_instance,
                &enrollment.encrypted_record,
                &enrollment.pinned_keys[0],
            )?;
        }
        #[cfg(feature = "local")]
        for (operation_id, key_ref) in engine.backend_registry().pending_local_derivations() {
            if engine.custody_receipt(&operation_id)?.is_some() {
                engine
                    .backend_registry()
                    .finalize_local_derived_key(&key_ref, &operation_id)?;
            } else {
                engine
                    .backend_registry()
                    .rollback_local_derived_key(&key_ref)?;
            }
        }
        let (wallet_backups, persisted_credentials) = engine.load_ceremony_custody()?;
        let wallets = wallet_backups
            .into_iter()
            .map(|backup| {
                Ok((
                    backup.wallet_id.clone(),
                    Arc::new(WalletCustody::restore(backup)?),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, ProtocolError>>()?;
        let credentials = persisted_credentials
            .into_iter()
            .map(|(wallet_id, credential)| {
                (
                    credential.credential_id.encoded().to_owned(),
                    BoundCredential {
                        wallet_id,
                        credential,
                    },
                )
            })
            .collect();
        Ok(Self {
            engine,
            signer_key_id,
            signing_key,
            pending: Mutex::new(HashMap::new()),
            pending_owner_attestations: Mutex::new(HashMap::new()),
            completed: Mutex::new(HashMap::new()),
            credentials: Mutex::new(credentials),
            wallets: Mutex::new(wallets),
            legacy_migrations: None,
            preparation_barrier: Mutex::new(()),
            approval_completion_barrier: AsyncMutex::new(()),
            custody_completion_barrier: Mutex::new(()),
            owner_attestation_completion_barrier: Mutex::new(()),
        })
    }

    pub fn with_legacy_migrations(mut self, store: Arc<LegacyMigrationStore>) -> Self {
        self.legacy_migrations = Some(store);
        self
    }

    pub fn register_existing_credential(
        &self,
        wallet_id: Token,
        credential: WebAuthnCredential,
    ) -> Result<(), ProtocolError> {
        let key = credential.credential_id.encoded().to_owned();
        let mut credentials = self.credentials.lock();
        if credentials.contains_key(&key) {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "credential ID is already registered",
            ));
        }
        credentials.insert(
            key,
            BoundCredential {
                wallet_id,
                credential,
            },
        );
        Ok(())
    }

    pub fn prepare_owner_attestation(
        &self,
        request: OwnerAttestationPrepareRequest,
        now_ms: u64,
    ) -> Result<PreparedOwnerAttestation, ProtocolError> {
        let _preparation_barrier = self.preparation_barrier.lock();
        let terms_digest = request.terms.digest()?;
        if self.signing_key.verifying_key() != *self.engine.ceremony_public_key() {
            return Err(protocol(
                ProtocolErrorCode::UnauthenticatedPeer,
                "owner attestation ceremony key does not match Signer configuration",
            ));
        }
        if request.terms.authority_edge_digest != self.authority_edge_digest() {
            return Err(protocol(
                ProtocolErrorCode::UnauthenticatedPeer,
                "owner attestation authority edge does not match this Signer",
            ));
        }
        let request_digest = canonical_digest(&request)?;
        if let Some(existing) = self
            .pending_owner_attestations
            .lock()
            .get(&request.terms.operation_id)
        {
            if existing.request_digest != request_digest {
                return Err(operation_conflict());
            }
            return Ok(self.prepared_owner_attestation(existing));
        }
        if self
            .pending
            .lock()
            .contains_key(&request.terms.operation_id)
        {
            return Err(kind_mismatch());
        }
        self.require_unopened_operation_id(&request.terms.operation_id)?;

        let ceremony_id = random_digest();
        let signer_nonce = random_digest();
        let expires_at_ms = DecimalU64::new(now_ms.saturating_add(CEREMONY_TTL_MS));
        let public_binding_digest = canonical_digest(&OwnerAttestationPublicBinding {
            terms_digest: &terms_digest,
            ceremony_id: &ceremony_id,
            signer_nonce: &signer_nonce,
            expires_at_ms: &expires_at_ms,
        })?;
        let mut contribution = OwnerAttestationSignerContribution {
            ceremony_id: ceremony_id.clone(),
            operation_id: request.terms.operation_id.clone(),
            terms_digest: terms_digest.clone(),
            public_binding_digest: public_binding_digest.clone(),
            signer_key_id: self.signer_key_id.clone(),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        contribution.signer_signature = Base64UrlBytes::from_bytes(
            &self
                .signing_key
                .sign(&contribution.signature_message()?)
                .to_bytes(),
        );
        let challenge = OwnerAttestationChallenge {
            ceremony_id,
            operation_id: request.terms.operation_id.clone(),
            terms_digest,
            public_binding_digest,
            signer_contribution_digest: contribution.digest()?,
        };
        let pending = PendingOwnerAttestation {
            request_digest,
            terms: request.terms.clone(),
            contribution,
            challenge,
            signer_nonce,
            expires_at_ms,
        };
        let prepared = self.prepared_owner_attestation(&pending);
        self.pending_owner_attestations
            .lock()
            .insert(request.terms.operation_id, pending);
        Ok(prepared)
    }

    pub fn complete_owner_attestation(
        &self,
        request: OwnerAttestationCompleteRequest,
        now_ms: u64,
    ) -> Result<OwnerAttestationReceipt, ProtocolError> {
        let _preparation_barrier = self.preparation_barrier.lock();
        let _completion_barrier = self.owner_attestation_completion_barrier.lock();
        if let Some(receipt) = self
            .engine
            .owner_attestation_receipt(&request.operation_id)?
        {
            let terms = OwnerAttestationTerms {
                schema: Token::new(bloom_signer_api::OWNER_ATTESTATION_SCHEMA)?,
                operation_id: receipt.operation_id.clone(),
                owner_wallet_id: receipt.owner_wallet_id.clone(),
                authority_edge_digest: receipt.authority_edge_digest.clone(),
                context_digest: receipt.context_digest.clone(),
                subject_digest: receipt.subject_digest.clone(),
            };
            let expected_receipt_digest = canonical_digest(&OwnerAttestationReceiptPreimage {
                operation_id: &receipt.operation_id,
                ceremony_id: &receipt.ceremony_id,
                terms_digest: &terms.digest()?,
                public_binding_digest: &request.public_binding_digest,
            })?;
            if receipt.ceremony_id != request.ceremony_id
                || receipt.receipt_digest != expected_receipt_digest
            {
                return Err(operation_conflict());
            }
            return Ok(receipt);
        }

        let pending = self
            .pending_owner_attestations
            .lock()
            .get(&request.operation_id)
            .cloned()
            .ok_or_else(replay)?;
        if request.ceremony_id != pending.contribution.ceremony_id
            || request.public_binding_digest != pending.contribution.public_binding_digest
        {
            return Err(operation_conflict());
        }
        self.pending_owner_attestations
            .lock()
            .remove(&request.operation_id)
            .ok_or_else(replay)?;

        let terminal_operation_id = request.operation_id.clone();
        let terminal_ceremony_id = pending.contribution.ceremony_id.clone();
        let terminal_expires_at_ms = pending.expires_at_ms.clone();
        let terminal_public_binding_digest = pending.contribution.public_binding_digest.clone();
        let result = (|| {
            let terms_digest = pending.terms.digest()?;
            let expected_binding = canonical_digest(&OwnerAttestationPublicBinding {
                terms_digest: &terms_digest,
                ceremony_id: &pending.contribution.ceremony_id,
                signer_nonce: &pending.signer_nonce,
                expires_at_ms: &pending.expires_at_ms,
            })?;
            if pending.expires_at_ms.get() <= now_ms
                || pending.contribution.operation_id != request.operation_id
                || pending.contribution.terms_digest != terms_digest
                || pending.contribution.public_binding_digest != expected_binding
                || pending.challenge.ceremony_id != pending.contribution.ceremony_id
                || pending.challenge.operation_id != request.operation_id
                || pending.challenge.terms_digest != terms_digest
                || pending.challenge.public_binding_digest != expected_binding
                || pending.challenge.signer_contribution_digest != pending.contribution.digest()?
            {
                return Err(replay());
            }
            let assertion = match &request.browser_proof {
                WebAuthnCeremonyProof::Assertion { assertion } => assertion,
                _ => return Err(kind_mismatch()),
            };
            let bound =
                self.bound_credential(&assertion.credential_id, &pending.terms.owner_wallet_id)?;
            let verified = verify_webauthn_assertion(
                assertion,
                &bound.credential,
                &pending.challenge.canonical_bytes()?,
                true,
            )?;
            let receipt_digest = canonical_digest(&OwnerAttestationReceiptPreimage {
                operation_id: &request.operation_id,
                ceremony_id: &request.ceremony_id,
                terms_digest: &terms_digest,
                public_binding_digest: &request.public_binding_digest,
            })?;
            let mut receipt = OwnerAttestationReceipt {
                operation_id: request.operation_id,
                ceremony_id: request.ceremony_id,
                owner_wallet_id: pending.terms.owner_wallet_id.clone(),
                authority_edge_digest: pending.terms.authority_edge_digest,
                context_digest: pending.terms.context_digest,
                subject_digest: pending.terms.subject_digest,
                receipt_digest,
                signer_key_id: self.signer_key_id.clone(),
                signer_signature: Base64UrlBytes::from_bytes(&[]),
            };
            receipt.signer_signature = Base64UrlBytes::from_bytes(
                &self
                    .signing_key
                    .sign(&receipt.signature_message()?)
                    .to_bytes(),
            );
            let mut advanced_credential = bound.credential;
            advanced_credential.sign_count = DecimalU64::new(u64::from(verified.sign_count));
            self.engine.persist_owner_attestation(
                &receipt,
                &pending.expires_at_ms,
                &request.public_binding_digest,
                &pending.terms.owner_wallet_id,
                &advanced_credential,
            )?;
            self.advance_counter(&verified.credential_id, verified.sign_count);
            Ok(receipt)
        })();
        if result.is_err() {
            let state = if terminal_expires_at_ms.get() <= now_ms {
                CeremonyState::Expired
            } else {
                CeremonyState::Failed
            };
            if let Err(error) = self.engine.persist_owner_attestation_terminal_status(
                &terminal_operation_id,
                &terminal_ceremony_id,
                state,
                &terminal_expires_at_ms,
                &terminal_public_binding_digest,
            ) {
                tracing::warn!(
                    event = "signer.owner_attestation_terminalization_failed",
                    operation_id = terminal_operation_id.as_str(),
                    error_code = error.code.as_str(),
                    "Signer could not persist a rejected owner attestation's terminal state"
                );
            }
        }
        result
    }

    fn prepared_owner_attestation(
        &self,
        pending: &PendingOwnerAttestation,
    ) -> PreparedOwnerAttestation {
        PreparedOwnerAttestation {
            contribution: pending.contribution.clone(),
            challenges: vec![pending.challenge.clone()],
            webauthn_options: self.options_for_wallet(Some(&pending.terms.owner_wallet_id)),
            verification_credentials: self
                .options_for_wallet(Some(&pending.terms.owner_wallet_id))
                .allowed_credentials
                .into_iter()
                .filter_map(|allowed| {
                    self.credential(&pending.terms.owner_wallet_id, &allowed.credential_id)
                        .ok()
                })
                .collect(),
        }
    }

    fn authority_edge_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(b"bloom-authority-edge/v1\0");
        hasher.update(self.engine.broker_public_key().as_bytes());
        hasher.update(self.engine.ceremony_public_key().as_bytes());
        Digest32::from_bytes(hasher.finalize().into())
    }

    pub fn prepare_approval(
        &self,
        request: CeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<PreparedApprovalCeremony, ProtocolError> {
        let _preparation_barrier = self.preparation_barrier.lock();
        request.terms.validate()?;
        self.engine
            .validate_petal_scope_for_approval(&request.terms, now_ms)?;
        if request.terms.approval_digest()? != request.terms.approval_id()? {
            return Err(protocol(
                ProtocolErrorCode::SelectorMismatch,
                "approval digest construction is inconsistent",
            ));
        }
        if !self
            .engine
            .backend_registry()
            .key_is_registered(&request.terms.key_ref)?
        {
            return Err(protocol(
                ProtocolErrorCode::KeyrefMismatch,
                "approval key is not registered",
            ));
        }
        let capabilities = self
            .engine
            .backend_registry()
            .get(
                &request.terms.key_ref.backend,
                &request.terms.key_ref.backend_instance,
            )?
            .capabilities();
        if request.terms.allowed_crypto_suites.is_empty()
            || request
                .terms
                .allowed_crypto_suites
                .iter()
                .any(|suite| !capabilities.supported_crypto_suites.contains(suite))
        {
            return Err(protocol(
                ProtocolErrorCode::SuiteNotAllowed,
                "approval contains a suite unsupported by the exact backend",
            ));
        }
        let request_digest = canonical_digest(&request)?;
        if self
            .pending_owner_attestations
            .lock()
            .contains_key(&request.activation_operation_id)
        {
            return Err(kind_mismatch());
        }
        if let Some(existing) = self.pending.lock().get(&request.activation_operation_id) {
            if existing.request_digest != request_digest {
                tracing::warn!(
                    event = "signer.ceremony_retry_conflict",
                    operation_id = request.activation_operation_id.as_str(),
                    ceremony_kind = "sealed_approval",
                    "Signer rejected a conflicting ceremony retry"
                );
                return Err(operation_conflict());
            }
            if let PendingContribution::Approval(contribution) = &existing.contribution {
                tracing::info!(
                    event = "signer.ceremony_recovered",
                    operation_id = request.activation_operation_id.as_str(),
                    ceremony_kind = "sealed_approval",
                    outcome = "pending_retry",
                    "Signer recovered a pending ceremony"
                );
                return Ok(PreparedApprovalCeremony {
                    contribution: contribution.clone(),
                    challenges: existing.challenges.clone(),
                    webauthn_options: self.options_for_approval(&request.terms.wallet_id),
                });
            }
            return Err(kind_mismatch());
        }
        self.require_unopened_operation_id(&request.activation_operation_id)?;
        self.require_no_live_wallet_session(&request.terms.wallet_id)?;

        let ceremony_id = random_digest();
        let signer_nonce = random_digest();
        let recipient = (!matches!(
            &request.terms.activation_mode,
            ActivationMode::BackendManaged
        ))
        .then(HpkeRecipient::generate);
        let mut contribution = SignerCeremonyContribution {
            ceremony_id: ceremony_id.clone(),
            signer_nonce: signer_nonce.clone(),
            approval_digest: request.terms.approval_digest()?,
            review_manifest_digest: request.review_manifest_digest.clone(),
            key_ref: request.terms.key_ref.clone(),
            allowed_crypto_suites: request.terms.allowed_crypto_suites.clone(),
            activation_mode: request.terms.activation_mode.clone(),
            wallet_revocation_epoch: request.terms.wallet_revocation_epoch.clone(),
            required_user_verification: true,
            ephemeral_encryption_public_key: recipient
                .as_ref()
                .map(|recipient| recipient.public_key().clone()),
            expires_at_ms: DecimalU64::new(now_ms.saturating_add(CEREMONY_TTL_MS)),
            signer_key_id: self.signer_key_id.clone(),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        contribution.signer_signature =
            self.sign_contribution(&contribution.unsigned_canonical_bytes()?);
        let challenge = CeremonyChallenge {
            schema: Token::new("bloom.ceremony.challenge.v1")?,
            ceremony_id,
            ceremony_kind: CeremonyKind::SealedApproval,
            operation_id: request.activation_operation_id.clone(),
            signer_nonce,
            review_manifest_digest: request.review_manifest_digest.clone(),
            signer_contribution_digest: contribution.digest()?,
            exact_terms_digest: request.terms.approval_digest()?,
            phase: CeremonyPhase::Approve,
        };
        let prepared = PreparedApprovalCeremony {
            contribution: contribution.clone(),
            challenges: vec![challenge.clone()],
            webauthn_options: self.options_for_approval(&request.terms.wallet_id),
        };
        self.pending.lock().insert(
            request.activation_operation_id.clone(),
            PendingCeremony {
                request_digest,
                request: PendingRequest::Approval(Box::new(request)),
                contribution: PendingContribution::Approval(contribution),
                challenges: vec![challenge],
                hpke_recipient: recipient,
                registration: None,
                credential_creation: None,
                legacy_migration: None,
            },
        );
        tracing::info!(
            event = "signer.ceremony_prepared",
            operation_id = prepared.challenges[0].operation_id.as_str(),
            ceremony_kind = "sealed_approval",
            "Signer prepared a ceremony"
        );
        Ok(prepared)
    }

    pub fn prepare_custody(
        &self,
        request: CustodyPrepareRequest,
        now_ms: u64,
    ) -> Result<PreparedCustodyCeremony, ProtocolError> {
        let _preparation_barrier = self.preparation_barrier.lock();
        self.prepare_custody_inner(request, now_ms)
    }

    fn prepare_custody_inner(
        &self,
        request: CustodyPrepareRequest,
        now_ms: u64,
    ) -> Result<PreparedCustodyCeremony, ProtocolError> {
        if request.ceremony_kind == CeremonyKind::SealedApproval {
            return Err(kind_mismatch());
        }
        if request.browser_output_recipient_key.is_some() {
            return Err(protocol(
                ProtocolErrorCode::BackendInvalidRequest,
                "Browser output recipient keys are bound from the authenticated browser session",
            ));
        }
        request.validate_wallet_creation_binding()?;
        request.validate_legacy_passkey_migration_binding()?;
        request.validate_petal_key_scope_binding()?;
        if let Some(scope) = &request.petal_key_scope {
            self.engine
                .require_enrolled_parent_key(&scope.wallet_id, &scope.parent_key_ref)?;
        }
        let request_digest = canonical_digest(&request)?;
        if self
            .pending_owner_attestations
            .lock()
            .contains_key(&request.custody_operation_id)
        {
            return Err(kind_mismatch());
        }
        if let Some(existing) = self.pending.lock().get(&request.custody_operation_id) {
            if existing.request_digest != request_digest {
                tracing::warn!(
                    event = "signer.ceremony_retry_conflict",
                    operation_id = request.custody_operation_id.as_str(),
                    ceremony_kind = ceremony_kind_name(request.ceremony_kind),
                    "Signer rejected a conflicting ceremony retry"
                );
                return Err(operation_conflict());
            }
            if let PendingContribution::Custody(contribution) = &existing.contribution {
                tracing::info!(
                    event = "signer.ceremony_recovered",
                    operation_id = request.custody_operation_id.as_str(),
                    ceremony_kind = ceremony_kind_name(request.ceremony_kind),
                    outcome = "pending_retry",
                    "Signer recovered a pending ceremony"
                );
                return Ok(PreparedCustodyCeremony {
                    contribution: contribution.clone(),
                    challenges: existing.challenges.clone(),
                    webauthn_options: self.options_for_pending(existing),
                    verification_credentials: self.verification_credentials_for_pending(existing),
                });
            }
            return Err(kind_mismatch());
        }
        self.require_unopened_operation_id(&request.custody_operation_id)?;
        if let Some(wallet_id) = &request.wallet_id {
            self.require_no_live_wallet_session(wallet_id)?;
        }

        let ceremony_id = random_digest();
        let signer_nonce = random_digest();
        let recipient = HpkeRecipient::generate();
        let legacy_migration =
            if request.expected_input_class.as_str() == LEGACY_PASSKEY_INPUT_CLASS {
                if request.ceremony_kind != CeremonyKind::WalletImport {
                    return Err(kind_mismatch());
                }
                let store = self.legacy_migrations.as_ref().ok_or_else(|| {
                    protocol(
                        ProtocolErrorCode::ServiceUnavailable,
                        "legacy passkey migration staging is unavailable",
                    )
                })?;
                let prepared = store.load(&request.custody_operation_id)?;
                if prepared.receipt.exact_terms_digest != request.exact_terms_digest
                    || request.legacy_passkey_migration.as_ref()
                        != Some(&prepared.receipt.public_terms()?)
                {
                    return Err(operation_conflict());
                }
                self.require_no_live_wallet_session(&prepared.receipt.wallet_name)?;
                if self
                    .wallets
                    .lock()
                    .contains_key(&prepared.receipt.wallet_name)
                    || self
                        .credentials
                        .lock()
                        .contains_key(prepared.credential.credential_id.encoded())
                {
                    return Err(protocol(
                        ProtocolErrorCode::OperationIdConflict,
                        "legacy wallet or passkey credential is already enrolled",
                    ));
                }
                Some(prepared)
            } else {
                None
            };
        let registration = if matches!(
            request.ceremony_kind,
            CeremonyKind::WalletRegistration | CeremonyKind::WalletImport
        ) {
            if request.key_ref.is_some() {
                return Err(protocol(
                    ProtocolErrorCode::KeyrefMismatch,
                    "registration and wallet import derive their root KeyRef inside Signer",
                ));
            }
            let wallet_id = legacy_migration
                .as_ref()
                .map(|legacy| legacy.receipt.wallet_name.clone())
                .or_else(|| request.wallet_id.clone())
                .ok_or_else(|| {
                    protocol(
                        ProtocolErrorCode::MalformedFrame,
                        "registration and wallet import require an authoritative wallet ID",
                    )
                })?;
            self.require_no_live_wallet_session(&wallet_id)?;
            if self.wallets.lock().contains_key(&wallet_id) {
                return Err(protocol(
                    ProtocolErrorCode::OperationIdConflict,
                    "wallet ID is already enrolled",
                ));
            }
            Some(RegistrationSecrets::generate(wallet_id)?)
        } else {
            None
        };
        let mut registration = registration;
        if let (Some(registration), Some(legacy)) =
            (registration.as_mut(), legacy_migration.as_ref())
        {
            registration.user_handle = legacy.credential.user_handle.clone();
            registration.prf_salt = legacy.credential.prf_salt.clone();
        }
        let credential_creation = if matches!(
            request.ceremony_kind,
            CeremonyKind::CredentialAdd
                | CeremonyKind::CredentialReplace
                | CeremonyKind::WalletRecovery
        ) {
            Some(self.new_credential_creation(request.wallet_id.as_ref()))
        } else {
            None
        };
        let effective_wallet_id = registration
            .as_ref()
            .map(|registration| registration.wallet_id.clone())
            .or_else(|| request.wallet_id.clone());
        let mut contribution = CustodySignerContribution {
            ceremony_id: ceremony_id.clone(),
            ceremony_kind: request.ceremony_kind,
            custody_operation_id: request.custody_operation_id.clone(),
            signer_nonce: signer_nonce.clone(),
            review_manifest_digest: request.exact_terms_digest.clone(),
            wallet_id: effective_wallet_id,
            key_ref: request.key_ref.clone(),
            expected_input_class: request.expected_input_class.clone(),
            required_user_verification: true,
            hpke_recipient_key: recipient.public_key().clone(),
            browser_output_recipient_key: request.browser_output_recipient_key.clone(),
            petal_key_scope: request.petal_key_scope.clone(),
            expires_at_ms: DecimalU64::new(now_ms.saturating_add(CEREMONY_TTL_MS)),
            signer_key_id: self.signer_key_id.clone(),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        contribution.signer_signature =
            self.sign_contribution(&contribution.unsigned_canonical_bytes()?);
        let phases = required_phases(request.ceremony_kind, legacy_migration.is_some());
        let challenges = phases
            .into_iter()
            .map(|phase| CeremonyChallenge {
                schema: Token::new("bloom.ceremony.challenge.v1").expect("static protocol token"),
                ceremony_id: ceremony_id.clone(),
                ceremony_kind: request.ceremony_kind,
                operation_id: request.custody_operation_id.clone(),
                signer_nonce: signer_nonce.clone(),
                review_manifest_digest: request.exact_terms_digest.clone(),
                signer_contribution_digest: contribution
                    .digest()
                    .expect("serializable contribution"),
                exact_terms_digest: request.exact_terms_digest.clone(),
                phase,
            })
            .collect::<Vec<_>>();
        let webauthn_options = legacy_migration
            .as_ref()
            .map(|legacy| CeremonyWebAuthnOptions {
                allowed_credentials: vec![CredentialPrfInput {
                    credential_id: legacy.credential.credential_id.clone(),
                    prf_salt: legacy.credential.prf_salt.clone(),
                }],
                registration_user_handle: None,
                registration_prf_salt: None,
            })
            .or_else(|| {
                registration
                    .as_ref()
                    .map(|registration| CeremonyWebAuthnOptions {
                        allowed_credentials: Vec::new(),
                        registration_user_handle: Some(registration.user_handle.clone()),
                        registration_prf_salt: Some(registration.prf_salt.clone()),
                    })
            })
            .or_else(|| {
                credential_creation.as_ref().map(|creation| {
                    let mut options = self.options_for_wallet(request.wallet_id.as_ref());
                    options.registration_user_handle = Some(creation.user_handle.clone());
                    options.registration_prf_salt = Some(creation.prf_salt.clone());
                    options
                })
            })
            .unwrap_or_else(|| self.options_for_wallet(request.wallet_id.as_ref()));
        let verification_credentials = legacy_migration
            .as_ref()
            .map(|legacy| vec![legacy.credential.clone()])
            .unwrap_or_else(|| {
                contribution
                    .wallet_id
                    .as_ref()
                    .map(|wallet_id| {
                        webauthn_options
                            .allowed_credentials
                            .iter()
                            .filter_map(|allowed| {
                                self.credential(wallet_id, &allowed.credential_id).ok()
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            });
        let prepared = PreparedCustodyCeremony {
            contribution: contribution.clone(),
            challenges: challenges.clone(),
            webauthn_options,
            verification_credentials,
        };
        self.pending.lock().insert(
            request.custody_operation_id.clone(),
            PendingCeremony {
                request_digest,
                request: PendingRequest::Custody(Box::new(request)),
                contribution: PendingContribution::Custody(contribution),
                challenges,
                hpke_recipient: Some(recipient),
                registration,
                credential_creation,
                legacy_migration,
            },
        );
        tracing::info!(
            event = "signer.ceremony_prepared",
            operation_id = prepared.contribution.custody_operation_id.as_str(),
            ceremony_kind = ceremony_kind_name(prepared.contribution.ceremony_kind),
            "Signer prepared a ceremony"
        );
        Ok(prepared)
    }

    pub fn prepare_policy_update(
        &self,
        request: PolicyUpdateCeremonyPrepareRequest,
        now_ms: u64,
    ) -> Result<PreparedCustodyCeremony, ProtocolError> {
        let _preparation_barrier = self.preparation_barrier.lock();
        self.engine.validate_policy_ceremony_prepare(&request)?;
        let request_digest = canonical_digest(&request)?;
        if let Some(existing) = self.pending.lock().get(&request.update.operation_id) {
            if existing.request_digest != request_digest {
                return Err(operation_conflict());
            }
            if let (PendingRequest::PolicyUpdate(_), PendingContribution::Custody(contribution)) =
                (&existing.request, &existing.contribution)
            {
                return Ok(PreparedCustodyCeremony {
                    contribution: contribution.clone(),
                    challenges: existing.challenges.clone(),
                    webauthn_options: self.options_for_pending(existing),
                    verification_credentials: self.verification_credentials_for_pending(existing),
                });
            }
            return Err(kind_mismatch());
        }
        self.prepare_custody_inner(request.custody.clone(), now_ms)?;
        let mut pending = self.pending.lock();
        let entry = pending
            .get_mut(&request.update.operation_id)
            .ok_or_else(replay)?;
        entry.request_digest = request_digest;
        entry.request = PendingRequest::PolicyUpdate(Box::new(request));
        let review_manifest_digest = match &entry.request {
            PendingRequest::PolicyUpdate(policy) => policy
                .broker_validation_receipt
                .review_manifest_digest
                .clone(),
            _ => return Err(kind_mismatch()),
        };
        let contribution = match &mut entry.contribution {
            PendingContribution::Custody(contribution) => contribution,
            _ => return Err(kind_mismatch()),
        };
        contribution.review_manifest_digest = review_manifest_digest;
        contribution.signer_signature = Base64UrlBytes::from_bytes(&[]);
        contribution.signer_signature =
            self.sign_contribution(&contribution.unsigned_canonical_bytes()?);
        let contribution_digest = contribution.digest()?;
        for challenge in &mut entry.challenges {
            challenge.review_manifest_digest = contribution.review_manifest_digest.clone();
            challenge.signer_contribution_digest = contribution_digest.clone();
        }
        Ok(PreparedCustodyCeremony {
            contribution: contribution.clone(),
            challenges: entry.challenges.clone(),
            webauthn_options: self.options_for_pending(entry),
            verification_credentials: self.verification_credentials_for_pending(entry),
        })
    }

    pub fn bind_custody_output_recipient(
        &self,
        operation_id: &OperationId,
        recipient_key: Base64UrlBytes,
        now_ms: u64,
    ) -> Result<PreparedCustodyCeremony, ProtocolError> {
        if recipient_key.decode().len() != 32 {
            return Err(protocol(
                ProtocolErrorCode::BackendInvalidRequest,
                "Browser HPKE recipient key must contain 32 bytes",
            ));
        }
        seal_to_recipient(
            &recipient_key,
            CUSTODY_OUTPUT_INFO,
            b"bloom-output-recipient-validation/v1",
            b"",
        )?;
        let mut pending_map = self.pending.lock();
        let pending = pending_map.get_mut(operation_id).ok_or_else(replay)?;
        let (request, contribution) = match (&mut pending.request, &mut pending.contribution) {
            (PendingRequest::Custody(request), PendingContribution::Custody(contribution)) => {
                (request, contribution)
            }
            _ => return Err(kind_mismatch()),
        };
        if !matches!(
            request.ceremony_kind,
            CeremonyKind::WalletRegistration
                | CeremonyKind::WalletImport
                | CeremonyKind::WalletExport
                | CeremonyKind::KeyDerive
        ) || contribution.expires_at_ms.get() <= now_ms
        {
            return Err(kind_mismatch());
        }
        if let Some(existing) = &contribution.browser_output_recipient_key {
            if existing != &recipient_key {
                return Err(operation_conflict());
            }
            return Ok(PreparedCustodyCeremony {
                contribution: contribution.clone(),
                challenges: pending.challenges.clone(),
                webauthn_options: self.options_for_pending(pending),
                verification_credentials: self.verification_credentials_for_pending(pending),
            });
        }
        request.browser_output_recipient_key = Some(recipient_key.clone());
        contribution.browser_output_recipient_key = Some(recipient_key);
        contribution.signer_signature = Base64UrlBytes::from_bytes(&[]);
        contribution.signer_signature =
            self.sign_contribution(&contribution.unsigned_canonical_bytes()?);
        let contribution_digest = contribution.digest()?;
        pending.challenges =
            required_phases(request.ceremony_kind, pending.legacy_migration.is_some())
                .into_iter()
                .map(|phase| CeremonyChallenge {
                    schema: Token::new("bloom.ceremony.challenge.v1")
                        .expect("static protocol token"),
                    ceremony_id: contribution.ceremony_id.clone(),
                    ceremony_kind: contribution.ceremony_kind,
                    operation_id: operation_id.clone(),
                    signer_nonce: contribution.signer_nonce.clone(),
                    review_manifest_digest: contribution.review_manifest_digest.clone(),
                    signer_contribution_digest: contribution_digest.clone(),
                    exact_terms_digest: request.exact_terms_digest.clone(),
                    phase,
                })
                .collect();
        Ok(PreparedCustodyCeremony {
            contribution: contribution.clone(),
            challenges: pending.challenges.clone(),
            webauthn_options: self.options_for_pending(pending),
            verification_credentials: self.verification_credentials_for_pending(pending),
        })
    }

    pub async fn complete_approval(
        &self,
        request: CeremonyCompleteRequest,
        now_ms: u64,
    ) -> Result<SignerActivationReceipt, ProtocolError> {
        let _completion_barrier = self.approval_completion_barrier.lock().await;
        if let Some(CompletedCeremony::Approval(receipt)) =
            self.completed.lock().get(&request.activation_operation_id)
        {
            tracing::info!(
                event = "signer.ceremony_recovered",
                operation_id = request.activation_operation_id.as_str(),
                ceremony_kind = "sealed_approval",
                outcome = "completed_retry",
                "Signer recovered a completed ceremony"
            );
            return Ok(receipt.as_ref().clone());
        }
        if let Some(receipt) = self
            .engine
            .activation_receipt(&request.activation_operation_id)?
        {
            if receipt.ceremony_id != request.contribution.ceremony_id
                || receipt.approval_digest != request.contribution.approval_digest
            {
                tracing::warn!(
                    event = "signer.ceremony_retry_conflict",
                    operation_id = request.activation_operation_id.as_str(),
                    ceremony_kind = "sealed_approval",
                    "Signer rejected a conflicting completed ceremony retry"
                );
                return Err(operation_conflict());
            }
            tracing::info!(
                event = "signer.ceremony_recovered",
                operation_id = request.activation_operation_id.as_str(),
                ceremony_kind = "sealed_approval",
                outcome = "durable_receipt",
                "Signer recovered a durable ceremony receipt"
            );
            return Ok(receipt);
        }
        let operation_id = request.activation_operation_id.clone();
        let mut pending = self
            .pending
            .lock()
            .remove(&operation_id)
            .ok_or_else(replay)?;
        match self
            .apply_approval_completion(request, now_ms, &mut pending)
            .await
        {
            Ok(receipt) => Ok(receipt),
            Err(error) => {
                self.terminalize_consumed_ceremony(&operation_id, &pending.contribution, now_ms);
                Err(error)
            }
        }
    }

    async fn apply_approval_completion(
        &self,
        request: CeremonyCompleteRequest,
        now_ms: u64,
        pending: &mut PendingCeremony,
    ) -> Result<SignerActivationReceipt, ProtocolError> {
        let (prepare, contribution) = match (&pending.request, &pending.contribution) {
            (PendingRequest::Approval(prepare), PendingContribution::Approval(contribution)) => {
                (prepare, contribution)
            }
            _ => return Err(kind_mismatch()),
        };
        if contribution != &request.contribution
            || contribution.expires_at_ms.get() <= now_ms
            || !self.verify_contribution(
                &contribution.unsigned_canonical_bytes()?,
                &contribution.signer_signature,
            )
        {
            return Err(replay());
        }
        let assertion = match &request.proof {
            WebAuthnCeremonyProof::Assertion { assertion } => assertion,
            _ => return Err(kind_mismatch()),
        };
        let bound = self.bound_credential(&assertion.credential_id, &prepare.terms.wallet_id)?;
        let verified = verify_webauthn_assertion(
            assertion,
            &bound.credential,
            &pending.challenges[0].canonical_bytes()?,
            true,
        )?;

        if !matches!(
            &prepare.terms.activation_mode,
            ActivationMode::BackendManaged
        ) {
            let envelope = request.encrypted_local_prf.as_ref().ok_or_else(|| {
                protocol(
                    ProtocolErrorCode::BackendInvalidRequest,
                    "local activation requires encrypted PRF output",
                )
            })?;
            let aad = LocalPrfHpkeAad {
                ceremony_id: contribution.ceremony_id.clone(),
                signer_nonce: contribution.signer_nonce.clone(),
                approval_id: prepare.terms.approval_id()?,
                approval_digest: contribution.approval_digest.clone(),
                review_manifest_digest: contribution.review_manifest_digest.clone(),
                key_ref: contribution.key_ref.clone(),
                allowed_crypto_suites: contribution.allowed_crypto_suites.clone(),
                credential_id: assertion.credential_id.clone(),
                activation_mode: contribution.activation_mode.clone(),
                wallet_revocation_epoch: contribution.wallet_revocation_epoch.clone(),
            }
            .canonical_bytes()?;
            let secret = pending.hpke_recipient.take().ok_or_else(replay)?.open(
                envelope,
                LOCAL_PRF_INFO,
                &aad,
            )?;
            let credential_key =
                credential_wrap_key(&secret, &prepare.terms.wallet_id, &assertion.credential_id)?;
            let backend_activation_secret = self
                .wallet(&prepare.terms.wallet_id)?
                .unlock_with_credential(&assertion.credential_id, &credential_key)?
                .local_backend_activation_secret()?;
            self.engine
                .backend_registry()
                .activate_key(&prepare.terms.key_ref, backend_activation_secret)
                .await?;
        } else if request.encrypted_local_prf.is_some() {
            return Err(protocol(
                ProtocolErrorCode::BackendInvalidRequest,
                "backend-managed activation rejects a local PRF envelope",
            ));
        }

        let mut receipt = SignerActivationReceipt {
            activation_operation_id: request.activation_operation_id.clone(),
            ceremony_id: contribution.ceremony_id.clone(),
            approval_id: prepare.terms.approval_id()?,
            approval_digest: contribution.approval_digest.clone(),
            review_manifest_digest: contribution.review_manifest_digest.clone(),
            key_ref: contribution.key_ref.clone(),
            allowed_crypto_suites: contribution.allowed_crypto_suites.clone(),
            activation_mode: contribution.activation_mode.clone(),
            wallet_revocation_epoch: contribution.wallet_revocation_epoch.clone(),
            replaced_approval_id: prepare.replacement_approval_id.clone(),
            activated_at_ms: DecimalU64::new(now_ms),
            expires_at_ms: prepare.terms.expires_at_ms.clone(),
            signer_key_id: self.signer_key_id.clone(),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        receipt.signer_signature = self.sign_receipt(&approval_receipt_bytes(&receipt)?);
        self.engine.activate_approval_from_ceremony(
            &prepare.terms,
            &receipt,
            VerifiedCeremonyActivation(()),
        )?;
        self.advance_counter(&verified.credential_id, verified.sign_count);
        self.completed.lock().insert(
            request.activation_operation_id,
            CompletedCeremony::Approval(Box::new(receipt.clone())),
        );
        tracing::info!(
            event = "signer.ceremony_terminal",
            operation_id = receipt.activation_operation_id.as_str(),
            ceremony_kind = "sealed_approval",
            state = "completed",
            "Signer committed a terminal ceremony outcome"
        );
        Ok(receipt)
    }

    pub fn complete_custody(
        &self,
        request: CustodyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, ProtocolError> {
        self.complete_custody_inner(request, now_ms, false)
    }

    pub fn complete_policy_update(
        &self,
        request: PolicyUpdateCeremonyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, ProtocolError> {
        self.complete_custody_inner(request.custody, now_ms, true)
    }

    fn complete_custody_inner(
        &self,
        request: CustodyCompleteRequest,
        now_ms: u64,
        policy_update: bool,
    ) -> Result<CustodyResult, ProtocolError> {
        if policy_update != (request.ceremony_kind == CeremonyKind::PolicyUpdate) {
            return Err(kind_mismatch());
        }
        let _completion_barrier = self.custody_completion_barrier.lock();
        if let Some(CompletedCeremony::Custody { result, .. }) =
            self.completed.lock().get(&request.custody_operation_id)
        {
            tracing::info!(
                event = "signer.ceremony_recovered",
                operation_id = request.custody_operation_id.as_str(),
                ceremony_kind = ceremony_kind_name(request.ceremony_kind),
                outcome = "completed_retry",
                "Signer recovered a completed ceremony"
            );
            return Ok((**result).clone());
        }
        if let Some(result) = self.engine.custody_receipt(&request.custody_operation_id)? {
            if result.ceremony_kind != request.ceremony_kind {
                tracing::warn!(
                    event = "signer.ceremony_retry_conflict",
                    operation_id = request.custody_operation_id.as_str(),
                    ceremony_kind = ceremony_kind_name(request.ceremony_kind),
                    "Signer rejected a conflicting completed ceremony retry"
                );
                return Err(operation_conflict());
            }
            tracing::info!(
                event = "signer.ceremony_recovered",
                operation_id = request.custody_operation_id.as_str(),
                ceremony_kind = ceremony_kind_name(request.ceremony_kind),
                outcome = "durable_receipt",
                "Signer recovered a durable ceremony receipt"
            );
            return Ok(result);
        }
        let operation_id = request.custody_operation_id.clone();
        let mut pending = self
            .pending
            .lock()
            .remove(&operation_id)
            .ok_or_else(replay)?;
        match self.apply_custody_completion(request, now_ms, policy_update, &mut pending) {
            Ok(result) => Ok(result),
            Err(error) => {
                self.terminalize_consumed_ceremony(&operation_id, &pending.contribution, now_ms);
                Err(error)
            }
        }
    }

    /// Complete a custody ceremony whose single-use pending record has already
    /// been consumed by the caller.
    ///
    /// Every exit from here is terminal for that record: the caller either
    /// commits a receipt or durably terminalizes the ceremony, so a rejected
    /// proof never leaves the operation merely absent.
    fn apply_custody_completion(
        &self,
        request: CustodyCompleteRequest,
        now_ms: u64,
        policy_update: bool,
        pending: &mut PendingCeremony,
    ) -> Result<CustodyResult, ProtocolError> {
        let (prepare, policy_prepare, contribution) =
            match (&pending.request, &pending.contribution) {
                (PendingRequest::Custody(prepare), PendingContribution::Custody(contribution)) => {
                    (prepare.as_ref(), None, contribution)
                }
                (
                    PendingRequest::PolicyUpdate(policy),
                    PendingContribution::Custody(contribution),
                ) => (&policy.custody, Some(policy.as_ref()), contribution),
                _ => return Err(kind_mismatch()),
            };
        if policy_update != policy_prepare.is_some() {
            return Err(kind_mismatch());
        }
        if request.ceremony_kind != prepare.ceremony_kind
            || request.ceremony_id != contribution.ceremony_id
            || contribution.expires_at_ms.get() <= now_ms
            || request.public_binding_digest != prepare.exact_terms_digest
            || !self.verify_contribution(
                &contribution.unsigned_canonical_bytes()?,
                &contribution.signer_signature,
            )
        {
            return Err(kind_mismatch());
        }
        if prepare.petal_key_scope.is_some() {
            contribution.validate_petal_key_scope_binding(prepare)?;
        }
        let before = self.custody_snapshot();
        let apply_outcome = match self.verify_custody_proof_and_apply(
            prepare,
            contribution,
            &pending.challenges,
            &request,
            policy_prepare,
            CustodyApplyContext {
                recipient: pending.hpke_recipient.take(),
                registration: pending.registration.take(),
                credential_creation: pending.credential_creation.take(),
                legacy_migration: pending.legacy_migration.take(),
            },
        ) {
            Ok(output) => output,
            Err(error) => {
                self.restore_custody_snapshot(before)?;
                return Err(error);
            }
        };
        let receipt_digest = canonical_digest(&CustodyReceiptPreimage {
            ceremony_id: &contribution.ceremony_id,
            ceremony_kind: contribution.ceremony_kind,
            operation_id: &contribution.custody_operation_id,
            public_binding_digest: &request.public_binding_digest,
            completed_at_ms: now_ms,
        })?;
        let encrypted_browser_result = apply_outcome
            .sensitive_output
            .map(|plaintext| {
                let recipient = contribution
                    .browser_output_recipient_key
                    .as_ref()
                    .ok_or_else(|| {
                        protocol(
                            ProtocolErrorCode::BackendInvalidRequest,
                            "sensitive custody output requires a Browser recipient key",
                        )
                    })?;
                let aad = CustodyOutputHpkeAad {
                    ceremony_id: contribution.ceremony_id.clone(),
                    ceremony_kind: contribution.ceremony_kind,
                    custody_operation_id: contribution.custody_operation_id.clone(),
                    signer_contribution_digest: contribution.digest()?,
                    public_binding_digest: request.public_binding_digest.clone(),
                }
                .canonical_bytes()?;
                seal_to_recipient(recipient, CUSTODY_OUTPUT_INFO, &aad, &plaintext)
            })
            .transpose();
        let encrypted_browser_result = match encrypted_browser_result {
            Ok(result) => result,
            Err(error) => {
                self.rollback_derived_key(apply_outcome.rollback_derived_key.as_ref())?;
                self.rollback_provisioned_backend(
                    apply_outcome.rollback_provisioned_backend.as_ref(),
                );
                self.restore_custody_snapshot(before)?;
                return Err(error);
            }
        };
        let wallet_id = contribution.wallet_id.clone();
        let credential_summaries = wallet_id
            .as_ref()
            .map(|wallet_id| {
                self.credentials
                    .lock()
                    .values()
                    .filter(|bound| &bound.wallet_id == wallet_id)
                    .map(|bound| CredentialSummary {
                        credential_id: bound.credential.credential_id.clone(),
                        rp_id: bound.credential.rp_id.clone(),
                        active: true,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let initial_policy = match &apply_outcome.database_effect {
            CeremonyDatabaseEffect::InitialPolicy { snapshot, .. } => Some(snapshot.clone()),
            _ => None,
        };
        let mut result = CustodyResult {
            ceremony_kind: request.ceremony_kind,
            custody_operation_id: request.custody_operation_id.clone(),
            public_status: request
                .ceremony_kind
                .successful_terminal_state()
                .ok_or_else(kind_mismatch)?,
            wallet_id,
            public_key_refs: apply_outcome.public_key_refs,
            credential_summaries,
            initial_policy,
            receipt_digest,
            encrypted_browser_result,
            signer_key_id: self.signer_key_id.clone(),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        result.signer_signature = self.sign_receipt(&result.unsigned_canonical_bytes()?);
        let after = self.custody_snapshot();
        let durable_status = CeremonyPublicStatus {
            ceremony_id: contribution.ceremony_id.clone(),
            ceremony_kind: request.ceremony_kind,
            operation_id: request.custody_operation_id.clone(),
            state: result.public_status,
            expires_at_ms: contribution.expires_at_ms.clone(),
            ceremony_url: None,
            receipt_digest: Some(result.receipt_digest.clone()),
        };
        if let Err(error) = self.engine.commit_custody_snapshot_with_effect(
            &result,
            &after.0,
            &after.1,
            now_ms,
            &durable_status,
            apply_outcome.database_effect,
        ) {
            self.rollback_derived_key(apply_outcome.rollback_derived_key.as_ref())?;
            self.rollback_provisioned_backend(apply_outcome.rollback_provisioned_backend.as_ref());
            self.restore_custody_snapshot(before)?;
            return Err(error);
        }
        if let Some(key_ref) = apply_outcome.rollback_derived_key.as_ref() {
            #[cfg(feature = "local")]
            self.engine
                .backend_registry()
                .finalize_local_derived_key(key_ref, &request.custody_operation_id)?;
        }
        if apply_outcome.consume_legacy_migration {
            self.legacy_migrations
                .as_ref()
                .ok_or_else(kind_mismatch)?
                .consume(&request.custody_operation_id)?;
        }
        self.completed.lock().insert(
            request.custody_operation_id,
            CompletedCeremony::Custody {
                result: Box::new(result.clone()),
                ceremony_id: contribution.ceremony_id.clone(),
                expires_at_ms: contribution.expires_at_ms.clone(),
            },
        );
        tracing::info!(
            event = "signer.ceremony_terminal",
            operation_id = result.custody_operation_id.as_str(),
            ceremony_kind = ceremony_kind_name(result.ceremony_kind),
            state = ceremony_state_name(result.public_status),
            "Signer committed a terminal ceremony outcome"
        );
        Ok(result)
    }

    pub fn cancel(
        &self,
        operation_id: &OperationId,
    ) -> Result<SignerCeremonyCancellation, ProtocolError> {
        let _preparation_barrier = self.preparation_barrier.lock();
        let _owner_completion_barrier = self.owner_attestation_completion_barrier.lock();
        if self.completed.lock().contains_key(operation_id)
            || self
                .engine
                .owner_attestation_receipt(operation_id)?
                .is_some()
        {
            return Err(committed_conflict());
        }
        if let Some(pending) = self.pending_owner_attestations.lock().remove(operation_id) {
            self.engine.persist_owner_attestation_terminal_status(
                operation_id,
                &pending.contribution.ceremony_id,
                CeremonyState::Cancelled,
                &pending.expires_at_ms,
                &pending.contribution.public_binding_digest,
            )?;
            return Ok(SignerCeremonyCancellation::OwnerAttestation(
                SignerCeremonyStatus::Terminal(CeremonyState::Cancelled),
            ));
        }
        if let Some(state) = self.engine.owner_attestation_terminal_state(operation_id)? {
            return match state {
                CeremonyState::Cancelled | CeremonyState::Expired | CeremonyState::Failed => {
                    Ok(SignerCeremonyCancellation::OwnerAttestation(
                        SignerCeremonyStatus::Terminal(state),
                    ))
                }
                _ => Err(committed_conflict()),
            };
        }
        let Some(pending) = self.pending.lock().remove(operation_id) else {
            return self
                .cancel_consumed_ceremony(operation_id)
                .map(SignerCeremonyCancellation::Public);
        };
        let status = pending_public_status(
            operation_id,
            &pending.contribution,
            CeremonyState::Cancelled,
        );
        self.engine.persist_ceremony_public_status(&status)?;
        Ok(SignerCeremonyCancellation::Public(status))
    }

    /// Answer cancellation for a ceremony whose pending record is gone.
    ///
    /// Completion consumes that record before it can validate the user's proof,
    /// so the ordinary cleanup a peer performs after a rejected proof arrives
    /// here. Reporting `ApprovalNotFound` left the peer unable to distinguish
    /// "already failed closed" from "unknown", and a peer that treats the error
    /// as fatal abandons its own session mid-flight, so a ceremony that already
    /// reached a durable non-successful terminal answers idempotently. A
    /// committed ceremony still refuses.
    fn cancel_consumed_ceremony(
        &self,
        operation_id: &OperationId,
    ) -> Result<CeremonyPublicStatus, ProtocolError> {
        if self.engine.activation_receipt(operation_id)?.is_some()
            || self.engine.custody_receipt(operation_id)?.is_some()
            || self
                .engine
                .owner_attestation_receipt(operation_id)?
                .is_some()
        {
            return Err(committed_conflict());
        }
        match self.engine.ceremony_public_status(operation_id)? {
            Some(status) => match status.state {
                CeremonyState::Cancelled | CeremonyState::Expired | CeremonyState::Failed => {
                    Ok(status)
                }
                _ => Err(committed_conflict()),
            },
            None => Err(protocol(
                ProtocolErrorCode::ApprovalNotFound,
                "ceremony not found",
            )),
        }
    }

    /// Refuse to prepare an operation ID that already reached a durable
    /// outcome.
    ///
    /// Preparation is the only way back into `pending`, and `pending` is what
    /// `status` reports first. Without this a terminal ceremony is reopenable:
    /// the operation ID whose rejected proof left a `FAILED` row could be
    /// prepared again, reverting the reported state to `Pending`, granting the
    /// fail-closed ceremony a second attempt, and letting its completion
    /// overwrite the durable terminal row. A committed receipt is equally
    /// closed — replaying it belongs to `complete`, which returns the existing
    /// receipt rather than arming a fresh ceremony.
    fn require_unopened_operation_id(
        &self,
        operation_id: &OperationId,
    ) -> Result<(), ProtocolError> {
        if self.engine.ceremony_operation_exists(operation_id)? {
            return Err(terminal_conflict());
        }
        Ok(())
    }

    /// Record the durable terminal state of a consumed ceremony that produced
    /// no receipt.
    ///
    /// Signer removes the pending record before it can verify the WebAuthn
    /// proof, which is what keeps completion single-use. Without this the
    /// rejected ceremony became invisible instead of terminal: status,
    /// cancellation and reconciliation all reported it absent, and the peer
    /// holding the live session had nothing to converge on.
    ///
    /// Best effort by design. The caller's answer is the proof rejection, so a
    /// storage failure here is reported on the operator's channel rather than
    /// replacing the structured authentication error.
    fn terminalize_consumed_ceremony(
        &self,
        operation_id: &OperationId,
        contribution: &PendingContribution,
        now_ms: u64,
    ) {
        // `apply_custody_completion` has a small amount of cleanup after its
        // durable commit; never let that later error overwrite a committed
        // receipt's successful public status.
        if self
            .engine
            .activation_receipt(operation_id)
            .ok()
            .flatten()
            .is_some()
            || self
                .engine
                .custody_receipt(operation_id)
                .ok()
                .flatten()
                .is_some()
        {
            return;
        }
        let mut status = pending_public_status(operation_id, contribution, CeremonyState::Failed);
        if status.expires_at_ms.get() <= now_ms {
            status.state = CeremonyState::Expired;
        }
        if let Err(error) = self.engine.persist_ceremony_public_status(&status) {
            tracing::warn!(
                event = "signer.ceremony_terminalization_failed",
                operation_id = operation_id.as_str(),
                ceremony_state = ceremony_state_name(status.state),
                error_code = error.code.as_str(),
                "Signer could not persist a rejected ceremony's terminal state"
            );
        } else {
            tracing::warn!(
                event = "signer.ceremony_terminal",
                operation_id = operation_id.as_str(),
                ceremony_kind = match contribution {
                    PendingContribution::Approval(_) => "sealed_approval",
                    PendingContribution::Custody(contribution) => {
                        ceremony_kind_name(contribution.ceremony_kind)
                    }
                },
                state = ceremony_state_name(status.state),
                "Signer committed a rejected ceremony's terminal outcome"
            );
        }
    }

    pub fn status(
        &self,
        operation_id: &OperationId,
    ) -> Result<SignerCeremonyStatus, ProtocolError> {
        if let Some(receipt) = self.engine.owner_attestation_receipt(operation_id)? {
            return Ok(SignerCeremonyStatus::CompletedOwnerAttestation(Box::new(
                receipt,
            )));
        }
        if self
            .pending_owner_attestations
            .lock()
            .contains_key(operation_id)
        {
            return Ok(SignerCeremonyStatus::Pending);
        }
        if let Some(state) = self.engine.owner_attestation_terminal_state(operation_id)? {
            return Ok(SignerCeremonyStatus::Terminal(state));
        }
        if let Some(completed) = self.completed.lock().get(operation_id) {
            return Ok(match completed {
                CompletedCeremony::Approval(receipt) => {
                    SignerCeremonyStatus::CompletedApproval(Box::new((**receipt).clone()))
                }
                CompletedCeremony::Custody { result, .. } => {
                    SignerCeremonyStatus::CompletedCustody(result.clone())
                }
            });
        }
        if let Some(receipt) = self.engine.activation_receipt(operation_id)? {
            return Ok(SignerCeremonyStatus::CompletedApproval(Box::new(receipt)));
        }
        if let Some(result) = self.engine.custody_receipt(operation_id)? {
            return Ok(SignerCeremonyStatus::CompletedCustody(Box::new(result)));
        }
        if self.pending.lock().contains_key(operation_id) {
            return Ok(SignerCeremonyStatus::Pending);
        }
        // A ceremony that failed closed, expired or was cancelled keeps only a
        // durable public status, so reporting `Missing` here would tell a peer
        // reconciling its own live session that Signer never saw the operation.
        Ok(match self.engine.ceremony_public_status(operation_id)? {
            Some(status) => SignerCeremonyStatus::Terminal(status.state),
            None => SignerCeremonyStatus::Missing,
        })
    }

    pub fn public_status(
        &self,
        operation_id: &OperationId,
    ) -> Result<CeremonyPublicStatus, ProtocolError> {
        if let Some(completed) = self.completed.lock().get(operation_id) {
            return match completed {
                CompletedCeremony::Approval(receipt) => Ok(CeremonyPublicStatus {
                    ceremony_id: receipt.ceremony_id.clone(),
                    ceremony_kind: CeremonyKind::SealedApproval,
                    operation_id: operation_id.clone(),
                    state: CeremonyState::Succeeded,
                    expires_at_ms: receipt.expires_at_ms.clone(),
                    ceremony_url: None,
                    receipt_digest: Some(canonical_digest(receipt.as_ref())?),
                }),
                CompletedCeremony::Custody {
                    result,
                    ceremony_id,
                    expires_at_ms,
                } => Ok(CeremonyPublicStatus {
                    ceremony_id: ceremony_id.clone(),
                    ceremony_kind: result.ceremony_kind,
                    operation_id: operation_id.clone(),
                    state: result.public_status,
                    expires_at_ms: expires_at_ms.clone(),
                    ceremony_url: None,
                    receipt_digest: Some(result.receipt_digest.clone()),
                }),
            };
        }
        if let Some(pending) = self.pending.lock().get(operation_id) {
            return Ok(match &pending.contribution {
                PendingContribution::Approval(contribution) => CeremonyPublicStatus {
                    ceremony_id: contribution.ceremony_id.clone(),
                    ceremony_kind: CeremonyKind::SealedApproval,
                    operation_id: operation_id.clone(),
                    state: CeremonyState::AwaitingUser,
                    expires_at_ms: contribution.expires_at_ms.clone(),
                    ceremony_url: None,
                    receipt_digest: None,
                },
                PendingContribution::Custody(contribution) => CeremonyPublicStatus {
                    ceremony_id: contribution.ceremony_id.clone(),
                    ceremony_kind: contribution.ceremony_kind,
                    operation_id: operation_id.clone(),
                    state: CeremonyState::AwaitingUser,
                    expires_at_ms: contribution.expires_at_ms.clone(),
                    ceremony_url: None,
                    receipt_digest: None,
                },
            });
        }
        if let Some(status) = self.engine.ceremony_public_status(operation_id)? {
            return Ok(status);
        }
        Err(protocol(
            ProtocolErrorCode::ApprovalNotFound,
            "ceremony not found",
        ))
    }

    pub fn credential(
        &self,
        wallet_id: &Token,
        credential_id: &Base64UrlBytes,
    ) -> Result<WebAuthnCredential, ProtocolError> {
        Ok(self.bound_credential(credential_id, wallet_id)?.credential)
    }

    fn verify_custody_proof_and_apply(
        &self,
        prepare: &CustodyPrepareRequest,
        contribution: &CustodySignerContribution,
        challenges: &[CeremonyChallenge],
        complete: &CustodyCompleteRequest,
        policy_prepare: Option<&PolicyUpdateCeremonyPrepareRequest>,
        mut context: CustodyApplyContext,
    ) -> Result<CustodyApplyOutcome, ProtocolError> {
        let mut sensitive_output = None;
        let mut database_effect = CeremonyDatabaseEffect::None;
        let mut rollback_derived_key = None;
        let mut rollback_provisioned_backend = None;
        let mut public_key_refs = Vec::new();
        let mut consume_legacy_migration = false;
        let effect = match prepare.ceremony_kind {
            CeremonyKind::WalletRegistration | CeremonyKind::WalletImport => {
                let registration = context.registration.take().ok_or_else(kind_mismatch)?;
                let (credential, root, prf) = if let Some(legacy) = context.legacy_migration.take()
                {
                    let assertion = assertion_only(&complete.proof)?;
                    let verified = verify_webauthn_assertion(
                        assertion,
                        &legacy.credential,
                        &challenges[0].canonical_bytes()?,
                        true,
                    )?;
                    if verified
                        .user_handle
                        .as_ref()
                        .is_some_and(|handle| handle != &legacy.credential.user_handle)
                    {
                        return Err(protocol(
                            ProtocolErrorCode::UnauthenticatedPeer,
                            "legacy passkey user handle does not match the staged credential",
                        ));
                    }
                    let input = self.decrypt_custody_input(
                        prepare,
                        contribution,
                        complete,
                        context.recipient.take(),
                        Some(&legacy.credential.credential_id),
                    )?;
                    let input: LegacyPasskeyPrfInput =
                        serde_json::from_slice(input.expose_to_backend()).map_err(malformed)?;
                    let prf = SecretBytes::new(input.credential_prf.decode());
                    let root = self
                        .legacy_migrations
                        .as_ref()
                        .ok_or_else(kind_mismatch)?
                        .decrypt_root(&prepare.custody_operation_id, &prf)?;
                    let mut credential = legacy.credential;
                    credential.sign_count = DecimalU64::new(u64::from(verified.sign_count));
                    consume_legacy_migration = true;
                    (credential, root, prf)
                } else {
                    let (attestation, prf_assertion) = match &complete.proof {
                        WebAuthnCeremonyProof::Registration {
                            attestation,
                            prf_assertion,
                        } => (attestation, prf_assertion),
                        _ => return Err(kind_mismatch()),
                    };
                    let mut credential = verify_webauthn_attestation(
                        attestation,
                        &challenges[0].canonical_bytes()?,
                        registration.user_handle.clone(),
                        registration.prf_salt.clone(),
                    )?;
                    if let Some(assertion) = prf_assertion {
                        let verified = verify_webauthn_assertion(
                            assertion,
                            &credential,
                            &challenges[1].canonical_bytes()?,
                            true,
                        )?;
                        credential.sign_count = DecimalU64::new(u64::from(verified.sign_count));
                    }
                    let input = self.decrypt_custody_input(
                        prepare,
                        contribution,
                        complete,
                        context.recipient.take(),
                        Some(&credential.credential_id),
                    )?;
                    let (root, prf) = if prepare.ceremony_kind == CeremonyKind::WalletImport {
                        let import: RawWalletImportInput =
                            serde_json::from_slice(input.expose_to_backend()).map_err(malformed)?;
                        let raw_private_key = import.raw_private_key.decode();
                        if raw_private_key.len() != 32 {
                            return Err(protocol(
                                ProtocolErrorCode::BackendInvalidRequest,
                                "raw secp256k1 private key must contain exactly 32 bytes",
                            ));
                        }
                        (
                            SecretBytes::new(raw_private_key),
                            SecretBytes::new(import.credential_prf.decode()),
                        )
                    } else {
                        (registration.root, input)
                    };
                    (credential, root, prf)
                };
                let backend_seed = root.expose_to_backend().to_vec();
                let credential_key =
                    credential_wrap_key(&prf, &registration.wallet_id, &credential.credential_id)?;
                let wallet = Arc::new(WalletCustody::register(
                    registration.wallet_id.clone(),
                    root,
                    registration.policy_seed,
                    registration.wkek,
                    credential.credential_id.clone(),
                    credential_key,
                )?);
                let unlock_key =
                    credential_wrap_key(&prf, &registration.wallet_id, &credential.credential_id)?;
                let unlocked =
                    wallet.unlock_with_credential(&credential.credential_id, &unlock_key)?;
                let backend_activation_secret = unlocked
                    .local_backend_activation_secret()?
                    .expose_to_backend()
                    .to_vec();
                let initial_policy = bloom_signer_api::CanonicalWalletPolicy {
                    wallet_id: registration.wallet_id.clone(),
                    maximum_approval_lifetime_ms: 30 * 24 * 60 * 60 * 1_000,
                    allowed_petal_packages: Vec::new(),
                    allowed_destinations: Vec::new(),
                    required_verifiers: Vec::new(),
                };
                database_effect = self.engine.prepare_initial_policy_effect(
                    &registration.wallet_id,
                    Base64UrlBytes::from_bytes(
                        &serde_jcs::to_vec(&initial_policy).map_err(malformed)?,
                    ),
                    Token::new("wallet-policy-key-v1").expect("static token"),
                    &unlocked,
                )?;
                if contribution.browser_output_recipient_key.is_some() {
                    let recovery_key =
                        recovery_wrap_key(&registration.recovery_secret, &registration.wallet_id)?;
                    wallet.set_recovery(
                        &unlocked,
                        registration.recovery_id.clone(),
                        &recovery_key,
                    )?;
                    sensitive_output = Some(
                        serde_jcs::to_vec(&RegistrationRecoveryOutput {
                            recovery_id: registration.recovery_id,
                            recovery_secret: registration.recovery_secret,
                        })
                        .map_err(malformed)?,
                    );
                }
                {
                    let mut wallets = self.wallets.lock();
                    if wallets.contains_key(&registration.wallet_id) {
                        return Err(protocol(
                            ProtocolErrorCode::OperationIdConflict,
                            "wallet ID is already enrolled",
                        ));
                    }
                    wallets.insert(registration.wallet_id.clone(), wallet);
                }
                self.register_existing_credential(registration.wallet_id.clone(), credential)?;
                #[cfg(feature = "local")]
                {
                    let (root_key_ref, encrypted_record) = self
                        .engine
                        .backend_registry()
                        .provision_local_wallet_backend(
                            &registration.wallet_id,
                            SecretBytes::new(backend_seed),
                            prepare.ceremony_kind == CeremonyKind::WalletImport,
                            SecretBytes::new(backend_activation_secret),
                            self.signing_key.verifying_key(),
                        )?;
                    let enrollment = crate::engine::BackendEnrollmentBackup {
                        backend: root_key_ref.backend.clone(),
                        backend_instance: root_key_ref.backend_instance.clone(),
                        encrypted_record,
                        pinned_keys: vec![root_key_ref.clone()],
                    };
                    let CeremonyDatabaseEffect::InitialPolicy {
                        backend_enrollment, ..
                    } = &mut database_effect
                    else {
                        return Err(kind_mismatch());
                    };
                    *backend_enrollment = Some(enrollment);
                    public_key_refs = vec![root_key_ref.clone()];
                    rollback_provisioned_backend = Some(root_key_ref);
                }
                #[cfg(not(feature = "local"))]
                {
                    let _ = (backend_seed, backend_activation_secret);
                    return Err(protocol(
                        ProtocolErrorCode::BackendUnsupported,
                        "no wallet-provisioning backend is compiled",
                    ));
                }
                Ok(())
            }
            CeremonyKind::CredentialAdd | CeremonyKind::CredentialReplace => {
                let wallet_id = prepare.wallet_id.as_ref().ok_or_else(kind_mismatch)?;
                let (authority, attestation, prf_assertion) = match &complete.proof {
                    WebAuthnCeremonyProof::AuthorityCredentialChange {
                        authority_assertion,
                        new_credential_attestation,
                        new_credential_prf_assertion,
                    } => (
                        authority_assertion,
                        new_credential_attestation,
                        new_credential_prf_assertion,
                    ),
                    _ => return Err(kind_mismatch()),
                };
                let authority_bound = self.bound_credential(&authority.credential_id, wallet_id)?;
                let authority_verified = verify_webauthn_assertion(
                    authority,
                    &authority_bound.credential,
                    &challenges[0].canonical_bytes()?,
                    true,
                )?;
                let new_credential = verify_webauthn_attestation(
                    attestation,
                    &challenges[1].canonical_bytes()?,
                    authority_bound.credential.user_handle.clone(),
                    context
                        .credential_creation
                        .as_ref()
                        .map(|creation| creation.prf_salt.clone())
                        .ok_or_else(kind_mismatch)?,
                )?;
                let mut new_credential = new_credential;
                if let Some(assertion) = prf_assertion {
                    let verified = verify_webauthn_assertion(
                        assertion,
                        &new_credential,
                        &challenges[2].canonical_bytes()?,
                        true,
                    )?;
                    new_credential.sign_count = DecimalU64::new(u64::from(verified.sign_count));
                }
                let input = self.decrypt_custody_input(
                    prepare,
                    contribution,
                    complete,
                    context.recipient.take(),
                    Some(&new_credential.credential_id),
                )?;
                let secrets: CredentialChangeInput =
                    serde_json::from_slice(input.expose_to_backend()).map_err(malformed)?;
                let old_key = credential_wrap_key(
                    &SecretBytes::new(secrets.authority_prf.decode()),
                    wallet_id,
                    &authority.credential_id,
                )?;
                let new_key = credential_wrap_key(
                    &SecretBytes::new(secrets.new_credential_prf.decode()),
                    wallet_id,
                    &new_credential.credential_id,
                )?;
                let wallet = self.wallet(wallet_id)?;
                let unlocked = wallet.unlock_with_credential(&authority.credential_id, &old_key)?;
                wallet.add_credential(&unlocked, new_credential.credential_id.clone(), &new_key)?;
                self.register_existing_credential(wallet_id.clone(), new_credential)?;
                self.advance_counter(
                    &authority_verified.credential_id,
                    authority_verified.sign_count,
                );
                if prepare.ceremony_kind == CeremonyKind::CredentialReplace {
                    wallet.revoke_credential(&authority.credential_id)?;
                    self.credentials
                        .lock()
                        .remove(authority.credential_id.encoded());
                }
                Ok(())
            }
            CeremonyKind::CredentialRemove => {
                let wallet_id = prepare.wallet_id.as_ref().ok_or_else(kind_mismatch)?;
                let assertion = assertion_only(&complete.proof)?;
                let bound = self.bound_credential(&assertion.credential_id, wallet_id)?;
                let verified = verify_webauthn_assertion(
                    assertion,
                    &bound.credential,
                    &challenges[0].canonical_bytes()?,
                    true,
                )?;
                let target = prepare.key_ref.as_ref().ok_or_else(|| {
                    protocol(
                        ProtocolErrorCode::BackendInvalidRequest,
                        "credential removal must bind its target in typed terms",
                    )
                })?;
                let target_id = Base64UrlBytes::parse(target.locator.clone())?;
                self.wallet(wallet_id)?.revoke_credential(&target_id)?;
                self.advance_counter(&verified.credential_id, verified.sign_count);
                self.credentials.lock().remove(target_id.encoded());
                Ok(())
            }
            CeremonyKind::WalletRecovery => {
                let wallet_id = prepare.wallet_id.as_ref().ok_or_else(kind_mismatch)?;
                let creation = context
                    .credential_creation
                    .as_ref()
                    .ok_or_else(kind_mismatch)?;
                let (attestation, prf_assertion) = match &complete.proof {
                    WebAuthnCeremonyProof::RecoveryCredentialChange {
                        new_credential_attestation,
                        new_credential_prf_assertion,
                    } => (new_credential_attestation, new_credential_prf_assertion),
                    _ => return Err(kind_mismatch()),
                };
                let mut new_credential = verify_webauthn_attestation(
                    attestation,
                    &challenges[0].canonical_bytes()?,
                    creation.user_handle.clone(),
                    creation.prf_salt.clone(),
                )?;
                if let Some(assertion) = prf_assertion {
                    let verified = verify_webauthn_assertion(
                        assertion,
                        &new_credential,
                        &challenges[1].canonical_bytes()?,
                        true,
                    )?;
                    new_credential.sign_count = DecimalU64::new(u64::from(verified.sign_count));
                }
                let input = self.decrypt_custody_input(
                    prepare,
                    contribution,
                    complete,
                    context.recipient.take(),
                    Some(&new_credential.credential_id),
                )?;
                let secrets: RecoveryInput =
                    serde_json::from_slice(input.expose_to_backend()).map_err(malformed)?;
                let recovery_key = recovery_wrap_key(&secrets.recovery_secret, wallet_id)?;
                let wallet = self.wallet(wallet_id)?;
                let unlocked = wallet.unlock_with_recovery(&secrets.recovery_id, &recovery_key)?;
                let credential_key = credential_wrap_key(
                    &SecretBytes::new(secrets.new_credential_prf.decode()),
                    wallet_id,
                    &new_credential.credential_id,
                )?;
                wallet.add_credential(
                    &unlocked,
                    new_credential.credential_id.clone(),
                    &credential_key,
                )?;
                self.register_existing_credential(wallet_id.clone(), new_credential)
            }
            CeremonyKind::WalletExport
            | CeremonyKind::WalletDelete
            | CeremonyKind::BackendEnrollment
            | CeremonyKind::KeyDerive
            | CeremonyKind::PolicyUpdate => {
                let wallet_id = prepare.wallet_id.as_ref().ok_or_else(kind_mismatch)?;
                let assertion = assertion_only(&complete.proof)?;
                let bound = self.bound_credential(&assertion.credential_id, wallet_id)?;
                let verified = verify_webauthn_assertion(
                    assertion,
                    &bound.credential,
                    &challenges[0].canonical_bytes()?,
                    true,
                )?;
                let encrypted = self.decrypt_custody_input(
                    prepare,
                    contribution,
                    complete,
                    context.recipient.take(),
                    Some(&assertion.credential_id),
                )?;
                let input: GenericCustodyInput =
                    serde_json::from_slice(encrypted.expose_to_backend()).map_err(malformed)?;
                let credential_key = credential_wrap_key(
                    &SecretBytes::new(input.credential_prf.decode()),
                    wallet_id,
                    &assertion.credential_id,
                )?;
                let unlocked = self
                    .wallet(wallet_id)?
                    .unlock_with_credential(&assertion.credential_id, &credential_key)?;
                let generic = if prepare.ceremony_kind == CeremonyKind::PolicyUpdate {
                    if !matches!(input.effect, GenericCustodyEffect::PolicyUpdate) {
                        return Err(kind_mismatch());
                    }
                    let (_, database_effect) = self.engine.prepare_policy_update_effect(
                        policy_prepare.ok_or_else(kind_mismatch)?,
                        &unlocked,
                        VerifiedCeremonyActivation(()),
                    )?;
                    GenericCustodyOutcome {
                        sensitive_output: None,
                        database_effect,
                        rollback_derived_key: None,
                        public_key_refs: Vec::new(),
                    }
                } else {
                    if policy_prepare.is_some() {
                        return Err(kind_mismatch());
                    }
                    self.apply_generic_custody_effect(prepare, input.effect, &unlocked)?
                };
                sensitive_output = generic.sensitive_output;
                database_effect = generic.database_effect;
                rollback_derived_key = generic.rollback_derived_key;
                public_key_refs = generic.public_key_refs;
                self.advance_counter(&verified.credential_id, verified.sign_count);
                Ok(())
            }
            CeremonyKind::SealedApproval => Err(kind_mismatch()),
        };
        effect?;
        Ok(CustodyApplyOutcome {
            sensitive_output,
            database_effect,
            rollback_derived_key,
            rollback_provisioned_backend,
            public_key_refs,
            consume_legacy_migration,
        })
    }

    fn apply_generic_custody_effect(
        &self,
        prepare: &CustodyPrepareRequest,
        effect: GenericCustodyEffect,
        unlocked: &UnlockedWallet,
    ) -> Result<GenericCustodyOutcome, ProtocolError> {
        let wallet_id = prepare.wallet_id.as_ref().ok_or_else(kind_mismatch)?;
        match (prepare.ceremony_kind, effect) {
            (CeremonyKind::WalletExport, GenericCustodyEffect::WalletExport) => {
                let export = WalletExportBundle {
                    wallet: self.wallet(wallet_id)?.backup(),
                    credentials: self
                        .credentials
                        .lock()
                        .values()
                        .filter(|bound| &bound.wallet_id == wallet_id)
                        .map(|bound| bound.credential.clone())
                        .collect(),
                };
                Ok(GenericCustodyOutcome {
                    sensitive_output: Some(serde_jcs::to_vec(&export).map_err(malformed)?),
                    database_effect: CeremonyDatabaseEffect::None,
                    rollback_derived_key: None,
                    public_key_refs: Vec::new(),
                })
            }
            (CeremonyKind::WalletDelete, GenericCustodyEffect::WalletDelete) => {
                self.wallets.lock().remove(wallet_id);
                self.credentials
                    .lock()
                    .retain(|_, bound| &bound.wallet_id != wallet_id);
                Ok(GenericCustodyOutcome {
                    sensitive_output: None,
                    database_effect: CeremonyDatabaseEffect::None,
                    rollback_derived_key: None,
                    public_key_refs: Vec::new(),
                })
            }
            (CeremonyKind::BackendEnrollment, GenericCustodyEffect::BackendEnrollment) => {
                let key_ref = prepare.key_ref.as_ref().ok_or_else(kind_mismatch)?;
                if !self.engine.backend_registry().key_is_registered(key_ref)? {
                    return Err(protocol(
                        ProtocolErrorCode::KeyrefMismatch,
                        "backend enrollment key is not pinned by the selected backend",
                    ));
                }
                Ok(GenericCustodyOutcome {
                    sensitive_output: None,
                    database_effect: CeremonyDatabaseEffect::EnrollKey {
                        key_ref: key_ref.clone(),
                        petal_scope: None,
                    },
                    rollback_derived_key: None,
                    public_key_refs: vec![key_ref.clone()],
                })
            }
            (
                CeremonyKind::KeyDerive,
                GenericCustodyEffect::KeyDerive {
                    namespace_id,
                    grant,
                    authority_signature,
                },
            ) => {
                let root = prepare.key_ref.as_ref().ok_or_else(kind_mismatch)?;
                #[cfg(feature = "local")]
                {
                    if let Some(scope) = &prepare.petal_key_scope {
                        if namespace_id.is_some()
                            || grant.is_some()
                            || authority_signature.is_some()
                        {
                            return Err(protocol(
                                ProtocolErrorCode::BackendInvalidRequest,
                                "Petal key derivation parameters are owned by Signer",
                            ));
                        }
                        // Activate from this ceremony's own credential PRF.
                        //
                        // A Petal session is created by a KeyDerive followed by
                        // a SealedApproval that registers the derived key with
                        // the venue. Only the second activates the local
                        // backend, and they cannot be reordered because the
                        // approval registers the address this step mints. Every
                        // other activating ceremony arms the backend itself;
                        // KeyDerive was added later and never did, so on a
                        // Signer with no owner ceremony since boot this failed
                        // outright.
                        //
                        // Scoped deliberately to this branch. The enclosing
                        // block also serves WalletExport, WalletDelete,
                        // BackendEnrollment and PolicyUpdate; arming there would
                        // make all of them activation vectors.
                        self.engine.backend_registry().activate_key_blocking(
                            root,
                            unlocked.local_backend_activation_secret()?,
                        )?;
                        self.engine
                            .record_backend_activation(&scope.wallet_id, root)?;
                        // Still checked: activation can legitimately fail, and
                        // the distinct error keeps that case diagnosable.
                        self.engine
                            .require_activated_parent_key(&scope.wallet_id, root)?;
                        return self.apply_petal_key_derivation(root, scope);
                    }
                    let namespace_id = namespace_id.ok_or_else(kind_mismatch)?;
                    let grant = grant.ok_or_else(kind_mismatch)?;
                    let authority_signature = authority_signature.ok_or_else(kind_mismatch)?;
                    let description = self.engine.backend_registry().allocate_local_derived_key(
                        root,
                        &namespace_id,
                        bloom_signer_backend_local::DerivationGrant {
                            authority_kind: grant.authority_kind,
                            namespace_id: grant.namespace_id,
                            canonical_prefix: grant.canonical_prefix,
                            starting_index: grant.starting_index,
                            maximum_children: grant.maximum_children,
                        },
                        authority_signature,
                        &prepare.custody_operation_id,
                    )?;
                    let derived_key_ref = description.key_ref.clone();
                    Ok(GenericCustodyOutcome {
                        sensitive_output: Some(serde_jcs::to_vec(&description).map_err(malformed)?),
                        database_effect: CeremonyDatabaseEffect::EnrollKey {
                            key_ref: description.key_ref.clone(),
                            petal_scope: None,
                        },
                        rollback_derived_key: Some(derived_key_ref),
                        public_key_refs: vec![description.key_ref],
                    })
                }
                #[cfg(not(feature = "local"))]
                {
                    let _ = (root, namespace_id, grant, authority_signature);
                    Err(protocol(
                        ProtocolErrorCode::BackendUnsupported,
                        "no derivation backend is compiled",
                    ))
                }
            }
            (CeremonyKind::PolicyUpdate, GenericCustodyEffect::PolicyUpdate) => {
                Err(kind_mismatch())
            }
            _ => Err(kind_mismatch()),
        }
    }

    #[cfg(feature = "local")]
    fn apply_petal_key_derivation(
        &self,
        root: &bloom_signer_api::KeyRef,
        scope: &PetalKeyScope,
    ) -> Result<GenericCustodyOutcome, ProtocolError> {
        let namespace_id = Token::new(PETAL_SUBKEY_NAMESPACE).expect("static token");
        let grant = bloom_signer_backend_local::DerivationGrant {
            authority_kind: Token::new("ceremony").expect("static token"),
            namespace_id: namespace_id.clone(),
            canonical_prefix: PETAL_SUBKEY_PREFIX.to_owned(),
            starting_index: DecimalU64::new(0),
            maximum_children: DecimalU64::new(0x8000_0000),
        };
        let mut authority_message = DERIVATION_AUTHORITY_DOMAIN.to_vec();
        authority_message.extend_from_slice(&serde_jcs::to_vec(&grant).map_err(malformed)?);
        let authority_signature =
            Base64UrlBytes::from_bytes(&self.signing_key.sign(&authority_message).to_bytes());
        self.engine
            .backend_registry()
            .configure_local_derivation_namespace(
                root,
                grant.clone(),
                authority_signature.clone(),
            )?;
        let description = self.engine.backend_registry().allocate_local_derived_key(
            root,
            &namespace_id,
            grant,
            authority_signature,
            &scope.custody_operation_id,
        )?;
        let derived_key_ref = description.key_ref.clone();
        Ok(GenericCustodyOutcome {
            sensitive_output: None,
            database_effect: CeremonyDatabaseEffect::EnrollKey {
                key_ref: description.key_ref.clone(),
                petal_scope: Some(scope.clone()),
            },
            rollback_derived_key: Some(derived_key_ref),
            public_key_refs: vec![description.key_ref],
        })
    }

    fn rollback_derived_key(
        &self,
        key_ref: Option<&bloom_signer_api::KeyRef>,
    ) -> Result<(), ProtocolError> {
        let Some(key_ref) = key_ref else {
            return Ok(());
        };
        #[cfg(feature = "local")]
        {
            self.engine
                .backend_registry()
                .rollback_local_derived_key(key_ref)
        }
        #[cfg(not(feature = "local"))]
        {
            let _ = key_ref;
            Err(protocol(
                ProtocolErrorCode::ServiceUnavailable,
                "derived-key rollback backend is unavailable",
            ))
        }
    }

    fn rollback_provisioned_backend(&self, key_ref: Option<&bloom_signer_api::KeyRef>) {
        let Some(key_ref) = key_ref else {
            return;
        };
        #[cfg(feature = "local")]
        self.engine
            .backend_registry()
            .remove_local_wallet_backend(key_ref);
    }

    fn decrypt_custody_input(
        &self,
        prepare: &CustodyPrepareRequest,
        contribution: &CustodySignerContribution,
        complete: &CustodyCompleteRequest,
        recipient: Option<HpkeRecipient>,
        credential_id: Option<&Base64UrlBytes>,
    ) -> Result<SecretBytes, ProtocolError> {
        let envelope = complete.encrypted_input.as_ref().ok_or_else(|| {
            protocol(
                ProtocolErrorCode::BackendInvalidRequest,
                "custody workflow requires encrypted input",
            )
        })?;
        let aad = CustodyHpkeAad {
            ceremony_id: contribution.ceremony_id.clone(),
            ceremony_kind: contribution.ceremony_kind,
            custody_operation_id: contribution.custody_operation_id.clone(),
            signer_nonce: contribution.signer_nonce.clone(),
            signer_contribution_digest: contribution.digest()?,
            wallet_id: contribution.wallet_id.clone(),
            key_ref: contribution.key_ref.clone(),
            credential_id: credential_id.cloned(),
            expected_input_class: prepare.expected_input_class.clone(),
        }
        .canonical_bytes()?;
        recipient
            .ok_or_else(replay)?
            .open(envelope, CUSTODY_INPUT_INFO, &aad)
    }

    fn bound_credential(
        &self,
        credential_id: &Base64UrlBytes,
        wallet_id: &Token,
    ) -> Result<BoundCredential, ProtocolError> {
        self.credentials
            .lock()
            .get(credential_id.encoded())
            .filter(|bound| &bound.wallet_id == wallet_id)
            .cloned()
            .ok_or_else(|| {
                protocol(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "credential is not bound to the requested wallet",
                )
            })
    }

    fn advance_counter(&self, credential_id: &Base64UrlBytes, sign_count: u32) {
        if let Some(bound) = self.credentials.lock().get_mut(credential_id.encoded()) {
            let current = bound.credential.sign_count.get();
            let proposed = u64::from(sign_count);
            if proposed != 0 && (current == 0 || proposed > current) {
                bound.credential.sign_count = DecimalU64::new(proposed);
            }
        }
    }

    fn wallet(&self, wallet_id: &Token) -> Result<Arc<WalletCustody>, ProtocolError> {
        self.wallets.lock().get(wallet_id).cloned().ok_or_else(|| {
            protocol(
                ProtocolErrorCode::ApprovalNotFound,
                "wallet custody state is unavailable",
            )
        })
    }

    fn custody_snapshot(
        &self,
    ) -> (
        Vec<crate::custody::WalletCustodyBackup>,
        Vec<(Token, WebAuthnCredential)>,
    ) {
        let wallets = self
            .wallets
            .lock()
            .values()
            .map(|wallet| wallet.backup())
            .collect();
        let credentials = self
            .credentials
            .lock()
            .values()
            .map(|bound| (bound.wallet_id.clone(), bound.credential.clone()))
            .collect();
        (wallets, credentials)
    }

    fn restore_custody_snapshot(
        &self,
        snapshot: (
            Vec<crate::custody::WalletCustodyBackup>,
            Vec<(Token, WebAuthnCredential)>,
        ),
    ) -> Result<(), ProtocolError> {
        let wallets = snapshot
            .0
            .into_iter()
            .map(|backup| {
                Ok((
                    backup.wallet_id.clone(),
                    Arc::new(WalletCustody::restore(backup)?),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, ProtocolError>>()?;
        let credentials = snapshot
            .1
            .into_iter()
            .map(|(wallet_id, credential)| {
                (
                    credential.credential_id.encoded().to_owned(),
                    BoundCredential {
                        wallet_id,
                        credential,
                    },
                )
            })
            .collect();
        *self.wallets.lock() = wallets;
        *self.credentials.lock() = credentials;
        Ok(())
    }

    fn require_no_live_wallet_session(&self, wallet_id: &Token) -> Result<(), ProtocolError> {
        if self
            .pending
            .lock()
            .values()
            .any(|pending| match &pending.request {
                PendingRequest::Approval(request) => &request.terms.wallet_id == wallet_id,
                PendingRequest::Custody(request) => request.wallet_id.as_ref() == Some(wallet_id),
                PendingRequest::PolicyUpdate(request) => &request.update.wallet_id == wallet_id,
            })
        {
            return Err(protocol(
                ProtocolErrorCode::QuotaExceeded,
                "wallet already has a live ceremony",
            ));
        }
        Ok(())
    }

    fn options_for_approval(&self, wallet_id: &Token) -> CeremonyWebAuthnOptions {
        self.options_for_wallet(Some(wallet_id))
    }

    fn options_for_wallet(&self, wallet_id: Option<&Token>) -> CeremonyWebAuthnOptions {
        let allowed_credentials = wallet_id
            .map(|wallet_id| {
                self.credentials
                    .lock()
                    .values()
                    .filter(|bound| &bound.wallet_id == wallet_id)
                    .map(|bound| CredentialPrfInput {
                        credential_id: bound.credential.credential_id.clone(),
                        prf_salt: bound.credential.prf_salt.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        CeremonyWebAuthnOptions {
            allowed_credentials,
            registration_user_handle: None,
            registration_prf_salt: None,
        }
    }

    fn options_for_pending(&self, pending: &PendingCeremony) -> CeremonyWebAuthnOptions {
        pending
            .legacy_migration
            .as_ref()
            .map(|legacy| CeremonyWebAuthnOptions {
                allowed_credentials: vec![CredentialPrfInput {
                    credential_id: legacy.credential.credential_id.clone(),
                    prf_salt: legacy.credential.prf_salt.clone(),
                }],
                registration_user_handle: None,
                registration_prf_salt: None,
            })
            .or_else(|| {
                pending
                    .registration
                    .as_ref()
                    .map(|registration| CeremonyWebAuthnOptions {
                        allowed_credentials: Vec::new(),
                        registration_user_handle: Some(registration.user_handle.clone()),
                        registration_prf_salt: Some(registration.prf_salt.clone()),
                    })
            })
            .or_else(|| {
                pending.credential_creation.as_ref().map(|creation| {
                    let mut options = match &pending.request {
                        PendingRequest::Approval(request) => {
                            self.options_for_wallet(Some(&request.terms.wallet_id))
                        }
                        PendingRequest::Custody(request) => {
                            self.options_for_wallet(request.wallet_id.as_ref())
                        }
                        PendingRequest::PolicyUpdate(request) => {
                            self.options_for_wallet(Some(&request.update.wallet_id))
                        }
                    };
                    options.registration_user_handle = Some(creation.user_handle.clone());
                    options.registration_prf_salt = Some(creation.prf_salt.clone());
                    options
                })
            })
            .unwrap_or_else(|| match &pending.request {
                PendingRequest::Approval(request) => {
                    self.options_for_wallet(Some(&request.terms.wallet_id))
                }
                PendingRequest::Custody(request) => {
                    self.options_for_wallet(request.wallet_id.as_ref())
                }
                PendingRequest::PolicyUpdate(request) => {
                    self.options_for_wallet(Some(&request.update.wallet_id))
                }
            })
    }

    fn verification_credentials_for_pending(
        &self,
        pending: &PendingCeremony,
    ) -> Vec<WebAuthnCredential> {
        if let Some(legacy) = &pending.legacy_migration {
            return vec![legacy.credential.clone()];
        }
        let options = self.options_for_pending(pending);
        let wallet_id = match &pending.request {
            PendingRequest::Approval(request) => Some(&request.terms.wallet_id),
            PendingRequest::Custody(request) => request.wallet_id.as_ref(),
            PendingRequest::PolicyUpdate(request) => Some(&request.update.wallet_id),
        };
        let Some(wallet_id) = wallet_id else {
            return Vec::new();
        };
        options
            .allowed_credentials
            .into_iter()
            .filter_map(|allowed| self.credential(wallet_id, &allowed.credential_id).ok())
            .collect()
    }

    fn new_credential_creation(&self, wallet_id: Option<&Token>) -> CredentialCreation {
        let existing_user_handle = wallet_id.and_then(|wallet_id| {
            self.credentials
                .lock()
                .values()
                .find(|bound| &bound.wallet_id == wallet_id)
                .map(|bound| bound.credential.user_handle.clone())
        });
        CredentialCreation {
            user_handle: existing_user_handle
                .unwrap_or_else(|| Base64UrlBytes::from_bytes(&random_32())),
            prf_salt: Base64UrlBytes::from_bytes(&random_32()),
        }
    }

    fn sign_contribution(&self, unsigned: &[u8]) -> Base64UrlBytes {
        let message = [CONTRIBUTION_DOMAIN, unsigned].concat();
        Base64UrlBytes::from_bytes(&self.signing_key.sign(&message).to_bytes())
    }

    fn verify_contribution(&self, unsigned: &[u8], signature: &Base64UrlBytes) -> bool {
        use ed25519_dalek::{Signature, Verifier as _};
        let Ok(signature) = Signature::from_slice(&signature.decode()) else {
            return false;
        };
        self.signing_key
            .verifying_key()
            .verify(&[CONTRIBUTION_DOMAIN, unsigned].concat(), &signature)
            .is_ok()
    }

    fn sign_receipt(&self, unsigned: &[u8]) -> Base64UrlBytes {
        Base64UrlBytes::from_bytes(
            &self
                .signing_key
                .sign(&[RECEIPT_DOMAIN, unsigned].concat())
                .to_bytes(),
        )
    }
}

impl RegistrationSecrets {
    fn generate(wallet_id: Token) -> Result<Self, ProtocolError> {
        let mut root = vec![0_u8; 32];
        let mut policy_seed = vec![0_u8; 32];
        let mut wkek = vec![0_u8; 32];
        let mut user_handle = vec![0_u8; 32];
        let mut prf_salt = vec![0_u8; 32];
        let mut recovery_secret = vec![0_u8; 32];
        OsRng.fill_bytes(&mut root);
        OsRng.fill_bytes(&mut policy_seed);
        OsRng.fill_bytes(&mut wkek);
        OsRng.fill_bytes(&mut user_handle);
        OsRng.fill_bytes(&mut prf_salt);
        OsRng.fill_bytes(&mut recovery_secret);
        Ok(Self {
            wallet_id,
            user_handle: Base64UrlBytes::from_bytes(&user_handle),
            prf_salt: Base64UrlBytes::from_bytes(&prf_salt),
            root: SecretBytes::new(root),
            policy_seed: SecretBytes::new(policy_seed),
            wkek: SecretBytes::new(wkek),
            recovery_id: Token::new(format!("recovery-{}", &random_digest().as_str()[..24]))?,
            recovery_secret: Base64UrlBytes::from_bytes(&recovery_secret),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWalletImportInput {
    raw_private_key: Base64UrlBytes,
    credential_prf: Base64UrlBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPasskeyPrfInput {
    credential_prf: Base64UrlBytes,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RegistrationRecoveryOutput {
    recovery_id: Token,
    recovery_secret: Base64UrlBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialChangeInput {
    authority_prf: Base64UrlBytes,
    new_credential_prf: Base64UrlBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryInput {
    recovery_id: Token,
    recovery_secret: Base64UrlBytes,
    new_credential_prf: Base64UrlBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenericCustodyInput {
    credential_prf: Base64UrlBytes,
    effect: GenericCustodyEffect,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum GenericCustodyEffect {
    WalletExport,
    WalletDelete,
    BackendEnrollment,
    KeyDerive {
        #[serde(default)]
        namespace_id: Option<Token>,
        #[serde(default)]
        grant: Option<DerivationGrantInput>,
        #[serde(default)]
        authority_signature: Option<Base64UrlBytes>,
    },
    PolicyUpdate,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivationGrantInput {
    authority_kind: Token,
    namespace_id: Token,
    canonical_prefix: String,
    starting_index: DecimalU64,
    maximum_children: DecimalU64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WalletExportBundle {
    wallet: WalletCustodyBackup,
    credentials: Vec<WebAuthnCredential>,
}

#[derive(Serialize)]
struct CustodyReceiptPreimage<'a> {
    ceremony_id: &'a Digest32,
    ceremony_kind: CeremonyKind,
    operation_id: &'a OperationId,
    public_binding_digest: &'a Digest32,
    completed_at_ms: u64,
}

fn required_phases(kind: CeremonyKind, legacy_passkey_import: bool) -> Vec<CeremonyPhase> {
    if legacy_passkey_import {
        return vec![CeremonyPhase::Approve];
    }
    match kind {
        CeremonyKind::WalletRegistration
        | CeremonyKind::WalletImport
        | CeremonyKind::WalletRecovery => {
            vec![CeremonyPhase::RegisterCredential, CeremonyPhase::ConfirmPrf]
        }
        CeremonyKind::CredentialAdd | CeremonyKind::CredentialReplace => vec![
            CeremonyPhase::Approve,
            CeremonyPhase::RegisterCredential,
            CeremonyPhase::ConfirmPrf,
        ],
        _ => vec![CeremonyPhase::Approve],
    }
}

fn assertion_only(
    proof: &WebAuthnCeremonyProof,
) -> Result<&bloom_signer_api::WebAuthnAssertion, ProtocolError> {
    match proof {
        WebAuthnCeremonyProof::Assertion { assertion } => Ok(assertion),
        _ => Err(kind_mismatch()),
    }
}

fn credential_wrap_key(
    prf: &SecretBytes,
    wallet_id: &Token,
    credential_id: &Base64UrlBytes,
) -> Result<SecretBytes, ProtocolError> {
    #[derive(Serialize)]
    struct Salt<'a> {
        wallet_id: &'a Token,
        credential_id: &'a Base64UrlBytes,
    }
    let salt: [u8; 32] = Sha256::digest(
        serde_jcs::to_vec(&Salt {
            wallet_id,
            credential_id,
        })
        .map_err(malformed)?,
    )
    .into();
    let mut key = vec![0_u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), prf.expose_to_backend())
        .expand(WRAP_INFO, &mut key)
        .map_err(|_| protocol(ProtocolErrorCode::BackendInvalidRequest, "PRF HKDF failed"))?;
    Ok(SecretBytes::new(key))
}

fn recovery_wrap_key(
    recovery_secret: &Base64UrlBytes,
    wallet_id: &Token,
) -> Result<SecretBytes, ProtocolError> {
    let mut key = vec![0_u8; 32];
    Hkdf::<Sha256>::new(
        Some(wallet_id.as_str().as_bytes()),
        &recovery_secret.decode(),
    )
    .expand(b"bloom-recovery-wallet-wrap/v1", &mut key)
    .map_err(|_| {
        protocol(
            ProtocolErrorCode::BackendInvalidRequest,
            "recovery HKDF failed",
        )
    })?;
    Ok(SecretBytes::new(key))
}

fn approval_receipt_bytes(receipt: &SignerActivationReceipt) -> Result<Vec<u8>, ProtocolError> {
    #[derive(Serialize)]
    struct Unsigned<'a> {
        activation_operation_id: &'a OperationId,
        ceremony_id: &'a Digest32,
        approval_id: &'a Digest32,
        approval_digest: &'a Digest32,
        review_manifest_digest: &'a Digest32,
        key_ref: &'a bloom_signer_api::KeyRef,
        allowed_crypto_suites: &'a [CryptoSuite],
        activation_mode: ActivationMode,
        wallet_revocation_epoch: &'a DecimalU64,
        replaced_approval_id: &'a Option<Digest32>,
        activated_at_ms: &'a DecimalU64,
        expires_at_ms: &'a DecimalU64,
        signer_key_id: &'a Token,
    }
    serde_jcs::to_vec(&Unsigned {
        activation_operation_id: &receipt.activation_operation_id,
        ceremony_id: &receipt.ceremony_id,
        approval_id: &receipt.approval_id,
        approval_digest: &receipt.approval_digest,
        review_manifest_digest: &receipt.review_manifest_digest,
        key_ref: &receipt.key_ref,
        allowed_crypto_suites: &receipt.allowed_crypto_suites,
        activation_mode: receipt.activation_mode.clone(),
        wallet_revocation_epoch: &receipt.wallet_revocation_epoch,
        replaced_approval_id: &receipt.replaced_approval_id,
        activated_at_ms: &receipt.activated_at_ms,
        expires_at_ms: &receipt.expires_at_ms,
        signer_key_id: &receipt.signer_key_id,
    })
    .map_err(malformed)
}

fn canonical_digest(value: &impl Serialize) -> Result<Digest32, ProtocolError> {
    Ok(Digest32::from_bytes(
        Sha256::digest(serde_jcs::to_vec(value).map_err(malformed)?).into(),
    ))
}

fn random_digest() -> Digest32 {
    Digest32::from_bytes(random_32())
}

fn random_32() -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn pending_public_status(
    operation_id: &OperationId,
    contribution: &PendingContribution,
    state: CeremonyState,
) -> CeremonyPublicStatus {
    let (ceremony_id, ceremony_kind, expires_at_ms) = match contribution {
        PendingContribution::Approval(contribution) => (
            contribution.ceremony_id.clone(),
            CeremonyKind::SealedApproval,
            contribution.expires_at_ms.clone(),
        ),
        PendingContribution::Custody(contribution) => (
            contribution.ceremony_id.clone(),
            contribution.ceremony_kind,
            contribution.expires_at_ms.clone(),
        ),
    };
    CeremonyPublicStatus {
        ceremony_id,
        ceremony_kind,
        operation_id: operation_id.clone(),
        state,
        expires_at_ms,
        ceremony_url: None,
        receipt_digest: None,
    }
}

fn committed_conflict() -> ProtocolError {
    protocol(
        ProtocolErrorCode::OperationIdConflict,
        "committed ceremony cannot be cancelled",
    )
}

fn replay() -> ProtocolError {
    protocol(
        ProtocolErrorCode::CeremonyReplay,
        "ceremony is absent, expired, or already consumed",
    )
}

fn terminal_conflict() -> ProtocolError {
    protocol(
        ProtocolErrorCode::OperationIdConflict,
        "ceremony operation ID already reached a durable terminal state or receipt",
    )
}

fn operation_conflict() -> ProtocolError {
    protocol(
        ProtocolErrorCode::OperationIdConflict,
        "ceremony operation ID was reused with different stable input",
    )
}

fn kind_mismatch() -> ProtocolError {
    protocol(
        ProtocolErrorCode::CeremonyKindMismatch,
        "ceremony proof or durable effect kind does not match preparation",
    )
}

fn malformed(error: impl std::fmt::Display) -> ProtocolError {
    protocol(ProtocolErrorCode::MalformedFrame, error.to_string())
}

fn protocol(code: ProtocolErrorCode, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(code, message)
}
