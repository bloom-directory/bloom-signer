use bloom_signer_api::{
    ApprovalLifecycleState, ApprovalPublicStatus, ApprovalSelector, ApprovalSubject,
    ApprovalTombstone, Base64UrlBytes, CeremonyPublicStatus, CredentialPublic, CredentialState,
    CustodyResult, DecimalU64, Digest32, KeyRef, OperationId, OperationPublicStatus,
    OperationState, OwnerAttestationReceipt, PetalKeyScope, PolicyCommitReceipt,
    PolicyCompareAndSwapRequest, PolicyUpdateCeremonyPrepareRequest, PolicyUpdateRequest,
    PolicyValidationReceipt, ProtocolError, ProtocolErrorCode, RevocationState,
    SealedApprovalTerms, SelectorKind, SignRequest, SignedPolicySnapshot, SignerActivationReceipt,
    SigningResult, Token, WalletTombstone, WebAuthnCredential,
};
use bloom_trusted_time::{DurableClockCondition, PersistedClockState, evaluate_durable_clock};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use parking_lot::{Mutex, RwLock};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::clock::{ClockCondition, ClockDecision};
use crate::custody::UnlockedWallet;
use crate::custody::{WalletCustody, WalletCustodyBackup};
use crate::registry::BackendRegistry;

const POLICY_SIGNATURE_DOMAIN: &[u8] = b"bloom-policy-snapshot/v1";
const POLICY_VALIDATION_DOMAIN: &[u8] = b"bloom-policy-validation-receipt/v1";
const APPROVAL_TOMBSTONE_DOMAIN: &[u8] = b"bloom-approval-tombstone/v1";
const WALLET_TOMBSTONE_DOMAIN: &[u8] = b"bloom-wallet-tombstone/v1";
const REVOCATION_STATE_DOMAIN: &[u8] = b"bloom-revocation-state/v1";
const REVOCATION_OPERATION_DOMAIN: &[u8] = b"bloom-revocation-operation/v1";
const SIGNER_RETRY_BINDING_DOMAIN: &[u8] = b"bloom-signer-retry-binding/v1";
const AUDIT_DOMAIN: &[u8] = b"bloom-signer-audit-entry/v1";
const AUDIT_SIGNATURE_DOMAIN: &[u8] = b"bloom-signer-audit-signature/v1";
const AUDIT_ROTATION_DOMAIN: &[u8] = b"bloom-signer-audit-key-rotation/v1";
const MAX_APPROVAL_LIFETIME_MS: u64 = 90 * 24 * 60 * 60 * 1_000;

type StoredOperationTuple = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
);

pub(crate) type PersistedCeremonyCustody =
    (Vec<WalletCustodyBackup>, Vec<(Token, WebAuthnCredential)>);

#[allow(clippy::large_enum_variant)]
pub(crate) enum CeremonyDatabaseEffect {
    None,
    InitialPolicy {
        snapshot: SignedPolicySnapshot,
        policy_verifying_key: Base64UrlBytes,
        backend_enrollment: Option<BackendEnrollmentBackup>,
    },
    PolicyUpdatePending(Box<CeremonyPolicyUpdate>),
    EnrollKey {
        key_ref: KeyRef,
        petal_scope: Option<PetalKeyScope>,
    },
}

pub(crate) struct CeremonyPolicyUpdate {
    update: PolicyUpdateRequest,
    validation: PolicyValidationReceipt,
    receipt: PolicyCommitReceipt,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerAttestationStoredStatus<'a> {
    operation_id: &'a OperationId,
    ceremony_id: &'a Digest32,
    state: bloom_signer_api::CeremonyState,
    expires_at_ms: &'a DecimalU64,
    receipt_digest: Option<&'a Digest32>,
    public_binding_digest: &'a Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingPolicyAuthorization {
    update: PolicyUpdateRequest,
    validation: PolicyValidationReceipt,
    ceremony_receipt: CustodyResult,
    commit_receipt: PolicyCommitReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignAuthorization {
    NewOperation,
    SameOperationRetry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerOperationEffect {
    Committed,
    Released,
    Quarantined,
}

impl SignerOperationEffect {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "COMMITTED",
            Self::Released => "RELEASED",
            Self::Quarantined => "QUARANTINED",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum WalletDerivationStatus {
    #[serde(rename = "READY")]
    Ready,
    #[serde(rename = "DERIVATION_REGISTRY_MISSING")]
    DerivationRegistryMissing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCounterBackup {
    pub approval_id: Digest32,
    pub committed_operations: DecimalU64,
    pub committed_signatures: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalStateBackup {
    pub approval_id: Digest32,
    pub terms: SealedApprovalTerms,
    pub active: bool,
    pub committed_operations: DecimalU64,
    pub committed_signatures: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationStateBackup {
    pub operation_id: OperationId,
    pub operation_digest: Digest32,
    pub retry_binding_digest: Digest32,
    pub approval_id: Digest32,
    pub signature_count: DecimalU64,
    pub accepted_at_ms: DecimalU64,
    #[serde(default)]
    pub observed_utc_ms: Option<DecimalU64>,
    #[serde(default = "zero_decimal_u64")]
    pub monotonic_anchor_ns: DecimalU64,
    #[serde(default = "zero_boot_epoch")]
    pub clock_boot_epoch: bloom_signer_api::BootEpoch,
    pub state: BackupOperationState,
    pub normalized_result: Option<Base64UrlBytes>,
}

fn zero_decimal_u64() -> DecimalU64 {
    DecimalU64::new(0)
}

fn zero_boot_epoch() -> bloom_signer_api::BootEpoch {
    bloom_signer_api::BootEpoch::from_bytes([0; 16])
}

/// A boot epoch usable for comparing monotonic domains, or `None` when the
/// domain is unknown. The all-zero sentinel means "not recorded" and must not
/// compare equal to itself, or two unknown boots would look like one.
fn comparable_boot_epoch(epoch: &bloom_signer_api::BootEpoch) -> Option<[u8; 16]> {
    let bytes = epoch.to_bytes();
    (bytes != [0; 16]).then_some(bytes)
}

fn malformed_boot_epoch() -> ProtocolError {
    error(
        ProtocolErrorCode::ClockUntrusted,
        "persisted clock state has a malformed boot epoch",
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupOperationState {
    Reserved,
    Dispatched,
    Committed,
    Released,
    Quarantined,
}

impl BackupOperationState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "RESERVED",
            Self::Dispatched => "DISPATCHED",
            Self::Committed => "COMMITTED",
            Self::Released => "RELEASED",
            Self::Quarantined => "QUARANTINED",
        }
    }

    fn parse(value: &str) -> Result<Self, ProtocolError> {
        match value {
            "RESERVED" => Ok(Self::Reserved),
            "DISPATCHED" => Ok(Self::Dispatched),
            "COMMITTED" => Ok(Self::Committed),
            "RELEASED" => Ok(Self::Released),
            "QUARANTINED" => Ok(Self::Quarantined),
            _ => Err(error(
                ProtocolErrorCode::MalformedFrame,
                "backup operation has unknown state",
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptStateBackup {
    pub attempt_id: Digest32,
    pub attempt_digest: Digest32,
    pub operation_id: OperationId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationOperationBackup {
    pub operation_id: OperationId,
    pub request_digest: Digest32,
    pub canonical_result: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationNamespaceBackup {
    pub namespace_id: Token,
    pub canonical_prefix: String,
    pub next_index: DecimalU64,
    pub maximum_children: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationRegistryBackup {
    pub allocated_keys: Vec<KeyRef>,
    pub tombstoned_paths: Vec<String>,
    pub namespaces: Vec<DerivationNamespaceBackup>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendEnrollmentBackup {
    pub backend: Token,
    pub backend_instance: Token,
    pub encrypted_record: Base64UrlBytes,
    pub pinned_keys: Vec<KeyRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBackup {
    pub snapshot: SignedPolicySnapshot,
    pub policy_verifying_key: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalKeyScopeBackup {
    pub key_ref: KeyRef,
    pub scope: PetalKeyScope,
    pub created_at_ms: DecimalU64,
    pub expires_at_ms: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntryBackup {
    pub sequence: DecimalU64,
    pub event_type: String,
    pub payload_jcs: String,
    pub previous_hash: Digest32,
    pub entry_hash: Digest32,
    pub signing_key_id: Token,
    pub signature: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRotationBackup {
    pub old_key_id: Token,
    pub new_key_id: Token,
    pub final_old_sequence: DecimalU64,
    pub final_old_head: Digest32,
    pub first_new_sequence: DecimalU64,
    pub first_new_head: Digest32,
    pub old_key_signature: Base64UrlBytes,
    pub new_key_signature: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPublicKeyBackup {
    pub key_id: Token,
    pub verifying_key: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerBackupSet {
    pub wallet_id: Token,
    pub wallet_revocation_epoch: DecimalU64,
    pub custody: Option<WalletCustodyBackup>,
    pub derivation_registry: Option<DerivationRegistryBackup>,
    pub backend_enrollments: Vec<BackendEnrollmentBackup>,
    pub policy: Option<PolicyBackup>,
    #[serde(default)]
    pub petal_key_scopes: Vec<PetalKeyScopeBackup>,
    pub approvals: Vec<ApprovalStateBackup>,
    pub approval_tombstones: Vec<ApprovalTombstone>,
    pub wallet_tombstone: Option<WalletTombstone>,
    pub operations: Vec<OperationStateBackup>,
    pub attempts: Vec<AttemptStateBackup>,
    pub revocation_operations: Vec<RevocationOperationBackup>,
    pub approval_counters: Vec<ApprovalCounterBackup>,
    /// Complete signed Signer audit chain through the `custody.export` event
    /// that produced this backup.
    pub audit_entries: Vec<AuditEntryBackup>,
    /// Cross-signatures binding every audit-key transition to the exact final
    /// old-key and first new-key heads. This is mandatory backup material.
    pub audit_rotations: Vec<AuditRotationBackup>,
    /// Complete verification-only keyring needed to authenticate the backed-up
    /// multi-key audit chain. Restore still pins these against local config.
    pub audit_verifying_keys: Vec<AuditPublicKeyBackup>,
}

#[cfg(feature = "local")]
impl SignerBackupSet {
    pub fn restore_local_backend(
        &self,
        backend_instance: &Token,
    ) -> Result<bloom_signer_backend_local::LocalSignerBackend, ProtocolError> {
        let enrollment = self
            .backend_enrollments
            .iter()
            .find(|record| {
                record.backend.as_str() == "local" && &record.backend_instance == backend_instance
            })
            .ok_or_else(|| {
                error(
                    ProtocolErrorCode::ServiceUnavailable,
                    "local backend enrollment is absent from backup set",
                )
            })?;
        let backup =
            serde_json::from_slice(&enrollment.encrypted_record.decode()).map_err(malformed)?;
        let backend = bloom_signer_backend_local::LocalSignerBackend::restore(
            backend_instance.clone(),
            backup,
        )
        .map_err(|cause| {
            error(
                ProtocolErrorCode::ServiceUnavailable,
                format!("local backend restore failed: {cause:?}"),
            )
        })?;
        if enrollment
            .pinned_keys
            .iter()
            .any(|key| !backend.key_is_registered(key))
        {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "restored local derivation registry differs from pinned backup keys",
            ));
        }
        Ok(backend)
    }
}

pub struct SignerEngine {
    connection: Mutex<Connection>,
    audit_degraded: AtomicBool,
    audit_degradation: Mutex<Option<AuditDegradation>>,
    audit_tail: Mutex<AuditTailState>,
    broker_key_id: Token,
    broker_public_key: VerifyingKey,
    ceremony_public_key: VerifyingKey,
    revocation_key_id: Token,
    revocation_signing_key: Arc<SigningKey>,
    audit_keys: RwLock<AuditKeyState>,
    backend_registry: Arc<BackendRegistry>,
}

/// Safe, first-write-wins diagnostics for the failure that disabled mutations.
///
/// Values here are deliberately limited to operational identifiers. Request
/// payloads, signatures, and arbitrary error text do not belong in this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditDegradation {
    pub cause_code: &'static str,
    pub peer_service_id: Option<String>,
    pub peer_key_id: Option<String>,
    pub attempted_sequence: Option<u64>,
    pub attempted_head_digest: Option<String>,
    pub retained_sequence: Option<u64>,
    pub retained_head_digest: Option<String>,
}

impl AuditDegradation {
    pub const fn new(cause_code: &'static str) -> Self {
        Self {
            cause_code,
            peer_service_id: None,
            peer_key_id: None,
            attempted_sequence: None,
            attempted_head_digest: None,
            retained_sequence: None,
            retained_head_digest: None,
        }
    }
}

#[derive(Clone)]
struct VerifiedAuditTail {
    sequence: u64,
    head_hash: Digest32,
    data_version: i64,
    total_changes: u64,
}

#[derive(Default)]
struct AuditTailState {
    verified: Option<VerifiedAuditTail>,
    pending: Option<VerifiedAuditTail>,
}

struct AuditKeyState {
    current_key_id: Token,
    current_signing_key: Arc<SigningKey>,
    trusted_keys: BTreeMap<Token, VerifyingKey>,
}

/// Dedicated Signer audit key material. Historical keys are verification-only;
/// callers must never place a wallet, ceremony, or revocation key here.
pub struct SignerAuditKeys {
    pub current_key_id: Token,
    pub current_signing_key: SigningKey,
    pub historical_verifying_keys: BTreeMap<Token, VerifyingKey>,
}

impl SignerEngine {
    pub(crate) fn backend_registry(&self) -> &Arc<BackendRegistry> {
        &self.backend_registry
    }

    pub(crate) const fn broker_public_key(&self) -> &VerifyingKey {
        &self.broker_public_key
    }

    pub(crate) const fn ceremony_public_key(&self) -> &VerifyingKey {
        &self.ceremony_public_key
    }

    /// Return the startup-verified, incrementally maintained audit head.
    /// An empty journal is `(0, 00..00)`; DB head sequence N maps to count N+1.
    pub fn verified_audit_head(&self) -> Result<(u64, Digest32), ProtocolError> {
        let connection = self.connection.lock();
        let audit_keys = self.audit_keys.read();
        let result = self.cached_audit_head(&connection, &audit_keys);
        if result.is_err() {
            self.latch_audit_degraded();
        }
        result
    }

    /// Permanently fail closed for mutations after an independently detected
    /// peer/OS checkpoint violation. Read and status methods remain available.
    pub fn latch_audit_degraded(&self) {
        self.latch_audit_degraded_with(AuditDegradation::new("audit_verification_failed"));
    }

    /// Latch the first safe degradation cause and emit it exactly once.
    pub fn latch_audit_degraded_with(&self, cause: AuditDegradation) {
        self.audit_degraded.store(true, Ordering::SeqCst);
        let mut retained = self.audit_degradation.lock();
        if retained.is_some() {
            return;
        }
        tracing::error!(
            event = "signer.mutations_disabled",
            cause_code = cause.cause_code,
            peer_service_id = cause.peer_service_id.as_deref(),
            peer_key_id = cause.peer_key_id.as_deref(),
            attempted_sequence = cause.attempted_sequence,
            attempted_head_digest = cause.attempted_head_digest.as_deref(),
            retained_sequence = cause.retained_sequence,
            retained_head_digest = cause.retained_head_digest.as_deref(),
            "Signer mutations disabled"
        );
        *retained = Some(cause);
    }

    pub fn audit_is_degraded(&self) -> bool {
        self.audit_degraded.load(Ordering::SeqCst)
    }

    pub fn audit_degradation(&self) -> Option<AuditDegradation> {
        self.audit_degradation.lock().clone()
    }

    /// Atomically cross-sign the exact final old-key and first new-key heads,
    /// then select the replacement key for subsequent journal entries.
    pub fn rotate_audit_key(
        &self,
        new_key_id: Token,
        new_signing_key: SigningKey,
    ) -> Result<(), ProtocolError> {
        if self.audit_degraded.load(Ordering::SeqCst) {
            return Err(audit_degraded_error());
        }
        let mut connection = self.connection.lock();
        let mut keys = self.audit_keys.write();
        if new_key_id == keys.current_key_id
            || new_signing_key.verifying_key() == keys.current_signing_key.verifying_key()
        {
            return Err(malformed(
                "replacement Signer audit key ID and material must differ",
            ));
        }
        let transaction = connection.transaction().map_err(storage)?;
        verify_audit_chain(&transaction, &keys.current_key_id, &keys.trusted_keys)?;
        if transaction
            .query_row("SELECT 1 FROM audit_chain LIMIT 1", [], |_| Ok(()))
            .optional()
            .map_err(storage)?
            .is_none()
        {
            append_audit_entry(
                &transaction,
                "audit.key_rotation_anchor",
                &serde_json::json!({"key_id": keys.current_key_id}),
                &keys.current_key_id,
                keys.current_signing_key.as_ref(),
                &keys.current_key_id,
                &keys.trusted_keys,
            )
            .inspect_err(|_cause| {
                self.latch_audit_degraded();
            })?;
        }
        let (final_old_sequence, final_old_head) = transaction
            .query_row(
                "SELECT sequence, entry_hash FROM audit_chain ORDER BY sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(storage)?;
        let final_old_sequence = u64::try_from(final_old_sequence).map_err(malformed)?;
        let final_old_head = Digest32::new(final_old_head).map_err(malformed)?;
        let first_new_sequence = final_old_sequence
            .checked_add(1)
            .ok_or_else(|| malformed("Signer audit rotation sequence overflow"))?;
        let old_key_id = keys.current_key_id.clone();
        let old_signing_key = keys.current_signing_key.clone();
        let mut trusted = keys.trusted_keys.clone();
        insert_trusted_audit_key(
            &mut trusted,
            new_key_id.clone(),
            new_signing_key.verifying_key(),
        )?;
        append_audit_entry(
            &transaction,
            "audit.key_rotated",
            &serde_json::json!({
                "old_key_id": old_key_id,
                "new_key_id": new_key_id,
                "final_old_sequence": final_old_sequence.to_string(),
                "final_old_head": final_old_head,
            }),
            &new_key_id,
            &new_signing_key,
            &old_key_id,
            &keys.trusted_keys,
        )
        .inspect_err(|_cause| {
            self.latch_audit_degraded();
        })?;
        let first_new_head = transaction
            .query_row(
                "SELECT entry_hash FROM audit_chain WHERE sequence = ?1",
                [i64::try_from(first_new_sequence).map_err(malformed)?],
                |row| row.get::<_, String>(0),
            )
            .map_err(storage)?;
        let mut rotation = AuditRotationBackup {
            old_key_id: old_key_id.clone(),
            new_key_id: new_key_id.clone(),
            final_old_sequence: DecimalU64::new(final_old_sequence),
            final_old_head,
            first_new_sequence: DecimalU64::new(first_new_sequence),
            first_new_head: Digest32::new(first_new_head).map_err(malformed)?,
            old_key_signature: Base64UrlBytes::from_bytes(&[]),
            new_key_signature: Base64UrlBytes::from_bytes(&[]),
        };
        let message = audit_rotation_message(&rotation)?;
        rotation.old_key_signature =
            Base64UrlBytes::from_bytes(&old_signing_key.sign(&message).to_bytes());
        rotation.new_key_signature =
            Base64UrlBytes::from_bytes(&new_signing_key.sign(&message).to_bytes());
        transaction
            .execute(
                "INSERT INTO audit_key_rotations(
                    first_new_sequence, old_key_id, new_key_id, final_old_sequence,
                    final_old_head, first_new_head, old_key_signature, new_key_signature
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    i64::try_from(first_new_sequence).map_err(malformed)?,
                    old_key_id.as_str(),
                    new_key_id.as_str(),
                    i64::try_from(final_old_sequence).map_err(malformed)?,
                    rotation.final_old_head.as_str(),
                    rotation.first_new_head.as_str(),
                    rotation.old_key_signature.encoded(),
                    rotation.new_key_signature.encoded(),
                ],
            )
            .map_err(|cause| {
                self.latch_audit_degraded();
                storage(cause)
            })?;
        verify_audit_chain(&transaction, &new_key_id, &trusted).inspect_err(|_cause| {
            self.latch_audit_degraded();
        })?;
        transaction.commit().map_err(|cause| {
            self.latch_audit_degraded();
            storage(cause)
        })?;
        keys.current_key_id = new_key_id;
        keys.current_signing_key = Arc::new(new_signing_key);
        keys.trusted_keys = trusted;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open(
        path: impl AsRef<Path>,
        broker_key_id: Token,
        broker_public_key: VerifyingKey,
        ceremony_public_key: VerifyingKey,
        revocation_key_id: Token,
        revocation_signing_key: SigningKey,
        audit_keys: SignerAuditKeys,
        backend_registry: Arc<BackendRegistry>,
    ) -> Result<Self, ProtocolError> {
        Self::from_connection(
            Connection::open(path).map_err(storage)?,
            broker_key_id,
            broker_public_key,
            ceremony_public_key,
            revocation_key_id,
            revocation_signing_key,
            audit_keys,
            backend_registry,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_in_memory(
        broker_key_id: Token,
        broker_public_key: VerifyingKey,
        ceremony_public_key: VerifyingKey,
        revocation_key_id: Token,
        revocation_signing_key: SigningKey,
        audit_keys: SignerAuditKeys,
        backend_registry: Arc<BackendRegistry>,
    ) -> Result<Self, ProtocolError> {
        Self::from_connection(
            Connection::open_in_memory().map_err(storage)?,
            broker_key_id,
            broker_public_key,
            ceremony_public_key,
            revocation_key_id,
            revocation_signing_key,
            audit_keys,
            backend_registry,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_connection(
        connection: Connection,
        broker_key_id: Token,
        broker_public_key: VerifyingKey,
        ceremony_public_key: VerifyingKey,
        revocation_key_id: Token,
        revocation_signing_key: SigningKey,
        mut audit_keys: SignerAuditKeys,
        backend_registry: Arc<BackendRegistry>,
    ) -> Result<Self, ProtocolError> {
        if audit_keys.current_key_id == revocation_key_id
            || audit_keys.current_signing_key.verifying_key()
                == revocation_signing_key.verifying_key()
            || audit_keys.current_signing_key.verifying_key() == ceremony_public_key
            || audit_keys.current_signing_key.verifying_key() == broker_public_key
        {
            return Err(error(
                ProtocolErrorCode::MalformedFrame,
                "Signer audit key must be distinct from revocation, ceremony, and Broker keys",
            ));
        }
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(storage)?;
        connection
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    wallet_id TEXT NOT NULL,
                    terms_jcs TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    committed_operations TEXT NOT NULL,
                    committed_signatures TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS clock_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    last_effective_ms TEXT NOT NULL,
                    condition TEXT NOT NULL,
                    observed_utc_ms TEXT,
                    monotonic_anchor_ns TEXT NOT NULL,
                    boot_epoch TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS enrolled_keys (
                    key_fingerprint TEXT PRIMARY KEY,
                    key_ref_jcs TEXT NOT NULL,
                    available INTEGER NOT NULL,
                    authority_class TEXT NOT NULL DEFAULT 'unscoped',
                    wallet_id TEXT
                );
                CREATE TABLE IF NOT EXISTS petal_key_scopes (
                    key_fingerprint TEXT PRIMARY KEY,
                    wallet_id TEXT NOT NULL,
                    custody_operation_id TEXT NOT NULL UNIQUE,
                    scope_digest TEXT NOT NULL,
                    scope_jcs TEXT NOT NULL,
                    created_at_ms TEXT NOT NULL,
                    expires_at_ms TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ceremony_backend_enrollments (
                    backend_instance TEXT PRIMARY KEY,
                    enrollment_jcs TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS attempts (
                    attempt_id TEXT PRIMARY KEY,
                    attempt_digest TEXT NOT NULL,
                    operation_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    operation_digest TEXT NOT NULL,
                    retry_binding_digest TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    signature_count TEXT NOT NULL,
                    accepted_at_ms TEXT NOT NULL,
                    state TEXT NOT NULL,
                    normalized_result TEXT
                );
                CREATE TABLE IF NOT EXISTS operation_clock_anchors (
                    operation_id TEXT PRIMARY KEY,
                    observed_utc_ms TEXT,
                    monotonic_anchor_ns TEXT NOT NULL,
                    boot_epoch TEXT NOT NULL,
                    FOREIGN KEY (operation_id) REFERENCES operations(operation_id)
                );
                CREATE TABLE IF NOT EXISTS audit_chain (
                    sequence INTEGER PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    payload_jcs TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    signing_key_id TEXT NOT NULL,
                    signature TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_key_rotations (
                    first_new_sequence INTEGER PRIMARY KEY,
                    old_key_id TEXT NOT NULL,
                    new_key_id TEXT NOT NULL,
                    final_old_sequence INTEGER NOT NULL,
                    final_old_head TEXT NOT NULL,
                    first_new_head TEXT NOT NULL,
                    old_key_signature TEXT NOT NULL,
                    new_key_signature TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS wallet_state (
                    wallet_id TEXT PRIMARY KEY,
                    revocation_epoch TEXT NOT NULL,
                    derivation_status TEXT NOT NULL,
                    derivation_registry_jcs TEXT,
                    backup_set_jcs TEXT
                );
                CREATE TABLE IF NOT EXISTS approval_tombstones (
                    approval_id TEXT PRIMARY KEY,
                    wallet_id TEXT NOT NULL,
                    tombstone_jcs TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS wallet_tombstones (
                    wallet_id TEXT PRIMARY KEY,
                    tombstone_jcs TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS revocation_operations (
                    operation_id TEXT PRIMARY KEY,
                    wallet_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    result_jcs TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS policies (
                    wallet_id TEXT PRIMARY KEY,
                    version TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    canonical_policy TEXT NOT NULL,
                    snapshot_jcs TEXT NOT NULL,
                    policy_signing_key_id TEXT NOT NULL,
                    policy_verifying_key TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS policy_authorizations (
                    operation_id TEXT PRIMARY KEY,
                    request_jcs TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS policy_commit_receipts (
                    operation_id TEXT PRIMARY KEY,
                    request_jcs TEXT NOT NULL,
                    receipt_jcs TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ceremony_receipts (
                    operation_id TEXT PRIMARY KEY,
                    receipt_kind TEXT NOT NULL,
                    receipt_jcs TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ceremony_statuses (
                    operation_id TEXT PRIMARY KEY,
                    status_jcs TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ceremony_wallets (
                    wallet_id TEXT PRIMARY KEY,
                    custody_jcs TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS webauthn_credentials (
                    credential_id TEXT PRIMARY KEY,
                    wallet_id TEXT NOT NULL,
                    credential_jcs TEXT NOT NULL,
                    created_at_ms TEXT NOT NULL
                );
                ",
            )
            .map_err(storage)?;
        let has_credential_created_at = {
            let mut statement = connection
                .prepare("PRAGMA table_info(webauthn_credentials)")
                .map_err(storage)?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage)?;
            columns.iter().any(|column| column == "created_at_ms")
        };
        if !has_credential_created_at {
            connection
                .execute(
                    "ALTER TABLE webauthn_credentials
                     ADD COLUMN created_at_ms TEXT NOT NULL DEFAULT '0'",
                    [],
                )
                .map_err(storage)?;
        }
        ensure_column(&connection, "clock_state", "observed_utc_ms", "TEXT")?;
        ensure_column(
            &connection,
            "clock_state",
            "monotonic_anchor_ns",
            "TEXT NOT NULL DEFAULT '0'",
        )?;
        ensure_column(
            &connection,
            "enrolled_keys",
            "authority_class",
            "TEXT NOT NULL DEFAULT 'unscoped'",
        )?;
        ensure_column(&connection, "enrolled_keys", "wallet_id", "TEXT")?;
        backfill_unambiguous_wallet_root_bindings(&connection)?;
        ensure_column(
            &connection,
            "clock_state",
            "boot_epoch",
            "TEXT NOT NULL DEFAULT '00000000000000000000000000000000'",
        )?;
        connection
            .execute(
                "INSERT INTO operation_clock_anchors(
                    operation_id, observed_utc_ms, monotonic_anchor_ns, boot_epoch
                 )
                 SELECT operation_id, NULL, '0', '00000000000000000000000000000000'
                 FROM operations
                 WHERE operation_id NOT IN (
                    SELECT operation_id FROM operation_clock_anchors
                 )",
                [],
            )
            .map_err(storage)?;
        insert_trusted_audit_key(
            &mut audit_keys.historical_verifying_keys,
            audit_keys.current_key_id.clone(),
            audit_keys.current_signing_key.verifying_key(),
        )?;
        let audit_degraded = verify_audit_chain(
            &connection,
            &audit_keys.current_key_id,
            &audit_keys.historical_verifying_keys,
        )
        .is_err();
        let verified_tail = if audit_degraded {
            None
        } else {
            Some(read_verified_audit_tail(&connection)?)
        };
        let engine = Self {
            connection: Mutex::new(connection),
            audit_degraded: AtomicBool::new(false),
            audit_degradation: Mutex::new(None),
            audit_tail: Mutex::new(AuditTailState {
                verified: verified_tail,
                pending: None,
            }),
            broker_key_id,
            broker_public_key,
            ceremony_public_key,
            revocation_key_id,
            revocation_signing_key: Arc::new(revocation_signing_key),
            audit_keys: RwLock::new(AuditKeyState {
                current_key_id: audit_keys.current_key_id,
                current_signing_key: Arc::new(audit_keys.current_signing_key),
                trusted_keys: audit_keys.historical_verifying_keys,
            }),
            backend_registry,
        };
        if audit_degraded {
            engine.latch_audit_degraded_with(AuditDegradation::new("journal_verification_failed"));
        }
        Ok(engine)
    }

    fn mutation_transaction<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, ProtocolError> {
        if self.audit_degraded.load(Ordering::SeqCst) {
            return Err(audit_degraded_error());
        }
        let audit_keys = self.audit_keys.read();
        if self.cached_audit_head(connection, &audit_keys).is_err() {
            self.latch_audit_degraded_with(AuditDegradation::new("journal_verification_failed"));
            return Err(audit_degraded_error());
        }
        connection.transaction().map_err(storage)
    }

    fn append_audit(
        &self,
        transaction: &Transaction<'_>,
        event_type: &str,
        payload: &impl Serialize,
    ) -> Result<(), ProtocolError> {
        let audit_keys = self.audit_keys.read();
        if let Err(cause) = append_audit_entry(
            transaction,
            event_type,
            payload,
            &audit_keys.current_key_id,
            audit_keys.current_signing_key.as_ref(),
            &audit_keys.current_key_id,
            &audit_keys.trusted_keys,
        ) {
            self.latch_audit_degraded_with(AuditDegradation::new("audit_append_failed"));
            return Err(error(
                ProtocolErrorCode::ServiceUnavailable,
                format!("Signer audit append failed; mutations are latched closed: {cause}"),
            ));
        }
        let mut pending = read_verified_audit_tail(transaction)?;
        pending.data_version = self
            .audit_tail
            .lock()
            .verified
            .as_ref()
            .map_or(pending.data_version, |tail| tail.data_version);
        self.audit_tail.lock().pending = Some(pending);
        Ok(())
    }

    fn cached_audit_head(
        &self,
        connection: &Connection,
        audit_keys: &AuditKeyState,
    ) -> Result<(u64, Digest32), ProtocolError> {
        let observed = read_verified_audit_tail(connection)?;
        let mut state = self.audit_tail.lock();
        if let Some(verified) = state.verified.as_ref().filter(|tail| {
            tail.data_version == observed.data_version
                && tail.total_changes == observed.total_changes
                && tail.sequence == observed.sequence
                && tail.head_hash == observed.head_hash
        }) {
            return Ok((verified.sequence, verified.head_hash.clone()));
        }
        if let Some(pending) = state.pending.as_ref().filter(|tail| {
            tail.data_version == observed.data_version
                && tail.total_changes == observed.total_changes
                && tail.sequence == observed.sequence
                && tail.head_hash == observed.head_hash
                && state
                    .verified
                    .as_ref()
                    .is_some_and(|verified| verified.data_version == observed.data_version)
        }) {
            let promoted = pending.clone();
            let head = (promoted.sequence, promoted.head_hash.clone());
            state.verified = Some(promoted);
            state.pending = None;
            return Ok(head);
        }
        verify_audit_chain(
            connection,
            &audit_keys.current_key_id,
            &audit_keys.trusted_keys,
        )?;
        let verified = read_verified_audit_tail(connection)?;
        let head = (verified.sequence, verified.head_hash.clone());
        state.verified = Some(verified);
        state.pending = None;
        Ok(head)
    }

    pub(crate) fn observe_time(
        &self,
        reading: bloom_trusted_time::PlatformTimeReading,
        boot_epoch: bloom_signer_api::BootEpoch,
        max_forward_step_ms: u64,
        rate_limited_mutation: bool,
    ) -> Result<ClockDecision, ProtocolError> {
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        let decision = |effective_now_ms, condition| ClockDecision {
            effective_now_ms,
            condition,
            observed_utc_ms: reading.utc_ms,
            monotonic_anchor_ns: reading.monotonic_anchor_ns,
            boot_epoch: boot_epoch.clone(),
        };
        let stored: Option<(String, String, String, String)> = transaction
            .query_row(
                "SELECT last_effective_ms, condition, monotonic_anchor_ns, boot_epoch
                 FROM clock_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(storage)?;
        let initializing = stored.is_none();
        let previous = stored
            .as_ref()
            .map(|(value, _, anchor, persisted_epoch)| {
                Ok::<_, ProtocolError>(PersistedClockState {
                    last_effective_ms: value.parse().map_err(malformed)?,
                    monotonic_anchor_ns: anchor.parse().map_err(malformed)?,
                    // The absolute anchor is only comparable within the boot it
                    // was sampled in. Rows written before this was read back,
                    // and the zero sentinel, are unknown rather than matching.
                    boot_epoch: comparable_boot_epoch(
                        &bloom_signer_api::BootEpoch::new(persisted_epoch.clone())
                            .map_err(|_| malformed_boot_epoch())?,
                    ),
                })
            })
            .transpose()?;
        let shared = evaluate_durable_clock(
            previous,
            &reading,
            comparable_boot_epoch(&boot_epoch),
            max_forward_step_ms,
        )
        .map_err(|cause| error(ProtocolErrorCode::ClockUntrusted, cause.to_string()))?;
        let condition = signer_clock_condition(shared.condition);
        let effective_now_ms = shared.effective_now_ms;

        if shared.condition == DurableClockCondition::Untrusted {
            write_clock_state(
                &transaction,
                effective_now_ms,
                condition,
                &reading,
                &boot_epoch,
            )?;
            self.append_audit(
                &transaction,
                "clock.untrusted",
                &serde_json::json!({
                    "effective_now_ms": effective_now_ms.to_string(),
                    "monotonic_anchor_ns": reading.monotonic_anchor_ns.to_string(),
                    "boot_epoch": boot_epoch
                }),
            )?;
            transaction.commit().map_err(storage)?;
            log_clock_transition(condition, effective_now_ms, !rate_limited_mutation);
            if rate_limited_mutation {
                return Err(error(
                    ProtocolErrorCode::ClockUntrusted,
                    "trusted platform time source is unavailable",
                ));
            }
            return Ok(decision(effective_now_ms, condition));
        }

        let utc_ms = reading.utc_ms.ok_or_else(|| {
            error(
                ProtocolErrorCode::ClockUntrusted,
                "durable clock returned a trusted decision without UTC",
            )
        })?;
        match shared.condition {
            DurableClockCondition::Healthy => {
                write_clock_state(
                    &transaction,
                    effective_now_ms,
                    condition,
                    &reading,
                    &boot_epoch,
                )?;
                let (event_type, payload) = if initializing {
                    (
                        "clock.initialized",
                        serde_json::json!({
                            "effective_now_ms": effective_now_ms.to_string(),
                            "monotonic_anchor_ns": reading.monotonic_anchor_ns.to_string(),
                            "boot_epoch": boot_epoch
                        }),
                    )
                } else {
                    (
                        "clock.observed",
                        serde_json::json!({
                            "observed_utc_ms": utc_ms.to_string(),
                            "effective_now_ms": effective_now_ms.to_string(),
                            "monotonic_anchor_ns": reading.monotonic_anchor_ns.to_string(),
                            "boot_epoch": boot_epoch
                        }),
                    )
                };
                self.append_audit(&transaction, event_type, &payload)?;
                transaction.commit().map_err(storage)?;
                log_clock_transition(condition, effective_now_ms, true);
                Ok(decision(effective_now_ms, condition))
            }
            DurableClockCondition::RollbackFrozen => {
                write_clock_state(
                    &transaction,
                    effective_now_ms,
                    condition,
                    &reading,
                    &boot_epoch,
                )?;
                self.append_audit(
                    &transaction,
                    "clock.rollback",
                    &serde_json::json!({
                        "observed_utc_ms": utc_ms.to_string(),
                        "effective_now_ms": effective_now_ms.to_string(),
                        "monotonic_anchor_ns": reading.monotonic_anchor_ns.to_string(),
                        "boot_epoch": boot_epoch
                    }),
                )?;
                transaction.commit().map_err(storage)?;
                log_clock_transition(condition, effective_now_ms, !rate_limited_mutation);
                if rate_limited_mutation {
                    return Err(error(
                        ProtocolErrorCode::ClockRollback,
                        "UTC rollback detected; effective time is frozen",
                    ));
                }
                Ok(decision(effective_now_ms, condition))
            }
            DurableClockCondition::ForwardJumpRejected => {
                write_clock_state(
                    &transaction,
                    effective_now_ms,
                    condition,
                    &reading,
                    &boot_epoch,
                )?;
                self.append_audit(
                    &transaction,
                    "clock.forward_jump",
                    &serde_json::json!({
                        "observed_utc_ms": utc_ms.to_string(),
                        "effective_now_ms": effective_now_ms.to_string(),
                        "monotonic_anchor_ns": reading.monotonic_anchor_ns.to_string(),
                        "boot_epoch": boot_epoch
                    }),
                )?;
                transaction.commit().map_err(storage)?;
                log_clock_transition(condition, effective_now_ms, false);
                Ok(decision(effective_now_ms, condition))
            }
            DurableClockCondition::Untrusted => unreachable!("handled above"),
        }
    }

    /// Evaluate trusted time for a read/status request without changing clock
    /// state or requiring an audit append. This is intentionally available
    /// while the mutation latch is closed.
    pub(crate) fn observe_time_read_only(
        &self,
        reading: bloom_trusted_time::PlatformTimeReading,
        boot_epoch: bloom_signer_api::BootEpoch,
        max_forward_step_ms: u64,
    ) -> Result<ClockDecision, ProtocolError> {
        let connection = self.connection.lock();
        let stored: Option<(String, String, String)> = connection
            .query_row(
                "SELECT last_effective_ms, monotonic_anchor_ns, boot_epoch
                 FROM clock_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage)?;
        let previous = stored
            .map(|(value, anchor, persisted_epoch)| {
                Ok::<_, ProtocolError>(PersistedClockState {
                    last_effective_ms: value.parse().map_err(malformed)?,
                    monotonic_anchor_ns: anchor.parse().map_err(malformed)?,
                    boot_epoch: comparable_boot_epoch(
                        &bloom_signer_api::BootEpoch::new(persisted_epoch)
                            .map_err(|_| malformed_boot_epoch())?,
                    ),
                })
            })
            .transpose()?;
        let shared = evaluate_durable_clock(
            previous,
            &reading,
            comparable_boot_epoch(&boot_epoch),
            max_forward_step_ms,
        )
        .map_err(|cause| error(ProtocolErrorCode::ClockUntrusted, cause.to_string()))?;
        Ok(ClockDecision {
            effective_now_ms: shared.effective_now_ms,
            condition: signer_clock_condition(shared.condition),
            observed_utc_ms: reading.utc_ms,
            monotonic_anchor_ns: reading.monotonic_anchor_ns,
            boot_epoch,
        })
    }

    pub fn repair_clock(&self, accepted_utc_ms: u64) -> Result<ClockDecision, ProtocolError> {
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        let prior: Option<(String, String, String)> = transaction
            .query_row(
                "SELECT last_effective_ms, monotonic_anchor_ns, boot_epoch
                 FROM clock_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage)?;
        let (prior, monotonic_anchor_ns, boot_epoch) = prior.ok_or_else(|| {
            error(
                ProtocolErrorCode::ClockUntrusted,
                "clock repair requires initialized durable clock state",
            )
        })?;
        let prior = prior.parse::<u64>().map_err(malformed)?;
        if accepted_utc_ms < prior {
            tracing::warn!(
                event = "signer.clock_transition",
                condition = "repair",
                effective_now_ms = prior,
                outcome = "rejected",
                error_code = ProtocolErrorCode::ClockRollback.as_str(),
                "Signer rejected a durable clock transition"
            );
            return Err(error(
                ProtocolErrorCode::ClockRollback,
                "clock repair cannot move effective time backwards",
            ));
        }
        let monotonic_anchor_ns = monotonic_anchor_ns.parse::<u64>().map_err(malformed)?;
        let boot_epoch: bloom_signer_api::BootEpoch = boot_epoch.parse().map_err(malformed)?;
        let reading = bloom_trusted_time::PlatformTimeReading {
            utc_ms: Some(accepted_utc_ms),
            monotonic_elapsed_ms: 0,
            monotonic_anchor_ns,
        };
        write_clock_state(
            &transaction,
            accepted_utc_ms,
            ClockCondition::Repaired,
            &reading,
            &boot_epoch,
        )?;
        self.append_audit(
            &transaction,
            "clock.repaired",
            &serde_json::json!({
                "prior_effective_ms": prior.to_string(),
                "accepted_utc_ms": accepted_utc_ms.to_string(),
                "monotonic_anchor_ns": monotonic_anchor_ns.to_string(),
                "boot_epoch": boot_epoch
            }),
        )?;
        transaction.commit().map_err(storage)?;
        log_clock_transition(ClockCondition::Repaired, accepted_utc_ms, true);
        Ok(ClockDecision {
            effective_now_ms: accepted_utc_ms,
            condition: ClockCondition::Repaired,
            observed_utc_ms: Some(accepted_utc_ms),
            monotonic_anchor_ns,
            boot_epoch,
        })
    }

    pub fn active_approvals_expiring_by(
        &self,
        accepted_utc_ms: u64,
    ) -> Result<Vec<Digest32>, ProtocolError> {
        let connection = self.connection.lock();
        let mut statement = connection
            .prepare(
                "SELECT approval_id, terms_jcs FROM approvals
                 WHERE active = 1 ORDER BY approval_id",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage)?;
        let mut expiring = Vec::new();
        for row in rows {
            let (approval_id, terms_jcs) = row.map_err(storage)?;
            let terms: SealedApprovalTerms = serde_json::from_str(&terms_jcs).map_err(malformed)?;
            if terms.expires_at_ms.get() <= accepted_utc_ms {
                expiring.push(Digest32::new(approval_id).map_err(malformed)?);
            }
        }
        Ok(expiring)
    }

    pub(crate) fn approval_requires_trusted_time(
        &self,
        approval_id: &Digest32,
    ) -> Result<bool, ProtocolError> {
        let terms_jcs: String = self
            .connection
            .lock()
            .query_row(
                "SELECT terms_jcs FROM approvals WHERE approval_id = ?1",
                [approval_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| error(ProtocolErrorCode::ApprovalNotFound, "approval not found"))?;
        let terms: SealedApprovalTerms = serde_json::from_str(&terms_jcs).map_err(malformed)?;
        Ok(!terms.limits.operation_rate_limits.is_empty()
            || !terms.limits.signature_rate_limits.is_empty()
            || terms
                .limits
                .value_limits
                .iter()
                .any(|limit| !limit.rolling_windows.is_empty()))
    }

    pub(crate) fn activate_approval_from_ceremony(
        &self,
        terms: &SealedApprovalTerms,
        receipt: &SignerActivationReceipt,
        _proof: crate::ceremony::VerifiedCeremonyActivation,
    ) -> Result<Digest32, ProtocolError> {
        if receipt.approval_id != terms.approval_id()?
            || receipt.activation_operation_id.as_str().is_empty()
        {
            return Err(error(
                ProtocolErrorCode::CeremonyKindMismatch,
                "activation receipt does not match approval terms",
            ));
        }
        self.persist_approval(terms, Some(receipt))
    }

    /// Debug-build setup seam for lower-layer W3 tests. This symbol is absent
    /// from release artifacts; production activation is ceremony-only.
    #[cfg(debug_assertions)]
    pub fn install_approval_for_test(
        &self,
        terms: &SealedApprovalTerms,
    ) -> Result<Digest32, ProtocolError> {
        self.persist_approval(terms, None)
    }

    fn persist_approval(
        &self,
        terms: &SealedApprovalTerms,
        receipt: Option<&SignerActivationReceipt>,
    ) -> Result<Digest32, ProtocolError> {
        terms.validate()?;
        if terms
            .expires_at_ms
            .get()
            .saturating_sub(terms.not_before_ms.get())
            > MAX_APPROVAL_LIFETIME_MS
        {
            return Err(error(
                ProtocolErrorCode::ApprovalExpired,
                "approval exceeds Signer's compiled 90-day ceiling",
            ));
        }
        let approval_id = terms.approval_id()?;
        let terms_jcs = String::from_utf8(terms.canonical_bytes()?).map_err(malformed)?;
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        if !self.backend_registry.key_is_registered(&terms.key_ref)? {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "approval key is not registered in a compiled backend",
            ));
        }
        validate_petal_key_approval(&transaction, terms, terms.issued_at_ms.get())?;
        let stored_epoch: Option<String> = transaction
            .query_row(
                "SELECT revocation_epoch FROM wallet_state WHERE wallet_id = ?1",
                [terms.wallet_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        if stored_epoch.is_none() {
            transaction
                .execute(
                    "INSERT INTO wallet_state(
                        wallet_id, revocation_epoch, derivation_status,
                        derivation_registry_jcs, backup_set_jcs
                     ) VALUES (?1, ?2, 'DERIVATION_REGISTRY_MISSING', NULL, NULL)",
                    params![
                        terms.wallet_id.as_str(),
                        terms.wallet_revocation_epoch.get().to_string()
                    ],
                )
                .map_err(storage)?;
        } else if stored_epoch
            .as_deref()
            .and_then(|value| value.parse::<u64>().ok())
            != Some(terms.wallet_revocation_epoch.get())
        {
            return Err(error(
                ProtocolErrorCode::RevocationEpochUnreconciled,
                "approval epoch differs from the Signer wallet epoch",
            ));
        }
        transaction
            .execute(
                "INSERT INTO approvals(
                    approval_id, wallet_id, terms_jcs, active,
                    committed_operations, committed_signatures
                 ) VALUES (?1, ?2, ?3, 1, '0', '0')",
                params![approval_id.as_str(), terms.wallet_id.as_str(), terms_jcs],
            )
            .map_err(storage)?;
        if let Some(receipt) = receipt {
            transaction
                .execute(
                    "INSERT INTO ceremony_receipts(
                        operation_id, receipt_kind, receipt_jcs
                     ) VALUES (?1, 'sealed_approval', ?2)",
                    params![
                        receipt.activation_operation_id.as_str(),
                        serde_jcs::to_string(receipt).map_err(malformed)?
                    ],
                )
                .map_err(storage)?;
            let status = CeremonyPublicStatus {
                ceremony_id: receipt.ceremony_id.clone(),
                ceremony_kind: bloom_signer_api::CeremonyKind::SealedApproval,
                operation_id: receipt.activation_operation_id.clone(),
                state: bloom_signer_api::CeremonyState::Succeeded,
                expires_at_ms: receipt.expires_at_ms.clone(),
                ceremony_url: None,
                receipt_digest: Some(Digest32::from_bytes(
                    Sha256::digest(serde_jcs::to_vec(receipt).map_err(malformed)?).into(),
                )),
            };
            transaction
                .execute(
                    "INSERT INTO ceremony_statuses(operation_id, status_jcs)
                     VALUES (?1, ?2)",
                    params![
                        status.operation_id.as_str(),
                        serde_jcs::to_string(&status).map_err(malformed)?
                    ],
                )
                .map_err(storage)?;
        }
        self.append_audit(
            &transaction,
            "approval.activation",
            &serde_json::json!({
                "approval_id": approval_id,
                "terms": terms,
                "activation_receipt": receipt,
                "key_ref": terms.key_ref,
            }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(approval_id)
    }

    pub(crate) fn activation_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<SignerActivationReceipt>, ProtocolError> {
        self.connection
            .lock()
            .query_row(
                "SELECT receipt_jcs FROM ceremony_receipts
                 WHERE operation_id = ?1 AND receipt_kind = 'sealed_approval'",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?
            .map(|encoded| serde_json::from_str(&encoded).map_err(malformed))
            .transpose()
    }

    pub(crate) fn custody_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<CustodyResult>, ProtocolError> {
        self.connection
            .lock()
            .query_row(
                "SELECT receipt_jcs FROM ceremony_receipts
                 WHERE operation_id = ?1 AND receipt_kind = 'custody'",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?
            .map(|encoded| serde_json::from_str(&encoded).map_err(malformed))
            .transpose()
    }

    pub(crate) fn owner_attestation_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<OwnerAttestationReceipt>, ProtocolError> {
        self.connection
            .lock()
            .query_row(
                "SELECT receipt_jcs FROM ceremony_receipts
                 WHERE operation_id = ?1 AND receipt_kind = 'owner_attestation'",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?
            .map(|encoded| serde_json::from_str(&encoded).map_err(malformed))
            .transpose()
    }

    pub(crate) fn persist_owner_attestation(
        &self,
        receipt: &OwnerAttestationReceipt,
        expires_at_ms: &DecimalU64,
        public_binding_digest: &Digest32,
        wallet_id: &Token,
        proposed_credential: &WebAuthnCredential,
    ) -> Result<(), ProtocolError> {
        let status = OwnerAttestationStoredStatus {
            operation_id: &receipt.operation_id,
            ceremony_id: &receipt.ceremony_id,
            state: bloom_signer_api::CeremonyState::Succeeded,
            expires_at_ms,
            receipt_digest: Some(&receipt.receipt_digest),
            public_binding_digest,
        };
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        let stored_credential_jcs = transaction
            .query_row(
                "SELECT credential_jcs FROM webauthn_credentials
                 WHERE credential_id = ?1 AND wallet_id = ?2",
                params![
                    proposed_credential.credential_id.encoded(),
                    wallet_id.as_str()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| {
                error(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "owner attestation credential is not durably bound to the wallet",
                )
            })?;
        let mut stored_credential: WebAuthnCredential =
            serde_json::from_str(&stored_credential_jcs).map_err(malformed)?;
        let stored_count = stored_credential.sign_count.get();
        let proposed_count = proposed_credential.sign_count.get();
        let mut expected_metadata = proposed_credential.clone();
        expected_metadata.sign_count = stored_credential.sign_count.clone();
        if stored_credential != expected_metadata
            || stored_count > u64::from(u32::MAX)
            || proposed_count > u64::from(u32::MAX)
        {
            return Err(error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "owner attestation credential metadata is not the current durable enrollment",
            ));
        }
        let committed_count = if proposed_count == 0 {
            stored_count
        } else if stored_count != 0 && proposed_count <= stored_count {
            return Err(error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "authenticator signature counter did not advance",
            ));
        } else {
            proposed_count
        };
        stored_credential.sign_count = DecimalU64::new(committed_count);
        let updated = transaction
            .execute(
                "UPDATE webauthn_credentials SET credential_jcs = ?3
                 WHERE credential_id = ?1 AND wallet_id = ?2",
                params![
                    stored_credential.credential_id.encoded(),
                    wallet_id.as_str(),
                    serde_jcs::to_string(&stored_credential).map_err(malformed)?,
                ],
            )
            .map_err(storage)?;
        if updated != 1 {
            return Err(error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "owner attestation credential is not durably bound to the wallet",
            ));
        }
        transaction
            .execute(
                "INSERT INTO ceremony_receipts(operation_id, receipt_kind, receipt_jcs)
                 VALUES (?1, 'owner_attestation', ?2)",
                params![
                    receipt.operation_id.as_str(),
                    serde_jcs::to_string(receipt).map_err(malformed)?
                ],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "INSERT INTO ceremony_statuses(operation_id, status_jcs) VALUES (?1, ?2)",
                params![
                    receipt.operation_id.as_str(),
                    serde_jcs::to_string(&status).map_err(malformed)?
                ],
            )
            .map_err(storage)?;
        self.append_audit(
            &transaction,
            "owner_attestation.commit",
            &serde_json::json!({
                "receipt": receipt,
                "status": status,
                "credential_id": stored_credential.credential_id,
                "credential_sign_count": stored_credential.sign_count,
            }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    pub(crate) fn persist_owner_attestation_terminal_status(
        &self,
        operation_id: &OperationId,
        ceremony_id: &Digest32,
        state: bloom_signer_api::CeremonyState,
        expires_at_ms: &DecimalU64,
        public_binding_digest: &Digest32,
    ) -> Result<(), ProtocolError> {
        let status = OwnerAttestationStoredStatus {
            operation_id,
            ceremony_id,
            state,
            expires_at_ms,
            receipt_digest: None,
            public_binding_digest,
        };
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        transaction
            .execute(
                "INSERT INTO ceremony_statuses(operation_id, status_jcs) VALUES (?1, ?2)",
                params![
                    operation_id.as_str(),
                    serde_jcs::to_string(&status).map_err(malformed)?
                ],
            )
            .map_err(storage)?;
        self.append_audit(
            &transaction,
            "owner_attestation.status",
            &serde_json::json!({ "status": status }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    pub(crate) fn owner_attestation_terminal_state(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<bloom_signer_api::CeremonyState>, ProtocolError> {
        let encoded = self
            .connection
            .lock()
            .query_row(
                "SELECT status_jcs FROM ceremony_statuses WHERE operation_id = ?1",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?;
        let Some(encoded) = encoded else {
            return Ok(None);
        };
        let status: serde_json::Value = serde_json::from_str(&encoded).map_err(malformed)?;
        if status.get("public_binding_digest").is_none() || status.get("ceremony_kind").is_some() {
            return Ok(None);
        }
        status
            .get("state")
            .cloned()
            .map(|state| serde_json::from_value(state).map_err(malformed))
            .transpose()
    }

    pub(crate) fn ceremony_operation_exists(
        &self,
        operation_id: &OperationId,
    ) -> Result<bool, ProtocolError> {
        let connection = self.connection.lock();
        let receipt = connection
            .query_row(
                "SELECT 1 FROM ceremony_receipts WHERE operation_id = ?1",
                [operation_id.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map_err(storage)?
            .is_some();
        let status = connection
            .query_row(
                "SELECT 1 FROM ceremony_statuses WHERE operation_id = ?1",
                [operation_id.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map_err(storage)?
            .is_some();
        Ok(receipt || status)
    }

    pub(crate) fn load_ceremony_custody(&self) -> Result<PersistedCeremonyCustody, ProtocolError> {
        let connection = self.connection.lock();
        let mut wallets_statement = connection
            .prepare("SELECT custody_jcs FROM ceremony_wallets ORDER BY wallet_id")
            .map_err(storage)?;
        let wallets = wallets_statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?
            .into_iter()
            .map(|encoded| serde_json::from_str(&encoded).map_err(malformed))
            .collect::<Result<Vec<_>, _>>()?;
        drop(wallets_statement);

        let mut credentials_statement = connection
            .prepare(
                "SELECT wallet_id, credential_jcs
                 FROM webauthn_credentials ORDER BY credential_id",
            )
            .map_err(storage)?;
        let credentials = credentials_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?
            .into_iter()
            .map(|(wallet_id, encoded)| {
                Ok((
                    Token::new(wallet_id)?,
                    serde_json::from_str(&encoded).map_err(malformed)?,
                ))
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        Ok((wallets, credentials))
    }

    pub(crate) fn load_ceremony_backend_enrollments(
        &self,
    ) -> Result<Vec<BackendEnrollmentBackup>, ProtocolError> {
        let connection = self.connection.lock();
        let mut statement = connection
            .prepare(
                "SELECT enrollment_jcs FROM ceremony_backend_enrollments
                 ORDER BY backend_instance",
            )
            .map_err(storage)?;
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?
            .into_iter()
            .map(|encoded| serde_json::from_str(&encoded).map_err(malformed))
            .collect()
    }

    pub(crate) fn commit_custody_snapshot_with_effect(
        &self,
        result: &CustodyResult,
        wallets: &[WalletCustodyBackup],
        credentials: &[(Token, WebAuthnCredential)],
        committed_at_ms: u64,
        status: &CeremonyPublicStatus,
        effect: CeremonyDatabaseEffect,
    ) -> Result<(), ProtocolError> {
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        let wallet_snapshot_digest = Digest32::from_bytes(
            Sha256::digest(serde_jcs::to_vec(wallets).map_err(malformed)?).into(),
        );
        let credential_snapshot_digest = Digest32::from_bytes(
            Sha256::digest(serde_jcs::to_vec(credentials).map_err(malformed)?).into(),
        );
        let database_effect = match &effect {
            CeremonyDatabaseEffect::None => serde_json::json!({ "kind": "custody_only" }),
            CeremonyDatabaseEffect::InitialPolicy {
                snapshot,
                policy_verifying_key,
                backend_enrollment,
            } => serde_json::json!({
                "kind": "initial_policy",
                "snapshot": snapshot,
                "policy_verifying_key": policy_verifying_key,
                "backend_enrollment": backend_enrollment,
            }),
            CeremonyDatabaseEffect::PolicyUpdatePending(update) => serde_json::json!({
                "kind": "policy_update_pending",
                "update": update.update,
                "validation": update.validation,
                "receipt": update.receipt,
            }),
            CeremonyDatabaseEffect::EnrollKey {
                key_ref,
                petal_scope,
            } => serde_json::json!({
                "kind": "enroll_key",
                "key_ref": key_ref,
                "petal_scope": petal_scope,
            }),
        };
        let existing_credential_times = {
            let mut statement = transaction
                .prepare(
                    "SELECT credential_id, created_at_ms
                     FROM webauthn_credentials",
                )
                .map_err(storage)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage)?;
            rows.into_iter().collect::<BTreeMap<_, _>>()
        };
        transaction
            .execute("DELETE FROM ceremony_wallets", [])
            .map_err(storage)?;
        for wallet in wallets {
            transaction
                .execute(
                    "INSERT INTO ceremony_wallets(wallet_id, custody_jcs)
                     VALUES (?1, ?2)",
                    params![
                        wallet.wallet_id.as_str(),
                        serde_jcs::to_string(wallet).map_err(malformed)?
                    ],
                )
                .map_err(storage)?;
        }
        transaction
            .execute("DELETE FROM webauthn_credentials", [])
            .map_err(storage)?;
        for (wallet_id, credential) in credentials {
            transaction
                .execute(
                    "INSERT INTO webauthn_credentials(
                        credential_id, wallet_id, credential_jcs, created_at_ms
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        credential.credential_id.encoded(),
                        wallet_id.as_str(),
                        serde_jcs::to_string(credential).map_err(malformed)?,
                        existing_credential_times
                            .get(credential.credential_id.encoded())
                            .cloned()
                            .unwrap_or_else(|| committed_at_ms.to_string())
                    ],
                )
                .map_err(storage)?;
        }
        match effect {
            CeremonyDatabaseEffect::None => {}
            CeremonyDatabaseEffect::InitialPolicy {
                snapshot,
                policy_verifying_key,
                backend_enrollment,
            } => {
                transaction
                    .execute(
                        "INSERT INTO policies(
                            wallet_id, version, digest, canonical_policy, snapshot_jcs,
                            policy_signing_key_id, policy_verifying_key
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            snapshot.wallet_id.as_str(),
                            snapshot.version.get().to_string(),
                            snapshot.policy_digest.as_str(),
                            snapshot.canonical_policy.encoded(),
                            serde_jcs::to_string(&snapshot).map_err(malformed)?,
                            snapshot.policy_signing_key_id.as_str(),
                            policy_verifying_key.encoded(),
                        ],
                    )
                    .map_err(storage)?;
                if let Some(enrollment) = backend_enrollment {
                    if enrollment.pinned_keys.len() != 1
                        || enrollment.pinned_keys[0].backend != enrollment.backend
                        || enrollment.pinned_keys[0].backend_instance != enrollment.backend_instance
                    {
                        return Err(error(
                            ProtocolErrorCode::KeyrefMismatch,
                            "registration backend enrollment is not bound to one root KeyRef",
                        ));
                    }
                    let key_ref = &enrollment.pinned_keys[0];
                    transaction
                        .execute(
                            "INSERT INTO enrolled_keys(
                                key_fingerprint, key_ref_jcs, available, authority_class, wallet_id
                             ) VALUES (?1, ?2, 1, 'wallet_root', ?3)",
                            params![
                                key_ref.public_key_fingerprint.as_str(),
                                serde_jcs::to_string(key_ref).map_err(malformed)?,
                                snapshot.wallet_id.as_str(),
                            ],
                        )
                        .map_err(storage)?;
                    transaction
                        .execute(
                            "INSERT INTO ceremony_backend_enrollments(
                                backend_instance, enrollment_jcs
                             ) VALUES (?1, ?2)",
                            params![
                                enrollment.backend_instance.as_str(),
                                serde_jcs::to_string(&enrollment).map_err(malformed)?,
                            ],
                        )
                        .map_err(storage)?;
                }
            }
            CeremonyDatabaseEffect::PolicyUpdatePending(update) => {
                let CeremonyPolicyUpdate {
                    update,
                    validation,
                    receipt,
                } = *update;
                let authorization = PendingPolicyAuthorization {
                    update,
                    validation,
                    ceremony_receipt: result.clone(),
                    commit_receipt: receipt,
                };
                transaction
                    .execute(
                        "INSERT INTO policy_authorizations(operation_id, request_jcs)
                         VALUES (?1, ?2)",
                        params![
                            authorization.update.operation_id.as_str(),
                            serde_jcs::to_string(&authorization).map_err(malformed)?,
                        ],
                    )
                    .map_err(storage)?;
            }
            CeremonyDatabaseEffect::EnrollKey {
                key_ref,
                petal_scope,
            } => {
                let authority_class = if petal_scope.is_some() {
                    "petal"
                } else {
                    "unscoped"
                };
                let wallet_id = petal_scope.as_ref().map(|scope| scope.wallet_id.as_str());
                transaction
                    .execute(
                        "INSERT INTO enrolled_keys(
                            key_fingerprint, key_ref_jcs, available, authority_class, wallet_id
                         ) VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT(key_fingerprint) DO UPDATE SET
                            key_ref_jcs = excluded.key_ref_jcs,
                            available = excluded.available,
                            authority_class = excluded.authority_class,
                            wallet_id = excluded.wallet_id",
                        params![
                            key_ref.public_key_fingerprint.as_str(),
                            serde_jcs::to_string(&key_ref).map_err(malformed)?,
                            true,
                            authority_class,
                            wallet_id,
                        ],
                    )
                    .map_err(storage)?;
                if let Some(scope) = petal_scope {
                    let scope_digest = scope.digest()?;
                    let expires_at_ms = committed_at_ms
                        .checked_add(scope.maximum_lifetime_ms.get())
                        .ok_or_else(|| {
                            error(
                                ProtocolErrorCode::MalformedFrame,
                                "Petal key scope lifetime overflows the protocol clock",
                            )
                        })?;
                    transaction
                        .execute(
                            "INSERT INTO petal_key_scopes(
                                key_fingerprint, wallet_id, custody_operation_id,
                                scope_digest, scope_jcs, created_at_ms, expires_at_ms
                             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                            params![
                                key_ref.public_key_fingerprint.as_str(),
                                scope.wallet_id.as_str(),
                                scope.custody_operation_id.as_str(),
                                scope_digest.as_str(),
                                serde_jcs::to_string(&scope).map_err(malformed)?,
                                committed_at_ms.to_string(),
                                expires_at_ms.to_string(),
                            ],
                        )
                        .map_err(storage)?;
                    #[cfg(feature = "local")]
                    {
                        let enrollment = BackendEnrollmentBackup {
                            backend: scope.parent_key_ref.backend.clone(),
                            backend_instance: scope.parent_key_ref.backend_instance.clone(),
                            encrypted_record: self
                                .backend_registry
                                .local_encrypted_backup(&scope.parent_key_ref)?,
                            pinned_keys: vec![scope.parent_key_ref.clone()],
                        };
                        let updated = transaction
                            .execute(
                                "UPDATE ceremony_backend_enrollments
                                 SET enrollment_jcs = ?2 WHERE backend_instance = ?1",
                                params![
                                    scope.parent_key_ref.backend_instance.as_str(),
                                    serde_jcs::to_string(&enrollment).map_err(malformed)?,
                                ],
                            )
                            .map_err(storage)?;
                        if updated != 1 {
                            return Err(error(
                                ProtocolErrorCode::KeyrefMismatch,
                                "Petal sub-key parent lacks durable wallet custody enrollment",
                            ));
                        }
                    }
                }
            }
        }
        transaction
            .execute(
                "INSERT INTO ceremony_receipts(
                    operation_id, receipt_kind, receipt_jcs
                 ) VALUES (?1, 'custody', ?2)",
                params![
                    result.custody_operation_id.as_str(),
                    serde_jcs::to_string(result).map_err(malformed)?
                ],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "INSERT INTO ceremony_statuses(operation_id, status_jcs)
                 VALUES (?1, ?2)
                 ON CONFLICT(operation_id) DO UPDATE SET status_jcs = excluded.status_jcs",
                params![
                    status.operation_id.as_str(),
                    serde_jcs::to_string(status).map_err(malformed)?
                ],
            )
            .map_err(storage)?;
        self.append_audit(
            &transaction,
            "custody.commit",
            &serde_json::json!({
                "operation_id": result.custody_operation_id,
                "ceremony_kind": result.ceremony_kind,
                "result": result,
                "status": status,
                "wallet_count": wallets.len().to_string(),
                "credential_count": credentials.len().to_string(),
                "wallet_snapshot_digest": wallet_snapshot_digest,
                "credential_snapshot_digest": credential_snapshot_digest,
                "database_effect": database_effect,
            }),
        )?;
        transaction.commit().map_err(storage)?;
        tracing::info!(
            event = "signer.mutation_committed",
            operation_id = result.custody_operation_id.as_str(),
            mutation_kind = ceremony_mutation_kind(result.ceremony_kind),
            "Signer committed a ceremony mutation"
        );
        Ok(())
    }

    pub(crate) fn ceremony_public_status(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<CeremonyPublicStatus>, ProtocolError> {
        self.connection
            .lock()
            .query_row(
                "SELECT status_jcs FROM ceremony_statuses WHERE operation_id = ?1",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?
            .map(|encoded| serde_json::from_str(&encoded).map_err(malformed))
            .transpose()
    }

    pub(crate) fn persist_ceremony_public_status(
        &self,
        status: &CeremonyPublicStatus,
    ) -> Result<(), ProtocolError> {
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        transaction
            .execute(
                "INSERT INTO ceremony_statuses(operation_id, status_jcs)
                 VALUES (?1, ?2)
                 ON CONFLICT(operation_id) DO UPDATE SET status_jcs = excluded.status_jcs",
                params![
                    status.operation_id.as_str(),
                    serde_jcs::to_string(status).map_err(malformed)?
                ],
            )
            .map_err(storage)?;
        self.append_audit(
            &transaction,
            "ceremony.status",
            &serde_json::json!({ "status": status }),
        )?;
        transaction.commit().map_err(storage)?;
        tracing::info!(
            event = "signer.ceremony_status_committed",
            operation_id = status.operation_id.as_str(),
            state = ceremony_state_code(status.state),
            "Signer committed a ceremony status"
        );
        Ok(())
    }

    /// Journal that a ceremony armed a wallet's local backend.
    ///
    /// Activation is otherwise invisible in the audit trail: the sealed-approval
    /// path records `approval.activation`, and a derivation records
    /// `key.enrolled`, so an operator asking when a wallet's signing capability
    /// was armed cannot distinguish a ceremony that activated the backend from
    /// one that ran on an already-armed boot.
    pub fn record_backend_activation(
        &self,
        wallet_id: &Token,
        key_ref: &KeyRef,
    ) -> Result<(), ProtocolError> {
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        self.append_audit(
            &transaction,
            "backend.activated",
            &serde_json::json!({ "wallet_id": wallet_id, "key_ref": key_ref }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    pub fn enroll_key(&self, key_ref: &KeyRef) -> Result<(), ProtocolError> {
        key_ref.validate()?;
        if !self.backend_registry.key_is_registered(key_ref)? {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "key is not registered in a compiled backend",
            ));
        }
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        transaction
            .execute(
                "INSERT INTO enrolled_keys(key_fingerprint, key_ref_jcs, available, authority_class, wallet_id)
                 VALUES (?1, ?2, ?3, 'unscoped', NULL)
                 ON CONFLICT(key_fingerprint) DO UPDATE SET
                    key_ref_jcs = excluded.key_ref_jcs,
                    available = excluded.available",
                params![
                    key_ref.public_key_fingerprint.as_str(),
                    serde_jcs::to_string(key_ref).map_err(malformed)?,
                    true
                ],
            )
            .map_err(storage)?;
        self.append_audit(
            &transaction,
            "key.enrolled",
            &serde_json::json!({ "key_ref": key_ref }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    /// Test and recovery helper for explicitly associating an already
    /// registered root with a wallet.  Production registration writes this
    /// binding atomically with its initial policy.
    pub fn enroll_wallet_root_key(
        &self,
        wallet_id: &Token,
        key_ref: &KeyRef,
    ) -> Result<(), ProtocolError> {
        key_ref.validate()?;
        if !self.backend_registry.key_is_registered(key_ref)? {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "key is not registered in a compiled backend",
            ));
        }
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        transaction
            .execute(
                "INSERT INTO enrolled_keys(
                    key_fingerprint, key_ref_jcs, available, authority_class, wallet_id
                 ) VALUES (?1, ?2, 1, 'wallet_root', ?3)
                 ON CONFLICT(key_fingerprint) DO UPDATE SET
                    key_ref_jcs = excluded.key_ref_jcs,
                    available = 1,
                    authority_class = 'wallet_root',
                    wallet_id = excluded.wallet_id",
                params![
                    key_ref.public_key_fingerprint.as_str(),
                    serde_jcs::to_string(key_ref).map_err(malformed)?,
                    wallet_id.as_str(),
                ],
            )
            .map_err(storage)?;
        self.append_audit(
            &transaction,
            "key.wallet_root_enrolled",
            &serde_json::json!({ "wallet_id": wallet_id, "key_ref": key_ref }),
        )?;
        transaction.commit().map_err(storage)
    }

    pub fn authorize_sign(
        &self,
        request: &SignRequest,
        clock: &ClockDecision,
    ) -> Result<SignAuthorization, ProtocolError> {
        let effective_now_ms = clock.effective_now_ms;
        request.validate_shape()?;
        self.verify_broker_signature(request)?;
        if request.unsigned.not_before_ms.get() > effective_now_ms
            || request.unsigned.expires_at_ms.get() <= effective_now_ms
        {
            return Err(error(
                ProtocolErrorCode::ApprovalExpired,
                "sign attempt is outside its validity window",
            ));
        }
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        let retry_binding_digest = retry_binding_digest(&request.unsigned)?;
        if transaction
            .query_row(
                "SELECT 1 FROM attempts WHERE attempt_id = ?1",
                [request.unsigned.attempt_id.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map_err(storage)?
            .is_some()
        {
            return Err(error(
                ProtocolErrorCode::CeremonyReplay,
                "sign attempt ID has already been consumed",
            ));
        }
        let approval: (String, bool) = transaction
            .query_row(
                "SELECT terms_jcs, active FROM approvals WHERE approval_id = ?1",
                [request.unsigned.approval_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| {
                error(
                    ProtocolErrorCode::ApprovalNotFound,
                    "active approval not found",
                )
            })?;
        if !approval.1 {
            return Err(error(
                ProtocolErrorCode::ApprovalRevoked,
                "approval is revoked or inactive",
            ));
        }
        let terms: SealedApprovalTerms = serde_json::from_str(&approval.0).map_err(malformed)?;
        require_key_available(&transaction, &self.backend_registry, &terms.key_ref)?;
        validate_petal_key_approval(&transaction, &terms, effective_now_ms)?;
        validate_against_approval(request, &terms, effective_now_ms)?;
        let epoch = wallet_epoch(&transaction, &terms.wallet_id)?;
        if epoch != terms.wallet_revocation_epoch.get() {
            return Err(error(
                ProtocolErrorCode::ApprovalRevoked,
                "wallet revocation epoch invalidates approval",
            ));
        }
        let existing: Option<(String, String, String, String)> = transaction
            .query_row(
                "SELECT operation_digest, approval_id, retry_binding_digest, state
                 FROM operations WHERE operation_id = ?1",
                [request.unsigned.operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(storage)?;
        let authorization = if let Some((digest, approval_id, stored_retry_binding, state)) =
            existing
        {
            if digest != request.unsigned.operation_digest.as_str()
                || approval_id != request.unsigned.approval_id.as_str()
                || stored_retry_binding != retry_binding_digest.as_str()
            {
                return Err(error(
                    ProtocolErrorCode::OperationIdConflict,
                    "operation retry changed stable identity, approval, or forbidden attempt fields",
                ));
            }
            match state.as_str() {
                "RESERVED" => {}
                "DISPATCHED" | "QUARANTINED" => {
                    return Err(error(
                        ProtocolErrorCode::AmbiguousProviderEffect,
                        "Signer operation may already have reached its backend",
                    ));
                }
                "COMMITTED" => {}
                "RELEASED" => {
                    return Err(error(
                        ProtocolErrorCode::OperationIdConflict,
                        "released Signer operation cannot be retried",
                    ));
                }
                _ => {
                    return Err(error(
                        ProtocolErrorCode::MalformedFrame,
                        "Signer operation has unknown durable state",
                    ));
                }
            }
            SignAuthorization::SameOperationRetry
        } else {
            let (next_operations, next_signatures) =
                reserve_parser_free_limits(&transaction, request, &terms, effective_now_ms)?;
            transaction
                .execute(
                    "INSERT INTO operations(
                        operation_id, operation_digest, retry_binding_digest, approval_id,
                        signature_count, accepted_at_ms, state
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'RESERVED')",
                    params![
                        request.unsigned.operation_id.as_str(),
                        request.unsigned.operation_digest.as_str(),
                        retry_binding_digest.as_str(),
                        request.unsigned.approval_id.as_str(),
                        request.unsigned.signature_count.get().to_string(),
                        effective_now_ms.to_string()
                    ],
                )
                .map_err(storage)?;
            transaction
                .execute(
                    "INSERT INTO operation_clock_anchors(
                         operation_id, observed_utc_ms, monotonic_anchor_ns, boot_epoch
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        request.unsigned.operation_id.as_str(),
                        clock.observed_utc_ms.map(|value| value.to_string()),
                        clock.monotonic_anchor_ns.to_string(),
                        clock.boot_epoch.as_str()
                    ],
                )
                .map_err(storage)?;
            transaction
                .execute(
                    "UPDATE approvals SET
                        committed_operations = ?2,
                        committed_signatures = ?3
                     WHERE approval_id = ?1",
                    params![
                        request.unsigned.approval_id.as_str(),
                        next_operations.to_string(),
                        next_signatures.to_string()
                    ],
                )
                .map_err(storage)?;
            SignAuthorization::NewOperation
        };
        transaction
            .execute(
                "INSERT INTO attempts(attempt_id, attempt_digest, operation_id)
                 VALUES (?1, ?2, ?3)",
                params![
                    request.unsigned.attempt_id.as_str(),
                    request.unsigned.attempt_digest.as_str(),
                    request.unsigned.operation_id.as_str()
                ],
            )
            .map_err(storage)?;
        self.append_audit(
            &transaction,
            "sign.authorized",
            &serde_json::json!({
                "operation_id": request.unsigned.operation_id,
                "operation_digest": request.unsigned.operation_digest,
                "attempt_id": request.unsigned.attempt_id,
                "attempt_digest": request.unsigned.attempt_digest,
                "approval_id": request.unsigned.approval_id,
                "key_ref": request.unsigned.key_ref,
                "crypto_suite": request.unsigned.crypto_suite,
                "ordered_payload_digests": request.unsigned.ordered_payload_digests,
                "ordered_hashes": request.unsigned.ordered_hashes,
                "validation_receipt_digest": request.unsigned.validation_receipt_digest,
                "broker_key_id": request.unsigned.broker_signing_key_id,
                "broker_signature": request.broker_signature,
                "authorization": format!("{authorization:?}"),
            }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(authorization)
    }

    pub fn finalize_operation(
        &self,
        operation_id: &OperationId,
        effect: SignerOperationEffect,
    ) -> Result<(), ProtocolError> {
        if effect == SignerOperationEffect::Committed {
            return Err(error(
                ProtocolErrorCode::BackendInvalidRequest,
                "committed operations require an atomically stored normalized result",
            ));
        }
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        let current: (String, String, String) = transaction
            .query_row(
                "SELECT state, approval_id, signature_count
                 FROM operations WHERE operation_id = ?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(storage)?;
        if current.0 == effect.as_str() {
            transaction.commit().map_err(storage)?;
            return Ok(());
        }
        if current.0 != "RESERVED"
            && !(current.0 == "DISPATCHED"
                && matches!(
                    effect,
                    SignerOperationEffect::Released | SignerOperationEffect::Quarantined
                ))
        {
            return Err(error(
                ProtocolErrorCode::OperationIdConflict,
                "Signer operation was already finalized differently",
            ));
        }
        if effect == SignerOperationEffect::Released {
            let counters: (String, String) = transaction
                .query_row(
                    "SELECT committed_operations, committed_signatures
                     FROM approvals WHERE approval_id = ?1",
                    [&current.1],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(storage)?;
            let operations = counters.0.parse::<u64>().map_err(malformed)?;
            let signatures = counters.1.parse::<u64>().map_err(malformed)?;
            let operation_signatures = current.2.parse::<u64>().map_err(malformed)?;
            let next_operations = operations.checked_sub(1).ok_or_else(|| {
                error(
                    ProtocolErrorCode::MalformedFrame,
                    "Signer operation counter underflow",
                )
            })?;
            let next_signatures =
                signatures
                    .checked_sub(operation_signatures)
                    .ok_or_else(|| {
                        error(
                            ProtocolErrorCode::MalformedFrame,
                            "Signer signature counter underflow",
                        )
                    })?;
            transaction
                .execute(
                    "UPDATE approvals SET committed_operations = ?2,
                        committed_signatures = ?3 WHERE approval_id = ?1",
                    params![
                        current.1,
                        next_operations.to_string(),
                        next_signatures.to_string()
                    ],
                )
                .map_err(storage)?;
        }
        transaction
            .execute(
                "UPDATE operations SET state = ?2 WHERE operation_id = ?1",
                params![operation_id.as_str(), effect.as_str()],
            )
            .map_err(storage)?;
        self.append_audit(
            &transaction,
            "sign.finalized",
            &serde_json::json!({
                "operation_id": operation_id,
                "effect": effect.as_str(),
            }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    pub fn commit_operation_result(
        &self,
        operation_id: &OperationId,
        normalized_result: Base64UrlBytes,
    ) -> Result<(), ProtocolError> {
        if normalized_result.decode().is_empty() {
            return Err(error(
                ProtocolErrorCode::BackendInvalidRequest,
                "normalized operation result cannot be empty",
            ));
        }
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        let changed = transaction
            .execute(
                "UPDATE operations SET state = 'COMMITTED', normalized_result = ?2
                 WHERE operation_id = ?1 AND state IN ('RESERVED', 'DISPATCHED')",
                params![operation_id.as_str(), normalized_result.encoded()],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(error(
                ProtocolErrorCode::OperationIdConflict,
                "operation is absent or already finalized",
            ));
        }
        self.append_audit(
            &transaction,
            "sign.result",
            &serde_json::json!({
                "operation_id": operation_id,
                "normalized_result": normalized_result,
            }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    /// Durably records the point after which a backend call may occur. A
    /// restart from this state is ambiguous and must never automatically
    /// dispatch the operation again.
    pub fn mark_operation_dispatched(
        &self,
        operation_id: &OperationId,
        key_ref: &KeyRef,
        provider_attempt_ids: &[Digest32],
    ) -> Result<(), ProtocolError> {
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        let changed = transaction
            .execute(
                "UPDATE operations SET state = 'DISPATCHED'
                 WHERE operation_id = ?1 AND state = 'RESERVED'",
                [operation_id.as_str()],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(error(
                ProtocolErrorCode::OperationIdConflict,
                "operation is absent or was already dispatched",
            ));
        }
        self.append_audit(
            &transaction,
            "backend.dispatched",
            &serde_json::json!({
                "operation_id": operation_id,
                "key_ref": key_ref,
                "provider_attempt_ids": provider_attempt_ids,
            }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    pub fn operation_status(
        &self,
        operation_id: &OperationId,
    ) -> Result<OperationPublicStatus, ProtocolError> {
        let row: (String, String, Option<String>) = self
            .connection
            .lock()
            .query_row(
                "SELECT operation_digest, state, normalized_result
                 FROM operations WHERE operation_id = ?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| {
                error(
                    ProtocolErrorCode::ApprovalNotFound,
                    "Signer operation not found",
                )
            })?;
        let state = match row.1.as_str() {
            "RESERVED" => OperationState::Reserved,
            "DISPATCHED" => OperationState::Dispatched,
            "COMMITTED" => OperationState::Succeeded,
            "RELEASED" => OperationState::Denied,
            "QUARANTINED" => OperationState::Quarantined,
            _ => {
                return Err(error(
                    ProtocolErrorCode::MalformedFrame,
                    "Signer operation has unknown durable state",
                ));
            }
        };
        let result = row
            .2
            .map(|encoded| -> Result<SigningResult, ProtocolError> {
                let bytes = Base64UrlBytes::parse(encoded)?;
                serde_json::from_slice::<SigningResult>(&bytes.decode()).map_err(malformed)
            })
            .transpose()?;
        Ok(OperationPublicStatus {
            operation_id: operation_id.clone(),
            operation_digest: Digest32::new(row.0)?,
            state,
            result,
            error: None,
        })
    }

    pub fn stored_operation_result(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<Base64UrlBytes>, ProtocolError> {
        let result: Option<Option<String>> = self
            .connection
            .lock()
            .query_row(
                "SELECT normalized_result FROM operations
                 WHERE operation_id = ?1 AND state = 'COMMITTED'",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        Ok(result.flatten().map(Base64UrlBytes::parse).transpose()?)
    }

    pub fn approval_public_status(
        &self,
        approval_id: &Digest32,
        now_ms: u64,
    ) -> Result<ApprovalPublicStatus, ProtocolError> {
        let (terms_jcs, active): (String, bool) = self
            .connection
            .lock()
            .query_row(
                "SELECT terms_jcs, active FROM approvals WHERE approval_id = ?1",
                [approval_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| error(ProtocolErrorCode::ApprovalNotFound, "approval not found"))?;
        let terms: SealedApprovalTerms = serde_json::from_str(&terms_jcs).map_err(malformed)?;
        let state = if !active {
            ApprovalLifecycleState::Revoked
        } else if terms.expires_at_ms.get() <= now_ms {
            ApprovalLifecycleState::Expired
        } else {
            ApprovalLifecycleState::Active
        };
        Ok(ApprovalPublicStatus {
            approval_id: approval_id.clone(),
            wallet_id: terms.wallet_id,
            state,
            effective_claim_assurance: None,
            ceremony_url: None,
            ceremony_expires_at_ms: None,
        })
    }

    pub fn policy_snapshot(
        &self,
        wallet_id: &Token,
    ) -> Result<SignedPolicySnapshot, ProtocolError> {
        self.connection
            .lock()
            .query_row(
                "SELECT snapshot_jcs FROM policies WHERE wallet_id = ?1",
                [wallet_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| {
                error(
                    ProtocolErrorCode::ApprovalNotFound,
                    "wallet policy not found",
                )
            })
            .and_then(|encoded| serde_json::from_str(&encoded).map_err(malformed))
    }

    pub fn enrolled_key_refs(&self, wallet_id: &Token) -> Result<Vec<KeyRef>, ProtocolError> {
        let connection = self.connection.lock();
        let mut statement = connection
            .prepare(
                "SELECT key_ref_jcs FROM enrolled_keys
                 WHERE available = 1 AND authority_class = 'wallet_root' AND wallet_id = ?1
                 ORDER BY key_fingerprint",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([wallet_id.as_str()], |row| row.get::<_, String>(0))
            .map_err(storage)?;
        let mut keys = Vec::new();
        for row in rows {
            let key: KeyRef = serde_json::from_str(&row.map_err(storage)?).map_err(malformed)?;
            keys.push(key);
        }
        Ok(keys)
    }

    pub fn enrolled_derived_key_refs(&self, parent: &KeyRef) -> Result<Vec<KeyRef>, ProtocolError> {
        let connection = self.connection.lock();
        let wallet_id: Option<String> = connection
            .query_row(
                "SELECT wallet_id FROM enrolled_keys
                 WHERE key_fingerprint = ?1 AND available = 1 AND authority_class = 'wallet_root'",
                [parent.public_key_fingerprint.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        let Some(wallet_id) = wallet_id else {
            return Ok(Vec::new());
        };
        let mut statement = connection
            .prepare(
                "SELECT key_ref_jcs FROM enrolled_keys
                 WHERE authority_class = 'petal' AND wallet_id = ?1
                 ORDER BY key_fingerprint",
            )
            .map_err(storage)?;
        statement
            .query_map([wallet_id], |row| row.get::<_, String>(0))
            .map_err(storage)?
            .map(|row| serde_json::from_str(&row.map_err(storage)?).map_err(malformed))
            .collect()
    }

    pub fn key_role(&self, key_ref: &KeyRef) -> Result<bloom_signer_api::KeyRole, ProtocolError> {
        let connection = self.connection.lock();
        let class: Option<String> = connection
            .query_row(
                "SELECT authority_class FROM enrolled_keys WHERE key_fingerprint = ?1",
                [key_ref.public_key_fingerprint.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        match class.as_deref() {
            Some("wallet_root") => Ok(bloom_signer_api::KeyRole::WalletRoot),
            Some("petal") if key_ref.derivation.is_some() => Ok(bloom_signer_api::KeyRole::Derived),
            _ => Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "key is not an enrolled wallet root or Signer-derived key",
            )),
        }
    }

    /// Durable enrollment of a Petal sub-key parent.
    ///
    /// This asserts only facts that survive a restart: the parent is enrolled,
    /// its KeyRef is byte-identical to the enrolled one, it is not withdrawn,
    /// it is a wallet root, and it belongs to this wallet. It deliberately does
    /// not assert that the backend is currently activated, because staging a
    /// ceremony is what later produces that activation. Callers that are about
    /// to use the parent must use `require_activated_parent_key` instead.
    pub(crate) fn require_enrolled_parent_key(
        &self,
        wallet_id: &Token,
        key_ref: &KeyRef,
    ) -> Result<(), ProtocolError> {
        let connection = self.connection.lock();
        let enrolled: Option<(String, bool, String, Option<String>)> = connection
            .query_row(
                "SELECT key_ref_jcs, available, authority_class, wallet_id FROM enrolled_keys
                 WHERE key_fingerprint = ?1",
                [key_ref.public_key_fingerprint.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(storage)?;
        let expected = serde_jcs::to_string(key_ref).map_err(malformed)?;
        if enrolled
            .as_ref()
            .map(|(stored, available, class, enrolled_wallet)| {
                (
                    stored,
                    *available,
                    class.as_str(),
                    enrolled_wallet.as_deref(),
                )
            })
            != Some((&expected, true, "wallet_root", Some(wallet_id.as_str())))
        {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "Petal sub-key parent is absent or unavailable for the named wallet",
            ));
        }
        Ok(())
    }

    /// Durable enrollment plus a currently activated backend.
    ///
    /// Use this immediately before deriving from the parent, where an inactive
    /// backend genuinely cannot serve the request.
    pub(crate) fn require_activated_parent_key(
        &self,
        wallet_id: &Token,
        key_ref: &KeyRef,
    ) -> Result<(), ProtocolError> {
        self.require_enrolled_parent_key(wallet_id, key_ref)?;
        if !self.backend_registry.key_is_available(key_ref)? {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "Petal sub-key parent backend is not activated for the named wallet",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_petal_scope_for_approval(
        &self,
        terms: &SealedApprovalTerms,
        effective_now_ms: u64,
    ) -> Result<(), ProtocolError> {
        validate_petal_key_approval(&self.connection.lock(), terms, effective_now_ms)
    }

    pub fn credential_public(
        &self,
        wallet_id: &Token,
    ) -> Result<Vec<CredentialPublic>, ProtocolError> {
        let connection = self.connection.lock();
        let mut statement = connection
            .prepare(
                "SELECT credential_jcs, created_at_ms FROM webauthn_credentials
                 WHERE wallet_id = ?1 ORDER BY credential_id",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([wallet_id.as_str()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage)?;
        let mut credentials = Vec::new();
        for row in rows {
            let (encoded, created_at_ms) = row.map_err(storage)?;
            let credential: WebAuthnCredential =
                serde_json::from_str(&encoded).map_err(malformed)?;
            credentials.push(CredentialPublic {
                credential_id: credential.credential_id,
                wallet_id: wallet_id.clone(),
                created_at_ms: DecimalU64::new(created_at_ms.parse().map_err(malformed)?),
                state: CredentialState::Active,
            });
        }
        Ok(credentials)
    }

    pub fn revoke_approval(
        &self,
        approval_id: &Digest32,
        reason: String,
        operation_id: OperationId,
        revoked_at_ms: u64,
    ) -> Result<ApprovalTombstone, ProtocolError> {
        if reason.is_empty() || reason.len() > 256 {
            return Err(error(
                ProtocolErrorCode::MalformedFrame,
                "revocation reason must contain 1-256 bytes",
            ));
        }
        #[derive(Serialize)]
        struct RevocationRequest<'a> {
            approval_id: &'a Digest32,
            reason: &'a str,
            operation_id: &'a OperationId,
            revoked_at_ms: DecimalU64,
        }
        let request_digest = revocation_request_digest(&RevocationRequest {
            approval_id,
            reason: &reason,
            operation_id: &operation_id,
            revoked_at_ms: DecimalU64::new(revoked_at_ms),
        })?;
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        if let Some(result) = load_revocation_operation::<ApprovalTombstone>(
            &transaction,
            &operation_id,
            &request_digest,
        )? {
            return Ok(result);
        }
        let wallet_id: String = transaction
            .query_row(
                "SELECT wallet_id FROM approvals WHERE approval_id = ?1",
                [approval_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| error(ProtocolErrorCode::ApprovalNotFound, "approval not found"))?;
        let wallet_id = Token::new(wallet_id).map_err(malformed)?;
        if let Some(existing) = transaction
            .query_row(
                "SELECT tombstone_jcs FROM approval_tombstones WHERE approval_id = ?1",
                [approval_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?
        {
            let existing: ApprovalTombstone = serde_json::from_str(&existing).map_err(malformed)?;
            store_revocation_operation(
                &transaction,
                &operation_id,
                &wallet_id,
                &request_digest,
                &existing,
            )?;
            self.append_audit(
                &transaction,
                "approval.revocation_reconciled",
                &serde_json::json!({
                    "operation_id": operation_id,
                    "approval_id": approval_id,
                    "wallet_id": wallet_id,
                    "tombstone": existing,
                }),
            )?;
            transaction.commit().map_err(storage)?;
            return Ok(existing);
        }
        let epoch = wallet_epoch(&transaction, &wallet_id)?;
        let mut tombstone = ApprovalTombstone {
            approval_id: approval_id.clone(),
            wallet_id: wallet_id.clone(),
            wallet_revocation_epoch: DecimalU64::new(epoch),
            reason,
            operation_id,
            revoked_at_ms: DecimalU64::new(revoked_at_ms),
            issuer_service_id: Token::new("bloom-signer").expect("static token"),
            key_id: self.revocation_key_id.clone(),
            signature: Base64UrlBytes::from_bytes(&[]),
        };
        tombstone.signature = sign_revocation(
            &self.revocation_signing_key,
            APPROVAL_TOMBSTONE_DOMAIN,
            &tombstone,
        )?;
        transaction
            .execute(
                "UPDATE approvals SET active = 0 WHERE approval_id = ?1",
                [approval_id.as_str()],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "INSERT INTO approval_tombstones(approval_id, wallet_id, tombstone_jcs)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(approval_id) DO NOTHING",
                params![
                    approval_id.as_str(),
                    wallet_id.as_str(),
                    serde_jcs::to_string(&tombstone).map_err(malformed)?
                ],
            )
            .map_err(storage)?;
        store_revocation_operation(
            &transaction,
            &tombstone.operation_id,
            &wallet_id,
            &request_digest,
            &tombstone,
        )?;
        self.append_audit(
            &transaction,
            "approval.revoked",
            &serde_json::json!({
                "operation_id": tombstone.operation_id,
                "approval_id": tombstone.approval_id,
                "wallet_id": tombstone.wallet_id,
                "tombstone": tombstone,
            }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(tombstone)
    }

    pub fn revoke_all(
        &self,
        wallet_id: &Token,
        operation_id: OperationId,
        revoked_at_ms: u64,
    ) -> Result<RevocationState, ProtocolError> {
        #[derive(Serialize)]
        struct RevokeAllRequest<'a> {
            wallet_id: &'a Token,
            operation_id: &'a OperationId,
            revoked_at_ms: DecimalU64,
        }
        let request_digest = revocation_request_digest(&RevokeAllRequest {
            wallet_id,
            operation_id: &operation_id,
            revoked_at_ms: DecimalU64::new(revoked_at_ms),
        })?;
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        if let Some(result) = load_revocation_operation::<RevocationState>(
            &transaction,
            &operation_id,
            &request_digest,
        )? {
            return Ok(result);
        }
        let next_epoch = wallet_epoch(&transaction, wallet_id)?
            .checked_add(1)
            .ok_or_else(|| {
                error(
                    ProtocolErrorCode::RevocationEpochUnreconciled,
                    "wallet revocation epoch overflow",
                )
            })?;
        let mut tombstone = WalletTombstone {
            wallet_id: wallet_id.clone(),
            wallet_revocation_epoch: DecimalU64::new(next_epoch),
            operation_id: operation_id.clone(),
            revoked_at_ms: DecimalU64::new(revoked_at_ms),
            issuer_service_id: Token::new("bloom-signer").expect("static token"),
            key_id: self.revocation_key_id.clone(),
            signature: Base64UrlBytes::from_bytes(&[]),
        };
        tombstone.signature = sign_revocation(
            &self.revocation_signing_key,
            WALLET_TOMBSTONE_DOMAIN,
            &tombstone,
        )?;
        transaction
            .execute(
                "INSERT INTO wallet_state(
                    wallet_id, revocation_epoch, derivation_status,
                    derivation_registry_jcs, backup_set_jcs
                 ) VALUES (?1, ?2, 'DERIVATION_REGISTRY_MISSING', NULL, NULL)
                 ON CONFLICT(wallet_id) DO UPDATE SET
                    revocation_epoch = excluded.revocation_epoch",
                params![wallet_id.as_str(), next_epoch.to_string()],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "INSERT INTO wallet_tombstones(wallet_id, tombstone_jcs)
                 VALUES (?1, ?2)
                 ON CONFLICT(wallet_id) DO UPDATE SET tombstone_jcs = excluded.tombstone_jcs",
                params![
                    wallet_id.as_str(),
                    serde_jcs::to_string(&tombstone).map_err(malformed)?
                ],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "UPDATE approvals SET active = 0 WHERE wallet_id = ?1",
                [wallet_id.as_str()],
            )
            .map_err(storage)?;
        let mut statement = transaction
            .prepare(
                "SELECT tombstone_jcs FROM approval_tombstones
                 WHERE wallet_id = ?1 ORDER BY approval_id",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([wallet_id.as_str()], |row| row.get::<_, String>(0))
            .map_err(storage)?;
        let mut approval_tombstones = Vec::new();
        for row in rows {
            approval_tombstones.push(
                serde_json::from_str::<ApprovalTombstone>(&row.map_err(storage)?)
                    .map_err(malformed)?,
            );
        }
        drop(statement);
        let approval_tombstone_digest = Digest32::from_bytes(
            Sha256::digest(serde_jcs::to_vec(&approval_tombstones).map_err(malformed)?).into(),
        );
        let mut state = RevocationState {
            wallet_id: wallet_id.clone(),
            wallet_revocation_epoch: DecimalU64::new(next_epoch),
            wallet_tombstone: Some(tombstone),
            approval_tombstone_digest,
            approval_tombstone_count: DecimalU64::new(approval_tombstones.len() as u64),
            observed_at_ms: DecimalU64::new(revoked_at_ms),
            issuer_service_id: Token::new("bloom-signer").expect("static token"),
            key_id: self.revocation_key_id.clone(),
            signature: Base64UrlBytes::from_bytes(&[]),
        };
        state.signature = sign_revocation(
            &self.revocation_signing_key,
            REVOCATION_STATE_DOMAIN,
            &state,
        )?;
        store_revocation_operation(
            &transaction,
            &operation_id,
            wallet_id,
            &request_digest,
            &state,
        )?;
        self.append_audit(
            &transaction,
            "wallet.revoked",
            &serde_json::json!({
                "operation_id": operation_id,
                "wallet_id": wallet_id,
                "revocation_state": state,
            }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(state)
    }

    pub fn revocation_state(
        &self,
        wallet_id: &Token,
        observed_at_ms: u64,
    ) -> Result<RevocationState, ProtocolError> {
        let connection = self.connection.lock();
        let epoch = connection
            .query_row(
                "SELECT revocation_epoch FROM wallet_state WHERE wallet_id = ?1",
                [wallet_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?
            .map(|value| value.parse::<u64>().map_err(malformed))
            .transpose()?
            .unwrap_or(0);
        let wallet_tombstone = connection
            .query_row(
                "SELECT tombstone_jcs FROM wallet_tombstones WHERE wallet_id = ?1",
                [wallet_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?
            .map(|value| serde_json::from_str::<WalletTombstone>(&value).map_err(malformed))
            .transpose()?;
        let mut statement = connection
            .prepare(
                "SELECT tombstone_jcs FROM approval_tombstones
                 WHERE wallet_id = ?1 ORDER BY approval_id",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([wallet_id.as_str()], |row| row.get::<_, String>(0))
            .map_err(storage)?;
        let mut tombstones = Vec::new();
        for row in rows {
            tombstones.push(
                serde_json::from_str::<ApprovalTombstone>(&row.map_err(storage)?)
                    .map_err(malformed)?,
            );
        }
        let tombstone_digest = Digest32::from_bytes(
            Sha256::digest(serde_jcs::to_vec(&tombstones).map_err(malformed)?).into(),
        );
        let mut state = RevocationState {
            wallet_id: wallet_id.clone(),
            wallet_revocation_epoch: DecimalU64::new(epoch),
            wallet_tombstone,
            approval_tombstone_digest: tombstone_digest,
            approval_tombstone_count: DecimalU64::new(tombstones.len() as u64),
            observed_at_ms: DecimalU64::new(observed_at_ms),
            issuer_service_id: Token::new("bloom-signer").expect("static token"),
            key_id: self.revocation_key_id.clone(),
            signature: Base64UrlBytes::from_bytes(&[]),
        };
        state.signature = sign_revocation(
            &self.revocation_signing_key,
            REVOCATION_STATE_DOMAIN,
            &state,
        )?;
        Ok(state)
    }

    pub fn approval_tombstones(
        &self,
        wallet_id: &Token,
    ) -> Result<Vec<ApprovalTombstone>, ProtocolError> {
        let connection = self.connection.lock();
        let mut statement = connection
            .prepare(
                "SELECT tombstone_jcs FROM approval_tombstones
                 WHERE wallet_id = ?1 ORDER BY approval_id",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([wallet_id.as_str()], |row| row.get::<_, String>(0))
            .map_err(storage)?;
        let mut tombstones = Vec::new();
        for row in rows {
            tombstones.push(
                serde_json::from_str::<ApprovalTombstone>(&row.map_err(storage)?)
                    .map_err(malformed)?,
            );
        }
        Ok(tombstones)
    }

    pub fn validate_policy_ceremony_prepare(
        &self,
        request: &PolicyUpdateCeremonyPrepareRequest,
    ) -> Result<(), ProtocolError> {
        if request.custody.ceremony_kind != bloom_signer_api::CeremonyKind::PolicyUpdate
            || request.custody.custody_operation_id != request.update.operation_id
            || request.custody.wallet_id.as_ref() != Some(&request.update.wallet_id)
            || request.custody.key_ref.is_some()
            || request.custody.exact_terms_digest != request.update.terms_digest()?
            || request.broker_validation_receipt.update_terms_digest
                != request.custody.exact_terms_digest
            || request.broker_validation_receipt.broker_key_id != self.broker_key_id
        {
            return Err(error(
                ProtocolErrorCode::CeremonyKindMismatch,
                "policy ceremony preparation bindings differ",
            ));
        }
        let signature: [u8; 64] = request
            .broker_validation_receipt
            .broker_signature
            .decode()
            .try_into()
            .map_err(|_| {
                error(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "policy validation signature must contain 64 bytes",
                )
            })?;
        let mut message = POLICY_VALIDATION_DOMAIN.to_vec();
        message.extend_from_slice(
            &request
                .broker_validation_receipt
                .unsigned_canonical_bytes()?,
        );
        self.broker_public_key
            .verify(&message, &Signature::from_bytes(&signature))
            .map_err(|_| {
                error(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "Broker policy validation receipt signature is invalid",
                )
            })
    }

    pub(crate) fn prepare_initial_policy_effect(
        &self,
        wallet_id: &Token,
        canonical_policy: Base64UrlBytes,
        policy_signing_key_id: Token,
        unlocked: &UnlockedWallet,
    ) -> Result<CeremonyDatabaseEffect, ProtocolError> {
        if unlocked.wallet_id() != wallet_id {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "unlocked policy key belongs to a different wallet",
            ));
        }
        Ok(CeremonyDatabaseEffect::InitialPolicy {
            snapshot: sign_policy_snapshot(
                wallet_id,
                1,
                canonical_policy,
                &policy_signing_key_id,
                unlocked,
            )?,
            policy_verifying_key: Base64UrlBytes::from_bytes(&unlocked.policy_verifying_key()?),
            backend_enrollment: None,
        })
    }

    pub(crate) fn prepare_policy_update_effect(
        &self,
        request: &PolicyUpdateCeremonyPrepareRequest,
        unlocked: &UnlockedWallet,
        _verified: crate::ceremony::VerifiedCeremonyActivation,
    ) -> Result<(PolicyCommitReceipt, CeremonyDatabaseEffect), ProtocolError> {
        let update = &request.update;
        if unlocked.wallet_id() != &update.wallet_id {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "unlocked policy key belongs to a different wallet",
            ));
        }
        let proposed_digest =
            Digest32::from_bytes(Sha256::digest(update.proposed_canonical_policy.decode()).into());
        if proposed_digest != update.proposed_policy_digest {
            return Err(error(
                ProtocolErrorCode::PolicyBaselineStale,
                "proposed policy digest mismatch",
            ));
        }
        let current: (String, String, String, String) = self
            .connection
            .lock()
            .query_row(
                "SELECT version, digest, policy_signing_key_id, policy_verifying_key
                 FROM policies WHERE wallet_id = ?1",
                [update.wallet_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(storage)?;
        if current.0 != update.baseline_version.get().to_string()
            || current.1 != update.baseline_digest.as_str()
        {
            return Err(error(
                ProtocolErrorCode::PolicyBaselineStale,
                "policy compare-and-swap baseline is stale",
            ));
        }
        if current.3 != Base64UrlBytes::from_bytes(&unlocked.policy_verifying_key()?).encoded() {
            return Err(error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "unlocked per-wallet policy key does not match installed policy",
            ));
        }
        let next_version = update
            .baseline_version
            .get()
            .checked_add(1)
            .ok_or_else(|| error(ProtocolErrorCode::PolicyBaselineStale, "version overflow"))?;
        let policy_signing_key_id = Token::new(current.2).map_err(malformed)?;
        let snapshot = sign_policy_snapshot(
            &update.wallet_id,
            next_version,
            update.proposed_canonical_policy.clone(),
            &policy_signing_key_id,
            unlocked,
        )?;
        let mut receipt = PolicyCommitReceipt {
            operation_id: update.operation_id.clone(),
            wallet_id: update.wallet_id.clone(),
            previous_version: update.baseline_version.clone(),
            committed: snapshot,
            authority_diff_digest: update.authority_diff_digest.clone(),
            signer_key_id: policy_signing_key_id,
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        receipt.signer_signature = Base64UrlBytes::from_bytes(
            &unlocked.sign_policy_message(&receipt.signature_message()?)?,
        );
        Ok((
            receipt.clone(),
            CeremonyDatabaseEffect::PolicyUpdatePending(Box::new(CeremonyPolicyUpdate {
                update: update.clone(),
                validation: request.broker_validation_receipt.clone(),
                receipt,
            })),
        ))
    }

    pub fn install_initial_policy(
        &self,
        wallet_id: &Token,
        canonical_policy: Base64UrlBytes,
        policy_signing_key_id: Token,
        unlocked: &UnlockedWallet,
    ) -> Result<SignedPolicySnapshot, ProtocolError> {
        if unlocked.wallet_id() != wallet_id {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "unlocked policy key belongs to a different wallet",
            ));
        }
        let snapshot = sign_policy_snapshot(
            wallet_id,
            1,
            canonical_policy,
            &policy_signing_key_id,
            unlocked,
        )?;
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        transaction
            .execute(
                "INSERT INTO policies(
                    wallet_id, version, digest, canonical_policy, snapshot_jcs,
                    policy_signing_key_id, policy_verifying_key
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    wallet_id.as_str(),
                    snapshot.version.get().to_string(),
                    snapshot.policy_digest.as_str(),
                    snapshot.canonical_policy.encoded(),
                    serde_jcs::to_string(&snapshot).map_err(malformed)?,
                    policy_signing_key_id.as_str(),
                    Base64UrlBytes::from_bytes(&unlocked.policy_verifying_key()?).encoded()
                ],
            )
            .map_err(storage)?;
        self.append_audit(
            &transaction,
            "policy.installed",
            &serde_json::json!({
                "wallet_id": wallet_id,
                "snapshot": snapshot,
                "policy_signing_key_id": policy_signing_key_id,
            }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(snapshot)
    }

    pub fn compare_and_swap_policy(
        &self,
        request: &PolicyCompareAndSwapRequest,
    ) -> Result<PolicyCommitReceipt, ProtocolError> {
        let update = &request.update;
        let proposed_digest =
            Digest32::from_bytes(Sha256::digest(update.proposed_canonical_policy.decode()).into());
        if proposed_digest != update.proposed_policy_digest {
            return Err(error(
                ProtocolErrorCode::PolicyBaselineStale,
                "proposed policy digest mismatch",
            ));
        }
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        let committed: Option<(String, String)> = transaction
            .query_row(
                "SELECT request_jcs, receipt_jcs FROM policy_commit_receipts
                 WHERE operation_id = ?1",
                [update.operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        if let Some((request_jcs, receipt_jcs)) = committed {
            if request_jcs != serde_jcs::to_string(request).map_err(malformed)? {
                return Err(error(
                    ProtocolErrorCode::OperationIdConflict,
                    "policy operation ID was committed for different terms",
                ));
            }
            return serde_json::from_str(&receipt_jcs).map_err(malformed);
        }
        let authorization: Option<String> = transaction
            .query_row(
                "SELECT request_jcs FROM policy_authorizations WHERE operation_id = ?1",
                [update.operation_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        let authorization: PendingPolicyAuthorization = authorization
            .ok_or_else(|| {
                error(
                    ProtocolErrorCode::PolicyBaselineStale,
                    "policy ceremony has not completed",
                )
            })
            .and_then(|encoded| serde_json::from_str(&encoded).map_err(malformed))?;
        if authorization.update != request.update
            || authorization.validation != request.broker_validation_receipt
            || authorization.ceremony_receipt != request.ceremony_receipt
            || request.ceremony_receipt.ceremony_kind
                != bloom_signer_api::CeremonyKind::PolicyUpdate
            || request.ceremony_receipt.custody_operation_id != update.operation_id
        {
            return Err(error(
                ProtocolErrorCode::OperationIdConflict,
                "policy ceremony authorization binding mismatch",
            ));
        }
        let current: (String, String) = transaction
            .query_row(
                "SELECT version, digest FROM policies WHERE wallet_id = ?1",
                [update.wallet_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage)?;
        if current.0 != update.baseline_version.get().to_string()
            || current.1 != update.baseline_digest.as_str()
        {
            return Err(error(
                ProtocolErrorCode::PolicyBaselineStale,
                "policy compare-and-swap baseline is stale",
            ));
        }
        let receipt = authorization.commit_receipt;
        let changed = transaction
            .execute(
                "UPDATE policies SET version = ?4, digest = ?5,
                    canonical_policy = ?6, snapshot_jcs = ?7
                 WHERE wallet_id = ?1 AND version = ?2 AND digest = ?3",
                params![
                    update.wallet_id.as_str(),
                    update.baseline_version.get().to_string(),
                    update.baseline_digest.as_str(),
                    receipt.committed.version.get().to_string(),
                    receipt.committed.policy_digest.as_str(),
                    receipt.committed.canonical_policy.encoded(),
                    serde_jcs::to_string(&receipt.committed).map_err(malformed)?
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(error(
                ProtocolErrorCode::PolicyBaselineStale,
                "policy baseline changed before compare-and-swap commit",
            ));
        }
        transaction
            .execute(
                "INSERT INTO policy_commit_receipts(operation_id, request_jcs, receipt_jcs)
                 VALUES (?1, ?2, ?3)",
                params![
                    update.operation_id.as_str(),
                    serde_jcs::to_string(request).map_err(malformed)?,
                    serde_jcs::to_string(&receipt).map_err(malformed)?,
                ],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "DELETE FROM policy_authorizations WHERE operation_id = ?1",
                [update.operation_id.as_str()],
            )
            .map_err(storage)?;
        self.append_audit(
            &transaction,
            "policy.committed",
            &serde_json::json!({
                "operation_id": update.operation_id,
                "wallet_id": update.wallet_id,
                "baseline_version": update.baseline_version,
                "baseline_digest": update.baseline_digest,
                "proposed_policy_digest": update.proposed_policy_digest,
                "receipt": receipt,
            }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(receipt)
    }

    pub fn restore_backup(&self, backup: &SignerBackupSet) -> Result<(), ProtocolError> {
        if backup
            .custody
            .as_ref()
            .is_some_and(|custody| custody.wallet_id != backup.wallet_id)
            || backup
                .policy
                .as_ref()
                .is_some_and(|policy| policy.snapshot.wallet_id != backup.wallet_id)
        {
            return Err(error(
                ProtocolErrorCode::MalformedFrame,
                "backup records are bound to a different wallet",
            ));
        }
        if let Some(custody) = &backup.custody {
            WalletCustody::restore(custody.clone())?;
        }
        if let Some(policy) = &backup.policy {
            verify_policy_backup(policy)?;
        }
        for scoped in &backup.petal_key_scopes {
            scoped.scope.validate()?;
            if scoped.scope.wallet_id != backup.wallet_id
                || scoped.scope.parent_key_ref.backend_instance != backup.wallet_id
                || scoped.key_ref.backend != scoped.scope.parent_key_ref.backend
                || scoped.key_ref.backend_instance != scoped.scope.parent_key_ref.backend_instance
                || scoped.key_ref.derivation.is_none()
                || scoped.expires_at_ms.get()
                    != scoped
                        .created_at_ms
                        .get()
                        .checked_add(scoped.scope.maximum_lifetime_ms.get())
                        .ok_or_else(|| {
                            error(
                                ProtocolErrorCode::MalformedFrame,
                                "Petal key scope backup lifetime overflows",
                            )
                        })?
            {
                return Err(error(
                    ProtocolErrorCode::KeyrefMismatch,
                    "Petal key scope backup binding is invalid",
                ));
            }
        }
        let revocation_public_key = self.revocation_signing_key.verifying_key();
        for tombstone in &backup.approval_tombstones {
            verify_approval_tombstone(tombstone, &revocation_public_key)?;
            if tombstone.wallet_id != backup.wallet_id
                || tombstone.wallet_revocation_epoch.get() > backup.wallet_revocation_epoch.get()
                || tombstone.issuer_service_id.as_str() != "bloom-signer"
                || tombstone.key_id != self.revocation_key_id
            {
                return Err(error(
                    ProtocolErrorCode::RevocationEpochUnreconciled,
                    "approval tombstone backup binding is invalid",
                ));
            }
        }
        if let Some(tombstone) = &backup.wallet_tombstone {
            verify_wallet_tombstone(tombstone, &revocation_public_key)?;
            if tombstone.wallet_id != backup.wallet_id
                || tombstone.wallet_revocation_epoch != backup.wallet_revocation_epoch
                || tombstone.issuer_service_id.as_str() != "bloom-signer"
                || tombstone.key_id != self.revocation_key_id
            {
                return Err(error(
                    ProtocolErrorCode::RevocationEpochUnreconciled,
                    "wallet tombstone backup binding is invalid",
                ));
            }
        }
        let reconstructed_registry =
            derivation_registry_from_enrollments(&backup.backend_enrollments)?;
        if backup.derivation_registry != reconstructed_registry {
            return Err(error(
                ProtocolErrorCode::MalformedFrame,
                "top-level derivation registry differs from encrypted backend enrollment",
            ));
        }
        let mut connection = self.connection.lock();
        let transaction = self.mutation_transaction(&mut connection)?;
        let audit_keys = self.audit_keys.read();
        let mut backup_key_ids = std::collections::BTreeSet::new();
        for backed_up_key in &backup.audit_verifying_keys {
            if !backup_key_ids.insert(backed_up_key.key_id.clone()) {
                return Err(malformed(
                    "backup audit keyring contains a duplicate key ID",
                ));
            }
            let encoded: [u8; 32] = backed_up_key
                .verifying_key
                .decode()
                .try_into()
                .map_err(|_| malformed("backup audit public key must contain 32 bytes"))?;
            let backed_up_key_value = VerifyingKey::from_bytes(&encoded)
                .map_err(|_| malformed("backup audit public key is invalid"))?;
            if audit_keys.trusted_keys.get(&backed_up_key.key_id) != Some(&backed_up_key_value) {
                return Err(error(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "backup audit keyring differs from locally pinned audit keys",
                ));
            }
        }
        if !backup_key_ids.contains(&audit_keys.current_key_id)
            || backup
                .audit_entries
                .iter()
                .any(|entry| !backup_key_ids.contains(&entry.signing_key_id))
        {
            return Err(error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "backup audit keyring is incomplete for its journal",
            ));
        }
        restore_audit_entries(
            &transaction,
            &backup.audit_entries,
            &backup.audit_rotations,
            &audit_keys.current_key_id,
            &audit_keys.trusted_keys,
        )?;
        let current_epoch = wallet_epoch(&transaction, &backup.wallet_id)?;
        if backup.wallet_revocation_epoch.get() < current_epoch {
            return Err(error(
                ProtocolErrorCode::RevocationEpochUnreconciled,
                "backup cannot lower wallet revocation epoch",
            ));
        }
        for approval in &backup.approvals {
            if approval.terms.wallet_id != backup.wallet_id
                || approval.terms.approval_id()? != approval.approval_id
            {
                return Err(error(
                    ProtocolErrorCode::MalformedFrame,
                    "backup approval identity or wallet binding is invalid",
                ));
            }
            let canonical_terms =
                String::from_utf8(approval.terms.canonical_bytes()?).map_err(malformed)?;
            let existing: Option<(String, String, String)> = transaction
                .query_row(
                    "SELECT terms_jcs, committed_operations, committed_signatures
                     FROM approvals WHERE approval_id = ?1",
                    [approval.approval_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(storage)?;
            if existing
                .as_ref()
                .is_some_and(|(terms, operations, signatures)| {
                    terms != &canonical_terms
                        || operations.parse::<u64>().ok()
                            > Some(approval.committed_operations.get())
                        || signatures.parse::<u64>().ok()
                            > Some(approval.committed_signatures.get())
                })
            {
                return Err(error(
                    ProtocolErrorCode::RevocationEpochUnreconciled,
                    "backup cannot lower parser-free counters",
                ));
            }
            let tombstoned = backup
                .approval_tombstones
                .iter()
                .any(|tombstone| tombstone.approval_id == approval.approval_id);
            transaction
                .execute(
                    "INSERT INTO approvals(
                        approval_id, wallet_id, terms_jcs, active,
                        committed_operations, committed_signatures
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(approval_id) DO UPDATE SET
                        active = CASE
                            WHEN approvals.active = 0 OR excluded.active = 0 THEN 0
                            ELSE 1
                        END,
                        committed_operations = excluded.committed_operations,
                        committed_signatures = excluded.committed_signatures",
                    params![
                        approval.approval_id.as_str(),
                        backup.wallet_id.as_str(),
                        canonical_terms,
                        approval.active && !tombstoned,
                        approval.committed_operations.get().to_string(),
                        approval.committed_signatures.get().to_string()
                    ],
                )
                .map_err(storage)?;
        }
        if backup.approval_tombstones.iter().any(|tombstone| {
            !backup
                .approvals
                .iter()
                .any(|approval| approval.approval_id == tombstone.approval_id)
        }) {
            return Err(error(
                ProtocolErrorCode::MalformedFrame,
                "backup approval tombstone has no approval record",
            ));
        }
        for tombstone in &backup.approval_tombstones {
            let canonical = serde_jcs::to_string(tombstone).map_err(malformed)?;
            let existing: Option<String> = transaction
                .query_row(
                    "SELECT tombstone_jcs FROM approval_tombstones WHERE approval_id = ?1",
                    [tombstone.approval_id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage)?;
            if existing.as_ref().is_some_and(|value| value != &canonical) {
                return Err(error(
                    ProtocolErrorCode::RevocationEpochUnreconciled,
                    "backup approval tombstone conflicts with durable tombstone",
                ));
            }
            transaction
                .execute(
                    "INSERT INTO approval_tombstones(approval_id, wallet_id, tombstone_jcs)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(approval_id) DO NOTHING",
                    params![
                        tombstone.approval_id.as_str(),
                        backup.wallet_id.as_str(),
                        canonical
                    ],
                )
                .map_err(storage)?;
        }
        if let Some(tombstone) = &backup.wallet_tombstone {
            let canonical = serde_jcs::to_string(tombstone).map_err(malformed)?;
            let existing: Option<String> = transaction
                .query_row(
                    "SELECT tombstone_jcs FROM wallet_tombstones WHERE wallet_id = ?1",
                    [backup.wallet_id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage)?;
            if existing.as_ref().is_some_and(|value| value != &canonical) {
                return Err(error(
                    ProtocolErrorCode::RevocationEpochUnreconciled,
                    "backup wallet tombstone conflicts with durable tombstone",
                ));
            }
            transaction
                .execute(
                    "INSERT INTO wallet_tombstones(wallet_id, tombstone_jcs)
                     VALUES (?1, ?2)
                     ON CONFLICT(wallet_id) DO UPDATE SET
                        tombstone_jcs = excluded.tombstone_jcs",
                    params![backup.wallet_id.as_str(), canonical],
                )
                .map_err(storage)?;
        }
        for counter in &backup.approval_counters {
            let current: Option<(String, String)> = transaction
                .query_row(
                    "SELECT committed_operations, committed_signatures
                     FROM approvals WHERE approval_id = ?1",
                    [counter.approval_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(storage)?;
            if current.as_ref().is_some_and(|(operations, signatures)| {
                operations.parse::<u64>().ok() > Some(counter.committed_operations.get())
                    || signatures.parse::<u64>().ok() > Some(counter.committed_signatures.get())
            }) {
                return Err(error(
                    ProtocolErrorCode::RevocationEpochUnreconciled,
                    "backup cannot lower parser-free counters",
                ));
            }
            if current.is_some() {
                transaction
                    .execute(
                        "UPDATE approvals SET committed_operations = ?2,
                            committed_signatures = ?3 WHERE approval_id = ?1",
                        params![
                            counter.approval_id.as_str(),
                            counter.committed_operations.get().to_string(),
                            counter.committed_signatures.get().to_string()
                        ],
                    )
                    .map_err(storage)?;
            }
        }
        let (status, registry) = match &backup.derivation_registry {
            Some(registry) => (
                "READY",
                Some(serde_jcs::to_string(registry).map_err(malformed)?),
            ),
            None => ("DERIVATION_REGISTRY_MISSING", None),
        };
        transaction
            .execute(
                "INSERT INTO wallet_state(
                    wallet_id, revocation_epoch, derivation_status,
                    derivation_registry_jcs, backup_set_jcs
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(wallet_id) DO UPDATE SET
                    revocation_epoch = excluded.revocation_epoch,
                    derivation_status = excluded.derivation_status,
                    derivation_registry_jcs = excluded.derivation_registry_jcs,
                    backup_set_jcs = excluded.backup_set_jcs",
                params![
                    backup.wallet_id.as_str(),
                    backup.wallet_revocation_epoch.get().to_string(),
                    status,
                    registry,
                    serde_jcs::to_string(backup).map_err(malformed)?
                ],
            )
            .map_err(storage)?;
        for scoped in &backup.petal_key_scopes {
            let key_ref_jcs = serde_jcs::to_string(&scoped.key_ref).map_err(malformed)?;
            let scope_jcs = serde_jcs::to_string(&scoped.scope).map_err(malformed)?;
            let existing: Option<(String, String, String, String)> = transaction
                .query_row(
                    "SELECT e.key_ref_jcs, p.scope_jcs, p.created_at_ms, p.expires_at_ms
                     FROM petal_key_scopes p
                     JOIN enrolled_keys e ON e.key_fingerprint = p.key_fingerprint
                     WHERE p.key_fingerprint = ?1",
                    [scoped.key_ref.public_key_fingerprint.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(storage)?;
            let expected = (
                key_ref_jcs.clone(),
                scope_jcs.clone(),
                scoped.created_at_ms.get().to_string(),
                scoped.expires_at_ms.get().to_string(),
            );
            if existing.as_ref().is_some_and(|stored| stored != &expected) {
                return Err(error(
                    ProtocolErrorCode::OperationIdConflict,
                    "Petal key scope backup conflicts with durable scope",
                ));
            }
            transaction
                .execute(
                    "INSERT INTO enrolled_keys(
                        key_fingerprint, key_ref_jcs, available, authority_class, wallet_id
                     ) VALUES (?1, ?2, 0, 'petal', ?3)
                     ON CONFLICT(key_fingerprint) DO UPDATE SET
                        key_ref_jcs = excluded.key_ref_jcs,
                        authority_class = 'petal',
                        wallet_id = excluded.wallet_id",
                    params![
                        scoped.key_ref.public_key_fingerprint.as_str(),
                        key_ref_jcs,
                        scoped.scope.wallet_id.as_str(),
                    ],
                )
                .map_err(storage)?;
            transaction
                .execute(
                    "INSERT INTO petal_key_scopes(
                        key_fingerprint, wallet_id, custody_operation_id,
                        scope_digest, scope_jcs, created_at_ms, expires_at_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(key_fingerprint) DO NOTHING",
                    params![
                        scoped.key_ref.public_key_fingerprint.as_str(),
                        scoped.scope.wallet_id.as_str(),
                        scoped.scope.custody_operation_id.as_str(),
                        scoped.scope.digest()?.as_str(),
                        scope_jcs,
                        scoped.created_at_ms.get().to_string(),
                        scoped.expires_at_ms.get().to_string(),
                    ],
                )
                .map_err(storage)?;
        }
        if let Some(policy) = &backup.policy {
            let current_policy: Option<(String, String)> = transaction
                .query_row(
                    "SELECT version, snapshot_jcs FROM policies WHERE wallet_id = ?1",
                    [backup.wallet_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(storage)?;
            let backup_snapshot = serde_jcs::to_string(&policy.snapshot).map_err(malformed)?;
            if current_policy.as_ref().is_some_and(|(version, snapshot)| {
                version.parse::<u64>().ok().is_none_or(|version| {
                    version > policy.snapshot.version.get()
                        || (version == policy.snapshot.version.get()
                            && snapshot != &backup_snapshot)
                })
            }) {
                return Err(error(
                    ProtocolErrorCode::PolicyBaselineStale,
                    "backup cannot lower policy version",
                ));
            }
            transaction
                .execute(
                    "INSERT INTO policies(
                        wallet_id, version, digest, canonical_policy, snapshot_jcs,
                        policy_signing_key_id, policy_verifying_key
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(wallet_id) DO UPDATE SET
                        version = excluded.version,
                        digest = excluded.digest,
                        canonical_policy = excluded.canonical_policy,
                        snapshot_jcs = excluded.snapshot_jcs,
                        policy_signing_key_id = excluded.policy_signing_key_id,
                        policy_verifying_key = excluded.policy_verifying_key",
                    params![
                        backup.wallet_id.as_str(),
                        policy.snapshot.version.get().to_string(),
                        policy.snapshot.policy_digest.as_str(),
                        policy.snapshot.canonical_policy.encoded(),
                        backup_snapshot,
                        policy.snapshot.policy_signing_key_id.as_str(),
                        policy.policy_verifying_key.encoded()
                    ],
                )
                .map_err(storage)?;
        }
        for enrollment in &backup.backend_enrollments {
            for key_ref in &enrollment.pinned_keys {
                if key_ref.backend != enrollment.backend
                    || key_ref.backend_instance != enrollment.backend_instance
                {
                    return Err(error(
                        ProtocolErrorCode::KeyrefMismatch,
                        "backup backend enrollment and pinned KeyRef differ",
                    ));
                }
                key_ref.validate()?;
                transaction
                    .execute(
                        "INSERT INTO enrolled_keys(
                            key_fingerprint, key_ref_jcs, available, authority_class, wallet_id
                         ) VALUES (?1, ?2, 0, 'wallet_root', ?3)
                         ON CONFLICT(key_fingerprint) DO UPDATE SET
                            key_ref_jcs = excluded.key_ref_jcs,
                            available = 0,
                            authority_class = 'wallet_root',
                            wallet_id = excluded.wallet_id",
                        params![
                            key_ref.public_key_fingerprint.as_str(),
                            serde_jcs::to_string(key_ref).map_err(malformed)?,
                            backup.wallet_id.as_str(),
                        ],
                    )
                    .map_err(storage)?;
            }
        }
        for operation in &backup.operations {
            if !backup
                .approvals
                .iter()
                .any(|approval| approval.approval_id == operation.approval_id)
            {
                return Err(error(
                    ProtocolErrorCode::MalformedFrame,
                    "backup operation refers to an absent approval",
                ));
            }
            let expected = (
                operation.operation_digest.as_str().to_owned(),
                operation.retry_binding_digest.as_str().to_owned(),
                operation.approval_id.as_str().to_owned(),
                operation.signature_count.get().to_string(),
                operation.accepted_at_ms.get().to_string(),
                operation.state.as_str().to_owned(),
                operation
                    .normalized_result
                    .as_ref()
                    .map(|result| result.encoded().to_owned()),
            );
            let existing: Option<StoredOperationTuple> = transaction
                .query_row(
                    "SELECT operation_digest, retry_binding_digest, approval_id,
                                signature_count, accepted_at_ms, state, normalized_result
                         FROM operations WHERE operation_id = ?1",
                    [operation.operation_id.as_str()],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .optional()
                .map_err(storage)?;
            if existing.as_ref().is_some_and(|stored| stored != &expected) {
                return Err(error(
                    ProtocolErrorCode::OperationIdConflict,
                    "backup operation conflicts with durable operation state",
                ));
            }
            transaction
                .execute(
                    "INSERT INTO operations(
                        operation_id, operation_digest, retry_binding_digest, approval_id,
                        signature_count, accepted_at_ms, state, normalized_result
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(operation_id) DO NOTHING",
                    params![
                        operation.operation_id.as_str(),
                        operation.operation_digest.as_str(),
                        operation.retry_binding_digest.as_str(),
                        operation.approval_id.as_str(),
                        operation.signature_count.get().to_string(),
                        operation.accepted_at_ms.get().to_string(),
                        operation.state.as_str(),
                        operation
                            .normalized_result
                            .as_ref()
                            .map(Base64UrlBytes::encoded)
                    ],
                )
                .map_err(storage)?;
            let expected_anchor = (
                operation
                    .observed_utc_ms
                    .as_ref()
                    .map(|value| value.get().to_string()),
                operation.monotonic_anchor_ns.get().to_string(),
                operation.clock_boot_epoch.to_string(),
            );
            let existing_anchor: Option<(Option<String>, String, String)> = transaction
                .query_row(
                    "SELECT observed_utc_ms, monotonic_anchor_ns, boot_epoch
                     FROM operation_clock_anchors WHERE operation_id = ?1",
                    [operation.operation_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(storage)?;
            if existing_anchor
                .as_ref()
                .is_some_and(|stored| stored != &expected_anchor)
            {
                return Err(error(
                    ProtocolErrorCode::OperationIdConflict,
                    "backup operation conflicts with its durable clock anchor",
                ));
            }
            transaction
                .execute(
                    "INSERT INTO operation_clock_anchors(
                        operation_id, observed_utc_ms, monotonic_anchor_ns, boot_epoch
                     ) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(operation_id) DO NOTHING",
                    params![
                        operation.operation_id.as_str(),
                        expected_anchor.0,
                        expected_anchor.1,
                        expected_anchor.2,
                    ],
                )
                .map_err(storage)?;
        }
        for attempt in &backup.attempts {
            if !backup
                .operations
                .iter()
                .any(|operation| operation.operation_id == attempt.operation_id)
            {
                return Err(error(
                    ProtocolErrorCode::MalformedFrame,
                    "backup attempt refers to an absent operation",
                ));
            }
            let existing: Option<(String, String)> = transaction
                .query_row(
                    "SELECT attempt_digest, operation_id FROM attempts WHERE attempt_id = ?1",
                    [attempt.attempt_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(storage)?;
            if existing.as_ref().is_some_and(|stored| {
                stored
                    != &(
                        attempt.attempt_digest.as_str().to_owned(),
                        attempt.operation_id.as_str().to_owned(),
                    )
            }) {
                return Err(error(
                    ProtocolErrorCode::CeremonyReplay,
                    "backup attempt conflicts with consumed attempt state",
                ));
            }
            transaction
                .execute(
                    "INSERT INTO attempts(attempt_id, attempt_digest, operation_id)
                     VALUES (?1, ?2, ?3) ON CONFLICT(attempt_id) DO NOTHING",
                    params![
                        attempt.attempt_id.as_str(),
                        attempt.attempt_digest.as_str(),
                        attempt.operation_id.as_str()
                    ],
                )
                .map_err(storage)?;
        }
        for operation in &backup.revocation_operations {
            let result_jcs =
                String::from_utf8(operation.canonical_result.decode()).map_err(malformed)?;
            let existing: Option<(String, String, String)> = transaction
                .query_row(
                    "SELECT wallet_id, request_digest, result_jcs
                     FROM revocation_operations WHERE operation_id = ?1",
                    [operation.operation_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(storage)?;
            let expected = (
                backup.wallet_id.as_str().to_owned(),
                operation.request_digest.as_str().to_owned(),
                result_jcs.clone(),
            );
            if existing.as_ref().is_some_and(|stored| stored != &expected) {
                return Err(error(
                    ProtocolErrorCode::OperationIdConflict,
                    "backup revocation operation conflicts with durable state",
                ));
            }
            transaction
                .execute(
                    "INSERT INTO revocation_operations(
                        operation_id, wallet_id, request_digest, result_jcs
                     ) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(operation_id) DO NOTHING",
                    params![
                        operation.operation_id.as_str(),
                        backup.wallet_id.as_str(),
                        operation.request_digest.as_str(),
                        result_jcs
                    ],
                )
                .map_err(storage)?;
        }
        self.append_audit(
            &transaction,
            "custody.import",
            &serde_json::json!({
                "wallet_id": backup.wallet_id,
                "revocation_epoch": backup.wallet_revocation_epoch,
                "backup_digest": Digest32::from_bytes(
                    Sha256::digest(serde_jcs::to_vec(backup).map_err(malformed)?).into()
                ),
            }),
        )?;
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    pub fn export_backup(
        &self,
        wallet_id: &Token,
        custody: Option<WalletCustodyBackup>,
        backend_enrollments: Vec<BackendEnrollmentBackup>,
    ) -> Result<SignerBackupSet, ProtocolError> {
        if custody
            .as_ref()
            .is_some_and(|record| &record.wallet_id != wallet_id)
        {
            return Err(error(
                ProtocolErrorCode::MalformedFrame,
                "custody export belongs to a different wallet",
            ));
        }
        let mut raw_connection = self.connection.lock();
        let connection = self.mutation_transaction(&mut raw_connection)?;
        let derivation_registry = derivation_registry_from_enrollments(&backend_enrollments)?;
        let wallet_revocation_epoch = DecimalU64::new(
            connection
                .query_row(
                    "SELECT revocation_epoch FROM wallet_state WHERE wallet_id = ?1",
                    [wallet_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(storage)?
                .map(|value| value.parse::<u64>().map_err(malformed))
                .transpose()?
                .unwrap_or(0),
        );
        let policy: Option<(String, String)> = connection
            .query_row(
                "SELECT snapshot_jcs, policy_verifying_key FROM policies WHERE wallet_id = ?1",
                [wallet_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        let policy = policy
            .map(
                |(snapshot, verifying_key)| -> Result<PolicyBackup, ProtocolError> {
                    Ok(PolicyBackup {
                        snapshot: serde_json::from_str(&snapshot).map_err(malformed)?,
                        policy_verifying_key: Base64UrlBytes::parse(verifying_key)?,
                    })
                },
            )
            .transpose()?;
        let mut statement = connection
            .prepare(
                "SELECT approval_id, terms_jcs, active,
                        committed_operations, committed_signatures
                 FROM approvals WHERE wallet_id = ?1 ORDER BY approval_id",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([wallet_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(storage)?;
        let mut approval_counters = Vec::new();
        let mut approvals = Vec::new();
        for row in rows {
            let (approval_id, terms_jcs, active, operations, signatures) = row.map_err(storage)?;
            let approval_id = Digest32::new(approval_id).map_err(malformed)?;
            approval_counters.push(ApprovalCounterBackup {
                approval_id: approval_id.clone(),
                committed_operations: DecimalU64::new(operations.parse().map_err(malformed)?),
                committed_signatures: DecimalU64::new(signatures.parse().map_err(malformed)?),
            });
            approvals.push(ApprovalStateBackup {
                approval_id: approval_id.clone(),
                terms: serde_json::from_str(&terms_jcs).map_err(malformed)?,
                active,
                committed_operations: DecimalU64::new(operations.parse().map_err(malformed)?),
                committed_signatures: DecimalU64::new(signatures.parse().map_err(malformed)?),
            });
        }
        drop(statement);
        let mut tombstone_statement = connection
            .prepare(
                "SELECT tombstone_jcs FROM approval_tombstones
                 WHERE wallet_id = ?1 ORDER BY approval_id",
            )
            .map_err(storage)?;
        let tombstone_rows = tombstone_statement
            .query_map([wallet_id.as_str()], |row| row.get::<_, String>(0))
            .map_err(storage)?;
        let mut approval_tombstones = Vec::new();
        for row in tombstone_rows {
            approval_tombstones.push(
                serde_json::from_str::<ApprovalTombstone>(&row.map_err(storage)?)
                    .map_err(malformed)?,
            );
        }
        drop(tombstone_statement);
        let wallet_tombstone = connection
            .query_row(
                "SELECT tombstone_jcs FROM wallet_tombstones WHERE wallet_id = ?1",
                [wallet_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage)?
            .map(|value| serde_json::from_str::<WalletTombstone>(&value).map_err(malformed))
            .transpose()?;
        let mut operation_statement = connection
            .prepare(
                "SELECT operations.operation_id, operation_digest, retry_binding_digest,
                        approval_id, signature_count, accepted_at_ms, state, normalized_result,
                        operation_clock_anchors.observed_utc_ms,
                        operation_clock_anchors.monotonic_anchor_ns,
                        operation_clock_anchors.boot_epoch
                 FROM operations
                 LEFT JOIN operation_clock_anchors USING(operation_id)
                 WHERE approval_id IN (
                    SELECT approval_id FROM approvals WHERE wallet_id = ?1
                 ) ORDER BY operation_id",
            )
            .map_err(storage)?;
        let operation_rows = operation_statement
            .query_map([wallet_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            })
            .map_err(storage)?;
        let mut operations = Vec::new();
        for row in operation_rows {
            let (
                operation_id,
                operation_digest,
                retry_binding_digest,
                approval_id,
                signature_count,
                accepted_at_ms,
                state,
                normalized_result,
                observed_utc_ms,
                monotonic_anchor_ns,
                clock_boot_epoch,
            ) = row.map_err(storage)?;
            let monotonic_anchor_ns = monotonic_anchor_ns.unwrap_or_else(|| "0".into());
            let clock_boot_epoch =
                clock_boot_epoch.unwrap_or_else(|| zero_boot_epoch().to_string());
            operations.push(OperationStateBackup {
                operation_id: OperationId::new(operation_id).map_err(malformed)?,
                operation_digest: Digest32::new(operation_digest).map_err(malformed)?,
                retry_binding_digest: Digest32::new(retry_binding_digest).map_err(malformed)?,
                approval_id: Digest32::new(approval_id).map_err(malformed)?,
                signature_count: DecimalU64::new(signature_count.parse().map_err(malformed)?),
                accepted_at_ms: DecimalU64::new(accepted_at_ms.parse().map_err(malformed)?),
                observed_utc_ms: observed_utc_ms
                    .map(|value| value.parse().map(DecimalU64::new).map_err(malformed))
                    .transpose()?,
                monotonic_anchor_ns: DecimalU64::new(
                    monotonic_anchor_ns.parse().map_err(malformed)?,
                ),
                clock_boot_epoch: clock_boot_epoch.parse().map_err(malformed)?,
                state: BackupOperationState::parse(&state)?,
                normalized_result: normalized_result.map(Base64UrlBytes::parse).transpose()?,
            });
        }
        drop(operation_statement);
        let mut attempt_statement = connection
            .prepare(
                "SELECT attempt_id, attempt_digest, operation_id FROM attempts
                 WHERE operation_id IN (
                    SELECT operation_id FROM operations WHERE approval_id IN (
                        SELECT approval_id FROM approvals WHERE wallet_id = ?1
                    )
                 ) ORDER BY attempt_id",
            )
            .map_err(storage)?;
        let attempt_rows = attempt_statement
            .query_map([wallet_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(storage)?;
        let mut attempts = Vec::new();
        for row in attempt_rows {
            let (attempt_id, attempt_digest, operation_id) = row.map_err(storage)?;
            attempts.push(AttemptStateBackup {
                attempt_id: Digest32::new(attempt_id).map_err(malformed)?,
                attempt_digest: Digest32::new(attempt_digest).map_err(malformed)?,
                operation_id: OperationId::new(operation_id).map_err(malformed)?,
            });
        }
        drop(attempt_statement);
        let mut revocation_statement = connection
            .prepare(
                "SELECT operation_id, request_digest, result_jcs
                 FROM revocation_operations WHERE wallet_id = ?1 ORDER BY operation_id",
            )
            .map_err(storage)?;
        let revocation_rows = revocation_statement
            .query_map([wallet_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(storage)?;
        let mut revocation_operations = Vec::new();
        for row in revocation_rows {
            let (operation_id, request_digest, result_jcs) = row.map_err(storage)?;
            revocation_operations.push(RevocationOperationBackup {
                operation_id: OperationId::new(operation_id).map_err(malformed)?,
                request_digest: Digest32::new(request_digest).map_err(malformed)?,
                canonical_result: Base64UrlBytes::from_bytes(result_jcs.as_bytes()),
            });
        }
        drop(revocation_statement);
        let mut scope_statement = connection
            .prepare(
                "SELECT e.key_ref_jcs, p.scope_jcs, p.created_at_ms, p.expires_at_ms
                 FROM petal_key_scopes p
                 JOIN enrolled_keys e ON e.key_fingerprint = p.key_fingerprint
                 WHERE p.wallet_id = ?1 ORDER BY p.scope_digest",
            )
            .map_err(storage)?;
        let scope_rows = scope_statement
            .query_map([wallet_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(storage)?;
        let mut petal_key_scopes = Vec::new();
        for row in scope_rows {
            let (key_ref, scope, created_at_ms, expires_at_ms) = row.map_err(storage)?;
            petal_key_scopes.push(PetalKeyScopeBackup {
                key_ref: serde_json::from_str(&key_ref).map_err(malformed)?,
                scope: serde_json::from_str(&scope).map_err(malformed)?,
                created_at_ms: DecimalU64::new(created_at_ms.parse().map_err(malformed)?),
                expires_at_ms: DecimalU64::new(expires_at_ms.parse().map_err(malformed)?),
            });
        }
        drop(scope_statement);
        let audit_entries = load_audit_entries(&connection)?;
        let audit_rotations = load_audit_rotations(&connection)?
            .into_values()
            .collect::<Vec<_>>();
        let audit_verifying_keys = self
            .audit_keys
            .read()
            .trusted_keys
            .iter()
            .map(|(key_id, key)| AuditPublicKeyBackup {
                key_id: key_id.clone(),
                verifying_key: Base64UrlBytes::from_bytes(&key.to_bytes()),
            })
            .collect();
        let mut backup = SignerBackupSet {
            wallet_id: wallet_id.clone(),
            wallet_revocation_epoch,
            custody,
            derivation_registry,
            backend_enrollments,
            policy,
            petal_key_scopes,
            approvals,
            approval_tombstones,
            wallet_tombstone,
            operations,
            attempts,
            revocation_operations,
            approval_counters,
            audit_entries,
            audit_rotations,
            audit_verifying_keys,
        };
        self.append_audit(
            &connection,
            "custody.export",
            &serde_json::json!({
                "wallet_id": wallet_id,
                // Exclude the journal from this content digest so the export
                // event can itself be included in the returned journal
                // without circular digest construction.
                "backup_digest": backup_export_material_digest(&backup)?,
            }),
        )?;
        backup.audit_entries = load_audit_entries(&connection)?;
        backup.audit_rotations = load_audit_rotations(&connection)?.into_values().collect();
        connection.commit().map_err(storage)?;
        Ok(backup)
    }

    pub fn derivation_status(
        &self,
        wallet_id: &Token,
    ) -> Result<WalletDerivationStatus, ProtocolError> {
        let value: Option<String> = self
            .connection
            .lock()
            .query_row(
                "SELECT derivation_status FROM wallet_state WHERE wallet_id = ?1",
                [wallet_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        match value.as_deref() {
            Some("READY") => Ok(WalletDerivationStatus::Ready),
            Some("DERIVATION_REGISTRY_MISSING") | None => {
                Ok(WalletDerivationStatus::DerivationRegistryMissing)
            }
            _ => Err(error(
                ProtocolErrorCode::MalformedFrame,
                "unknown derivation status in durable state",
            )),
        }
    }

    pub fn require_derivation_ready(&self, wallet_id: &Token) -> Result<(), ProtocolError> {
        if self.derivation_status(wallet_id)? != WalletDerivationStatus::Ready {
            return Err(error(
                ProtocolErrorCode::ServiceUnavailable,
                "derivation registry is missing; new child allocation is disabled",
            ));
        }
        Ok(())
    }

    fn verify_broker_signature(&self, request: &SignRequest) -> Result<(), ProtocolError> {
        if request.unsigned.issuer_service_id.as_str() != "bloom-broker"
            || request.unsigned.broker_signing_key_id != self.broker_key_id
        {
            return Err(error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "broker signing key ID mismatch",
            ));
        }
        let bytes: [u8; 64] = request.broker_signature.decode().try_into().map_err(|_| {
            error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "broker signature must be 64 bytes",
            )
        })?;
        let attempt_digest = hex::decode(request.unsigned.attempt_digest.as_str())
            .map_err(|_| malformed("attempt digest is not canonical hex"))?;
        self.broker_public_key
            .verify(&attempt_digest, &Signature::from_bytes(&bytes))
            .map_err(|_| {
                error(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "broker SignRequest signature is invalid",
                )
            })
    }
}

fn ensure_column(
    connection: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), ProtocolError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(storage)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    drop(statement);
    if !columns.iter().any(|candidate| candidate == column) {
        connection
            .execute(
                &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
                [],
            )
            .map_err(storage)?;
    }
    Ok(())
}

/// Older databases recorded a root key without recording which wallet enrolled
/// it, then reconstructed ownership from `backend_instance`.  That locator is
/// shared by keys (notably AWS KMS keys) and is not an identity.  We can safely
/// recover the only unambiguous legacy layout; multi-wallet legacy databases
/// deliberately remain unbound and fail closed until re-enrolled.
fn backfill_unambiguous_wallet_root_bindings(connection: &Connection) -> Result<(), ProtocolError> {
    let wallets = connection
        .prepare("SELECT wallet_id FROM policies ORDER BY wallet_id")
        .map_err(storage)?
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    let [wallet_id] = wallets.as_slice() else {
        return Ok(());
    };
    let enrollments = connection
        .prepare("SELECT enrollment_jcs FROM ceremony_backend_enrollments")
        .map_err(storage)?
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    for encoded in enrollments {
        let enrollment: BackendEnrollmentBackup =
            serde_json::from_str(&encoded).map_err(malformed)?;
        for key_ref in enrollment.pinned_keys {
            connection
                .execute(
                    "UPDATE enrolled_keys
                     SET authority_class = 'wallet_root', wallet_id = ?1
                     WHERE key_fingerprint = ?2
                       AND authority_class = 'unscoped' AND wallet_id IS NULL",
                    [wallet_id, key_ref.public_key_fingerprint.as_str()],
                )
                .map_err(storage)?;
        }
    }
    Ok(())
}

fn sign_policy_snapshot(
    wallet_id: &Token,
    version: u64,
    canonical_policy: Base64UrlBytes,
    policy_signing_key_id: &Token,
    unlocked: &UnlockedWallet,
) -> Result<SignedPolicySnapshot, ProtocolError> {
    let policy_digest = Digest32::from_bytes(Sha256::digest(canonical_policy.decode()).into());
    let mut snapshot = SignedPolicySnapshot {
        wallet_id: wallet_id.clone(),
        version: DecimalU64::new(version),
        canonical_policy,
        policy_digest,
        policy_signing_key_id: policy_signing_key_id.clone(),
        policy_verifying_key: Base64UrlBytes::from_bytes(&unlocked.policy_verifying_key()?),
        signer_signature: Base64UrlBytes::from_bytes(&[]),
    };
    let mut message = POLICY_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&snapshot).map_err(malformed)?);
    snapshot.signer_signature =
        Base64UrlBytes::from_bytes(&unlocked.sign_policy_message(&message)?);
    Ok(snapshot)
}

fn sign_revocation<T: Serialize>(
    key: &SigningKey,
    domain: &[u8],
    unsigned: &T,
) -> Result<Base64UrlBytes, ProtocolError> {
    let mut message = domain.to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(unsigned).map_err(malformed)?);
    Ok(Base64UrlBytes::from_bytes(&key.sign(&message).to_bytes()))
}

fn revocation_request_digest<T: Serialize>(request: &T) -> Result<Digest32, ProtocolError> {
    let mut hasher = Sha256::new();
    hasher.update(REVOCATION_OPERATION_DOMAIN);
    hasher.update(serde_jcs::to_vec(request).map_err(malformed)?);
    Ok(Digest32::from_bytes(hasher.finalize().into()))
}

fn load_revocation_operation<T: for<'de> Deserialize<'de>>(
    transaction: &Transaction<'_>,
    operation_id: &OperationId,
    request_digest: &Digest32,
) -> Result<Option<T>, ProtocolError> {
    let existing: Option<(String, String)> = transaction
        .query_row(
            "SELECT request_digest, result_jcs FROM revocation_operations
             WHERE operation_id = ?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    match existing {
        Some((stored_digest, _)) if stored_digest != request_digest.as_str() => Err(error(
            ProtocolErrorCode::OperationIdConflict,
            "revocation operation ID was reused with changed request fields",
        )),
        Some((_, result)) => serde_json::from_str(&result).map(Some).map_err(malformed),
        None => Ok(None),
    }
}

fn store_revocation_operation<T: Serialize>(
    transaction: &Transaction<'_>,
    operation_id: &OperationId,
    wallet_id: &Token,
    request_digest: &Digest32,
    result: &T,
) -> Result<(), ProtocolError> {
    transaction
        .execute(
            "INSERT INTO revocation_operations(
                operation_id, wallet_id, request_digest, result_jcs
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                operation_id.as_str(),
                wallet_id.as_str(),
                request_digest.as_str(),
                serde_jcs::to_string(result).map_err(malformed)?
            ],
        )
        .map_err(storage)?;
    Ok(())
}

fn verify_approval_tombstone(
    tombstone: &ApprovalTombstone,
    key: &VerifyingKey,
) -> Result<(), ProtocolError> {
    let mut unsigned = tombstone.clone();
    let signature = signature_bytes(&unsigned.signature)?;
    unsigned.signature = Base64UrlBytes::from_bytes(&[]);
    verify_revocation_signature(key, APPROVAL_TOMBSTONE_DOMAIN, &unsigned, &signature)
}

fn verify_wallet_tombstone(
    tombstone: &WalletTombstone,
    key: &VerifyingKey,
) -> Result<(), ProtocolError> {
    let mut unsigned = tombstone.clone();
    let signature = signature_bytes(&unsigned.signature)?;
    unsigned.signature = Base64UrlBytes::from_bytes(&[]);
    verify_revocation_signature(key, WALLET_TOMBSTONE_DOMAIN, &unsigned, &signature)
}

fn signature_bytes(value: &Base64UrlBytes) -> Result<[u8; 64], ProtocolError> {
    value.decode().try_into().map_err(|_| {
        error(
            ProtocolErrorCode::UnauthenticatedPeer,
            "revocation signature must contain 64 bytes",
        )
    })
}

fn verify_revocation_signature<T: Serialize>(
    key: &VerifyingKey,
    domain: &[u8],
    unsigned: &T,
    signature: &[u8; 64],
) -> Result<(), ProtocolError> {
    let mut message = domain.to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(unsigned).map_err(malformed)?);
    key.verify(&message, &Signature::from_bytes(signature))
        .map_err(|_| {
            error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "revocation signature is invalid",
            )
        })
}

fn verify_policy_backup(policy: &PolicyBackup) -> Result<(), ProtocolError> {
    let verifying_key_bytes: [u8; 32] =
        policy
            .policy_verifying_key
            .decode()
            .try_into()
            .map_err(|_| {
                error(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "backup policy verifying key must contain 32 bytes",
                )
            })?;
    let signature_bytes: [u8; 64] = policy
        .snapshot
        .signer_signature
        .decode()
        .try_into()
        .map_err(|_| {
            error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "backup policy signature must contain 64 bytes",
            )
        })?;
    let expected_digest =
        Digest32::from_bytes(Sha256::digest(policy.snapshot.canonical_policy.decode()).into());
    if expected_digest != policy.snapshot.policy_digest {
        return Err(error(
            ProtocolErrorCode::PolicyBaselineStale,
            "backup policy digest mismatch",
        ));
    }
    let mut unsigned = policy.snapshot.clone();
    unsigned.signer_signature = Base64UrlBytes::from_bytes(&[]);
    let mut message = POLICY_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&unsigned).map_err(malformed)?);
    VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| {
            error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "backup policy verifying key is invalid",
            )
        })?
        .verify(&message, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| {
            error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "backup policy signature is invalid",
            )
        })
}

#[cfg(feature = "local")]
fn derivation_registry_from_enrollments(
    enrollments: &[BackendEnrollmentBackup],
) -> Result<Option<DerivationRegistryBackup>, ProtocolError> {
    let mut allocated_keys = Vec::new();
    let mut tombstoned_paths = Vec::new();
    let mut namespaces = Vec::new();
    for enrollment in enrollments
        .iter()
        .filter(|record| record.backend.as_str() == "local")
    {
        let backup: bloom_signer_backend_local::EncryptedLocalBackup =
            serde_json::from_slice(&enrollment.encrypted_record.decode()).map_err(malformed)?;
        let pinned_derived = enrollment
            .pinned_keys
            .iter()
            .filter(|key| key.derivation.is_some())
            .cloned()
            .collect::<Vec<_>>();
        let pinned_root = enrollment
            .pinned_keys
            .iter()
            .find(|key| key.derivation.is_none());
        if backup.derivation_registry != pinned_derived
            || pinned_root
                .zip(backup.pinned_root.as_ref())
                .is_some_and(|(enrollment_root, backup_root)| enrollment_root != backup_root)
        {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "local encrypted registry differs from pinned enrollment keys",
            ));
        }
        allocated_keys.extend(backup.derivation_registry);
        tombstoned_paths.extend(backup.derivation_tombstones);
        namespaces.extend(backup.derivation_namespaces.into_iter().map(|namespace| {
            DerivationNamespaceBackup {
                namespace_id: namespace.namespace_id,
                canonical_prefix: namespace.canonical_prefix,
                next_index: namespace.next_index,
                maximum_children: namespace.maximum_children,
            }
        }));
    }
    if allocated_keys.is_empty() && tombstoned_paths.is_empty() && namespaces.is_empty() {
        return Ok(None);
    }
    allocated_keys.sort_by(|left, right| {
        (
            left.backend.as_str(),
            left.backend_instance.as_str(),
            left.locator.as_str(),
        )
            .cmp(&(
                right.backend.as_str(),
                right.backend_instance.as_str(),
                right.locator.as_str(),
            ))
    });
    tombstoned_paths.sort();
    namespaces.sort_by(|left, right| {
        (left.namespace_id.as_str(), left.canonical_prefix.as_str())
            .cmp(&(right.namespace_id.as_str(), right.canonical_prefix.as_str()))
    });
    Ok(Some(DerivationRegistryBackup {
        allocated_keys,
        tombstoned_paths,
        namespaces,
    }))
}

#[cfg(not(feature = "local"))]
fn derivation_registry_from_enrollments(
    _enrollments: &[BackendEnrollmentBackup],
) -> Result<Option<DerivationRegistryBackup>, ProtocolError> {
    Ok(None)
}

fn validate_against_approval(
    request: &SignRequest,
    terms: &SealedApprovalTerms,
    effective_now_ms: u64,
) -> Result<(), ProtocolError> {
    if terms.expires_at_ms.get() <= effective_now_ms
        || terms.not_before_ms.get() > effective_now_ms
        || request.unsigned.not_before_ms.get() < terms.not_before_ms.get()
        || request.unsigned.expires_at_ms.get() > terms.expires_at_ms.get()
    {
        return Err(error(
            ProtocolErrorCode::ApprovalExpired,
            "approval is expired or attempt outlives it",
        ));
    }
    if request.unsigned.wallet_id != terms.wallet_id || request.unsigned.key_ref != terms.key_ref {
        return Err(error(
            ProtocolErrorCode::KeyrefMismatch,
            "wallet or KeyRef does not exactly match approval",
        ));
    }
    if !terms
        .allowed_crypto_suites
        .contains(&request.unsigned.crypto_suite)
    {
        return Err(error(
            ProtocolErrorCode::SuiteNotAllowed,
            "CryptoSuite is not in the approval",
        ));
    }
    if request.unsigned.policy_version != terms.policy_version
        || request.unsigned.policy_digest != terms.policy_digest
    {
        return Err(error(
            ProtocolErrorCode::PolicyBaselineStale,
            "SignRequest policy binding differs from approval",
        ));
    }
    if request.unsigned.ordered_payload_digests.len() != request.unsigned.ordered_hashes.len() {
        return Err(error(
            ProtocolErrorCode::SelectorMismatch,
            "payload and hash counts differ",
        ));
    }
    match (&terms.selector, request.unsigned.selector_kind) {
        (
            ApprovalSelector::Exact {
                ordered_payload_digests,
                ordered_hashes,
            },
            SelectorKind::Exact,
        ) if ordered_payload_digests == &request.unsigned.ordered_payload_digests
            && ordered_hashes == &request.unsigned.ordered_hashes
            && request.unsigned.signature_count.get() == ordered_hashes.len() as u64 => {}
        (ApprovalSelector::Petal { .. }, SelectorKind::Petal)
            if request.unsigned.petal_use_claim_digest.is_some()
                && request.unsigned.claim_assurance_digest.is_some() => {}
        _ => {
            return Err(error(
                ProtocolErrorCode::SelectorMismatch,
                "selector kind, exact ordered inputs, or signature count differs from approval",
            ));
        }
    }
    Ok(())
}

/// A public KeyRef is not an authority to use a Petal-owned child. Signer
/// therefore repeats this check both when an approval is activated and for
/// every sign reservation, independently of Broker's provenance checks.
fn validate_petal_key_approval(
    connection: &Connection,
    terms: &SealedApprovalTerms,
    effective_now_ms: u64,
) -> Result<(), ProtocolError> {
    let authority_class: Option<String> = connection
        .query_row(
            "SELECT authority_class FROM enrolled_keys WHERE key_fingerprint = ?1",
            [terms.key_ref.public_key_fingerprint.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    if authority_class.as_deref() != Some("petal") {
        return Ok(());
    }
    let stored: Option<(String, String, String)> = connection
        .query_row(
            "SELECT scope_jcs, created_at_ms, expires_at_ms
             FROM petal_key_scopes WHERE key_fingerprint = ?1",
            [terms.key_ref.public_key_fingerprint.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(storage)?;
    let (scope_jcs, created_at_ms, scope_expires_at_ms) = stored.ok_or_else(|| {
        error(
            ProtocolErrorCode::ServiceUnavailable,
            "Petal sub-key scope record is missing",
        )
    })?;
    let scope: PetalKeyScope = serde_json::from_str(&scope_jcs).map_err(malformed)?;
    let created_at_ms = created_at_ms.parse::<u64>().map_err(malformed)?;
    let scope_expires_at_ms = scope_expires_at_ms.parse::<u64>().map_err(malformed)?;

    if terms.wallet_id != scope.wallet_id {
        return Err(error(
            ProtocolErrorCode::KeyrefMismatch,
            "Petal sub-key approval names a different wallet",
        ));
    }
    let ApprovalSubject::Petal {
        package_hash,
        route,
        agent_id,
    } = &terms.subject
    else {
        return Err(error(
            ProtocolErrorCode::SelectorMismatch,
            "Petal sub-key requires a Petal approval subject",
        ));
    };
    if package_hash != &scope.package_hash
        || !scope.allowed_routes.contains(route)
        || agent_id
            .as_deref()
            .is_some_and(|agent| agent != scope.key_slot.as_str())
    {
        return Err(error(
            ProtocolErrorCode::SelectorMismatch,
            "Petal approval identity differs from the derived-key scope",
        ));
    }
    if let ApprovalSelector::Petal {
        package_hash: selector_package,
        route: selector_route,
        allowed_operation_classes,
        route_grants,
        ..
    } = &terms.selector
    {
        if selector_package != package_hash || selector_route != route {
            return Err(error(
                ProtocolErrorCode::SelectorMismatch,
                "Petal selector identity differs from the derived-key scope",
            ));
        }
        if allowed_operation_classes.is_empty()
            || allowed_operation_classes
                .iter()
                .any(|operation_class| !scope.allowed_operation_classes.contains(operation_class))
        {
            return Err(error(
                ProtocolErrorCode::SelectorMismatch,
                "Petal selector operation classes exceed the derived-key purpose",
            ));
        }
        if route_grants.iter().any(|grant| {
            !scope.allowed_routes.contains(&grant.route)
                || grant.allowed_operation_classes.is_empty()
                || grant
                    .allowed_operation_classes
                    .iter()
                    .any(|operation_class| {
                        !scope.allowed_operation_classes.contains(operation_class)
                    })
        }) {
            return Err(error(
                ProtocolErrorCode::SelectorMismatch,
                "Petal route grant exceeds the derived-key route or purpose scope",
            ));
        }
    }
    if terms.allowed_crypto_suites.is_empty()
        || terms
            .allowed_crypto_suites
            .iter()
            .any(|suite| !scope.allowed_crypto_suites.contains(suite))
    {
        return Err(error(
            ProtocolErrorCode::SuiteNotAllowed,
            "approval suite exceeds the Petal derived-key scope",
        ));
    }
    if effective_now_ms < created_at_ms
        || effective_now_ms >= scope_expires_at_ms
        || terms.not_before_ms.get() < created_at_ms
        || terms.expires_at_ms.get() > scope_expires_at_ms
        || terms
            .expires_at_ms
            .get()
            .saturating_sub(terms.not_before_ms.get())
            > scope.maximum_lifetime_ms.get()
    {
        return Err(error(
            ProtocolErrorCode::ApprovalExpired,
            "approval validity exceeds the Petal derived-key scope",
        ));
    }
    Ok(())
}

fn require_key_available(
    transaction: &Transaction<'_>,
    backend_registry: &BackendRegistry,
    key_ref: &KeyRef,
) -> Result<(), ProtocolError> {
    let enrolled: Option<(String, bool)> = transaction
        .query_row(
            "SELECT key_ref_jcs, available FROM enrolled_keys WHERE key_fingerprint = ?1",
            [key_ref.public_key_fingerprint.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    if enrolled.as_ref().map(|(stored, _)| stored)
        != Some(&serde_jcs::to_string(key_ref).map_err(malformed)?)
        || !backend_registry.key_is_available(key_ref)?
    {
        return Err(error(
            ProtocolErrorCode::KeyrefMismatch,
            "approval key is absent, inactive, or differs from compiled backend enrollment",
        ));
    }
    Ok(())
}

fn reserve_parser_free_limits(
    transaction: &Transaction<'_>,
    request: &SignRequest,
    terms: &SealedApprovalTerms,
    effective_now_ms: u64,
) -> Result<(u64, u64), ProtocolError> {
    let (operations, signatures): (String, String) = transaction
        .query_row(
            "SELECT committed_operations, committed_signatures
             FROM approvals WHERE approval_id = ?1",
            [request.unsigned.approval_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(storage)?;
    let operations = operations.parse::<u64>().map_err(malformed)?;
    let signatures = signatures.parse::<u64>().map_err(malformed)?;
    let next_operations = operations.checked_add(1).ok_or_else(|| {
        error(
            ProtocolErrorCode::LimitExceededOperations,
            "Signer operation counter overflow",
        )
    })?;
    if next_operations > terms.limits.max_operations.get() {
        return Err(error(
            ProtocolErrorCode::LimitExceededOperations,
            "Signer operation backstop exceeded",
        ));
    }
    let next_signatures = signatures
        .checked_add(request.unsigned.signature_count.get())
        .ok_or_else(|| {
            error(
                ProtocolErrorCode::LimitExceededSignatures,
                "Signer signature counter overflow",
            )
        })?;
    if next_signatures > terms.limits.max_signatures.get() {
        return Err(error(
            ProtocolErrorCode::LimitExceededSignatures,
            "Signer signature backstop exceeded",
        ));
    }
    for window in &terms.limits.operation_rate_limits {
        let start = effective_now_ms.saturating_sub(window.duration_ms.get());
        let count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM operations
                 WHERE approval_id = ?1
                   AND state != 'RELEASED'
                   AND CAST(accepted_at_ms AS INTEGER) > ?2
                   AND CAST(accepted_at_ms AS INTEGER) <= ?3",
                params![
                    request.unsigned.approval_id.as_str(),
                    i64::try_from(start).map_err(malformed)?,
                    i64::try_from(effective_now_ms).map_err(malformed)?
                ],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if u64::try_from(count)
            .ok()
            .and_then(|count| count.checked_add(1))
            .is_none_or(|count| count > window.maximum.get())
        {
            return Err(error(
                ProtocolErrorCode::SignerRateBackstopDenied,
                "Signer operation-rate backstop exceeded",
            ));
        }
    }
    for window in &terms.limits.signature_rate_limits {
        let start = effective_now_ms.saturating_sub(window.duration_ms.get());
        let values = {
            let mut statement = transaction
                .prepare(
                    "SELECT signature_count FROM operations
                     WHERE approval_id = ?1
                       AND state != 'RELEASED'
                       AND CAST(accepted_at_ms AS INTEGER) > ?2
                       AND CAST(accepted_at_ms AS INTEGER) <= ?3",
                )
                .map_err(storage)?;
            let rows = statement
                .query_map(
                    params![
                        request.unsigned.approval_id.as_str(),
                        i64::try_from(start).map_err(malformed)?,
                        i64::try_from(effective_now_ms).map_err(malformed)?
                    ],
                    |row| row.get::<_, String>(0),
                )
                .map_err(storage)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(storage)?
        };
        let mut count = 0_u64;
        for value in values {
            count = count
                .checked_add(value.parse::<u64>().map_err(malformed)?)
                .ok_or_else(|| {
                    error(
                        ProtocolErrorCode::SignerRateBackstopDenied,
                        "Signer signature-rate counter overflow",
                    )
                })?;
        }
        if count
            .checked_add(request.unsigned.signature_count.get())
            .is_none_or(|count| count > window.maximum.get())
        {
            return Err(error(
                ProtocolErrorCode::SignerRateBackstopDenied,
                "Signer signature-rate backstop exceeded",
            ));
        }
    }
    Ok((next_operations, next_signatures))
}

fn wallet_epoch(transaction: &Transaction<'_>, wallet_id: &Token) -> Result<u64, ProtocolError> {
    transaction
        .query_row(
            "SELECT revocation_epoch FROM wallet_state WHERE wallet_id = ?1",
            [wallet_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(storage)?
        .map(|value| value.parse::<u64>().map_err(malformed))
        .transpose()
        .map(|value| value.unwrap_or(0))
}

fn signer_clock_condition(condition: DurableClockCondition) -> ClockCondition {
    match condition {
        DurableClockCondition::Healthy => ClockCondition::Healthy,
        DurableClockCondition::Untrusted => ClockCondition::Untrusted,
        DurableClockCondition::RollbackFrozen => ClockCondition::RollbackFrozen,
        DurableClockCondition::ForwardJumpRejected => ClockCondition::ForwardJumpRejected,
    }
}

fn write_clock_state(
    transaction: &Transaction<'_>,
    effective_now_ms: u64,
    condition: ClockCondition,
    reading: &bloom_trusted_time::PlatformTimeReading,
    boot_epoch: &bloom_signer_api::BootEpoch,
) -> Result<(), ProtocolError> {
    let condition = match condition {
        ClockCondition::Healthy => "HEALTHY",
        ClockCondition::ForwardJumpRejected => "FORWARD_JUMP_REJECTED",
        ClockCondition::Untrusted => "UNTRUSTED",
        ClockCondition::RollbackFrozen => "ROLLBACK_FROZEN",
        ClockCondition::Repaired => "REPAIRED",
    };
    transaction
        .execute(
            "INSERT INTO clock_state(
                 singleton, last_effective_ms, condition, observed_utc_ms,
                 monotonic_anchor_ns, boot_epoch
             )
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(singleton) DO UPDATE SET
                 last_effective_ms = excluded.last_effective_ms,
                 condition = excluded.condition,
                 observed_utc_ms = excluded.observed_utc_ms,
                 monotonic_anchor_ns = excluded.monotonic_anchor_ns,
                 boot_epoch = excluded.boot_epoch",
            params![
                effective_now_ms.to_string(),
                condition,
                reading.utc_ms.map(|value| value.to_string()),
                reading.monotonic_anchor_ns.to_string(),
                boot_epoch.as_str()
            ],
        )
        .map_err(storage)?;
    Ok(())
}

fn backup_export_material_digest(backup: &SignerBackupSet) -> Result<Digest32, ProtocolError> {
    let mut material = backup.clone();
    material.audit_entries.clear();
    Ok(Digest32::from_bytes(
        Sha256::digest(serde_jcs::to_vec(&material).map_err(malformed)?).into(),
    ))
}

fn load_audit_entries(connection: &Connection) -> Result<Vec<AuditEntryBackup>, ProtocolError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence, event_type, payload_jcs, previous_hash, entry_hash,
                    signing_key_id, signature FROM audit_chain ORDER BY sequence",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(storage)?;
    rows.map(|row| {
        let (sequence, event_type, payload_jcs, previous_hash, entry_hash, key_id, signature) =
            row.map_err(storage)?;
        Ok(AuditEntryBackup {
            sequence: DecimalU64::new(u64::try_from(sequence).map_err(malformed)?),
            event_type,
            payload_jcs,
            previous_hash: Digest32::new(previous_hash).map_err(malformed)?,
            entry_hash: Digest32::new(entry_hash).map_err(malformed)?,
            signing_key_id: Token::new(key_id).map_err(malformed)?,
            signature: Base64UrlBytes::parse(signature)?,
        })
    })
    .collect()
}

fn restore_audit_entries(
    transaction: &Transaction<'_>,
    backup: &[AuditEntryBackup],
    backup_rotations: &[AuditRotationBackup],
    expected_key_id: &Token,
    verifying_keys: &BTreeMap<Token, VerifyingKey>,
) -> Result<(), ProtocolError> {
    let current = load_audit_entries(transaction)?;
    if backup.len() < current.len() {
        log_journal_verification_failure_with_state(
            backup.len() as u64,
            "durable_state_correlation",
            None,
            false,
        );
        return Err(error(
            ProtocolErrorCode::RevocationEpochUnreconciled,
            "backup cannot lower the Signer audit sequence",
        ));
    }
    if current != backup[..current.len()] {
        let sequence = current
            .iter()
            .zip(backup)
            .position(|(durable, candidate)| durable != candidate)
            .unwrap_or(current.len()) as u64;
        log_journal_verification_failure_with_state(
            sequence,
            "durable_state_correlation",
            None,
            false,
        );
        return Err(error(
            ProtocolErrorCode::OperationIdConflict,
            "backup audit chain does not extend the durable chain",
        ));
    }
    let current_rotations = load_audit_rotations(transaction)?;
    let mut backup_rotation_map = BTreeMap::new();
    let mut backup_transitions = std::collections::BTreeSet::new();
    for rotation in backup_rotations {
        let sequence = rotation.first_new_sequence.get();
        if backup_rotation_map
            .insert(sequence, rotation.clone())
            .is_some()
        {
            return Err(error(
                ProtocolErrorCode::MalformedFrame,
                "backup contains duplicate audit rotation first-new sequence",
            ));
        }
        if !backup_transitions.insert((rotation.old_key_id.clone(), rotation.new_key_id.clone())) {
            return Err(error(
                ProtocolErrorCode::MalformedFrame,
                "backup contains a duplicate audit key-transition proof",
            ));
        }
    }
    if log_first_backup_rotation_mismatch(&current_rotations, &backup_rotation_map).is_some() {
        return Err(error(
            ProtocolErrorCode::OperationIdConflict,
            "backup audit rotations do not extend the durable rotation chain",
        ));
    }
    for entry in &backup[current.len()..] {
        transaction
            .execute(
                "INSERT INTO audit_chain(
                    sequence, event_type, payload_jcs, previous_hash, entry_hash,
                    signing_key_id, signature
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    i64::try_from(entry.sequence.get()).map_err(malformed)?,
                    entry.event_type,
                    entry.payload_jcs,
                    entry.previous_hash.as_str(),
                    entry.entry_hash.as_str(),
                    entry.signing_key_id.as_str(),
                    entry.signature.encoded(),
                ],
            )
            .map_err(storage)?;
    }
    for (sequence, rotation) in backup_rotation_map {
        if current_rotations.contains_key(&sequence) {
            continue;
        }
        transaction
            .execute(
                "INSERT INTO audit_key_rotations(
                    first_new_sequence, old_key_id, new_key_id, final_old_sequence,
                    final_old_head, first_new_head, old_key_signature, new_key_signature
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    i64::try_from(sequence).map_err(malformed)?,
                    rotation.old_key_id.as_str(),
                    rotation.new_key_id.as_str(),
                    i64::try_from(rotation.final_old_sequence.get()).map_err(malformed)?,
                    rotation.final_old_head.as_str(),
                    rotation.first_new_head.as_str(),
                    rotation.old_key_signature.encoded(),
                    rotation.new_key_signature.encoded(),
                ],
            )
            .map_err(storage)?;
    }
    verify_audit_chain_with_state(transaction, expected_key_id, verifying_keys, false).map_err(
        |cause| {
            error(
                ProtocolErrorCode::MalformedFrame,
                format!("backup audit chain or rotation proof is invalid: {cause}"),
            )
        },
    )
}

fn log_first_backup_rotation_mismatch(
    durable: &BTreeMap<u64, AuditRotationBackup>,
    candidate: &BTreeMap<u64, AuditRotationBackup>,
) -> Option<u64> {
    let sequence = durable.iter().find_map(|(sequence, rotation)| {
        (candidate.get(sequence) != Some(rotation)).then_some(*sequence)
    })?;
    log_journal_verification_failure_with_state(sequence, "durable_state_correlation", None, false);
    Some(sequence)
}

fn append_audit_entry(
    transaction: &Transaction<'_>,
    event_type: &str,
    payload: &impl Serialize,
    signing_key_id: &Token,
    signing_key: &SigningKey,
    expected_final_key_id: &Token,
    trusted_keys: &BTreeMap<Token, VerifyingKey>,
) -> Result<(), ProtocolError> {
    verify_audit_chain(transaction, expected_final_key_id, trusted_keys)?;
    let (sequence, previous_hash) = transaction
        .query_row(
            "SELECT sequence, entry_hash FROM audit_chain ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)? + 1, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(storage)?
        .unwrap_or((0, "00".repeat(32)));
    let sequence = u64::try_from(sequence).map_err(malformed)?;
    let previous_hash = Digest32::new(previous_hash).map_err(malformed)?;
    let payload_jcs =
        String::from_utf8(serde_jcs::to_vec(payload).map_err(malformed)?).map_err(malformed)?;
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_DOMAIN);
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous_hash.as_str().as_bytes());
    hasher.update(event_type.as_bytes());
    hasher.update(payload_jcs.as_bytes());
    let entry_hash = Digest32::from_bytes(hasher.finalize().into());
    let signature =
        signing_key.sign(&[AUDIT_SIGNATURE_DOMAIN, entry_hash.as_str().as_bytes()].concat());
    transaction
        .execute(
            "INSERT INTO audit_chain(
                sequence, event_type, payload_jcs, previous_hash, entry_hash,
                signing_key_id, signature
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                i64::try_from(sequence).map_err(malformed)?,
                event_type,
                payload_jcs,
                previous_hash.as_str(),
                entry_hash.as_str(),
                signing_key_id.as_str(),
                Base64UrlBytes::from_bytes(&signature.to_bytes()).encoded(),
            ],
        )
        .map_err(storage)?;
    Ok(())
}

fn read_verified_audit_tail(connection: &Connection) -> Result<VerifiedAuditTail, ProtocolError> {
    let (sequence, head_hash) = connection
        .query_row(
            "SELECT sequence, entry_hash FROM audit_chain ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(storage)?
        .map(
            |(sequence, head)| -> Result<(u64, Digest32), ProtocolError> {
                Ok((
                    u64::try_from(sequence)
                        .map_err(malformed)?
                        .checked_add(1)
                        .ok_or_else(|| malformed("audit entry count overflow"))?,
                    Digest32::new(head).map_err(malformed)?,
                ))
            },
        )
        .transpose()?
        .unwrap_or((0, Digest32::from_bytes([0; 32])));
    let data_version = connection
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .map_err(storage)?;
    Ok(VerifiedAuditTail {
        sequence,
        head_hash,
        data_version,
        total_changes: connection.total_changes(),
    })
}

fn verify_audit_chain(
    connection: &Connection,
    expected_final_key_id: &Token,
    verifying_keys: &BTreeMap<Token, VerifyingKey>,
) -> Result<(), ProtocolError> {
    verify_audit_chain_with_state(connection, expected_final_key_id, verifying_keys, true)
}

fn verify_audit_chain_with_state(
    connection: &Connection,
    expected_final_key_id: &Token,
    verifying_keys: &BTreeMap<Token, VerifyingKey>,
    mutations_disabled: bool,
) -> Result<(), ProtocolError> {
    macro_rules! verification_failure {
        ($sequence:expr, $invariant:expr, $signing_key_id:expr $(,)?) => {
            log_journal_verification_failure_with_state(
                $sequence,
                $invariant,
                $signing_key_id,
                mutations_disabled,
            )
        };
    }
    let mut statement = connection
        .prepare(
            "SELECT sequence, event_type, payload_jcs, previous_hash, entry_hash,
                    signing_key_id, signature
             FROM audit_chain ORDER BY sequence",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(storage)?;
    let rotations = load_audit_rotations(connection)?;
    let mut expected_sequence = 0_u64;
    let mut expected_previous_hash = Digest32::from_bytes([0; 32]);
    let mut active_key_id: Option<Token> = None;
    let mut observed_rotations = 0_usize;
    for row in rows {
        let (
            sequence,
            event_type,
            payload_jcs,
            previous_hash,
            entry_hash,
            signing_key_id,
            signature,
        ) = row.map_err(storage)?;
        let sequence = u64::try_from(sequence).map_err(|cause| {
            verification_failure!(expected_sequence, "row_sequence", None);
            malformed(cause)
        })?;
        let signing_key_id = Token::new(signing_key_id).map_err(|cause| {
            verification_failure!(sequence, "signing_key", None);
            malformed(cause)
        })?;
        if sequence != expected_sequence {
            verification_failure!(sequence, "sequence", Some(&signing_key_id));
            return Err(error(
                ProtocolErrorCode::ServiceUnavailable,
                "Signer audit chain sequence is invalid",
            ));
        }
        if previous_hash != expected_previous_hash.as_str() {
            verification_failure!(sequence, "predecessor_link", Some(&signing_key_id));
            return Err(error(
                ProtocolErrorCode::ServiceUnavailable,
                "Signer audit chain predecessor is invalid",
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(AUDIT_DOMAIN);
        hasher.update(sequence.to_be_bytes());
        hasher.update(expected_previous_hash.as_str().as_bytes());
        hasher.update(event_type.as_bytes());
        hasher.update(payload_jcs.as_bytes());
        let computed = Digest32::from_bytes(hasher.finalize().into());
        if computed.as_str() != entry_hash {
            verification_failure!(sequence, "content_hash", Some(&signing_key_id));
            return Err(error(
                ProtocolErrorCode::ServiceUnavailable,
                "Signer audit entry hash is invalid",
            ));
        }
        if let Some(old_key_id) = &active_key_id {
            if old_key_id != &signing_key_id {
                let rotation = rotations.get(&sequence).ok_or_else(|| {
                    verification_failure!(sequence, "key_rotation", Some(&signing_key_id),);
                    audit_degraded_error()
                })?;
                verify_audit_rotation(
                    rotation,
                    old_key_id,
                    &signing_key_id,
                    sequence,
                    &expected_previous_hash,
                    &computed,
                    verifying_keys,
                )
                .inspect_err(|_| {
                    verification_failure!(sequence, "key_rotation", Some(&signing_key_id),);
                })?;
                observed_rotations += 1;
            } else if rotations.contains_key(&sequence) {
                verification_failure!(sequence, "key_rotation", Some(&signing_key_id));
                return Err(audit_degraded_error());
            }
        } else if rotations.contains_key(&sequence) {
            verification_failure!(sequence, "key_rotation", Some(&signing_key_id));
            return Err(audit_degraded_error());
        }
        let signature_bytes: [u8; 64] = Base64UrlBytes::parse(signature)
            .inspect_err(|_| {
                verification_failure!(sequence, "signature_encoding", Some(&signing_key_id),);
            })?
            .decode()
            .try_into()
            .map_err(|_| {
                verification_failure!(sequence, "signature_length", Some(&signing_key_id),);
                error(
                    ProtocolErrorCode::ServiceUnavailable,
                    "Signer audit signature length is invalid",
                )
            })?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_keys
            .get(&signing_key_id)
            .ok_or_else(|| {
                verification_failure!(sequence, "signing_key", Some(&signing_key_id));
                audit_degraded_error()
            })?
            .verify(
                &[AUDIT_SIGNATURE_DOMAIN, computed.as_str().as_bytes()].concat(),
                &signature,
            )
            .map_err(|_| {
                verification_failure!(sequence, "signature", Some(&signing_key_id));
                error(
                    ProtocolErrorCode::ServiceUnavailable,
                    "Signer audit signature is invalid",
                )
            })?;
        active_key_id = Some(signing_key_id);
        expected_previous_hash = computed;
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            error(
                ProtocolErrorCode::ServiceUnavailable,
                "Signer audit sequence overflow",
            )
        })?;
    }
    if observed_rotations != rotations.len()
        || active_key_id
            .as_ref()
            .is_some_and(|key_id| key_id != expected_final_key_id)
    {
        verification_failure!(
            expected_sequence.saturating_sub(1),
            "key_rotation",
            active_key_id.as_ref(),
        );
        return Err(audit_degraded_error());
    }
    Ok(())
}

fn log_journal_verification_failure_with_state(
    sequence: u64,
    invariant: &'static str,
    signing_key_id: Option<&Token>,
    mutations_disabled: bool,
) {
    tracing::error!(
        event = "signer.journal_verification_failed",
        sequence,
        invariant,
        signing_key_id = signing_key_id.map(Token::as_str),
        mutations_disabled,
        "Signer journal verification failed"
    );
}

fn ceremony_mutation_kind(kind: bloom_signer_api::CeremonyKind) -> &'static str {
    use bloom_signer_api::CeremonyKind as Kind;
    match kind {
        Kind::WalletRegistration
        | Kind::WalletImport
        | Kind::WalletExport
        | Kind::WalletDelete
        | Kind::WalletRecovery => "wallet",
        Kind::CredentialAdd | Kind::CredentialReplace | Kind::CredentialRemove => "credential",
        Kind::PolicyUpdate => "policy",
        Kind::BackendEnrollment | Kind::KeyDerive => "key",
        Kind::SealedApproval => "approval",
    }
}

fn ceremony_state_code(state: bloom_signer_api::CeremonyState) -> &'static str {
    use bloom_signer_api::CeremonyState;
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

fn log_clock_transition(condition: ClockCondition, effective_now_ms: u64, accepted: bool) {
    if accepted {
        tracing::info!(
            event = "signer.clock_transition",
            condition = condition.as_str(),
            effective_now_ms,
            outcome = "accepted",
            "Signer accepted a durable clock transition"
        );
    } else {
        tracing::warn!(
            event = "signer.clock_transition",
            condition = condition.as_str(),
            effective_now_ms,
            outcome = "rejected",
            "Signer rejected a durable clock transition"
        );
    }
}

fn insert_trusted_audit_key(
    keys: &mut BTreeMap<Token, VerifyingKey>,
    key_id: Token,
    key: VerifyingKey,
) -> Result<(), ProtocolError> {
    if let Some(existing) = keys.insert(key_id.clone(), key) {
        if existing != key {
            return Err(error(
                ProtocolErrorCode::MalformedFrame,
                format!("Signer audit key ID {key_id} has conflicting public keys"),
            ));
        }
    }
    Ok(())
}

fn load_audit_rotations(
    connection: &Connection,
) -> Result<BTreeMap<u64, AuditRotationBackup>, ProtocolError> {
    let mut statement = connection
        .prepare(
            "SELECT old_key_id, new_key_id, final_old_sequence, final_old_head,
                    first_new_sequence, first_new_head, old_key_signature, new_key_signature
             FROM audit_key_rotations ORDER BY first_new_sequence",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(storage)?;
    let mut rotations = BTreeMap::new();
    for row in rows {
        let (old, new, old_seq, old_head, new_seq, new_head, old_sig, new_sig) =
            row.map_err(storage)?;
        let new_seq = u64::try_from(new_seq).map_err(malformed)?;
        let rotation = AuditRotationBackup {
            old_key_id: Token::new(old).map_err(malformed)?,
            new_key_id: Token::new(new).map_err(malformed)?,
            final_old_sequence: DecimalU64::new(u64::try_from(old_seq).map_err(malformed)?),
            final_old_head: Digest32::new(old_head).map_err(malformed)?,
            first_new_sequence: DecimalU64::new(new_seq),
            first_new_head: Digest32::new(new_head).map_err(malformed)?,
            old_key_signature: Base64UrlBytes::parse(old_sig)?,
            new_key_signature: Base64UrlBytes::parse(new_sig)?,
        };
        if rotations.insert(new_seq, rotation).is_some() {
            return Err(audit_degraded_error());
        }
    }
    Ok(rotations)
}

fn audit_rotation_message(rotation: &AuditRotationBackup) -> Result<Vec<u8>, ProtocolError> {
    #[derive(Serialize)]
    struct Unsigned<'a> {
        old_key_id: &'a Token,
        new_key_id: &'a Token,
        final_old_sequence: DecimalU64,
        final_old_head: &'a Digest32,
        first_new_sequence: DecimalU64,
        first_new_head: &'a Digest32,
    }
    let mut message = AUDIT_ROTATION_DOMAIN.to_vec();
    message.extend_from_slice(
        &serde_jcs::to_vec(&Unsigned {
            old_key_id: &rotation.old_key_id,
            new_key_id: &rotation.new_key_id,
            final_old_sequence: rotation.final_old_sequence.clone(),
            final_old_head: &rotation.final_old_head,
            first_new_sequence: rotation.first_new_sequence.clone(),
            first_new_head: &rotation.first_new_head,
        })
        .map_err(malformed)?,
    );
    Ok(message)
}

fn verify_audit_rotation(
    rotation: &AuditRotationBackup,
    old_key_id: &Token,
    new_key_id: &Token,
    first_new_sequence: u64,
    final_old_head: &Digest32,
    first_new_head: &Digest32,
    verifying_keys: &BTreeMap<Token, VerifyingKey>,
) -> Result<(), ProtocolError> {
    if rotation.old_key_id != *old_key_id
        || rotation.new_key_id != *new_key_id
        || rotation.first_new_sequence.get() != first_new_sequence
        || rotation.final_old_sequence.get().checked_add(1) != Some(first_new_sequence)
        || rotation.final_old_head != *final_old_head
        || rotation.first_new_head != *first_new_head
    {
        return Err(audit_degraded_error());
    }
    let message = audit_rotation_message(rotation)?;
    for (key_id, signature) in [
        (&rotation.old_key_id, &rotation.old_key_signature),
        (&rotation.new_key_id, &rotation.new_key_signature),
    ] {
        let signature: [u8; 64] = signature
            .decode()
            .try_into()
            .map_err(|_| audit_degraded_error())?;
        verifying_keys
            .get(key_id)
            .ok_or_else(audit_degraded_error)?
            .verify(&message, &Signature::from_bytes(&signature))
            .map_err(|_| audit_degraded_error())?;
    }
    Ok(())
}

fn audit_degraded_error() -> ProtocolError {
    error(
        ProtocolErrorCode::ServiceUnavailable,
        "Signer audit chain is degraded; mutations are disabled while read/status remains available",
    )
}

fn retry_binding_digest(
    request: &bloom_signer_api::UnsignedSignRequest,
) -> Result<Digest32, ProtocolError> {
    let mut value = serde_json::to_value(request).map_err(malformed)?;
    let object = value.as_object_mut().ok_or_else(|| {
        error(
            ProtocolErrorCode::MalformedFrame,
            "SignRequest attempt must be an object",
        )
    })?;
    for permitted in [
        "attempt_id",
        "attempt_digest",
        "issuer_boot_epoch",
        "issued_at_ms",
        "not_before_ms",
        "expires_at_ms",
    ] {
        object.remove(permitted);
    }
    let mut hasher = Sha256::new();
    hasher.update(SIGNER_RETRY_BINDING_DOMAIN);
    hasher.update(serde_jcs::to_vec(&value).map_err(malformed)?);
    Ok(Digest32::from_bytes(hasher.finalize().into()))
}

fn error(code: ProtocolErrorCode, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(code, message)
}

fn storage(cause: impl std::fmt::Display) -> ProtocolError {
    error(
        ProtocolErrorCode::ServiceUnavailable,
        format!("Signer durable state failure: {cause}"),
    )
}

fn malformed(cause: impl std::fmt::Display) -> ProtocolError {
    error(
        ProtocolErrorCode::MalformedFrame,
        format!("canonical value failure: {cause}"),
    )
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    use bloom_trusted_time::PlatformTimeReading;

    fn engine() -> SignerEngine {
        SignerEngine::open_in_memory(
            Token::new("broker-key").unwrap(),
            SigningKey::from_bytes(&[1; 32]).verifying_key(),
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
            Token::new("revocation-key").unwrap(),
            SigningKey::from_bytes(&[3; 32]),
            SignerAuditKeys {
                current_key_id: Token::new("audit-key").unwrap(),
                current_signing_key: SigningKey::from_bytes(&[30; 32]),
                historical_verifying_keys: BTreeMap::new(),
            },
            Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap()),
        )
        .unwrap()
    }

    fn file_engine(path: &Path) -> SignerEngine {
        SignerEngine::open(
            path,
            Token::new("broker-key").unwrap(),
            SigningKey::from_bytes(&[1; 32]).verifying_key(),
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
            Token::new("revocation-key").unwrap(),
            SigningKey::from_bytes(&[3; 32]),
            SignerAuditKeys {
                current_key_id: Token::new("audit-key").unwrap(),
                current_signing_key: SigningKey::from_bytes(&[30; 32]),
                historical_verifying_keys: BTreeMap::new(),
            },
            Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap()),
        )
        .unwrap()
    }

    fn dedicated_file_engine(
        path: &Path,
        current_key_id: Token,
        current_key: SigningKey,
        historical: BTreeMap<Token, VerifyingKey>,
    ) -> SignerEngine {
        SignerEngine::open(
            path,
            Token::new("broker-key").unwrap(),
            SigningKey::from_bytes(&[1; 32]).verifying_key(),
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
            Token::new("revocation-key").unwrap(),
            SigningKey::from_bytes(&[3; 32]),
            SignerAuditKeys {
                current_key_id,
                current_signing_key: current_key,
                historical_verifying_keys: historical,
            },
            Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap()),
        )
        .unwrap()
    }

    fn seed_audit(path: &Path) {
        let engine = file_engine(path);
        for index in 0..3_u64 {
            let mut connection = engine.connection.lock();
            let transaction = engine.mutation_transaction(&mut connection).unwrap();
            engine
                .append_audit(
                    &transaction,
                    "test.security_mutation",
                    &serde_json::json!({
                        "operation_id": format!("operation-{index}"),
                        "payload_digest": Digest32::from_bytes([index as u8; 32]),
                        "signature": Base64UrlBytes::from_bytes(&[index as u8; 65]),
                        "key_id": format!("key-{index}"),
                    }),
                )
                .unwrap();
            transaction.commit().unwrap();
        }
    }

    #[test]
    fn verified_audit_head_uses_entry_count_and_empty_zero_convention() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("signer.sqlite3");
        let engine = file_engine(&path);
        assert_eq!(
            engine.verified_audit_head().unwrap(),
            (0, Digest32::from_bytes([0; 32]))
        );
        drop(engine);
        seed_audit(&path);
        let engine = file_engine(&path);
        let (count, head) = engine.verified_audit_head().unwrap();
        assert_eq!(count, 3);
        assert_ne!(head, Digest32::from_bytes([0; 32]));
    }

    #[test]
    fn verified_audit_head_rejects_tamper_and_external_latch_blocks_mutations() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("signer.sqlite3");
        seed_audit(&path);
        let engine = file_engine(&path);
        engine
            .connection
            .lock()
            .execute(
                "UPDATE audit_chain SET payload_jcs = '{}' WHERE sequence = 0",
                [],
            )
            .unwrap();
        assert!(engine.verified_audit_head().is_err());
        assert!(engine.audit_is_degraded());
        assert_eq!(
            engine.repair_clock(1).unwrap_err().code,
            ProtocolErrorCode::ServiceUnavailable
        );

        let clean = file_engine(&directory.path().join("clean.sqlite3"));
        clean.latch_audit_degraded_with(AuditDegradation {
            cause_code: "checkpoint_sequence_rollback",
            peer_service_id: Some("bloom-broker".into()),
            peer_key_id: Some("broker-audit-1".into()),
            attempted_sequence: Some(7),
            attempted_head_digest: Some("11".repeat(32)),
            retained_sequence: Some(8),
            retained_head_digest: Some("22".repeat(32)),
        });
        clean.latch_audit_degraded_with(AuditDegradation::new("later_failure"));
        assert_eq!(
            clean.repair_clock(1).unwrap_err().code,
            ProtocolErrorCode::ServiceUnavailable
        );
        let cause = clean.audit_degradation().unwrap();
        assert_eq!(cause.cause_code, "checkpoint_sequence_rollback");
        assert_eq!(cause.attempted_sequence, Some(7));
        assert_eq!(cause.retained_sequence, Some(8));
        assert_eq!(
            clean.verified_audit_head().unwrap(),
            (0, Digest32::from_bytes([0; 32]))
        );
    }

    #[test]
    fn degradation_closes_mutations_before_first_cause_diagnostics_lock() {
        let directory = tempfile::TempDir::new().unwrap();
        let engine = file_engine(&directory.path().join("signer.sqlite3"));
        let diagnostics = engine.audit_degradation.lock();
        let started = std::sync::Barrier::new(2);

        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                started.wait();
                engine.latch_audit_degraded_with(AuditDegradation::new(
                    "checkpoint_sequence_rollback",
                ));
            });
            started.wait();

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            while !engine.audit_is_degraded() && std::time::Instant::now() < deadline {
                std::thread::yield_now();
            }
            assert!(
                engine.audit_is_degraded(),
                "the mutation latch must close before waiting for diagnostics"
            );
            assert_eq!(
                engine.repair_clock(1).unwrap_err().code,
                ProtocolErrorCode::ServiceUnavailable
            );

            drop(diagnostics);
            worker.join().unwrap();
        });
        assert_eq!(
            engine.audit_degradation().unwrap().cause_code,
            "checkpoint_sequence_rollback"
        );
    }

    #[test]
    fn journal_diagnostic_names_exact_row_and_invariant() {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            log_journal_verification_failure_with_state(
                17,
                "durable_state_correlation",
                Some(&Token::new("audit-key-17").unwrap()),
                true,
            );
        });
        let output = capture.text();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(
            event["fields"]["event"],
            "signer.journal_verification_failed"
        );
        assert_eq!(event["fields"]["sequence"], 17);
        assert_eq!(event["fields"]["invariant"], "durable_state_correlation");
    }

    #[test]
    fn rejected_backup_diagnostic_does_not_claim_mutations_are_disabled() {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            log_journal_verification_failure_with_state(
                4,
                "durable_state_correlation",
                None,
                false,
            );
        });
        let event: serde_json::Value = serde_json::from_str(capture.text().trim()).unwrap();
        assert_eq!(event["fields"]["mutations_disabled"], false);
    }

    #[test]
    fn backup_rotation_diagnostic_reports_first_actual_later_mismatch() {
        fn rotation(sequence: u64, label: u8) -> AuditRotationBackup {
            AuditRotationBackup {
                old_key_id: Token::new(format!("audit-old-{label}")).unwrap(),
                new_key_id: Token::new(format!("audit-new-{label}")).unwrap(),
                final_old_sequence: DecimalU64::new(sequence - 1),
                final_old_head: Digest32::from_bytes([label; 32]),
                first_new_sequence: DecimalU64::new(sequence),
                first_new_head: Digest32::from_bytes([label + 1; 32]),
                old_key_signature: Base64UrlBytes::from_bytes(&[label; 64]),
                new_key_signature: Base64UrlBytes::from_bytes(&[label + 1; 64]),
            }
        }

        let durable = BTreeMap::from([(4, rotation(4, 1)), (9, rotation(9, 2))]);
        let mut candidate = durable.clone();
        let marker_secret = "MARKER_BACKUP_ROTATION_SIGNATURE_DO_NOT_LOG";
        candidate.get_mut(&9).unwrap().old_key_signature =
            Base64UrlBytes::from_bytes(marker_secret.as_bytes());
        let encoded_signature = candidate.get(&9).unwrap().old_key_signature.encoded();
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(capture.clone())
            .finish();
        let mismatch = tracing::subscriber::with_default(subscriber, || {
            log_first_backup_rotation_mismatch(&durable, &candidate)
        });
        assert_eq!(mismatch, Some(9));
        let output = capture.text();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event["fields"]["sequence"], 9);
        assert_eq!(event["fields"]["mutations_disabled"], false);
        assert!(!output.contains(marker_secret));
        assert!(!output.contains(encoded_signature));
    }

    #[test]
    fn dedicated_audit_key_rotation_cross_signs_exact_heads_and_restarts() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("signer.sqlite3");
        let old_id = Token::new("signer-audit-old").unwrap();
        let new_id = Token::new("signer-audit-new").unwrap();
        let old = SigningKey::from_bytes(&[31; 32]);
        let new = SigningKey::from_bytes(&[32; 32]);
        let engine = dedicated_file_engine(&path, old_id.clone(), old.clone(), BTreeMap::new());
        engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(1_000),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 1,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                10_000,
                false,
            )
            .unwrap();
        let old_head = engine.verified_audit_head().unwrap();
        engine
            .rotate_audit_key(new_id.clone(), new.clone())
            .unwrap();
        let entries = load_audit_entries(&engine.connection.lock()).unwrap();
        let rotations = load_audit_rotations(&engine.connection.lock()).unwrap();
        let rotation = rotations.values().next().unwrap();
        assert_eq!(rotation.final_old_sequence.get() + 1, old_head.0);
        assert_eq!(rotation.final_old_head, old_head.1);
        assert_eq!(rotation.first_new_sequence.get(), old_head.0);
        assert_eq!(
            rotation.first_new_head,
            entries[rotation.first_new_sequence.get() as usize].entry_hash
        );
        assert_eq!(entries.last().unwrap().signing_key_id, new_id);
        assert_ne!(entries[0].signing_key_id.as_str(), "revocation-key");
        let rotation_backup = rotations.into_values().collect::<Vec<_>>();
        drop(engine);

        let mut historical = BTreeMap::new();
        historical.insert(old_id, old.verifying_key());
        let restarted = dedicated_file_engine(&path, new_id, new, historical);
        assert!(!restarted.audit_is_degraded());
        restarted.repair_clock(2_000).unwrap();

        let restore_path = directory.path().join("restored.sqlite3");
        let mut restore_history = BTreeMap::new();
        restore_history.insert(
            Token::new("signer-audit-old").unwrap(),
            SigningKey::from_bytes(&[31; 32]).verifying_key(),
        );
        let restored = dedicated_file_engine(
            &restore_path,
            Token::new("signer-audit-new").unwrap(),
            SigningKey::from_bytes(&[32; 32]),
            restore_history,
        );
        {
            let mut connection = restored.connection.lock();
            let transaction = restored.mutation_transaction(&mut connection).unwrap();
            let keys = restored.audit_keys.read();
            restore_audit_entries(
                &transaction,
                &entries,
                &rotation_backup,
                &keys.current_key_id,
                &keys.trusted_keys,
            )
            .unwrap();
            transaction.commit().unwrap();
        }
        assert_eq!(
            restored.verified_audit_head().unwrap().0,
            entries.len() as u64
        );
    }

    #[test]
    fn audit_rotation_tamper_and_atomic_write_failure_fail_closed() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("signer.sqlite3");
        let old_id = Token::new("signer-audit-old").unwrap();
        let new_id = Token::new("signer-audit-new").unwrap();
        let old = SigningKey::from_bytes(&[41; 32]);
        let new = SigningKey::from_bytes(&[42; 32]);
        let engine = dedicated_file_engine(&path, old_id.clone(), old.clone(), BTreeMap::new());
        engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(1_000),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 1,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                10_000,
                false,
            )
            .unwrap();
        engine
            .connection
            .lock()
            .execute_batch(
                "CREATE TRIGGER fail_rotation BEFORE INSERT ON audit_key_rotations
                 BEGIN SELECT RAISE(FAIL, 'forced rotation failure'); END;",
            )
            .unwrap();
        assert!(
            engine
                .rotate_audit_key(new_id.clone(), new.clone())
                .is_err()
        );
        assert_eq!(engine.verified_audit_head().unwrap().0, 1);
        assert!(engine.audit_is_degraded());
        engine
            .connection
            .lock()
            .execute_batch("DROP TRIGGER fail_rotation")
            .unwrap();
        drop(engine);
        let engine = dedicated_file_engine(&path, old_id.clone(), old.clone(), BTreeMap::new());
        engine
            .rotate_audit_key(new_id.clone(), new.clone())
            .unwrap();
        engine
            .connection
            .lock()
            .execute(
                "UPDATE audit_key_rotations SET old_key_signature = ?1",
                [Base64UrlBytes::from_bytes(&[0; 64]).encoded()],
            )
            .unwrap();
        assert!(engine.verified_audit_head().is_err());
        assert!(engine.audit_is_degraded());
        drop(engine);

        let mut historical = BTreeMap::new();
        historical.insert(old_id, old.verifying_key());
        let restarted = dedicated_file_engine(&path, new_id, new, historical);
        assert!(restarted.audit_is_degraded());
        assert_eq!(
            restarted.repair_clock(2_000).unwrap_err().code,
            ProtocolErrorCode::ServiceUnavailable
        );
    }

    fn assert_startup_latches_mutations(path: &Path) {
        let engine = file_engine(path);
        assert!(engine.audit_degraded.load(Ordering::SeqCst));
        assert!(
            engine
                .active_approvals_expiring_by(u64::MAX)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            engine.repair_clock(1).unwrap_err().code,
            ProtocolErrorCode::ServiceUnavailable
        );
    }

    #[test]
    fn signer_clock_denies_untrusted_and_rollback_rate_windows() {
        let engine = engine();
        let initialized = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 1_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                true,
            )
            .unwrap();
        assert_eq!(initialized.effective_now_ms, 10_000);

        let rollback = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(9_999),
                    monotonic_elapsed_ms: 100,
                    monotonic_anchor_ns: 101_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                true,
            )
            .unwrap_err();
        assert_eq!(rollback.code, ProtocolErrorCode::ClockRollback);

        let untrusted = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: None,
                    monotonic_elapsed_ms: 100,
                    monotonic_anchor_ns: 201_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                true,
            )
            .unwrap_err();
        assert_eq!(untrusted.code, ProtocolErrorCode::ClockUntrusted);
    }

    #[test]
    fn signer_clock_bounds_a_forward_jump_by_monotonic_elapsed() {
        let engine = engine();
        engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 1_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                1_000,
                false,
            )
            .unwrap();
        let forward = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(20_000),
                    monotonic_elapsed_ms: 125,
                    monotonic_anchor_ns: 126_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                1_000,
                false,
            )
            .unwrap();
        assert_eq!(forward.effective_now_ms, 10_125);
        assert_eq!(forward.condition, ClockCondition::ForwardJumpRejected);
        let repeated = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(20_001),
                    monotonic_elapsed_ms: 1,
                    monotonic_anchor_ns: 127_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                1_000,
                false,
            )
            .unwrap();
        assert_eq!(repeated.condition, ClockCondition::ForwardJumpRejected);
        let repaired = engine.repair_clock(20_000).unwrap();
        assert_eq!(repaired.condition, ClockCondition::Repaired);
        let events: Vec<String> = {
            let connection = engine.connection.lock();
            let mut statement = connection
                .prepare("SELECT event_type FROM audit_chain ORDER BY sequence")
                .unwrap();
            statement
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(
            events,
            [
                "clock.initialized",
                "clock.forward_jump",
                "clock.forward_jump",
                "clock.repaired"
            ]
        );
    }

    #[test]
    fn signer_clock_accepts_non_decreasing_wall_time_across_a_boot_change() {
        // A reboot restarts the kernel's suspend-aware clock. Bloom cannot
        // measure powered-off time from that new monotonic domain, so it uses
        // the durable floor to reject rollback and otherwise accepts the host
        // wall clock without requiring an external synchronization daemon.
        let engine = engine();
        engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000),
                    monotonic_elapsed_ms: 0,
                    // One minute into the prior boot.
                    monotonic_anchor_ns: 60 * 1_000_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                false,
            )
            .unwrap();

        let two_hours_ms = 2 * 60 * 60 * 1_000;
        let rebooted = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000 + two_hours_ms),
                    monotonic_elapsed_ms: 0,
                    // Two hours into the new boot: numerically larger, so the
                    // rollback check cannot catch it.
                    monotonic_anchor_ns: 2 * 60 * 60 * 1_000_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([2; 16]),
                3_600_000,
                false,
            )
            .unwrap();

        assert_eq!(rebooted.condition, ClockCondition::Healthy);
        assert_eq!(rebooted.effective_now_ms, 10_000 + two_hours_ms);
    }

    #[test]
    fn signer_clock_restart_credits_downtime_via_matching_absolute_monotonic_anchor() {
        let engine = engine();
        engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 1_000_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                false,
            )
            .unwrap();

        // Simulate a Signer process restart: the sampler's process-relative
        // accumulator resets to 0 even though > MAX_FORWARD_STEP_MS of real
        // downtime elapsed. The UTC delta (2h) and the absolute monotonic
        // anchor delta (2h, in the same suspend-aware kernel domain) agree,
        // so the restart must be credited rather than rejected as a forward
        // jump.
        let two_hours_ms = 2 * 60 * 60 * 1_000;
        let two_hours_ns = two_hours_ms * 1_000_000;
        let restarted = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000 + two_hours_ms),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 1_000_000_000 + two_hours_ns,
                },
                // Same boot: this models a Signer *process* restart, which is
                // what the anchor delta is allowed to credit. A different boot
                // is covered by the rejection test below.
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                false,
            )
            .unwrap();
        assert_eq!(restarted.condition, ClockCondition::Healthy);
        assert_eq!(restarted.effective_now_ms, 10_000 + two_hours_ms);
    }

    #[test]
    fn signer_clock_read_only_restart_credits_downtime_via_matching_absolute_monotonic_anchor() {
        let engine = engine();
        engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 1_000_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                false,
            )
            .unwrap();

        let two_hours_ms = 2 * 60 * 60 * 1_000;
        let two_hours_ns = two_hours_ms * 1_000_000;
        let restarted = engine
            .observe_time_read_only(
                PlatformTimeReading {
                    utc_ms: Some(10_000 + two_hours_ms),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 1_000_000_000 + two_hours_ns,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
            )
            .unwrap();
        assert_eq!(restarted.condition, ClockCondition::Healthy);
        assert_eq!(restarted.effective_now_ms, 10_000 + two_hours_ms);
    }

    #[test]
    fn signer_clock_new_boot_with_smaller_anchor_accepts_wall_time() {
        let engine = engine();
        engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 1_000_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                false,
            )
            .unwrap();

        // A kernel reboot normally makes the absolute anchor smaller. The new
        // boot epoch proves the old anchor is incomparable, so a nondecreasing
        // host wall clock recovers without operator repair.
        let two_hours_ms = 2 * 60 * 60 * 1_000;
        let rebooted = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000 + two_hours_ms),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 500_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([2; 16]),
                3_600_000,
                false,
            )
            .unwrap();
        assert_eq!(rebooted.condition, ClockCondition::Healthy);
        assert_eq!(rebooted.effective_now_ms, 10_000 + two_hours_ms);
    }

    #[test]
    fn signer_clock_legacy_zero_anchor_does_not_grant_unbounded_forward_credit() {
        let engine = engine();
        {
            let connection = engine.connection.lock();
            connection
                .execute(
                    "INSERT INTO clock_state(
                         singleton, last_effective_ms, condition, observed_utc_ms,
                         monotonic_anchor_ns, boot_epoch
                     ) VALUES (1, '10000', 'HEALTHY', '10000', '0', ?1)",
                    [bloom_signer_api::BootEpoch::from_bytes([1; 16]).as_str()],
                )
                .unwrap();
        }

        // A pre-migration row persists the '0' sentinel anchor. Treating
        // that as a real absolute anchor would let an attacker-controlled or
        // simply very large current anchor manufacture an unbounded forward
        // credit; the sampler's process-relative elapsed reading must be
        // used instead, preserving the existing fail-closed behavior.
        let two_hours_ms = 2 * 60 * 60 * 1_000;
        let decision = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000 + two_hours_ms),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 9_999_999_999,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                false,
            )
            .unwrap();
        assert_eq!(decision.condition, ClockCondition::ForwardJumpRejected);
        assert_eq!(decision.effective_now_ms, 10_000);
    }

    #[test]
    fn signer_clock_unknown_legacy_boot_epoch_does_not_impersonate_a_reboot() {
        let engine = engine();
        {
            let connection = engine.connection.lock();
            connection
                .execute(
                    "INSERT INTO clock_state(
                         singleton, last_effective_ms, condition, observed_utc_ms,
                         monotonic_anchor_ns, boot_epoch
                     ) VALUES (1, '10000', 'HEALTHY', '10000', '1000000000', ?1)",
                    [zero_boot_epoch().as_str()],
                )
                .unwrap();
        }

        let two_hours_ms = 2 * 60 * 60 * 1_000;
        let decision = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000 + two_hours_ms),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 1_000_000_000 + two_hours_ms * 1_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                false,
            )
            .unwrap();
        assert_eq!(decision.condition, ClockCondition::ForwardJumpRejected);
        assert_eq!(decision.effective_now_ms, 10_000);
    }

    #[test]
    fn signer_clock_same_process_incremental_elapsed_still_advances_healthily() {
        let engine = engine();
        engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000),
                    monotonic_elapsed_ms: 0,
                    monotonic_anchor_ns: 1_000_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                false,
            )
            .unwrap();

        // Two further observations within the same process, each advancing
        // the absolute anchor by exactly as much as the process-relative
        // elapsed reading reports. Same-process behavior must remain
        // unchanged: both signals agree, so the effective clock advances by
        // the same amount either way.
        let first = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_050),
                    monotonic_elapsed_ms: 50,
                    monotonic_anchor_ns: 1_050_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                false,
            )
            .unwrap();
        assert_eq!(first.condition, ClockCondition::Healthy);
        assert_eq!(first.effective_now_ms, 10_050);

        let second = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_100),
                    monotonic_elapsed_ms: 50,
                    monotonic_anchor_ns: 1_100_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([1; 16]),
                3_600_000,
                false,
            )
            .unwrap();
        assert_eq!(second.condition, ClockCondition::Healthy);
        assert_eq!(second.effective_now_ms, 10_100);
    }

    #[test]
    fn signer_clock_schema_migrates_an_existing_database() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("signer.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "
                CREATE TABLE clock_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    last_effective_ms TEXT NOT NULL,
                    condition TEXT NOT NULL
                );
                INSERT INTO clock_state(singleton, last_effective_ms, condition)
                VALUES (1, '1000', 'HEALTHY');
                CREATE TABLE operations (
                    operation_id TEXT PRIMARY KEY,
                    operation_digest TEXT NOT NULL,
                    retry_binding_digest TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    signature_count TEXT NOT NULL,
                    accepted_at_ms TEXT NOT NULL,
                    state TEXT NOT NULL,
                    normalized_result TEXT
                );
                INSERT INTO operations(
                    operation_id, operation_digest, retry_binding_digest, approval_id,
                    signature_count, accepted_at_ms, state, normalized_result
                ) VALUES (
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                    'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
                    '1', '1000', 'COMMITTED', NULL
                );
                ",
            )
            .unwrap();
        drop(connection);
        let engine = SignerEngine::open(
            &path,
            Token::new("broker-key").unwrap(),
            SigningKey::from_bytes(&[1; 32]).verifying_key(),
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
            Token::new("revocation-key").unwrap(),
            SigningKey::from_bytes(&[3; 32]),
            SignerAuditKeys {
                current_key_id: Token::new("audit-key").unwrap(),
                current_signing_key: SigningKey::from_bytes(&[30; 32]),
                historical_verifying_keys: BTreeMap::new(),
            },
            Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap()),
        )
        .unwrap();
        let decision = engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(1_001),
                    monotonic_elapsed_ms: 1,
                    monotonic_anchor_ns: 2_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([3; 16]),
                3_600_000,
                false,
            )
            .unwrap();
        assert_eq!(decision.effective_now_ms, 1_001);
        let migrated_anchor: (Option<String>, String, String) = engine
            .connection
            .lock()
            .query_row(
                "SELECT observed_utc_ms, monotonic_anchor_ns, boot_epoch
                 FROM operation_clock_anchors",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            migrated_anchor,
            (None, "0".into(), "00000000000000000000000000000000".into())
        );
        engine
            .observe_time(
                PlatformTimeReading {
                    utc_ms: Some(10_000),
                    monotonic_elapsed_ms: 1,
                    monotonic_anchor_ns: 3_000_000,
                },
                bloom_signer_api::BootEpoch::from_bytes([3; 16]),
                1_000,
                false,
            )
            .unwrap();
        drop(engine);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE audit_chain SET payload_jcs = '{\"tampered\":true}'
                 WHERE sequence = 0",
                [],
            )
            .unwrap();
        drop(connection);
        let reopened = SignerEngine::open(
            &path,
            Token::new("broker-key").unwrap(),
            SigningKey::from_bytes(&[1; 32]).verifying_key(),
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
            Token::new("revocation-key").unwrap(),
            SigningKey::from_bytes(&[3; 32]),
            SignerAuditKeys {
                current_key_id: Token::new("audit-key").unwrap(),
                current_signing_key: SigningKey::from_bytes(&[30; 32]),
                historical_verifying_keys: BTreeMap::new(),
            },
            Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap()),
        )
        .unwrap();
        assert_eq!(
            reopened
                .operation_status(
                    &OperationId::new(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    )
                    .unwrap()
                )
                .unwrap()
                .state,
            OperationState::Succeeded,
            "read/status must remain available after startup latches audit degradation"
        );
        assert_eq!(
            reopened
                .observe_time(
                    PlatformTimeReading {
                        utc_ms: Some(10_001),
                        monotonic_elapsed_ms: 1,
                        monotonic_anchor_ns: 4_000_000,
                    },
                    bloom_signer_api::BootEpoch::from_bytes([3; 16]),
                    1_000,
                    false,
                )
                .unwrap_err()
                .code,
            ProtocolErrorCode::ServiceUnavailable
        );
    }

    #[test]
    fn audit_detects_payload_hash_signature_and_key_id_mutation() {
        for mutation in ["payload", "hash", "signature", "key_id"] {
            let directory = tempfile::TempDir::new().unwrap();
            let path = directory.path().join("signer.sqlite3");
            seed_audit(&path);
            let connection = Connection::open(&path).unwrap();
            match mutation {
                "payload" => connection
                    .execute(
                        "UPDATE audit_chain SET payload_jcs = '{\"tampered\":true}' WHERE sequence = 1",
                        [],
                    )
                    .unwrap(),
                "hash" => connection
                    .execute(
                        "UPDATE audit_chain SET entry_hash = ?1 WHERE sequence = 1",
                        ["aa".repeat(32)],
                    )
                    .unwrap(),
                "signature" => connection
                    .execute(
                        "UPDATE audit_chain SET signature = ?1 WHERE sequence = 1",
                        [Base64UrlBytes::from_bytes(&[99; 64]).encoded()],
                    )
                    .unwrap(),
                "key_id" => connection
                    .execute(
                        "UPDATE audit_chain SET signing_key_id = 'foreign-key' WHERE sequence = 1",
                        [],
                    )
                    .unwrap(),
                _ => unreachable!(),
            };
            drop(connection);
            assert_startup_latches_mutations(&path);
        }
    }

    #[test]
    fn audit_detects_non_tail_deletion_and_reordering() {
        for mutation in ["delete", "reorder"] {
            let directory = tempfile::TempDir::new().unwrap();
            let path = directory.path().join("signer.sqlite3");
            seed_audit(&path);
            let connection = Connection::open(&path).unwrap();
            if mutation == "delete" {
                connection
                    .execute("DELETE FROM audit_chain WHERE sequence = 1", [])
                    .unwrap();
            } else {
                connection
                    .execute_batch(
                        "UPDATE audit_chain SET sequence = 99 WHERE sequence = 0;
                         UPDATE audit_chain SET sequence = 0 WHERE sequence = 1;
                         UPDATE audit_chain SET sequence = 1 WHERE sequence = 99;",
                    )
                    .unwrap();
            }
            drop(connection);
            assert_startup_latches_mutations(&path);
        }
    }

    #[test]
    fn forced_audit_write_failure_rolls_back_effect_and_latches_mutations() {
        let engine = engine();
        engine
            .connection
            .lock()
            .execute_batch(
                "CREATE TRIGGER fail_audit_insert BEFORE INSERT ON audit_chain
                 BEGIN SELECT RAISE(FAIL, 'forced audit failure'); END;",
            )
            .unwrap();
        let status = CeremonyPublicStatus {
            ceremony_id: Digest32::from_bytes([43; 32]),
            ceremony_kind: bloom_signer_api::CeremonyKind::WalletDelete,
            operation_id: OperationId::from_bytes([44; 32]),
            state: bloom_signer_api::CeremonyState::Succeeded,
            expires_at_ms: DecimalU64::new(10_000),
            ceremony_url: None,
            receipt_digest: Some(Digest32::from_bytes([45; 32])),
        };
        assert_eq!(
            engine
                .persist_ceremony_public_status(&status)
                .unwrap_err()
                .code,
            ProtocolErrorCode::ServiceUnavailable
        );
        assert!(
            engine
                .ceremony_public_status(&status.operation_id)
                .unwrap()
                .is_none()
        );
        let connection = engine.connection.lock();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM audit_chain", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        connection
            .execute("DROP TRIGGER fail_audit_insert", [])
            .unwrap();
        drop(connection);
        assert_eq!(
            engine
                .persist_ceremony_public_status(&status)
                .unwrap_err()
                .code,
            ProtocolErrorCode::ServiceUnavailable,
            "audit degradation must remain latched after the storage fault clears"
        );
    }

    #[test]
    fn runtime_full_chain_verification_latches_before_mutation() {
        let engine = engine();
        {
            let mut connection = engine.connection.lock();
            let transaction = engine.mutation_transaction(&mut connection).unwrap();
            engine
                .append_audit(
                    &transaction,
                    "test.first",
                    &serde_json::json!({ "value": "one" }),
                )
                .unwrap();
            engine
                .append_audit(
                    &transaction,
                    "test.second",
                    &serde_json::json!({ "value": "two" }),
                )
                .unwrap();
            transaction.commit().unwrap();
        }
        engine
            .connection
            .lock()
            .execute(
                "UPDATE audit_chain SET payload_jcs = '{\"value\":\"changed\"}' WHERE sequence = 0",
                [],
            )
            .unwrap();
        assert!(
            engine
                .active_approvals_expiring_by(u64::MAX)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            engine.repair_clock(1).unwrap_err().code,
            ProtocolErrorCode::ServiceUnavailable
        );
        assert!(engine.audit_degraded.load(Ordering::SeqCst));
    }
}
