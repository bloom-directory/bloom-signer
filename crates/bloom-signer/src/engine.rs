use bloom_triad_protocol::{
    ApprovalLifecycleState, ApprovalPublicStatus, ApprovalSelector, ApprovalTombstone,
    Base64UrlBytes, CeremonyPublicStatus, CredentialPublic, CredentialState, CustodyResult,
    DecimalU64, Digest32, KeyRef, OperationId, OperationPublicStatus, OperationState,
    PolicyCommitReceipt, PolicyCompareAndSwapRequest, ProtocolError, ProtocolErrorCode,
    RevocationState, SealedApprovalTerms, SelectorKind, SignRequest, SignedPolicySnapshot,
    SignerActivationReceipt, SigningResult, Token, WalletTombstone, WebAuthnCredential,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, path::Path, sync::Arc};

use crate::custody::UnlockedWallet;
use crate::custody::{WalletCustody, WalletCustodyBackup};
use crate::registry::BackendRegistry;

const POLICY_SIGNATURE_DOMAIN: &[u8] = b"bloom-policy-snapshot/v1";
const POLICY_RECEIPT_DOMAIN: &[u8] = b"bloom-policy-commit-receipt/v1";
const POLICY_CEREMONY_DOMAIN: &[u8] = b"bloom-policy-ceremony-authorization/v1";
const APPROVAL_TOMBSTONE_DOMAIN: &[u8] = b"bloom-approval-tombstone/v1";
const WALLET_TOMBSTONE_DOMAIN: &[u8] = b"bloom-wallet-tombstone/v1";
const REVOCATION_STATE_DOMAIN: &[u8] = b"bloom-revocation-state/v1";
const REVOCATION_OPERATION_DOMAIN: &[u8] = b"bloom-revocation-operation/v1";
const SIGNER_RETRY_BINDING_DOMAIN: &[u8] = b"bloom-signer-retry-binding/v1";
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

pub(crate) enum CeremonyDatabaseEffect {
    None,
    InitialPolicy {
        snapshot: SignedPolicySnapshot,
        policy_verifying_key: Base64UrlBytes,
        backend_enrollment: Option<BackendEnrollmentBackup>,
    },
    PolicyUpdate(Box<CeremonyPolicyUpdate>),
    EnrollKey(KeyRef),
}

pub(crate) struct CeremonyPolicyUpdate {
    request: PolicyCompareAndSwapRequest,
    receipt: PolicyCommitReceipt,
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
    pub state: BackupOperationState,
    pub normalized_result: Option<Base64UrlBytes>,
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
pub struct SignerBackupSet {
    pub wallet_id: Token,
    pub wallet_revocation_epoch: DecimalU64,
    pub custody: Option<WalletCustodyBackup>,
    pub derivation_registry: Option<DerivationRegistryBackup>,
    pub backend_enrollments: Vec<BackendEnrollmentBackup>,
    pub policy: Option<PolicyBackup>,
    pub approvals: Vec<ApprovalStateBackup>,
    pub approval_tombstones: Vec<ApprovalTombstone>,
    pub wallet_tombstone: Option<WalletTombstone>,
    pub operations: Vec<OperationStateBackup>,
    pub attempts: Vec<AttemptStateBackup>,
    pub revocation_operations: Vec<RevocationOperationBackup>,
    pub approval_counters: Vec<ApprovalCounterBackup>,
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
    broker_key_id: Token,
    broker_public_key: VerifyingKey,
    ceremony_public_key: VerifyingKey,
    revocation_key_id: Token,
    revocation_signing_key: Arc<SigningKey>,
    backend_registry: Arc<BackendRegistry>,
}

impl SignerEngine {
    pub(crate) fn backend_registry(&self) -> &Arc<BackendRegistry> {
        &self.backend_registry
    }

    pub fn open(
        path: impl AsRef<Path>,
        broker_key_id: Token,
        broker_public_key: VerifyingKey,
        ceremony_public_key: VerifyingKey,
        revocation_key_id: Token,
        revocation_signing_key: SigningKey,
        backend_registry: Arc<BackendRegistry>,
    ) -> Result<Self, ProtocolError> {
        Self::from_connection(
            Connection::open(path).map_err(storage)?,
            broker_key_id,
            broker_public_key,
            ceremony_public_key,
            revocation_key_id,
            revocation_signing_key,
            backend_registry,
        )
    }

    pub fn open_in_memory(
        broker_key_id: Token,
        broker_public_key: VerifyingKey,
        ceremony_public_key: VerifyingKey,
        revocation_key_id: Token,
        revocation_signing_key: SigningKey,
        backend_registry: Arc<BackendRegistry>,
    ) -> Result<Self, ProtocolError> {
        Self::from_connection(
            Connection::open_in_memory().map_err(storage)?,
            broker_key_id,
            broker_public_key,
            ceremony_public_key,
            revocation_key_id,
            revocation_signing_key,
            backend_registry,
        )
    }

    fn from_connection(
        connection: Connection,
        broker_key_id: Token,
        broker_public_key: VerifyingKey,
        ceremony_public_key: VerifyingKey,
        revocation_key_id: Token,
        revocation_signing_key: SigningKey,
        backend_registry: Arc<BackendRegistry>,
    ) -> Result<Self, ProtocolError> {
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
                CREATE TABLE IF NOT EXISTS enrolled_keys (
                    key_fingerprint TEXT PRIMARY KEY,
                    key_ref_jcs TEXT NOT NULL,
                    available INTEGER NOT NULL
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
        Ok(Self {
            connection: Mutex::new(connection),
            broker_key_id,
            broker_public_key,
            ceremony_public_key,
            revocation_key_id,
            revocation_signing_key: Arc::new(revocation_signing_key),
            backend_registry,
        })
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
        let transaction = connection.transaction().map_err(storage)?;
        if !self.backend_registry.key_is_registered(&terms.key_ref)? {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "approval key is not registered in a compiled backend",
            ));
        }
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
                ceremony_kind: bloom_triad_protocol::CeremonyKind::SealedApproval,
                operation_id: receipt.activation_operation_id.clone(),
                state: bloom_triad_protocol::CeremonyState::Succeeded,
                expires_at_ms: receipt.expires_at_ms.clone(),
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
        let transaction = connection.transaction().map_err(storage)?;
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
                                key_fingerprint, key_ref_jcs, available
                             ) VALUES (?1, ?2, 1)",
                            params![
                                key_ref.public_key_fingerprint.as_str(),
                                serde_jcs::to_string(key_ref).map_err(malformed)?,
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
            CeremonyDatabaseEffect::PolicyUpdate(update) => {
                let CeremonyPolicyUpdate { request, receipt } = *update;
                let changed = transaction
                    .execute(
                        "UPDATE policies SET version = ?4, digest = ?5,
                            canonical_policy = ?6, snapshot_jcs = ?7
                         WHERE wallet_id = ?1 AND version = ?2 AND digest = ?3",
                        params![
                            request.wallet_id.as_str(),
                            request.baseline_version.get().to_string(),
                            request.baseline_digest.as_str(),
                            receipt.committed.version.get().to_string(),
                            receipt.committed.policy_digest.as_str(),
                            receipt.committed.canonical_policy.encoded(),
                            serde_jcs::to_string(&receipt.committed).map_err(malformed)?,
                        ],
                    )
                    .map_err(storage)?;
                if changed != 1 {
                    return Err(error(
                        ProtocolErrorCode::PolicyBaselineStale,
                        "policy compare-and-swap baseline changed before ceremony commit",
                    ));
                }
                transaction
                    .execute(
                        "INSERT INTO policy_commit_receipts(
                            operation_id, request_jcs, receipt_jcs
                         ) VALUES (?1, ?2, ?3)",
                        params![
                            request.operation_id.as_str(),
                            serde_jcs::to_string(&request).map_err(malformed)?,
                            serde_jcs::to_string(&receipt).map_err(malformed)?,
                        ],
                    )
                    .map_err(storage)?;
            }
            CeremonyDatabaseEffect::EnrollKey(key_ref) => {
                transaction
                    .execute(
                        "INSERT INTO enrolled_keys(key_fingerprint, key_ref_jcs, available)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(key_fingerprint) DO UPDATE SET
                            key_ref_jcs = excluded.key_ref_jcs,
                            available = excluded.available",
                        params![
                            key_ref.public_key_fingerprint.as_str(),
                            serde_jcs::to_string(&key_ref).map_err(malformed)?,
                            true,
                        ],
                    )
                    .map_err(storage)?;
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
        transaction.commit().map_err(storage)
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
        self.connection
            .lock()
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
        self.connection
            .lock()
            .execute(
                "INSERT INTO enrolled_keys(key_fingerprint, key_ref_jcs, available)
                 VALUES (?1, ?2, ?3)
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
        Ok(())
    }

    pub fn authorize_sign(
        &self,
        request: &SignRequest,
        effective_now_ms: u64,
    ) -> Result<SignAuthorization, ProtocolError> {
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
        let transaction = connection.transaction().map_err(storage)?;
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
        let transaction = connection.transaction().map_err(storage)?;
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
        let changed = self
            .connection
            .lock()
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
        Ok(())
    }

    /// Durably records the point after which a backend call may occur. A
    /// restart from this state is ambiguous and must never automatically
    /// dispatch the operation again.
    pub fn mark_operation_dispatched(
        &self,
        operation_id: &OperationId,
    ) -> Result<(), ProtocolError> {
        let changed = self
            .connection
            .lock()
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
            .map(|encoded| {
                Base64UrlBytes::parse(encoded).and_then(|bytes| {
                    serde_json::from_slice::<SigningResult>(&bytes.decode()).map_err(malformed)
                })
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
        result.flatten().map(Base64UrlBytes::parse).transpose()
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

    pub fn policy_commit_receipt(
        &self,
        request: &PolicyCompareAndSwapRequest,
    ) -> Result<PolicyCommitReceipt, ProtocolError> {
        let row: (String, String) = self
            .connection
            .lock()
            .query_row(
                "SELECT request_jcs, receipt_jcs FROM policy_commit_receipts
                 WHERE operation_id = ?1",
                [request.operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| {
                error(
                    ProtocolErrorCode::ApprovalNotFound,
                    "policy ceremony has not committed",
                )
            })?;
        if row.0 != serde_jcs::to_string(request).map_err(malformed)? {
            return Err(error(
                ProtocolErrorCode::OperationIdConflict,
                "policy operation ID was committed for different request terms",
            ));
        }
        serde_json::from_str(&row.1).map_err(malformed)
    }

    pub fn enrolled_key_refs(&self, wallet_id: &Token) -> Result<Vec<KeyRef>, ProtocolError> {
        let connection = self.connection.lock();
        let mut statement = connection
            .prepare(
                "SELECT key_ref_jcs FROM enrolled_keys
                 WHERE available = 1 ORDER BY key_fingerprint",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(storage)?;
        let mut keys = Vec::new();
        for row in rows {
            let key: KeyRef = serde_json::from_str(&row.map_err(storage)?).map_err(malformed)?;
            if &key.backend_instance == wallet_id {
                keys.push(key);
            }
        }
        Ok(keys)
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
        let transaction = connection.transaction().map_err(storage)?;
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
        let transaction = connection.transaction().map_err(storage)?;
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

    pub fn authorize_policy_update(
        &self,
        request: &PolicyCompareAndSwapRequest,
        ceremony_signature: &Base64UrlBytes,
    ) -> Result<(), ProtocolError> {
        let request_jcs = serde_jcs::to_string(request).map_err(malformed)?;
        let signature: [u8; 64] = ceremony_signature.decode().try_into().map_err(|_| {
            error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "policy ceremony signature must contain 64 bytes",
            )
        })?;
        let mut message = POLICY_CEREMONY_DOMAIN.to_vec();
        message.extend_from_slice(request_jcs.as_bytes());
        self.ceremony_public_key
            .verify(&message, &Signature::from_bytes(&signature))
            .map_err(|_| {
                error(
                    ProtocolErrorCode::UnauthenticatedPeer,
                    "independent policy ceremony authorization is invalid",
                )
            })?;
        self.connection
            .lock()
            .execute(
                "INSERT INTO policy_authorizations(operation_id, request_jcs) VALUES (?1, ?2)",
                params![request.operation_id.as_str(), request_jcs],
            )
            .map_err(storage)?;
        Ok(())
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
        request: &PolicyCompareAndSwapRequest,
        unlocked: &UnlockedWallet,
        _verified: crate::ceremony::VerifiedCeremonyActivation,
    ) -> Result<(PolicyCommitReceipt, CeremonyDatabaseEffect), ProtocolError> {
        if unlocked.wallet_id() != &request.wallet_id {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "unlocked policy key belongs to a different wallet",
            ));
        }
        let proposed_digest =
            Digest32::from_bytes(Sha256::digest(request.proposed_canonical_policy.decode()).into());
        if proposed_digest != request.proposed_policy_digest {
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
                [request.wallet_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(storage)?;
        if current.0 != request.baseline_version.get().to_string()
            || current.1 != request.baseline_digest.as_str()
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
        let next_version = request
            .baseline_version
            .get()
            .checked_add(1)
            .ok_or_else(|| error(ProtocolErrorCode::PolicyBaselineStale, "version overflow"))?;
        let policy_signing_key_id = Token::new(current.2).map_err(malformed)?;
        let snapshot = sign_policy_snapshot(
            &request.wallet_id,
            next_version,
            request.proposed_canonical_policy.clone(),
            &policy_signing_key_id,
            unlocked,
        )?;
        let mut receipt = PolicyCommitReceipt {
            operation_id: request.operation_id.clone(),
            wallet_id: request.wallet_id.clone(),
            previous_version: request.baseline_version.clone(),
            committed: snapshot,
            authority_diff_digest: request.authority_diff_digest.clone(),
            signer_key_id: policy_signing_key_id,
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        let mut message = POLICY_RECEIPT_DOMAIN.to_vec();
        message.extend_from_slice(&serde_jcs::to_vec(&receipt).map_err(malformed)?);
        receipt.signer_signature =
            Base64UrlBytes::from_bytes(&unlocked.sign_policy_message(&message)?);
        Ok((
            receipt.clone(),
            CeremonyDatabaseEffect::PolicyUpdate(Box::new(CeremonyPolicyUpdate {
                request: request.clone(),
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
        self.connection
            .lock()
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
        Ok(snapshot)
    }

    pub fn compare_and_swap_policy(
        &self,
        request: &PolicyCompareAndSwapRequest,
        unlocked: &UnlockedWallet,
    ) -> Result<PolicyCommitReceipt, ProtocolError> {
        if unlocked.wallet_id() != &request.wallet_id {
            return Err(error(
                ProtocolErrorCode::KeyrefMismatch,
                "unlocked policy key belongs to a different wallet",
            ));
        }
        let proposed_digest =
            Digest32::from_bytes(Sha256::digest(request.proposed_canonical_policy.decode()).into());
        if proposed_digest != request.proposed_policy_digest {
            return Err(error(
                ProtocolErrorCode::PolicyBaselineStale,
                "proposed policy digest mismatch",
            ));
        }
        let mut connection = self.connection.lock();
        let transaction = connection.transaction().map_err(storage)?;
        let authorization: Option<String> = transaction
            .query_row(
                "SELECT request_jcs FROM policy_authorizations WHERE operation_id = ?1",
                [request.operation_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        if authorization.as_deref()
            != Some(serde_jcs::to_string(request).map_err(malformed)?.as_str())
        {
            return Err(error(
                ProtocolErrorCode::PolicyBaselineStale,
                "policy ceremony authorization binding mismatch",
            ));
        }
        let current: (String, String, String, String) = transaction
            .query_row(
                "SELECT version, digest, policy_signing_key_id, policy_verifying_key
                 FROM policies WHERE wallet_id = ?1",
                [request.wallet_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(storage)?;
        if current.0 != request.baseline_version.get().to_string()
            || current.1 != request.baseline_digest.as_str()
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
        let next_version = request
            .baseline_version
            .get()
            .checked_add(1)
            .ok_or_else(|| error(ProtocolErrorCode::PolicyBaselineStale, "version overflow"))?;
        let policy_signing_key_id = Token::new(current.2).map_err(malformed)?;
        let snapshot = sign_policy_snapshot(
            &request.wallet_id,
            next_version,
            request.proposed_canonical_policy.clone(),
            &policy_signing_key_id,
            unlocked,
        )?;
        let mut receipt = PolicyCommitReceipt {
            operation_id: request.operation_id.clone(),
            wallet_id: request.wallet_id.clone(),
            previous_version: request.baseline_version.clone(),
            committed: snapshot,
            authority_diff_digest: request.authority_diff_digest.clone(),
            signer_key_id: policy_signing_key_id,
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        let receipt_preimage = serde_jcs::to_vec(&receipt).map_err(malformed)?;
        let mut message = POLICY_RECEIPT_DOMAIN.to_vec();
        message.extend_from_slice(&receipt_preimage);
        receipt.signer_signature =
            Base64UrlBytes::from_bytes(&unlocked.sign_policy_message(&message)?);
        transaction
            .execute(
                "UPDATE policies SET version = ?2, digest = ?3,
                    canonical_policy = ?4, snapshot_jcs = ?5
                 WHERE wallet_id = ?1",
                params![
                    request.wallet_id.as_str(),
                    next_version.to_string(),
                    request.proposed_policy_digest.as_str(),
                    request.proposed_canonical_policy.encoded(),
                    serde_jcs::to_string(&receipt.committed).map_err(malformed)?
                ],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "DELETE FROM policy_authorizations WHERE operation_id = ?1",
                [request.operation_id.as_str()],
            )
            .map_err(storage)?;
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
        let transaction = connection.transaction().map_err(storage)?;
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
                        "INSERT INTO enrolled_keys(key_fingerprint, key_ref_jcs, available)
                         VALUES (?1, ?2, 0)
                         ON CONFLICT(key_fingerprint) DO UPDATE SET
                            key_ref_jcs = excluded.key_ref_jcs,
                            available = 0",
                        params![
                            key_ref.public_key_fingerprint.as_str(),
                            serde_jcs::to_string(key_ref).map_err(malformed)?
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
        let connection = self.connection.lock();
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
            .map(|(snapshot, verifying_key)| {
                Ok(PolicyBackup {
                    snapshot: serde_json::from_str(&snapshot).map_err(malformed)?,
                    policy_verifying_key: Base64UrlBytes::parse(verifying_key)?,
                })
            })
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
                "SELECT operation_id, operation_digest, retry_binding_digest, approval_id,
                        signature_count, accepted_at_ms, state, normalized_result
                 FROM operations WHERE approval_id IN (
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
            ) = row.map_err(storage)?;
            operations.push(OperationStateBackup {
                operation_id: OperationId::new(operation_id).map_err(malformed)?,
                operation_digest: Digest32::new(operation_digest).map_err(malformed)?,
                retry_binding_digest: Digest32::new(retry_binding_digest).map_err(malformed)?,
                approval_id: Digest32::new(approval_id).map_err(malformed)?,
                signature_count: DecimalU64::new(signature_count.parse().map_err(malformed)?),
                accepted_at_ms: DecimalU64::new(accepted_at_ms.parse().map_err(malformed)?),
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
        Ok(SignerBackupSet {
            wallet_id: wallet_id.clone(),
            wallet_revocation_epoch,
            custody,
            derivation_registry,
            backend_enrollments,
            policy,
            approvals,
            approval_tombstones,
            wallet_tombstone,
            operations,
            attempts,
            revocation_operations,
            approval_counters,
        })
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

fn retry_binding_digest(
    request: &bloom_triad_protocol::UnsignedSignRequest,
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
