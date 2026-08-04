use serde::{Deserialize, Serialize};

use crate::{
    Base64UrlBytes, BootEpoch, CeremonyKind, CustodyCompleteRequest, CustodyPrepareRequest,
    CustodyResult, DecimalU64, Digest32, HelloChallenge, KeyRef, OperationId, PolicyCommitReceipt,
    PolicyCompareAndSwapRequest, ProtocolError, RevocationState, ServiceFuture, SignRequest,
    SignedPolicySnapshot, SigningResult, Token,
};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    Ready,
    DegradedReadOnly,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Readiness {
    pub service_id: Token,
    pub service_version: String,
    pub build_digest: Digest32,
    pub boot_epoch: BootEpoch,
    pub state: ReadinessState,
    pub conditions: Vec<Token>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendPublicCapability {
    pub backend_id: Token,
    pub backend_instance_id: Token,
    pub crypto_suites: Vec<crate::CryptoSuite>,
    pub derivation_schemes: Vec<Token>,
    pub networked: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierPublicCapability {
    pub verifier_id: Token,
    pub verifier_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCapabilities {
    pub service_id: Token,
    pub service_version: String,
    pub build_digest: Digest32,
    pub protocol_major: u16,
    pub protocol_minor_min: u16,
    pub protocol_minor_max: u16,
    pub methods: Vec<Token>,
    pub schemas: Vec<Token>,
    pub backends: Vec<BackendPublicCapability>,
    pub assurance_verifiers: Vec<VerifierPublicCapability>,
    pub frame_max_bytes: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdRequest {
    pub id: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletRequest {
    pub wallet_id: Token,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletOperationRequest {
    pub operation_id: OperationId,
    pub wallet_id: Token,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyBindOutputRecipientRequest {
    pub operation_id: OperationId,
    pub recipient_key: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRequest {
    pub key_ref: KeyRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeRequest {
    pub operation_id: OperationId,
    pub approval_id: Digest32,
    pub wallet_id: Token,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ApprovalLifecycleState {
    #[serde(rename = "PREPARED")]
    Prepared,
    #[serde(rename = "AWAITING_CEREMONY")]
    AwaitingCeremony,
    #[serde(rename = "ORPHANED")]
    Orphaned,
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "EXHAUSTED")]
    Exhausted,
    #[serde(rename = "EXPIRED")]
    Expired,
    #[serde(rename = "REVOKED")]
    Revoked,
    #[serde(rename = "CANCELLED")]
    Cancelled,
    #[serde(rename = "FAILED")]
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalPublicStatus {
    pub approval_id: Digest32,
    pub wallet_id: Token,
    pub state: ApprovalLifecycleState,
    pub effective_claim_assurance: Option<crate::ClaimAssuranceLevel>,
    pub ceremony_url: Option<String>,
    pub ceremony_expires_at_ms: Option<DecimalU64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRequest {
    pub operation_id: OperationId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OperationState {
    #[serde(rename = "RECEIVED")]
    Received,
    #[serde(rename = "VALIDATED")]
    Validated,
    #[serde(rename = "RESERVED")]
    Reserved,
    #[serde(rename = "DISPATCHED")]
    Dispatched,
    #[serde(rename = "DOWNSTREAM_ACCEPTED")]
    DownstreamAccepted,
    #[serde(rename = "COMMITTED")]
    Committed,
    #[serde(rename = "SUCCEEDED")]
    Succeeded,
    #[serde(rename = "DENIED")]
    Denied,
    #[serde(rename = "CANCELLED")]
    Cancelled,
    #[serde(rename = "FAILED")]
    Failed,
    #[serde(rename = "QUARANTINED")]
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPublicStatus {
    pub operation_id: OperationId,
    pub operation_digest: Digest32,
    pub state: OperationState,
    pub result: Option<SigningResult>,
    pub error: Option<ProtocolError>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletPublic {
    pub wallet_id: Token,
    pub wallet_kind: Token,
    pub key_refs: Vec<KeyRef>,
    pub policy_version: DecimalU64,
    pub policy_digest: Digest32,
    pub wallet_revocation_epoch: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPublic {
    pub key_ref: KeyRef,
    pub canonical_public_key: Base64UrlBytes,
    pub addresses: Vec<String>,
    pub supported_crypto_suites: Vec<crate::CryptoSuite>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CredentialState {
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "REVOKED")]
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialPublic {
    pub credential_id: Base64UrlBytes,
    pub wallet_id: Token,
    pub created_at_ms: DecimalU64,
    pub state: CredentialState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CeremonyState {
    #[serde(rename = "PREPARED")]
    Prepared,
    #[serde(rename = "AWAITING_USER")]
    AwaitingUser,
    #[serde(rename = "VERIFYING")]
    Verifying,
    #[serde(rename = "WALLET_COMMITTED")]
    WalletCommitted,
    #[serde(rename = "AWAITING_RECOVERY_ACK")]
    AwaitingRecoveryAck,
    #[serde(rename = "COMPLETED")]
    Completed,
    #[serde(rename = "APPROVING_ROOT_CHANGE")]
    ApprovingRootChange,
    #[serde(rename = "CREATING_CREDENTIAL")]
    CreatingCredential,
    #[serde(rename = "COMMITTING")]
    Committing,
    #[serde(rename = "SUCCEEDED")]
    Succeeded,
    #[serde(rename = "CANCELLED")]
    Cancelled,
    #[serde(rename = "EXPIRED")]
    Expired,
    #[serde(rename = "FAILED")]
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyPublicStatus {
    pub ceremony_id: Digest32,
    pub ceremony_kind: CeremonyKind,
    pub operation_id: OperationId,
    pub state: CeremonyState,
    pub expires_at_ms: DecimalU64,
    /// Optional launch secret retained in the frozen v1 projection. Signer
    /// statuses omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceremony_url: Option<String>,
    pub receipt_digest: Option<Digest32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "method", content = "body", deny_unknown_fields)]
pub enum BrokerSignerRequest {
    #[serde(rename = "system.hello")]
    SystemHello(HelloChallenge),
    #[serde(rename = "signer.readiness")]
    SignerReadiness(Empty),
    #[serde(rename = "signer.capabilities")]
    SignerCapabilities(Empty),
    #[serde(rename = "key.get_public")]
    KeyGetPublic(KeyRequest),
    #[serde(rename = "key.list_public")]
    KeyListPublic(WalletRequest),
    #[serde(rename = "key.derivation_capabilities")]
    KeyDerivationCapabilities(KeyRequest),
    #[serde(rename = "key.derive_prepare")]
    KeyDerivePrepare(CustodyPrepareRequest),
    #[serde(rename = "key.list_derived")]
    KeyListDerived(KeyRequest),
    #[serde(rename = "key.enroll_prepare")]
    KeyEnrollPrepare(CustodyPrepareRequest),
    #[serde(rename = "key.enroll_status")]
    KeyEnrollStatus(OperationRequest),
    #[serde(rename = "ceremony.prepare")]
    CeremonyPrepare(crate::SignerCeremonyPrepareRequest),
    #[serde(rename = "ceremony.complete")]
    CeremonyComplete(crate::SignerCeremonyCompleteRequest),
    #[serde(rename = "ceremony.status")]
    CeremonyStatus(IdRequest),
    #[serde(rename = "ceremony.cancel")]
    CeremonyCancel(IdRequest),
    #[serde(rename = "sealed_approval.status")]
    SealedApprovalStatus(IdRequest),
    #[serde(rename = "sealed_approval.revoke")]
    SealedApprovalRevoke(RevokeRequest),
    #[serde(rename = "sealed_approval.revoke_all")]
    SealedApprovalRevokeAll(WalletOperationRequest),
    #[serde(rename = "revocation.state")]
    RevocationState(WalletRequest),
    #[serde(rename = "signer.sign")]
    SignerSign(SignRequest),
    #[serde(rename = "signer.sign_batch")]
    SignerSignBatch(SignRequest),
    #[serde(rename = "operation.status")]
    OperationStatus(OperationRequest),
    #[serde(rename = "policy.read")]
    PolicyRead(WalletRequest),
    #[serde(rename = "policy.compare_and_swap")]
    PolicyCompareAndSwap(PolicyCompareAndSwapRequest),
    #[serde(rename = "wallet.registration_prepare")]
    WalletRegistrationPrepare(CustodyPrepareRequest),
    #[serde(rename = "wallet.registration_status")]
    WalletRegistrationStatus(OperationRequest),
    #[serde(rename = "wallet.unlock_prepare")]
    WalletUnlockPrepare(CustodyPrepareRequest),
    #[serde(rename = "wallet.import_prepare")]
    WalletImportPrepare(CustodyPrepareRequest),
    #[serde(rename = "wallet.export_prepare")]
    WalletExportPrepare(CustodyPrepareRequest),
    #[serde(rename = "wallet.delete_prepare")]
    WalletDeletePrepare(CustodyPrepareRequest),
    #[serde(rename = "credential.list_public")]
    CredentialListPublic(WalletRequest),
    #[serde(rename = "credential.add_prepare")]
    CredentialAddPrepare(CustodyPrepareRequest),
    #[serde(rename = "credential.remove_prepare")]
    CredentialRemovePrepare(CustodyPrepareRequest),
    #[serde(rename = "credential.replace_prepare")]
    CredentialReplacePrepare(CustodyPrepareRequest),
    #[serde(rename = "recovery.prepare")]
    RecoveryPrepare(CustodyPrepareRequest),
    #[serde(rename = "custody.complete")]
    CustodyComplete(CustodyCompleteRequest),
    #[serde(rename = "custody.bind_output_recipient")]
    CustodyBindOutputRecipient(CustodyBindOutputRecipientRequest),
    #[serde(rename = "custody.result")]
    CustodyResult(OperationRequest),
    #[serde(rename = "custody.status")]
    CustodyStatus(OperationRequest),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "method", content = "body", deny_unknown_fields)]
pub enum BrokerSignerResponse {
    #[serde(rename = "system.hello")]
    SystemHello(HelloChallenge),
    #[serde(rename = "signer.readiness")]
    SignerReadiness(Readiness),
    #[serde(rename = "signer.capabilities")]
    SignerCapabilities(ServiceCapabilities),
    #[serde(rename = "key.get_public")]
    KeyGetPublic(KeyPublic),
    #[serde(rename = "key.list_public")]
    KeyListPublic(Vec<KeyPublic>),
    #[serde(rename = "key.derivation_capabilities")]
    KeyDerivationCapabilities(Vec<Token>),
    #[serde(rename = "key.list_derived")]
    KeyListDerived(Vec<KeyPublic>),
    #[serde(rename = "key.derive_prepare")]
    KeyDerivePrepare(crate::SignerPreparedCustody),
    #[serde(rename = "key.enroll_prepare")]
    KeyEnrollPrepare(crate::SignerPreparedCustody),
    #[serde(rename = "key.enroll_status")]
    KeyEnrollStatus(CeremonyPublicStatus),
    #[serde(rename = "ceremony.prepare")]
    CeremonyPrepare(crate::SignerCeremonyPrepareResponse),
    #[serde(rename = "ceremony.complete")]
    CeremonyComplete(crate::SignerCeremonyCompleteResponse),
    #[serde(rename = "ceremony.cancel")]
    CeremonyCancel(CeremonyPublicStatus),
    #[serde(rename = "operation.status")]
    OperationStatus(OperationPublicStatus),
    #[serde(rename = "ceremony.status")]
    CeremonyStatus(crate::SignerCeremonyStatus),
    #[serde(rename = "sealed_approval.status")]
    SealedApprovalStatus(ApprovalPublicStatus),
    #[serde(rename = "sealed_approval.revoke")]
    SealedApprovalRevoke(ApprovalPublicStatus),
    #[serde(rename = "sealed_approval.revoke_all")]
    SealedApprovalRevokeAll(RevocationState),
    #[serde(rename = "revocation.state")]
    RevocationState(crate::RevocationSnapshot),
    #[serde(rename = "signer.sign")]
    SignerSign(SigningResult),
    #[serde(rename = "signer.sign_batch")]
    SignerSignBatch(SigningResult),
    #[serde(rename = "policy.read")]
    PolicyRead(SignedPolicySnapshot),
    #[serde(rename = "policy.compare_and_swap")]
    PolicyCompareAndSwap(PolicyCommitReceipt),
    #[serde(rename = "wallet.registration_prepare")]
    WalletRegistrationPrepare(crate::SignerPreparedCustody),
    #[serde(rename = "wallet.registration_status")]
    WalletRegistrationStatus(CeremonyPublicStatus),
    #[serde(rename = "wallet.unlock_prepare")]
    WalletUnlockPrepare(crate::SignerPreparedCustody),
    #[serde(rename = "wallet.import_prepare")]
    WalletImportPrepare(crate::SignerPreparedCustody),
    #[serde(rename = "wallet.export_prepare")]
    WalletExportPrepare(crate::SignerPreparedCustody),
    #[serde(rename = "wallet.delete_prepare")]
    WalletDeletePrepare(crate::SignerPreparedCustody),
    #[serde(rename = "credential.list_public")]
    CredentialListPublic(Vec<CredentialPublic>),
    #[serde(rename = "credential.add_prepare")]
    CredentialAddPrepare(crate::SignerPreparedCustody),
    #[serde(rename = "credential.remove_prepare")]
    CredentialRemovePrepare(crate::SignerPreparedCustody),
    #[serde(rename = "credential.replace_prepare")]
    CredentialReplacePrepare(crate::SignerPreparedCustody),
    #[serde(rename = "recovery.prepare")]
    RecoveryPrepare(crate::SignerPreparedCustody),
    #[serde(rename = "custody.complete")]
    CustodyComplete(CustodyResult),
    #[serde(rename = "custody.bind_output_recipient")]
    CustodyBindOutputRecipient(crate::SignerPreparedCustody),
    #[serde(rename = "custody.result")]
    CustodyResult(CustodyResult),
    #[serde(rename = "custody.status")]
    CustodyStatus(CeremonyPublicStatus),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "method", content = "body", deny_unknown_fields)]
pub enum ControlRequest {
    #[serde(rename = "control.revoke")]
    Revoke(RevokeRequest),
    #[serde(rename = "control.revoke_all")]
    RevokeAll(WalletOperationRequest),
    #[serde(rename = "control.status")]
    Status(WalletRequest),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "method", content = "body", deny_unknown_fields)]
pub enum ControlResponse {
    #[serde(rename = "control.revoke")]
    Revoke(ApprovalPublicStatus),
    #[serde(rename = "control.revoke_all")]
    RevokeAll(RevocationState),
    #[serde(rename = "control.status")]
    Status(RevocationState),
}

pub trait BrokerSignerService: Send + Sync {
    fn dispatch<'a>(
        &'a self,
        request: BrokerSignerRequest,
    ) -> ServiceFuture<'a, BrokerSignerResponse>;
}

pub trait RevocationControlService: Send + Sync {
    fn dispatch<'a>(&'a self, request: ControlRequest) -> ServiceFuture<'a, ControlResponse>;
}

/// Transitional v1 method classification. Each edge API takes ownership of
/// its own closed inventory when the monolithic protocol crate is split.
pub fn is_read_only_method(method: &Token) -> bool {
    let method = method.as_str();
    method.ends_with(".read")
        || method.ends_with(".readiness")
        || method.ends_with(".capabilities")
        || method.ends_with(".status")
        || method.ends_with(".list")
        || method.ends_with(".list_public")
        || method.ends_with(".get_public")
        || method == "revocation.state"
        || method == "key.derivation_capabilities"
        || method == "key.list_derived"
        || method == "credential.list_public"
        || method == "custody.result"
}

impl crate::TypedRequestMethod for BrokerSignerRequest {
    fn operation_id(&self) -> Result<Option<OperationId>, crate::WireError> {
        use BrokerSignerRequest as Request;
        Ok(match self {
            Request::CeremonyPrepare(request) => Some(match request {
                crate::SignerCeremonyPrepareRequest::SealedApproval(request) => {
                    request.activation_operation_id.clone()
                }
                crate::SignerCeremonyPrepareRequest::PolicyUpdate(request) => {
                    request.custody.custody_operation_id.clone()
                }
            }),
            Request::CeremonyComplete(request) => Some(match request {
                crate::SignerCeremonyCompleteRequest::SealedApproval(request) => {
                    request.activation_operation_id.clone()
                }
                crate::SignerCeremonyCompleteRequest::PolicyUpdate(request) => {
                    request.custody.custody_operation_id.clone()
                }
            }),
            Request::SealedApprovalRevoke(request) => Some(request.operation_id.clone()),
            Request::SealedApprovalRevokeAll(request) => Some(request.operation_id.clone()),
            Request::SignerSign(request) | Request::SignerSignBatch(request) => {
                Some(request.unsigned.operation_id.clone())
            }
            Request::OperationStatus(request)
            | Request::KeyEnrollStatus(request)
            | Request::WalletRegistrationStatus(request)
            | Request::CustodyResult(request)
            | Request::CustodyStatus(request) => Some(request.operation_id.clone()),
            Request::PolicyCompareAndSwap(request) => Some(request.update.operation_id.clone()),
            Request::KeyDerivePrepare(request)
            | Request::KeyEnrollPrepare(request)
            | Request::WalletRegistrationPrepare(request)
            | Request::WalletUnlockPrepare(request)
            | Request::WalletImportPrepare(request)
            | Request::WalletExportPrepare(request)
            | Request::WalletDeletePrepare(request)
            | Request::CredentialAddPrepare(request)
            | Request::CredentialRemovePrepare(request)
            | Request::CredentialReplacePrepare(request)
            | Request::RecoveryPrepare(request) => Some(request.custody_operation_id.clone()),
            Request::CustodyComplete(request) => Some(request.custody_operation_id.clone()),
            Request::CustodyBindOutputRecipient(request) => Some(request.operation_id.clone()),
            _ => None,
        })
    }

    fn is_read_only(&self) -> bool {
        self.method()
            .is_ok_and(|method| is_read_only_method(&method))
    }
}
impl crate::TypedRequestMethod for ControlRequest {
    fn operation_id(&self) -> Result<Option<OperationId>, crate::WireError> {
        Ok(match self {
            Self::Revoke(request) => Some(request.operation_id.clone()),
            Self::RevokeAll(request) => Some(request.operation_id.clone()),
            Self::Status(_) => None,
        })
    }

    fn is_read_only(&self) -> bool {
        matches!(self, Self::Status(_))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn typed_request_inventories_cover_every_normative_method() {
        assert_eq!(crate::BrokerSignerMethod::ALL.len(), 38);
    }
}
