//! Production typed Broker→Signer RPC adapter.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bloom_signer_backend_api::{BackendError, BackendInput, BackendSignRequest};
use bloom_triad_protocol::{
    BackendPublicCapability, Base64UrlBytes, BootEpoch, BrokerSignerMethod, BrokerSignerRequest,
    BrokerSignerResponse, BrokerSignerService, ControlRequest, ControlResponse, CryptoInputKind,
    DecimalU64, Digest32, KeyPublic, OperationId, ProtocolError, ProtocolErrorCode,
    RPC_ENVELOPE_SCHEMA_V1, Readiness, ReadinessState, RevocationControlService,
    ServiceCapabilities, ServiceFuture, SignRequest, SigningResult, Token,
};
use k256::pkcs8::DecodePublicKey;
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use tokio::sync::Mutex;

use crate::{
    ceremony::SignerCeremonyService,
    engine::{SignAuthorization, SignerEngine, SignerOperationEffect},
};

const PROVIDER_ATTEMPT_DOMAIN: &[u8] = b"bloom-provider-attempt/v1";
const SIGNER_RECEIPT_DOMAIN: &[u8] = b"bloom-signer-signing-receipt/v1";

pub struct SignerRpcService {
    engine: Arc<SignerEngine>,
    ceremony: Arc<SignerCeremonyService>,
    boot_epoch: BootEpoch,
    build_digest: Digest32,
    service_version: String,
    signing_gate: Mutex<()>,
}

impl SignerRpcService {
    pub fn new(
        engine: Arc<SignerEngine>,
        ceremony: Arc<SignerCeremonyService>,
        boot_epoch: BootEpoch,
        build_digest: Digest32,
        service_version: impl Into<String>,
    ) -> Self {
        Self {
            engine,
            ceremony,
            boot_epoch,
            build_digest,
            service_version: service_version.into(),
            signing_gate: Mutex::new(()),
        }
    }

    async fn dispatch_inner(
        &self,
        request: BrokerSignerRequest,
    ) -> Result<BrokerSignerResponse, ProtocolError> {
        use BrokerSignerRequest as Request;
        use BrokerSignerResponse as Response;

        let now_ms = now_ms()?;
        match request {
            Request::SystemHello(_) => Err(ProtocolError::new(
                ProtocolErrorCode::UnknownMethod,
                "system.hello is consumed by the authenticated transport",
            )),
            Request::SignerReadiness(_) => Ok(Response::SignerReadiness(self.readiness())),
            Request::SignerCapabilities(_) => {
                Ok(Response::SignerCapabilities(self.capabilities()?))
            }
            Request::KeyGetPublic(request) => Ok(Response::KeyGetPublic(
                self.describe_key(&request.key_ref).await?,
            )),
            Request::KeyListPublic(request) => {
                let mut keys = Vec::new();
                for key_ref in self.engine.enrolled_key_refs(&request.wallet_id)? {
                    keys.push(self.describe_key(&key_ref).await?);
                }
                Ok(Response::KeyListPublic(keys))
            }
            Request::KeyDerivationCapabilities(request) => {
                let capabilities = self
                    .engine
                    .backend_registry()
                    .get(&request.key_ref.backend, &request.key_ref.backend_instance)?
                    .capabilities();
                Ok(Response::KeyDerivationCapabilities(
                    capabilities
                        .supported_derivation
                        .into_iter()
                        .map(|capability| capability.scheme)
                        .collect(),
                ))
            }
            Request::KeyListDerived(request) => {
                let mut keys = Vec::new();
                for key_ref in self
                    .engine
                    .enrolled_key_refs(&request.key_ref.backend_instance)?
                {
                    if key_ref.derivation.is_some() {
                        keys.push(self.describe_key(&key_ref).await?);
                    }
                }
                Ok(Response::KeyListDerived(keys))
            }
            Request::KeyDerivePrepare(request) => Ok(Response::KeyDerivePrepare(
                self.ceremony.prepare_custody(request, now_ms)?.contribution,
            )),
            Request::KeyEnrollPrepare(request) => Ok(Response::KeyEnrollPrepare(
                self.ceremony.prepare_custody(request, now_ms)?.contribution,
            )),
            Request::KeyEnrollStatus(request) => Ok(Response::KeyEnrollStatus(
                self.ceremony.public_status(&request.operation_id)?,
            )),
            Request::CeremonyPrepare(request) => Ok(Response::CeremonyPrepare(
                self.ceremony
                    .prepare_approval(request, now_ms)?
                    .contribution,
            )),
            Request::CeremonyComplete(request) => Ok(Response::CeremonyComplete(
                self.ceremony.complete_approval(request, now_ms).await?,
            )),
            Request::CeremonyStatus(request) => Ok(Response::CeremonyStatus(
                self.ceremony
                    .public_status(&OperationId::new(request.id.as_str().to_owned())?)?,
            )),
            Request::CeremonyCancel(request) => {
                let operation_id = OperationId::new(request.id.as_str().to_owned())?;
                let mut status = self.ceremony.public_status(&operation_id)?;
                self.ceremony.cancel(&operation_id)?;
                status.state = bloom_triad_protocol::CeremonyState::Cancelled;
                Ok(Response::CeremonyCancel(status))
            }
            Request::SealedApprovalStatus(request) => Ok(Response::SealedApprovalStatus(
                self.engine.approval_public_status(&request.id, now_ms)?,
            )),
            Request::SealedApprovalRevoke(request) => {
                let approval_id = request.approval_id.clone();
                self.engine.revoke_approval(
                    &request.approval_id,
                    request.reason,
                    request.operation_id,
                    now_ms,
                )?;
                Ok(Response::SealedApprovalRevoke(
                    self.engine.approval_public_status(&approval_id, now_ms)?,
                ))
            }
            Request::SealedApprovalRevokeAll(request) => Ok(Response::SealedApprovalRevokeAll(
                self.engine
                    .revoke_all(&request.wallet_id, request.operation_id, now_ms)?,
            )),
            Request::RevocationState(request) => Ok(Response::RevocationState(
                self.engine.revocation_state(&request.wallet_id, now_ms)?,
            )),
            Request::SignerSign(request) => {
                require_signature_count(&request, false)?;
                Ok(Response::SignerSign(self.sign(request).await?))
            }
            Request::SignerSignBatch(request) => {
                require_signature_count(&request, true)?;
                Ok(Response::SignerSignBatch(self.sign(request).await?))
            }
            Request::OperationStatus(request) => Ok(Response::OperationStatus(
                self.engine.operation_status(&request.operation_id)?,
            )),
            Request::PolicyRead(request) => Ok(Response::PolicyRead(
                self.engine.policy_snapshot(&request.wallet_id)?,
            )),
            Request::PolicyCompareAndSwap(request) => Ok(Response::PolicyCompareAndSwap(
                self.engine.policy_commit_receipt(&request)?,
            )),
            Request::WalletRegistrationPrepare(request) => Ok(Response::WalletRegistrationPrepare(
                self.ceremony.prepare_custody(request, now_ms)?.contribution,
            )),
            Request::WalletRegistrationStatus(request) => Ok(Response::WalletRegistrationStatus(
                self.ceremony.public_status(&request.operation_id)?,
            )),
            Request::WalletUnlockPrepare(request) => Ok(Response::WalletUnlockPrepare(
                self.ceremony.prepare_custody(request, now_ms)?.contribution,
            )),
            Request::WalletImportPrepare(request) => Ok(Response::WalletImportPrepare(
                self.ceremony.prepare_custody(request, now_ms)?.contribution,
            )),
            Request::WalletExportPrepare(request) => Ok(Response::WalletExportPrepare(
                self.ceremony.prepare_custody(request, now_ms)?.contribution,
            )),
            Request::WalletDeletePrepare(request) => Ok(Response::WalletDeletePrepare(
                self.ceremony.prepare_custody(request, now_ms)?.contribution,
            )),
            Request::CredentialListPublic(request) => Ok(Response::CredentialListPublic(
                self.engine.credential_public(&request.wallet_id)?,
            )),
            Request::CredentialAddPrepare(request) => Ok(Response::CredentialAddPrepare(
                self.ceremony.prepare_custody(request, now_ms)?.contribution,
            )),
            Request::CredentialRemovePrepare(request) => Ok(Response::CredentialRemovePrepare(
                self.ceremony.prepare_custody(request, now_ms)?.contribution,
            )),
            Request::CredentialReplacePrepare(request) => Ok(Response::CredentialReplacePrepare(
                self.ceremony.prepare_custody(request, now_ms)?.contribution,
            )),
            Request::RecoveryPrepare(request) => Ok(Response::RecoveryPrepare(
                self.ceremony.prepare_custody(request, now_ms)?.contribution,
            )),
            Request::CustodyComplete(request) => Ok(Response::CustodyComplete(
                self.ceremony.complete_custody(request, now_ms)?,
            )),
            Request::CustodyResult(request) => Ok(Response::CustodyResult(
                self.engine
                    .custody_receipt(&request.operation_id)?
                    .ok_or_else(|| {
                        ProtocolError::new(
                            ProtocolErrorCode::ApprovalNotFound,
                            "custody result not found",
                        )
                    })?,
            )),
            Request::CustodyStatus(request) => Ok(Response::CustodyStatus(
                self.ceremony.public_status(&request.operation_id)?,
            )),
        }
    }

    async fn dispatch_control_inner(
        &self,
        request: ControlRequest,
    ) -> Result<ControlResponse, ProtocolError> {
        let now_ms = now_ms()?;
        match request {
            ControlRequest::Revoke(request) => {
                let approval_id = request.approval_id.clone();
                self.engine.revoke_approval(
                    &request.approval_id,
                    request.reason,
                    request.operation_id,
                    now_ms,
                )?;
                Ok(ControlResponse::Revoke(
                    self.engine.approval_public_status(&approval_id, now_ms)?,
                ))
            }
            ControlRequest::RevokeAll(request) => Ok(ControlResponse::RevokeAll(
                self.engine
                    .revoke_all(&request.wallet_id, request.operation_id, now_ms)?,
            )),
            ControlRequest::Status(request) => Ok(ControlResponse::Status(
                self.engine.revocation_state(&request.wallet_id, now_ms)?,
            )),
        }
    }

    fn readiness(&self) -> Readiness {
        Readiness {
            service_id: Token::new("bloom-signer").expect("static service ID"),
            service_version: self.service_version.clone(),
            build_digest: self.build_digest.clone(),
            boot_epoch: self.boot_epoch.clone(),
            state: ReadinessState::Ready,
            conditions: Vec::new(),
        }
    }

    fn capabilities(&self) -> Result<ServiceCapabilities, ProtocolError> {
        let backends = self
            .engine
            .backend_registry()
            .capabilities()
            .into_iter()
            .map(|capability| BackendPublicCapability {
                backend_id: capability.backend_id,
                backend_instance_id: capability.backend_instance_id,
                crypto_suites: capability.supported_crypto_suites,
                derivation_schemes: capability
                    .supported_derivation
                    .into_iter()
                    .map(|derivation| derivation.scheme)
                    .collect(),
                networked: capability.networked,
            })
            .collect();
        Ok(ServiceCapabilities {
            service_id: Token::new("bloom-signer")?,
            service_version: self.service_version.clone(),
            build_digest: self.build_digest.clone(),
            protocol_major: bloom_triad_protocol::PROTOCOL_MAJOR,
            protocol_minor_min: bloom_triad_protocol::PROTOCOL_MINOR_MIN,
            protocol_minor_max: bloom_triad_protocol::PROTOCOL_MINOR_MAX,
            methods: BrokerSignerMethod::ALL
                .iter()
                .map(|method| Token::new(method.as_str()))
                .collect::<Result<_, _>>()?,
            schemas: vec![
                Token::new(RPC_ENVELOPE_SCHEMA_V1)?,
                Token::new("bloom.sign-request/1")?,
            ],
            backends,
            assurance_verifiers: Vec::new(),
            frame_max_bytes: DecimalU64::new(1024 * 1024),
        })
    }

    async fn describe_key(
        &self,
        key_ref: &bloom_triad_protocol::KeyRef,
    ) -> Result<KeyPublic, ProtocolError> {
        let description = self
            .engine
            .backend_registry()
            .get(&key_ref.backend, &key_ref.backend_instance)?
            .describe_key(key_ref)
            .await
            .map_err(map_backend_error)?;
        if description.key_ref != *key_ref
            || description.public_key_fingerprint != key_ref.public_key_fingerprint
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "backend public description changed the pinned KeyRef",
            ));
        }
        let addresses = ethereum_address(&description)?;
        Ok(KeyPublic {
            key_ref: description.key_ref,
            canonical_public_key: description.canonical_spki_der,
            addresses,
            supported_crypto_suites: description.supported_crypto_suites,
        })
    }

    async fn sign(&self, request: SignRequest) -> Result<SigningResult, ProtocolError> {
        let _gate = self.signing_gate.lock().await;
        let now_ms = now_ms()?;
        let authorization = self.engine.authorize_sign(&request, now_ms)?;
        if authorization == SignAuthorization::SameOperationRetry {
            if let Some(stored) = self
                .engine
                .stored_operation_result(&request.unsigned.operation_id)?
            {
                return serde_json::from_slice(&stored.decode()).map_err(|error| {
                    ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
                });
            }
        }

        self.engine
            .mark_operation_dispatched(&request.unsigned.operation_id)?;
        let backend = self.engine.backend_registry().get(
            &request.unsigned.key_ref.backend,
            &request.unsigned.key_ref.backend_instance,
        )?;
        let mut signatures = Vec::with_capacity(request.unsigned.ordered_hashes.len());
        for (index, hash) in request.unsigned.ordered_hashes.iter().enumerate() {
            let input = match request.unsigned.crypto_suite.input_kind() {
                CryptoInputKind::Digest32 => BackendInput::Digest32 {
                    digest: hash.clone(),
                },
                CryptoInputKind::Message => BackendInput::Message {
                    message: Base64UrlBytes::from_bytes(&hash.to_bytes()),
                },
            };
            let result = backend
                .sign(BackendSignRequest {
                    provider_attempt_id: provider_attempt_id(
                        &request.unsigned.operation_digest,
                        &self.boot_epoch,
                        index,
                    ),
                    key_ref: request.unsigned.key_ref.clone(),
                    crypto_suite: request.unsigned.crypto_suite,
                    input,
                    deadline_ms: request.unsigned.expires_at_ms.clone(),
                })
                .await;
            let signature = match result {
                Ok(signature) => signature,
                Err(error) => {
                    let effect = if signatures.is_empty()
                        && matches!(
                            error,
                            BackendError::DefinitiveRejected
                                | BackendError::RetryableBeforeAcceptance
                                | BackendError::Unsupported
                                | BackendError::InvalidRequest
                        ) {
                        SignerOperationEffect::Released
                    } else {
                        SignerOperationEffect::Quarantined
                    };
                    self.engine
                        .finalize_operation(&request.unsigned.operation_id, effect)?;
                    return Err(map_backend_error(error));
                }
            };
            if signature.crypto_suite != request.unsigned.crypto_suite
                || signature.encoding != request.unsigned.crypto_suite.signature_encoding()
            {
                self.engine.finalize_operation(
                    &request.unsigned.operation_id,
                    SignerOperationEffect::Quarantined,
                )?;
                return Err(ProtocolError::new(
                    ProtocolErrorCode::BackendInvalidRequest,
                    "backend returned a mismatched signature suite or encoding",
                ));
            }
            signatures.push(bloom_triad_protocol::NormalizedSignature {
                crypto_suite: signature.crypto_suite,
                bytes: signature.bytes,
            });
        }

        let signer_receipt_digest = signer_receipt_digest(&request, &signatures)?;
        let result = SigningResult {
            operation_id: request.unsigned.operation_id.clone(),
            operation_digest: request.unsigned.operation_digest.clone(),
            signatures,
            signer_receipt_digest,
            broker_receipt_digest: request.unsigned.validation_receipt_digest.clone(),
        };
        self.engine.commit_operation_result(
            &request.unsigned.operation_id,
            Base64UrlBytes::from_bytes(&serde_jcs::to_vec(&result).map_err(|error| {
                ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
            })?),
        )?;
        Ok(result)
    }
}

impl BrokerSignerService for SignerRpcService {
    fn dispatch<'a>(
        &'a self,
        request: BrokerSignerRequest,
    ) -> ServiceFuture<'a, BrokerSignerResponse> {
        Box::pin(async move { self.dispatch_inner(request).await })
    }
}

impl RevocationControlService for SignerRpcService {
    fn dispatch<'a>(&'a self, request: ControlRequest) -> ServiceFuture<'a, ControlResponse> {
        Box::pin(async move { self.dispatch_control_inner(request).await })
    }
}

fn require_signature_count(request: &SignRequest, batch: bool) -> Result<(), ProtocolError> {
    let count = request.unsigned.signature_count.get();
    if (batch && !(1..=32).contains(&count)) || (!batch && count != 1) {
        return Err(ProtocolError::new(
            ProtocolErrorCode::MalformedFrame,
            "signing method does not match the requested signature count",
        ));
    }
    Ok(())
}

fn provider_attempt_id(
    operation_digest: &Digest32,
    boot_epoch: &BootEpoch,
    child_index: usize,
) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_ATTEMPT_DOMAIN);
    hasher.update(operation_digest.to_bytes());
    hasher.update(boot_epoch.to_bytes());
    hasher.update((child_index as u32).to_be_bytes());
    Digest32::from_bytes(hasher.finalize().into())
}

fn signer_receipt_digest(
    request: &SignRequest,
    signatures: &[bloom_triad_protocol::NormalizedSignature],
) -> Result<Digest32, ProtocolError> {
    #[derive(serde::Serialize)]
    struct Receipt<'a> {
        operation_id: &'a OperationId,
        operation_digest: &'a Digest32,
        signatures: &'a [bloom_triad_protocol::NormalizedSignature],
        validation_receipt_digest: &'a Digest32,
    }
    let mut hasher = Sha256::new();
    hasher.update(SIGNER_RECEIPT_DOMAIN);
    hasher.update(
        serde_jcs::to_vec(&Receipt {
            operation_id: &request.unsigned.operation_id,
            operation_digest: &request.unsigned.operation_digest,
            signatures,
            validation_receipt_digest: &request.unsigned.validation_receipt_digest,
        })
        .map_err(|error| {
            ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
        })?,
    );
    Ok(Digest32::from_bytes(hasher.finalize().into()))
}

fn ethereum_address(
    description: &bloom_signer_backend_api::KeyDescription,
) -> Result<Vec<String>, ProtocolError> {
    if description.key_ref.key_spec != bloom_triad_protocol::KeySpec::Secp256k1 {
        return Ok(Vec::new());
    }
    let public_key = k256::PublicKey::from_public_key_der(&description.canonical_spki_der.decode())
        .map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "secp256k1 backend returned invalid canonical SPKI",
            )
        })?;
    let point = public_key.to_sec1_bytes();
    let digest = Keccak256::digest(&point[1..]);
    Ok(vec![format!("0x{}", hex::encode(&digest[12..]))])
}

fn map_backend_error(error: BackendError) -> ProtocolError {
    let code = match error {
        BackendError::DefinitiveRejected | BackendError::InvalidRequest => {
            ProtocolErrorCode::BackendInvalidRequest
        }
        BackendError::RetryableBeforeAcceptance => ProtocolErrorCode::ServiceUnavailable,
        BackendError::Unsupported => ProtocolErrorCode::BackendUnsupported,
        BackendError::IndeterminateAcceptance => ProtocolErrorCode::AmbiguousProviderEffect,
    };
    ProtocolError::new(code, format!("Signer backend failed: {error}"))
}

fn now_ms() -> Result<u64, ProtocolError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::ClockRollback,
                "system time predates Unix epoch",
            )
        })?
        .as_millis();
    u64::try_from(millis).map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCode::ClockUntrusted,
            "system time is out of range",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_signer_backend_api::{SecretBytes, SignerBackendActivation};
    use bloom_signer_backend_local::LocalSignerBackend;
    use bloom_triad_protocol::{
        ActivationMode, ApprovalLimits, ApprovalSelector, ApprovalSubject, CryptoSuite,
        RequestNonce, RevokeRequest, SealedApprovalTerms, SelectorKind, SignOperationIdentity,
        UnsignedSignRequest,
    };
    use ed25519_dalek::{Signer as _, SigningKey};

    async fn fixture() -> (SignerRpcService, SigningKey, SealedApprovalTerms) {
        let broker_key = SigningKey::from_bytes(&[7; 32]);
        let activation_secret = vec![9; 32];
        let backend = Arc::new(
            LocalSignerBackend::provision(
                Token::new("wallet-service-test").unwrap(),
                Token::new("root").unwrap(),
                SecretBytes::new((0_u8..32).collect()),
                SecretBytes::new(activation_secret.clone()),
                SigningKey::from_bytes(&[5; 32]).verifying_key(),
            )
            .unwrap(),
        );
        let key_ref = backend.root_key_ref().unwrap();
        backend
            .activate(&key_ref, SecretBytes::new(activation_secret))
            .await
            .unwrap();
        let registry = Arc::new(
            crate::registry::BackendRegistry::from_compiled(vec![
                crate::registry::CompiledBackend::Local(backend),
            ])
            .unwrap(),
        );
        let engine = Arc::new(
            SignerEngine::open_in_memory(
                Token::new("broker-signing-key").unwrap(),
                broker_key.verifying_key(),
                SigningKey::from_bytes(&[6; 32]).verifying_key(),
                Token::new("signer-revocation-key").unwrap(),
                SigningKey::from_bytes(&[4; 32]),
                registry,
            )
            .unwrap(),
        );
        engine.enroll_key(&key_ref).unwrap();
        let current = now_ms().unwrap();
        let terms = SealedApprovalTerms {
            subject: ApprovalSubject::Cli {
                client_id: Token::new("bloom-machine").unwrap(),
                command_class: Token::new("wallet.sign").unwrap(),
            },
            wallet_id: Token::new("wallet-service-test").unwrap(),
            key_ref,
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Sha256Recoverable],
            selector: ApprovalSelector::Exact {
                ordered_payload_digests: vec![Digest32::from_bytes([22; 32])],
                ordered_hashes: vec![Digest32::from_bytes([33; 32])],
            },
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(1),
                max_signatures: DecimalU64::new(1),
                operation_rate_limits: Vec::new(),
                signature_rate_limits: Vec::new(),
                value_limits: Vec::new(),
            },
            activation_mode: ActivationMode::BootBound,
            wallet_revocation_epoch: DecimalU64::new(0),
            policy_version: DecimalU64::new(1),
            policy_digest: Digest32::from_bytes([44; 32]),
            provenance_digest: Digest32::from_bytes([55; 32]),
            request_nonce: RequestNonce::from_bytes([66; 16]),
            issued_at_ms: DecimalU64::new(current - 1_000),
            not_before_ms: DecimalU64::new(current - 1_000),
            expires_at_ms: DecimalU64::new(current + 60_000),
            renewal_of: None,
        };
        engine.install_approval_for_test(&terms).unwrap();
        let ceremony = Arc::new(
            SignerCeremonyService::new(
                engine.clone(),
                Token::new("signer-ceremony-key").unwrap(),
                SigningKey::from_bytes(&[8; 32]),
            )
            .unwrap(),
        );
        (
            SignerRpcService::new(
                engine,
                ceremony,
                BootEpoch::from_bytes([3; 16]),
                Digest32::from_bytes([2; 32]),
                "test",
            ),
            broker_key,
            terms,
        )
    }

    fn sign_request(
        broker_key: &SigningKey,
        terms: &SealedApprovalTerms,
        attempt_byte: u8,
    ) -> SignRequest {
        let current = now_ms().unwrap();
        let operation_id = OperationId::from_bytes([1; 32]);
        let payloads = vec![Digest32::from_bytes([22; 32])];
        let hashes = vec![Digest32::from_bytes([33; 32])];
        let identity = SignOperationIdentity {
            operation_id: operation_id.clone(),
            approval_id: terms.approval_id().unwrap(),
            key_ref: terms.key_ref.clone(),
            crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
            ordered_payload_digests: payloads.clone(),
            ordered_hashes: hashes.clone(),
            petal_use_claim_digest: None,
            claim_assurance_digest: None,
            policy_version: terms.policy_version.clone(),
            policy_digest: terms.policy_digest.clone(),
        };
        let mut unsigned = UnsignedSignRequest {
            schema: Token::new("bloom.sign-request/1").unwrap(),
            attempt_id: Digest32::from_bytes([attempt_byte; 32]),
            operation_id,
            operation_digest: identity.digest().unwrap(),
            attempt_digest: Digest32::from_bytes([0; 32]),
            audience: Token::new("bloom-signer").unwrap(),
            issuer_service_id: Token::new("bloom-broker").unwrap(),
            issuer_boot_epoch: BootEpoch::from_bytes([9; 16]),
            broker_signing_key_id: Token::new("broker-signing-key").unwrap(),
            approval_id: identity.approval_id,
            wallet_id: terms.wallet_id.clone(),
            key_ref: identity.key_ref,
            crypto_suite: identity.crypto_suite,
            selector_kind: SelectorKind::Exact,
            ordered_payload_digests: payloads,
            ordered_hashes: hashes,
            signature_count: DecimalU64::new(1),
            petal_use_claim_digest: None,
            claim_assurance_digest: None,
            policy_version: terms.policy_version.clone(),
            policy_digest: terms.policy_digest.clone(),
            validation_receipt_digest: Digest32::from_bytes([77; 32]),
            issued_at_ms: DecimalU64::new(current),
            not_before_ms: DecimalU64::new(current),
            expires_at_ms: DecimalU64::new(current + 30_000),
        };
        unsigned.attempt_digest = unsigned.computed_attempt_digest().unwrap();
        SignRequest {
            broker_signature: Base64UrlBytes::from_bytes(
                &broker_key
                    .sign(&unsigned.attempt_digest.to_bytes())
                    .to_bytes(),
            ),
            unsigned,
        }
    }

    #[tokio::test]
    async fn rpc_signing_publishes_once_and_returns_stable_retry_result() {
        let (service, broker_key, terms) = fixture().await;
        let first = sign_request(&broker_key, &terms, 1);
        let first_result =
            match BrokerSignerService::dispatch(&service, BrokerSignerRequest::SignerSign(first))
                .await
                .unwrap()
            {
                BrokerSignerResponse::SignerSign(result) => result,
                _ => panic!("wrong response"),
            };
        assert_eq!(first_result.signatures.len(), 1);

        let retry = sign_request(&broker_key, &terms, 2);
        let retry_result =
            match BrokerSignerService::dispatch(&service, BrokerSignerRequest::SignerSign(retry))
                .await
                .unwrap()
            {
                BrokerSignerResponse::SignerSign(result) => result,
                _ => panic!("wrong response"),
            };
        assert_eq!(retry_result, first_result);
    }

    #[tokio::test]
    async fn dispatched_restart_state_never_calls_backend_again() {
        let (service, broker_key, terms) = fixture().await;
        let first = sign_request(&broker_key, &terms, 3);
        service
            .engine
            .authorize_sign(&first, now_ms().unwrap())
            .unwrap();
        service
            .engine
            .mark_operation_dispatched(&first.unsigned.operation_id)
            .unwrap();

        let retry = sign_request(&broker_key, &terms, 4);
        assert_eq!(
            BrokerSignerService::dispatch(&service, BrokerSignerRequest::SignerSign(retry))
                .await
                .unwrap_err()
                .code,
            ProtocolErrorCode::AmbiguousProviderEffect
        );
    }

    #[tokio::test]
    async fn independent_control_tombstone_stops_new_signing() {
        let (service, broker_key, terms) = fixture().await;
        let approval_id = terms.approval_id().unwrap();
        let response = RevocationControlService::dispatch(
            &service,
            ControlRequest::Revoke(RevokeRequest {
                operation_id: OperationId::from_bytes([90; 32]),
                approval_id: approval_id.clone(),
                wallet_id: terms.wallet_id.clone(),
                reason: "panic revoke".into(),
            }),
        )
        .await
        .unwrap();
        assert!(matches!(response, ControlResponse::Revoke(_)));

        let request = sign_request(&broker_key, &terms, 5);
        assert_eq!(
            BrokerSignerService::dispatch(&service, BrokerSignerRequest::SignerSign(request))
                .await
                .unwrap_err()
                .code,
            ProtocolErrorCode::ApprovalRevoked
        );
        assert_eq!(
            service
                .engine
                .approval_public_status(&approval_id, now_ms().unwrap())
                .unwrap()
                .state,
            bloom_triad_protocol::ApprovalLifecycleState::Revoked
        );
    }
}
