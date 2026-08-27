//! Production typed Broker→Signer RPC adapter.

use std::sync::Arc;

use bloom_platform_containment::NetworkContainmentGuard;
use bloom_signer_api::{
    BackendPublicCapability, Base64UrlBytes, BootEpoch, BrokerSignerMethod, BrokerSignerRequest,
    BrokerSignerResponse, BrokerSignerService, ControlRequest, ControlResponse, CryptoInputKind,
    DecimalU64, Digest32, KeyPublic, OperationId, ProtocolError, ProtocolErrorCode,
    RPC_ENVELOPE_SCHEMA_V1, Readiness, ReadinessState, RevocationControlService,
    ServiceCapabilities, ServiceFuture, SignRequest, SignerCeremonyCompleteRequest,
    SignerCeremonyCompleteResponse, SignerCeremonyPrepareRequest, SignerCeremonyPrepareResponse,
    SignerPreparedApproval, SignerPreparedCustody, SigningResult, Token,
};
use bloom_signer_backend_api::{BackendError, BackendInput, BackendSignRequest};
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use k256::pkcs8::DecodePublicKey;
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use tokio::sync::Mutex;

use crate::{
    ceremony::{PreparedApprovalCeremony, PreparedCustodyCeremony, SignerCeremonyService},
    clock::SignerClock,
    engine::{SignAuthorization, SignerEngine, SignerOperationEffect},
};

const PROVIDER_ATTEMPT_DOMAIN: &[u8] = b"bloom-provider-attempt/v1";
const SIGNER_RECEIPT_DOMAIN: &[u8] = b"bloom-signer-signing-receipt/v1";

fn prepared_approval(
    ceremony: &SignerCeremonyService,
    wallet_id: &Token,
    prepared: PreparedApprovalCeremony,
) -> Result<SignerPreparedApproval, ProtocolError> {
    Ok(SignerPreparedApproval {
        verification_credentials: verification_credentials(
            ceremony,
            Some(wallet_id),
            &prepared.webauthn_options,
        )?,
        contribution: prepared.contribution,
        challenges: prepared.challenges,
        webauthn_options: prepared.webauthn_options,
    })
}

fn prepared_custody(
    _ceremony: &SignerCeremonyService,
    prepared: PreparedCustodyCeremony,
) -> Result<SignerPreparedCustody, ProtocolError> {
    Ok(SignerPreparedCustody {
        verification_credentials: prepared.verification_credentials,
        contribution: prepared.contribution,
        challenges: prepared.challenges,
        webauthn_options: prepared.webauthn_options,
    })
}

fn verification_credentials(
    ceremony: &SignerCeremonyService,
    wallet_id: Option<&Token>,
    options: &bloom_signer_api::CeremonyWebAuthnOptions,
) -> Result<Vec<bloom_signer_api::WebAuthnCredential>, ProtocolError> {
    let Some(wallet_id) = wallet_id else {
        return Ok(Vec::new());
    };
    options
        .allowed_credentials
        .iter()
        .map(|allowed| ceremony.credential(wallet_id, &allowed.credential_id))
        .collect()
}

pub struct SignerRpcService {
    engine: Arc<SignerEngine>,
    ceremony: Arc<SignerCeremonyService>,
    clock: Arc<SignerClock>,
    boot_epoch: BootEpoch,
    build_digest: Digest32,
    service_version: String,
    signing_gate: Mutex<()>,
    network_containment: Option<NetworkContainmentGuard>,
}

impl SignerRpcService {
    pub fn new(
        engine: Arc<SignerEngine>,
        ceremony: Arc<SignerCeremonyService>,
        clock: Arc<SignerClock>,
        boot_epoch: BootEpoch,
        build_digest: Digest32,
        service_version: impl Into<String>,
    ) -> Self {
        Self {
            engine,
            ceremony,
            clock,
            boot_epoch,
            build_digest,
            service_version: service_version.into(),
            signing_gate: Mutex::new(()),
            network_containment: None,
        }
    }

    pub fn with_network_containment(mut self, guard: NetworkContainmentGuard) -> Self {
        self.network_containment = Some(guard);
        self
    }

    async fn dispatch_inner(
        &self,
        request: BrokerSignerRequest,
    ) -> Result<BrokerSignerResponse, ProtocolError> {
        use BrokerSignerRequest as Request;
        use BrokerSignerResponse as Response;

        if signer_request_requires_containment(&request) {
            self.require_network_containment()?;
        }
        let now_ms = if broker_signer_request_is_read_only(&request) {
            self.clock.now_ms_read_only()?
        } else {
            self.clock.now_ms(false)?
        };
        match request {
            Request::SystemHello(_) => Err(ProtocolError::new(
                ProtocolErrorCode::UnknownMethod,
                "system.hello is consumed by the authenticated transport",
            )),
            Request::SignerReadiness(_) => Ok(Response::SignerReadiness(self.readiness()?)),
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
                for key_ref in self.engine.enrolled_derived_key_refs(&request.key_ref)? {
                    keys.push(self.describe_key(&key_ref).await?);
                }
                Ok(Response::KeyListDerived(keys))
            }
            Request::KeyDerivePrepare(request) => Ok(Response::KeyDerivePrepare(prepared_custody(
                &self.ceremony,
                self.ceremony.prepare_custody(request, now_ms)?,
            )?)),
            Request::KeyEnrollPrepare(request) => Ok(Response::KeyEnrollPrepare(prepared_custody(
                &self.ceremony,
                self.ceremony.prepare_custody(request, now_ms)?,
            )?)),
            Request::KeyEnrollStatus(request) => Ok(Response::KeyEnrollStatus(
                self.ceremony.public_status(&request.operation_id)?,
            )),
            Request::CeremonyPrepare(request) => Ok(Response::CeremonyPrepare(match request {
                SignerCeremonyPrepareRequest::SealedApproval(request) => {
                    let wallet_id = request.terms.wallet_id.clone();
                    SignerCeremonyPrepareResponse::SealedApproval(prepared_approval(
                        &self.ceremony,
                        &wallet_id,
                        self.ceremony.prepare_approval(*request, now_ms)?,
                    )?)
                }
                SignerCeremonyPrepareRequest::PolicyUpdate(request) => {
                    SignerCeremonyPrepareResponse::PolicyUpdate(prepared_custody(
                        &self.ceremony,
                        self.ceremony.prepare_policy_update(*request, now_ms)?,
                    )?)
                }
            })),
            Request::CeremonyComplete(request) => Ok(Response::CeremonyComplete(match request {
                SignerCeremonyCompleteRequest::SealedApproval(request) => {
                    SignerCeremonyCompleteResponse::SealedApproval(Box::new(
                        self.ceremony.complete_approval(*request, now_ms).await?,
                    ))
                }
                SignerCeremonyCompleteRequest::PolicyUpdate(request) => {
                    SignerCeremonyCompleteResponse::PolicyUpdate(Box::new(
                        self.ceremony.complete_policy_update(*request, now_ms)?,
                    ))
                }
            })),
            Request::CeremonyStatus(request) => {
                Ok(Response::CeremonyStatus(signer_ceremony_status(
                    self.ceremony
                        .status(&OperationId::new(request.id.as_str().to_owned())?)?,
                )))
            }
            Request::CeremonyCancel(request) => {
                let operation_id = OperationId::new(request.id.as_str().to_owned())?;
                self.ceremony.cancel(&operation_id)?;
                // Report the durable status rather than asserting `CANCELLED`:
                // a ceremony that already failed closed answers cancellation
                // idempotently, and callers reconciling it must see the state
                // `ceremony.status` will keep reporting.
                Ok(Response::CeremonyCancel(
                    self.ceremony.public_status(&operation_id)?,
                ))
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
                bloom_signer_api::RevocationSnapshot {
                    state: self.engine.revocation_state(&request.wallet_id, now_ms)?,
                    approval_tombstones: self.engine.approval_tombstones(&request.wallet_id)?,
                },
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
                self.engine.compare_and_swap_policy(&request)?,
            )),
            Request::WalletRegistrationPrepare(request) => {
                Ok(Response::WalletRegistrationPrepare(prepared_custody(
                    &self.ceremony,
                    self.ceremony.prepare_custody(request, now_ms)?,
                )?))
            }
            Request::WalletRegistrationStatus(request) => Ok(Response::WalletRegistrationStatus(
                self.ceremony.public_status(&request.operation_id)?,
            )),
            Request::WalletUnlockPrepare(request) => {
                Ok(Response::WalletUnlockPrepare(prepared_custody(
                    &self.ceremony,
                    self.ceremony.prepare_custody(request, now_ms)?,
                )?))
            }
            Request::WalletImportPrepare(request) => {
                Ok(Response::WalletImportPrepare(prepared_custody(
                    &self.ceremony,
                    self.ceremony.prepare_custody(request, now_ms)?,
                )?))
            }
            Request::WalletExportPrepare(request) => {
                Ok(Response::WalletExportPrepare(prepared_custody(
                    &self.ceremony,
                    self.ceremony.prepare_custody(request, now_ms)?,
                )?))
            }
            Request::WalletDeletePrepare(request) => {
                Ok(Response::WalletDeletePrepare(prepared_custody(
                    &self.ceremony,
                    self.ceremony.prepare_custody(request, now_ms)?,
                )?))
            }
            Request::CredentialListPublic(request) => Ok(Response::CredentialListPublic(
                self.engine.credential_public(&request.wallet_id)?,
            )),
            Request::CredentialAddPrepare(request) => {
                Ok(Response::CredentialAddPrepare(prepared_custody(
                    &self.ceremony,
                    self.ceremony.prepare_custody(request, now_ms)?,
                )?))
            }
            Request::CredentialRemovePrepare(request) => {
                Ok(Response::CredentialRemovePrepare(prepared_custody(
                    &self.ceremony,
                    self.ceremony.prepare_custody(request, now_ms)?,
                )?))
            }
            Request::CredentialReplacePrepare(request) => {
                Ok(Response::CredentialReplacePrepare(prepared_custody(
                    &self.ceremony,
                    self.ceremony.prepare_custody(request, now_ms)?,
                )?))
            }
            Request::RecoveryPrepare(request) => Ok(Response::RecoveryPrepare(prepared_custody(
                &self.ceremony,
                self.ceremony.prepare_custody(request, now_ms)?,
            )?)),
            Request::CustodyBindOutputRecipient(request) => {
                Ok(Response::CustodyBindOutputRecipient(prepared_custody(
                    &self.ceremony,
                    self.ceremony.bind_custody_output_recipient(
                        &request.operation_id,
                        request.recipient_key,
                        now_ms,
                    )?,
                )?))
            }
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
        let now_ms = if matches!(&request, ControlRequest::Status(_)) {
            self.clock.now_ms_read_only()?
        } else {
            self.clock.now_ms(false)?
        };
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

    fn readiness(&self) -> Result<Readiness, ProtocolError> {
        let (mut state, mut conditions) = self.clock.readiness()?;
        if self.require_network_containment().is_err() {
            state = ReadinessState::Unavailable;
            conditions.push(Token::new("network_containment_unavailable")?);
        }
        Ok(Readiness {
            service_id: Token::new("bloom-signer").expect("static service ID"),
            service_version: self.service_version.clone(),
            build_digest: self.build_digest.clone(),
            boot_epoch: self.boot_epoch.clone(),
            state,
            conditions,
        })
    }

    fn require_network_containment(&self) -> Result<(), ProtocolError> {
        match &self.network_containment {
            Some(guard) => Ok(guard.check()?),
            None => Ok(()),
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
            protocol_major: bloom_signer_api::SIGNER_API_MAJOR,
            protocol_minor_min: bloom_signer_api::SIGNER_API_MINOR_MIN,
            protocol_minor_max: bloom_signer_api::SIGNER_API_MINOR_MAX,
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
        key_ref: &bloom_signer_api::KeyRef,
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
            role: self.engine.key_role(key_ref)?,
            canonical_public_key: description.canonical_spki_der,
            addresses,
            supported_crypto_suites: description.supported_crypto_suites,
        })
    }

    async fn sign(&self, request: SignRequest) -> Result<SigningResult, ProtocolError> {
        let _gate = self.signing_gate.lock().await;
        let trusted_time_required = self
            .engine
            .approval_requires_trusted_time(&request.unsigned.approval_id)?;
        let clock = self.clock.observe(trusted_time_required)?;
        let authorization = self.engine.authorize_sign(&request, &clock)?;
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

        let provider_attempt_ids = (0..request.unsigned.ordered_hashes.len())
            .map(|index| {
                provider_attempt_id(&request.unsigned.operation_digest, &self.boot_epoch, index)
            })
            .collect::<Vec<_>>();
        self.engine.mark_operation_dispatched(
            &request.unsigned.operation_id,
            &request.unsigned.key_ref,
            &provider_attempt_ids,
        )?;
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
                    provider_attempt_id: provider_attempt_ids[index].clone(),
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
            signatures.push(bloom_signer_api::NormalizedSignature {
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

fn signer_request_requires_containment(request: &BrokerSignerRequest) -> bool {
    use BrokerSignerRequest as Request;

    matches!(
        request,
        Request::KeyDerivePrepare(_)
            | Request::KeyEnrollPrepare(_)
            | Request::CeremonyPrepare(_)
            | Request::CeremonyComplete(_)
            | Request::SignerSign(_)
            | Request::SignerSignBatch(_)
            | Request::PolicyCompareAndSwap(_)
            | Request::WalletRegistrationPrepare(_)
            | Request::WalletUnlockPrepare(_)
            | Request::WalletImportPrepare(_)
            | Request::WalletExportPrepare(_)
            | Request::WalletDeletePrepare(_)
            | Request::CredentialAddPrepare(_)
            | Request::CredentialRemovePrepare(_)
            | Request::CredentialReplacePrepare(_)
            | Request::RecoveryPrepare(_)
            | Request::CustodyBindOutputRecipient(_)
            | Request::CustodyComplete(_)
    )
}

fn broker_signer_request_is_read_only(request: &BrokerSignerRequest) -> bool {
    use BrokerSignerRequest as Request;
    matches!(
        request,
        Request::SystemHello(_)
            | Request::SignerReadiness(_)
            | Request::SignerCapabilities(_)
            | Request::KeyGetPublic(_)
            | Request::KeyListPublic(_)
            | Request::KeyDerivationCapabilities(_)
            | Request::KeyListDerived(_)
            | Request::KeyEnrollStatus(_)
            | Request::CeremonyStatus(_)
            | Request::SealedApprovalStatus(_)
            | Request::RevocationState(_)
            | Request::OperationStatus(_)
            | Request::PolicyRead(_)
            | Request::WalletRegistrationStatus(_)
            | Request::CredentialListPublic(_)
            | Request::CustodyResult(_)
            | Request::CustodyStatus(_)
    )
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
    signatures: &[bloom_signer_api::NormalizedSignature],
) -> Result<Digest32, ProtocolError> {
    #[derive(serde::Serialize)]
    struct Receipt<'a> {
        operation_id: &'a OperationId,
        operation_digest: &'a Digest32,
        signatures: &'a [bloom_signer_api::NormalizedSignature],
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
    if description.key_ref.key_spec != bloom_signer_api::KeySpec::Secp256k1 {
        return Ok(Vec::new());
    }
    let public_key = k256::PublicKey::from_public_key_der(&description.canonical_spki_der.decode())
        .map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "secp256k1 backend returned invalid canonical SPKI",
            )
        })?;
    let point = public_key.to_encoded_point(false);
    let digest = Keccak256::digest(&point.as_bytes()[1..]);
    Ok(vec![format!("0x{}", hex::encode(&digest[12..]))])
}

fn signer_ceremony_status(
    status: crate::ceremony::SignerCeremonyStatus,
) -> bloom_signer_api::SignerCeremonyStatus {
    match status {
        crate::ceremony::SignerCeremonyStatus::Pending => {
            bloom_signer_api::SignerCeremonyStatus::Pending
        }
        crate::ceremony::SignerCeremonyStatus::CompletedApproval(receipt) => {
            bloom_signer_api::SignerCeremonyStatus::CompletedApproval(receipt)
        }
        crate::ceremony::SignerCeremonyStatus::CompletedCustody(result) => {
            bloom_signer_api::SignerCeremonyStatus::CompletedCustody(result)
        }
        crate::ceremony::SignerCeremonyStatus::Terminal(state) => {
            bloom_signer_api::SignerCeremonyStatus::Terminal(state)
        }
        crate::ceremony::SignerCeremonyStatus::Missing => {
            bloom_signer_api::SignerCeremonyStatus::Missing
        }
    }
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

#[cfg(test)]
fn now_ms() -> Result<u64, ProtocolError> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
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
    use crate::{custody::WalletCustody, engine::SignerAuditKeys};
    use bloom_signer_api::{
        ActivationMode, ApprovalLimits, ApprovalSelector, ApprovalSubject, CryptoSuite, KeyRef,
        KeySpec, ProtocolVersion, RequestNonce, RevokeRequest, SealedApprovalTerms, SelectorKind,
        SignOperationIdentity, UnsignedSignRequest,
    };
    use bloom_signer_backend_api::{SecretBytes, SignerBackend, SignerBackendActivation};
    use bloom_signer_backend_local::LocalSignerBackend;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::collections::BTreeMap;

    fn test_time_source() -> &'static str {
        #[cfg(target_os = "linux")]
        return "linux-system-clock";
        #[cfg(target_os = "macos")]
        return "macos-managed-timed";
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        panic!("Signer service tests require a reviewed trusted-time platform");
    }

    #[tokio::test]
    async fn ethereum_address_uses_the_uncompressed_sec1_public_key() {
        let mut private_key = vec![0_u8; 32];
        private_key[31] = 1;
        let activation_secret = vec![9_u8; 32];
        let backend = LocalSignerBackend::provision_imported_secp256k1(
            Token::new("address-vector").unwrap(),
            Token::new("root").unwrap(),
            SecretBytes::new(private_key),
            SecretBytes::new(activation_secret.clone()),
            SigningKey::from_bytes(&[5; 32]).verifying_key(),
        )
        .unwrap();
        let key_ref = backend.root_key_ref().unwrap();
        backend
            .activate(&key_ref, SecretBytes::new(activation_secret))
            .await
            .unwrap();
        let description = backend.describe_key(&key_ref).await.unwrap();

        assert_eq!(
            ethereum_address(&description).unwrap(),
            vec!["0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"]
        );
    }

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
                SignerAuditKeys {
                    current_key_id: Token::new("signer-audit-key").unwrap(),
                    current_signing_key: SigningKey::from_bytes(&[14; 32]),
                    historical_verifying_keys: BTreeMap::new(),
                },
                registry,
            )
            .unwrap(),
        );
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
        engine
            .enroll_wallet_root_key(&terms.wallet_id, &terms.key_ref)
            .unwrap();
        engine.install_approval_for_test(&terms).unwrap();
        let ceremony = Arc::new(
            SignerCeremonyService::new(
                engine.clone(),
                Token::new("signer-ceremony-key").unwrap(),
                SigningKey::from_bytes(&[8; 32]),
            )
            .unwrap(),
        );
        let clock = Arc::new(
            SignerClock::new(
                engine.clone(),
                test_time_source(),
                BootEpoch::from_bytes([3; 16]),
            )
            .unwrap(),
        );
        (
            SignerRpcService::new(
                engine,
                ceremony,
                clock,
                BootEpoch::from_bytes([3; 16]),
                Digest32::from_bytes([2; 32]),
                "test",
            ),
            broker_key,
            terms,
        )
    }

    #[tokio::test]
    async fn public_key_projection_identifies_wallet_root_and_derived_roles() {
        let (service, _, terms) = fixture().await;
        let response = BrokerSignerService::dispatch(
            &service,
            BrokerSignerRequest::KeyListPublic(bloom_signer_api::WalletRequest {
                wallet_id: terms.wallet_id.clone(),
            }),
        )
        .await
        .unwrap();
        let BrokerSignerResponse::KeyListPublic(keys) = response else {
            panic!("wrong key-list response");
        };
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_ref, terms.key_ref);
        assert_eq!(keys[0].role, bloom_signer_api::KeyRole::WalletRoot);
    }

    #[tokio::test]
    async fn signer_service_only_release_preserves_authority_control_and_session_contracts() {
        let (mut previous, _, _) = fixture().await;
        let (mut current, _, _) = fixture().await;
        previous.service_version = "1.0.0".into();
        previous.build_digest = Digest32::from_bytes([90; 32]);
        current.service_version = "1.0.1".into();
        current.build_digest = Digest32::from_bytes([91; 32]);

        let previous_capabilities = previous.capabilities().unwrap();
        let current_capabilities = current.capabilities().unwrap();
        assert_ne!(
            previous_capabilities.service_version,
            current_capabilities.service_version
        );
        assert_ne!(
            previous_capabilities.build_digest,
            current_capabilities.build_digest
        );
        assert_eq!(
            (
                previous_capabilities.protocol_major,
                previous_capabilities.protocol_minor_min,
                previous_capabilities.protocol_minor_max,
            ),
            (
                bloom_signer_api::SIGNER_API_MAJOR,
                bloom_signer_api::SIGNER_API_MINOR_MIN,
                bloom_signer_api::SIGNER_API_MINOR_MAX,
            )
        );
        assert_eq!(
            (
                current_capabilities.protocol_major,
                current_capabilities.protocol_minor_min,
                current_capabilities.protocol_minor_max,
            ),
            (
                bloom_signer_api::SIGNER_API_MAJOR,
                bloom_signer_api::SIGNER_API_MINOR_MIN,
                bloom_signer_api::SIGNER_API_MINOR_MAX,
            )
        );
        assert_eq!(previous_capabilities.methods, current_capabilities.methods);
        assert_eq!(previous_capabilities.schemas, current_capabilities.schemas);
        assert_eq!(
            previous_capabilities.backends,
            current_capabilities.backends
        );
        assert_eq!(
            previous_capabilities.assurance_verifiers,
            current_capabilities.assurance_verifiers
        );
        assert_eq!(
            previous_capabilities.frame_max_bytes,
            current_capabilities.frame_max_bytes
        );
        assert!(bloom_signer_api::SIGNER_API_RANGE.contains(bloom_signer_api::SIGNER_API_CURRENT));
        assert!(bloom_signer_api::SIGNER_CONTROL_RANGE.contains(ProtocolVersion::new(1, 0)));
        assert!(
            bloom_signer_api::SIGNER_CONTROL_RANGE
                .contains(bloom_signer_api::SIGNER_CONTROL_CURRENT)
        );
        assert!(
            bloom_service_activation::SESSION_PROTOCOL_RANGE
                .contains(bloom_service_activation::SESSION_PROTOCOL_CURRENT)
        );
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

    fn retarget_sign_request(
        broker_key: &SigningKey,
        terms: &SealedApprovalTerms,
        key_ref: KeyRef,
        attempt_byte: u8,
    ) -> SignRequest {
        let mut request = sign_request(broker_key, terms, attempt_byte);
        request.unsigned.operation_id = OperationId::from_bytes([attempt_byte; 32]);
        request.unsigned.key_ref = key_ref.clone();
        request.unsigned.crypto_suite = CryptoSuite::Ed25519Message;
        request.unsigned.operation_digest = SignOperationIdentity {
            operation_id: request.unsigned.operation_id.clone(),
            approval_id: request.unsigned.approval_id.clone(),
            key_ref,
            crypto_suite: CryptoSuite::Ed25519Message,
            ordered_payload_digests: request.unsigned.ordered_payload_digests.clone(),
            ordered_hashes: request.unsigned.ordered_hashes.clone(),
            petal_use_claim_digest: None,
            claim_assurance_digest: None,
            policy_version: request.unsigned.policy_version.clone(),
            policy_digest: request.unsigned.policy_digest.clone(),
        }
        .digest()
        .unwrap();
        request.unsigned.attempt_digest = request.unsigned.computed_attempt_digest().unwrap();
        request.broker_signature = Base64UrlBytes::from_bytes(
            &broker_key
                .sign(&request.unsigned.attempt_digest.to_bytes())
                .to_bytes(),
        );
        request
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
        let audit = service
            .engine
            .export_backup(&terms.wallet_id, None, Vec::new())
            .unwrap()
            .audit_entries;
        let authorized = audit
            .iter()
            .find(|entry| entry.event_type == "sign.authorized")
            .expect("sign authorization audit entry");
        let payload: serde_json::Value = serde_json::from_str(&authorized.payload_jcs).unwrap();
        assert_eq!(
            payload["validation_receipt_digest"],
            serde_json::to_value(Digest32::from_bytes([77; 32])).unwrap()
        );
        let dispatched = audit
            .iter()
            .find(|entry| entry.event_type == "backend.dispatched")
            .expect("backend dispatch correlation audit entry");
        let dispatched_payload: serde_json::Value =
            serde_json::from_str(&dispatched.payload_jcs).unwrap();
        assert_eq!(
            dispatched_payload["operation_id"],
            serde_json::to_value(&first_result.operation_id).unwrap()
        );
        assert!(
            !dispatched_payload["provider_attempt_ids"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let result_entry = audit
            .iter()
            .find(|entry| entry.event_type == "sign.result")
            .expect("normalized result correlation audit entry");
        let result_payload: serde_json::Value =
            serde_json::from_str(&result_entry.payload_jcs).unwrap();
        let encoded_result: Base64UrlBytes =
            serde_json::from_value(result_payload["normalized_result"].clone()).unwrap();
        let audited_result: SigningResult =
            serde_json::from_slice(&encoded_result.decode()).unwrap();
        assert_eq!(
            audited_result.signer_receipt_digest,
            first_result.signer_receipt_digest
        );
        assert_eq!(
            audited_result.broker_receipt_digest,
            Digest32::from_bytes([77; 32])
        );
    }

    #[tokio::test]
    async fn dedicated_policy_key_is_unreachable_through_single_and_batch_signing() {
        let (service, broker_key, terms) = fixture().await;
        let custody = WalletCustody::register(
            terms.wallet_id.clone(),
            SecretBytes::new(vec![1; 32]),
            SecretBytes::new(vec![2; 32]),
            SecretBytes::new(vec![3; 32]),
            Base64UrlBytes::from_bytes(b"service-policy-credential"),
            SecretBytes::new(vec![4; 32]),
        )
        .unwrap();
        let unlocked = custody
            .unlock_with_credential(
                &Base64UrlBytes::from_bytes(b"service-policy-credential"),
                &SecretBytes::new(vec![4; 32]),
            )
            .unwrap();
        let policy_signing_key_id = Token::new("dedicated-policy-key").unwrap();
        service
            .engine
            .install_initial_policy(
                &terms.wallet_id,
                Base64UrlBytes::from_bytes(br#"{"limit":1}"#),
                policy_signing_key_id.clone(),
                &unlocked,
            )
            .unwrap();
        let policy = service
            .engine
            .export_backup(&terms.wallet_id, Some(custody.backup()), Vec::new())
            .unwrap()
            .policy
            .expect("installed policy must be exportable");
        assert_eq!(policy.snapshot.policy_signing_key_id, policy_signing_key_id);
        let policy_key_ref = KeyRef {
            backend: terms.key_ref.backend.clone(),
            backend_instance: terms.key_ref.backend_instance.clone(),
            locator: policy.snapshot.policy_signing_key_id.as_str().to_owned(),
            key_spec: KeySpec::Ed25519,
            public_key_fingerprint: Digest32::from_bytes(
                Sha256::digest(policy.policy_verifying_key.decode()).into(),
            ),
            derivation: None,
        };
        assert!(
            !service
                .engine
                .backend_registry()
                .key_is_registered(&policy_key_ref)
                .unwrap(),
            "the dedicated policy key must not enter the general signing registry"
        );
        let mut policy_key_terms = terms.clone();
        policy_key_terms.key_ref = policy_key_ref.clone();
        policy_key_terms.allowed_crypto_suites = vec![CryptoSuite::Ed25519Message];
        policy_key_terms.request_nonce = RequestNonce::from_bytes([67; 16]);
        assert_eq!(
            service
                .engine
                .install_approval_for_test(&policy_key_terms)
                .unwrap_err()
                .code,
            ProtocolErrorCode::KeyrefMismatch
        );

        for (request, is_batch) in [
            (
                retarget_sign_request(&broker_key, &terms, policy_key_ref.clone(), 10),
                false,
            ),
            (
                retarget_sign_request(&broker_key, &terms, policy_key_ref, 11),
                true,
            ),
        ] {
            let result = if is_batch {
                BrokerSignerService::dispatch(
                    &service,
                    BrokerSignerRequest::SignerSignBatch(request),
                )
                .await
            } else {
                BrokerSignerService::dispatch(&service, BrokerSignerRequest::SignerSign(request))
                    .await
            };
            assert_eq!(result.unwrap_err().code, ProtocolErrorCode::KeyrefMismatch);
        }
    }

    #[tokio::test]
    async fn dispatched_restart_state_never_calls_backend_again() {
        let (service, broker_key, terms) = fixture().await;
        let first = sign_request(&broker_key, &terms, 3);
        let clock = service.clock.observe(false).unwrap();
        service.engine.authorize_sign(&first, &clock).unwrap();
        service
            .engine
            .mark_operation_dispatched(
                &first.unsigned.operation_id,
                &first.unsigned.key_ref,
                &[provider_attempt_id(
                    &first.unsigned.operation_digest,
                    &service.boot_epoch,
                    0,
                )],
            )
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
    async fn stale_or_missing_root_containment_blocks_signing_but_reports_readiness() {
        let (service, broker_key, terms) = fixture().await;
        let directory = tempfile::tempdir().unwrap();
        let service = service.with_network_containment(
            NetworkContainmentGuard::new(
                directory.path().join("missing-status.json"),
                501,
                Digest32::from_bytes([2; 32]),
                5_000,
            )
            .unwrap(),
        );
        let readiness = match BrokerSignerService::dispatch(
            &service,
            BrokerSignerRequest::SignerReadiness(bloom_signer_api::Empty {}),
        )
        .await
        .unwrap()
        {
            BrokerSignerResponse::SignerReadiness(readiness) => readiness,
            _ => panic!("wrong readiness response"),
        };
        assert_eq!(readiness.state, ReadinessState::Unavailable);
        assert!(
            readiness
                .conditions
                .iter()
                .any(|condition| condition.as_str() == "network_containment_unavailable")
        );
        assert_eq!(
            BrokerSignerService::dispatch(
                &service,
                BrokerSignerRequest::SignerSign(sign_request(&broker_key, &terms, 7)),
            )
            .await
            .unwrap_err()
            .code,
            ProtocolErrorCode::ServiceUnavailable
        );
        assert!(matches!(
            RevocationControlService::dispatch(
                &service,
                ControlRequest::Status(bloom_signer_api::WalletRequest {
                    wallet_id: terms.wallet_id.clone(),
                }),
            )
            .await
            .unwrap(),
            ControlResponse::Status(_)
        ));
    }

    #[tokio::test]
    async fn audit_degradation_preserves_rpc_reads_and_status_but_blocks_mutation() {
        let (service, broker_key, terms) = fixture().await;
        service.engine.latch_audit_degraded();

        let readiness = BrokerSignerService::dispatch(
            &service,
            BrokerSignerRequest::SignerReadiness(bloom_signer_api::Empty {}),
        )
        .await
        .unwrap();
        let BrokerSignerResponse::SignerReadiness(readiness) = readiness else {
            panic!("wrong readiness response");
        };
        assert_eq!(readiness.state, ReadinessState::DegradedReadOnly);
        assert!(
            readiness
                .conditions
                .iter()
                .any(|condition| condition.as_str() == "audit_degraded")
        );

        assert!(matches!(
            BrokerSignerService::dispatch(
                &service,
                BrokerSignerRequest::SignerCapabilities(bloom_signer_api::Empty {}),
            )
            .await
            .unwrap(),
            BrokerSignerResponse::SignerCapabilities(_)
        ));
        assert!(matches!(
            BrokerSignerService::dispatch(
                &service,
                BrokerSignerRequest::KeyListPublic(bloom_signer_api::WalletRequest {
                    wallet_id: terms.wallet_id.clone(),
                }),
            )
            .await
            .unwrap(),
            BrokerSignerResponse::KeyListPublic(_)
        ));
        assert!(matches!(
            BrokerSignerService::dispatch(
                &service,
                BrokerSignerRequest::SealedApprovalStatus(bloom_signer_api::IdRequest {
                    id: terms.approval_id().unwrap(),
                }),
            )
            .await
            .unwrap(),
            BrokerSignerResponse::SealedApprovalStatus(_)
        ));
        assert!(matches!(
            RevocationControlService::dispatch(
                &service,
                ControlRequest::Status(bloom_signer_api::WalletRequest {
                    wallet_id: terms.wallet_id.clone(),
                }),
            )
            .await
            .unwrap(),
            ControlResponse::Status(_)
        ));
        assert_eq!(
            BrokerSignerService::dispatch(
                &service,
                BrokerSignerRequest::SignerSign(sign_request(&broker_key, &terms, 8)),
            )
            .await
            .unwrap_err()
            .code,
            ProtocolErrorCode::ServiceUnavailable
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
            bloom_signer_api::ApprovalLifecycleState::Revoked
        );
    }
}
