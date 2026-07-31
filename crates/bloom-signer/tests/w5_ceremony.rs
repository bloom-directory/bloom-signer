use bloom_broker_debug_driver::{VirtualAuthenticator, seal_hpke};
use bloom_signer::{
    ceremony::SignerCeremonyService,
    clock::{ClockCondition, ClockDecision},
    engine::SignerEngine,
    hpke::{CUSTODY_OUTPUT_INFO, HpkeRecipient, LOCAL_PRF_INFO},
    registry::{BackendRegistry, CompiledBackend},
};
use bloom_signer_backend_api::{BackendInput, BackendSignRequest, SecretBytes};
use bloom_signer_backend_local::{DerivationAuthority, DerivationGrant, LocalSignerBackend};
use bloom_triad_protocol::*;
use ed25519_dalek::{Signer as _, SigningKey};
use k256::pkcs8::EncodePublicKey as _;
use sha2::Digest as _;
use std::sync::Arc;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HpkeVector {
    name: String,
    recipient_private_key: Base64UrlBytes,
    recipient_public_key: Base64UrlBytes,
    info: Base64UrlBytes,
    aad: Base64UrlBytes,
    plaintext: Base64UrlBytes,
    envelope: HpkeEnvelope,
}

fn digest(byte: &str) -> Digest32 {
    Digest32::new(byte.repeat(32)).unwrap()
}

fn operation(byte: &str) -> OperationId {
    OperationId::new(byte.repeat(32)).unwrap()
}

fn signed_petal_request(
    terms: &SealedApprovalTerms,
    broker: &SigningKey,
    operation_id: OperationId,
) -> SignRequest {
    let identity = SignOperationIdentity {
        operation_id: operation_id.clone(),
        approval_id: terms.approval_id().unwrap(),
        key_ref: terms.key_ref.clone(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        ordered_payload_digests: vec![digest("b5")],
        ordered_hashes: vec![digest("b6")],
        petal_use_claim_digest: Some(digest("bd")),
        claim_assurance_digest: Some(digest("be")),
        policy_version: terms.policy_version.clone(),
        policy_digest: terms.policy_digest.clone(),
    };
    let mut unsigned = UnsignedSignRequest {
        schema: Token::new("bloom.sign-request/1").unwrap(),
        attempt_id: digest("bf"),
        operation_id,
        operation_digest: identity.digest().unwrap(),
        attempt_digest: digest("00"),
        audience: Token::new("bloom-signer").unwrap(),
        issuer_service_id: Token::new("bloom-broker").unwrap(),
        issuer_boot_epoch: BootEpoch::new("c0".repeat(16)).unwrap(),
        broker_signing_key_id: Token::new("broker-app-1").unwrap(),
        approval_id: terms.approval_id().unwrap(),
        wallet_id: terms.wallet_id.clone(),
        key_ref: terms.key_ref.clone(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        selector_kind: SelectorKind::Petal,
        ordered_payload_digests: vec![digest("b5")],
        ordered_hashes: vec![digest("b6")],
        signature_count: DecimalU64::new(1),
        petal_use_claim_digest: Some(digest("bd")),
        claim_assurance_digest: Some(digest("be")),
        policy_version: terms.policy_version.clone(),
        policy_digest: terms.policy_digest.clone(),
        validation_receipt_digest: digest("c1"),
        issued_at_ms: DecimalU64::new(10_500),
        not_before_ms: DecimalU64::new(10_500),
        expires_at_ms: DecimalU64::new(11_000),
    };
    unsigned.attempt_digest = unsigned.computed_attempt_digest().unwrap();
    SignRequest {
        broker_signature: Base64UrlBytes::from_bytes(
            &broker.sign(&unsigned.attempt_digest.to_bytes()).to_bytes(),
        ),
        unsigned,
    }
}

fn backend(kek: [u8; 32]) -> (Arc<LocalSignerBackend>, KeyRef) {
    let authority_key = SigningKey::from_bytes(&[5; 32]);
    let backend = Arc::new(
        LocalSignerBackend::provision(
            Token::new("local-default").unwrap(),
            Token::new("root-1").unwrap(),
            SecretBytes::new((0_u8..16).collect()),
            SecretBytes::new(kek.to_vec()),
            authority_key.verifying_key(),
        )
        .unwrap(),
    );
    let root = backend.root_key_ref().unwrap();
    let namespace = Token::new("ethereum-account-0").unwrap();
    let grant = DerivationGrant {
        authority_kind: Token::new("ceremony").unwrap(),
        namespace_id: namespace.clone(),
        canonical_prefix: "m/44'/60'/0'/0".into(),
        starting_index: DecimalU64::new(0),
        maximum_children: DecimalU64::new(1),
    };
    let mut message = b"bloom-key-derive-authority/v1".to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&grant).unwrap());
    let authority = DerivationAuthority::from_signed(
        grant,
        Base64UrlBytes::from_bytes(&authority_key.sign(&message).to_bytes()),
    );
    backend.configure_namespace(&authority).unwrap();
    let key = backend
        .allocate_derived_key(&root, &namespace, &authority)
        .unwrap();
    (backend, key.key_ref)
}

fn service(
    authenticator: &VirtualAuthenticator,
) -> (
    SignerCeremonyService,
    KeyRef,
    Arc<SignerEngine>,
    Arc<BackendRegistry>,
) {
    let (backend, key_ref) = backend(authenticator.deterministic_prf());
    let registry =
        Arc::new(BackendRegistry::from_compiled(vec![CompiledBackend::Local(backend)]).unwrap());
    let engine = Arc::new(
        SignerEngine::open_in_memory(
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            registry.clone(),
        )
        .unwrap(),
    );
    engine.enroll_key(&key_ref).unwrap();
    let service = SignerCeremonyService::new(
        engine.clone(),
        Token::new("signer-ceremony-key").unwrap(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    (service, key_ref, engine, registry)
}

fn terms(key_ref: KeyRef) -> SealedApprovalTerms {
    SealedApprovalTerms {
        subject: ApprovalSubject::Cli {
            client_id: Token::new("bloom-cli").unwrap(),
            command_class: Token::new("wallet.sign").unwrap(),
        },
        wallet_id: Token::new("wallet-1").unwrap(),
        key_ref,
        allowed_crypto_suites: vec![
            CryptoSuite::Secp256k1Sha256Recoverable,
            CryptoSuite::Secp256k1Keccak256Recoverable,
        ],
        selector: ApprovalSelector::Exact {
            ordered_payload_digests: vec![digest("22")],
            ordered_hashes: vec![digest("33")],
        },
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(1),
            max_signatures: DecimalU64::new(1),
            operation_rate_limits: vec![],
            signature_rate_limits: vec![],
            value_limits: vec![],
        },
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: DecimalU64::new(1),
        policy_version: DecimalU64::new(1),
        policy_digest: digest("44"),
        provenance_digest: digest("55"),
        request_nonce: RequestNonce::new("66".repeat(16)).unwrap(),
        issued_at_ms: DecimalU64::new(1_000),
        not_before_ms: DecimalU64::new(1_000),
        expires_at_ms: DecimalU64::new(20_000),
        renewal_of: None,
    }
}

fn register_wallet(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    operation_id: OperationId,
    now_ms: u64,
) -> (Token, WebAuthnCredential) {
    let prepare = CustodyPrepareRequest {
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation_id.clone(),
        wallet_id: None,
        key_ref: None,
        exact_terms_digest: digest("a1"),
        expected_input_class: Token::new("passkey-prf").unwrap(),
        browser_output_recipient_key: None,
        petal_key_scope: None,
    };
    let prepared = service.prepare_custody(prepare, now_ms).unwrap();
    let attestation = authenticator.attestation(&prepared.challenges[0].canonical_bytes().unwrap());
    let credential = authenticator.credential(0);
    let prf_assertion =
        authenticator.assertion(&prepared.challenges[1].canonical_bytes().unwrap(), 1);
    let aad = CustodyHpkeAad {
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation_id.clone(),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        signer_contribution_digest: prepared.contribution.digest().unwrap(),
        wallet_id: prepared.contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(attestation.credential_id.clone()),
        expected_input_class: Token::new("passkey-prf").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let encrypted_input = seal_hpke(
        &prepared.contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &authenticator.deterministic_prf(),
    )
    .unwrap();
    let wallet_id = prepared.contribution.wallet_id.clone().unwrap();
    service
        .complete_custody(
            CustodyCompleteRequest {
                ceremony_kind: CeremonyKind::WalletRegistration,
                custody_operation_id: operation_id,
                ceremony_id: prepared.contribution.ceremony_id,
                proof: WebAuthnCeremonyProof::Registration {
                    attestation,
                    prf_assertion: Some(prf_assertion),
                },
                encrypted_input: Some(encrypted_input),
                public_binding_digest: digest("a1"),
            },
            now_ms + 100,
        )
        .unwrap();
    (wallet_id, credential)
}

fn complete_new_wallet(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    kind: CeremonyKind,
    operation_id: OperationId,
    raw_private_key: Option<&[u8]>,
    output_recipient: Option<&HpkeRecipient>,
    now_ms: u64,
) -> (CustodyResult, CustodySignerContribution) {
    let expected_input_class = if kind == CeremonyKind::WalletImport {
        Token::new("raw-private-key-v1").unwrap()
    } else {
        Token::new("passkey-prf").unwrap()
    };
    let mut prepared = service
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: kind,
                custody_operation_id: operation_id.clone(),
                wallet_id: None,
                key_ref: None,
                exact_terms_digest: digest("d1"),
                expected_input_class: expected_input_class.clone(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
            },
            now_ms,
        )
        .unwrap();
    if let Some(recipient) = output_recipient {
        prepared = service
            .bind_custody_output_recipient(
                &operation_id,
                recipient.public_key().clone(),
                now_ms + 1,
            )
            .unwrap();
    }
    let attestation = authenticator.attestation(&prepared.challenges[0].canonical_bytes().unwrap());
    let prf_assertion =
        authenticator.assertion(&prepared.challenges[1].canonical_bytes().unwrap(), 1);
    let plaintext = if kind == CeremonyKind::WalletImport {
        serde_jcs::to_vec(&serde_json::json!({
            "raw_private_key": Base64UrlBytes::from_bytes(raw_private_key.unwrap()),
            "credential_prf": Base64UrlBytes::from_bytes(
                &authenticator.deterministic_prf()
            ),
        }))
        .unwrap()
    } else {
        authenticator.deterministic_prf().to_vec()
    };
    let aad = CustodyHpkeAad {
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        ceremony_kind: kind,
        custody_operation_id: operation_id.clone(),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        signer_contribution_digest: prepared.contribution.digest().unwrap(),
        wallet_id: prepared.contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(attestation.credential_id.clone()),
        expected_input_class,
    }
    .canonical_bytes()
    .unwrap();
    let encrypted_input = seal_hpke(
        &prepared.contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &plaintext,
    )
    .unwrap();
    let result = service
        .complete_custody(
            CustodyCompleteRequest {
                ceremony_kind: kind,
                custody_operation_id: operation_id,
                ceremony_id: prepared.contribution.ceremony_id.clone(),
                proof: WebAuthnCeremonyProof::Registration {
                    attestation,
                    prf_assertion: Some(prf_assertion),
                },
                encrypted_input: Some(encrypted_input),
                public_binding_digest: digest("d1"),
            },
            now_ms + 100,
        )
        .unwrap();
    (result, prepared.contribution)
}

fn complete_generic(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    wallet_id: &Token,
    workflow: (CeremonyKind, OperationId, serde_json::Value),
    output_recipient: Option<&HpkeRecipient>,
    now_ms: u64,
) -> Result<(CustodyResult, CustodySignerContribution), ProtocolError> {
    let (kind, operation_id, effect) = workflow;
    let exact_terms_digest =
        Digest32::from_bytes(sha2::Sha256::digest(serde_jcs::to_vec(&effect).unwrap()).into());
    let mut prepared = service.prepare_custody(
        CustodyPrepareRequest {
            ceremony_kind: kind,
            custody_operation_id: operation_id.clone(),
            wallet_id: Some(wallet_id.clone()),
            key_ref: None,
            exact_terms_digest: exact_terms_digest.clone(),
            expected_input_class: Token::new("generic-custody-v1").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: None,
        },
        now_ms,
    )?;
    if let Some(recipient) = output_recipient {
        prepared = service.bind_custody_output_recipient(
            &operation_id,
            recipient.public_key().clone(),
            now_ms + 1,
        )?;
    }
    let assertion =
        authenticator.assertion(&prepared.challenges[0].canonical_bytes()?, now_ms as u32);
    let aad = CustodyHpkeAad {
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        ceremony_kind: kind,
        custody_operation_id: operation_id.clone(),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        signer_contribution_digest: prepared.contribution.digest()?,
        wallet_id: Some(wallet_id.clone()),
        key_ref: None,
        credential_id: Some(assertion.credential_id.clone()),
        expected_input_class: Token::new("generic-custody-v1").unwrap(),
    }
    .canonical_bytes()?;
    let plaintext = serde_jcs::to_vec(&serde_json::json!({
        "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
        "effect": effect,
    }))
    .unwrap();
    let encrypted_input = seal_hpke(
        &prepared.contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &plaintext,
    )
    .unwrap();
    let result = service.complete_custody(
        CustodyCompleteRequest {
            ceremony_kind: kind,
            custody_operation_id: operation_id,
            ceremony_id: prepared.contribution.ceremony_id.clone(),
            proof: WebAuthnCeremonyProof::Assertion { assertion },
            encrypted_input: Some(encrypted_input),
            public_binding_digest: exact_terms_digest,
        },
        now_ms + 100,
    )?;
    Ok((result, prepared.contribution))
}

fn complete_petal_key_derivation(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    scope: PetalKeyScope,
    browser_effect: Option<serde_json::Value>,
    now_ms: u64,
) -> Result<(CustodyResult, CustodyCompleteRequest), ProtocolError> {
    let scope_digest = scope.digest()?;
    let prepared = service.prepare_custody(
        CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::KeyDerive,
            custody_operation_id: scope.custody_operation_id.clone(),
            wallet_id: Some(scope.wallet_id.clone()),
            key_ref: Some(scope.parent_key_ref.clone()),
            exact_terms_digest: scope_digest.clone(),
            expected_input_class: Token::new("petal-subkey-v1").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: Some(scope.clone()),
        },
        now_ms,
    )?;
    assert_eq!(prepared.contribution.petal_key_scope, Some(scope.clone()));
    let assertion =
        authenticator.assertion(&prepared.challenges[0].canonical_bytes()?, now_ms as u32);
    let aad = CustodyHpkeAad {
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::KeyDerive,
        custody_operation_id: scope.custody_operation_id.clone(),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        signer_contribution_digest: prepared.contribution.digest()?,
        wallet_id: Some(scope.wallet_id.clone()),
        key_ref: Some(scope.parent_key_ref.clone()),
        credential_id: Some(assertion.credential_id.clone()),
        expected_input_class: Token::new("petal-subkey-v1").unwrap(),
    }
    .canonical_bytes()?;
    let plaintext = serde_jcs::to_vec(&serde_json::json!({
        "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
        "effect": browser_effect.unwrap_or_else(|| serde_json::json!({"kind": "key_derive"})),
    }))
    .unwrap();
    let encrypted_input = seal_hpke(
        &prepared.contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &plaintext,
    )?;
    let complete = CustodyCompleteRequest {
        ceremony_kind: CeremonyKind::KeyDerive,
        custody_operation_id: scope.custody_operation_id,
        ceremony_id: prepared.contribution.ceremony_id,
        proof: WebAuthnCeremonyProof::Assertion { assertion },
        encrypted_input: Some(encrypted_input),
        public_binding_digest: scope_digest,
    };
    let result = service.complete_custody(complete.clone(), now_ms + 100)?;
    Ok((result, complete))
}

fn complete_policy_update(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    wallet_id: &Token,
    update: PolicyUpdateRequest,
    now_ms: u64,
) -> Result<(CustodyResult, PolicyUpdateCeremonyPrepareRequest), ProtocolError> {
    let review_manifest_digest = digest("c3");
    let mut validation = PolicyValidationReceipt {
        update_terms_digest: update.terms_digest()?,
        review_manifest_digest,
        broker_key_id: Token::new("broker-app-1").unwrap(),
        broker_signature: Base64UrlBytes::from_bytes(&[]),
    };
    let mut validation_message = b"bloom-policy-validation-receipt/v1".to_vec();
    validation_message.extend_from_slice(&validation.unsigned_canonical_bytes()?);
    validation.broker_signature = Base64UrlBytes::from_bytes(
        &SigningKey::from_bytes(&[7; 32])
            .sign(&validation_message)
            .to_bytes(),
    );
    let request = PolicyUpdateCeremonyPrepareRequest {
        custody: CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::PolicyUpdate,
            custody_operation_id: update.operation_id.clone(),
            wallet_id: Some(wallet_id.clone()),
            key_ref: None,
            exact_terms_digest: update.terms_digest()?,
            expected_input_class: Token::new("policy_update_credential_prf").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: None,
        },
        update,
        broker_validation_receipt: validation,
    };
    let mut forged = request.clone();
    forged.broker_validation_receipt.broker_signature = Base64UrlBytes::from_bytes(&[0_u8; 64]);
    assert_eq!(
        service
            .prepare_policy_update(forged, now_ms)
            .unwrap_err()
            .code,
        ProtocolErrorCode::UnauthenticatedPeer
    );
    let prepared = service.prepare_policy_update(request.clone(), now_ms)?;
    assert_eq!(
        prepared.contribution.review_manifest_digest,
        request.broker_validation_receipt.review_manifest_digest
    );
    let assertion =
        authenticator.assertion(&prepared.challenges[0].canonical_bytes()?, now_ms as u32);
    let aad = CustodyHpkeAad {
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::PolicyUpdate,
        custody_operation_id: request.update.operation_id.clone(),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        signer_contribution_digest: prepared.contribution.digest()?,
        wallet_id: Some(wallet_id.clone()),
        key_ref: None,
        credential_id: Some(assertion.credential_id.clone()),
        expected_input_class: Token::new("policy_update_credential_prf").unwrap(),
    }
    .canonical_bytes()?;
    let plaintext = serde_jcs::to_vec(&serde_json::json!({
        "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
        "effect": {"kind": "policy_update"},
    }))
    .unwrap();
    let encrypted_input = seal_hpke(
        &prepared.contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &plaintext,
    )
    .unwrap();
    let result = service.complete_policy_update(
        PolicyUpdateCeremonyCompleteRequest {
            custody: CustodyCompleteRequest {
                ceremony_kind: CeremonyKind::PolicyUpdate,
                custody_operation_id: request.update.operation_id.clone(),
                ceremony_id: prepared.contribution.ceremony_id,
                proof: WebAuthnCeremonyProof::Assertion { assertion },
                encrypted_input: Some(encrypted_input),
                public_binding_digest: request.custody.exact_terms_digest.clone(),
            },
        },
        now_ms + 100,
    )?;
    Ok((result, request))
}

#[test]
fn petal_subkeys_are_signer_owned_scoped_restart_safe_and_never_cross_principals() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("signer.sqlite");
    let authenticator = VirtualAuthenticator::generate();
    let broker = SigningKey::from_bytes(&[7; 32]);
    let ceremony_key = SigningKey::from_bytes(&[9; 32]);
    let registry = Arc::new(BackendRegistry::from_compiled(vec![]).unwrap());
    let engine = Arc::new(
        SignerEngine::open(
            &database,
            Token::new("broker-app-1").unwrap(),
            broker.verifying_key(),
            ceremony_key.verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            registry,
        )
        .unwrap(),
    );
    let service = SignerCeremonyService::new(
        engine.clone(),
        Token::new("signer-ceremony-key").unwrap(),
        ceremony_key.clone(),
    )
    .unwrap();
    let (wallet_id, _) = register_wallet(&service, &authenticator, operation("b1"), 10_000);
    let parent = engine.enrolled_key_refs(&wallet_id).unwrap().remove(0);
    let base_scope = PetalKeyScope {
        wallet_id: wallet_id.clone(),
        parent_key_ref: parent.clone(),
        package_hash: digest("b2"),
        route: "/petals/exchange/sign".into(),
        agent_id: Some("account-a".into()),
        purpose: Token::new("exchange-agent").unwrap(),
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Sha256Recoverable],
        maximum_lifetime_ms: DecimalU64::new(20_000),
        custody_operation_id: operation("b3"),
    };

    let mut cross_wallet = base_scope.clone();
    cross_wallet.wallet_id = Token::new("another-wallet").unwrap();
    assert_eq!(
        service
            .prepare_custody(
                CustodyPrepareRequest {
                    ceremony_kind: CeremonyKind::KeyDerive,
                    custody_operation_id: cross_wallet.custody_operation_id.clone(),
                    wallet_id: Some(cross_wallet.wallet_id.clone()),
                    key_ref: Some(parent.clone()),
                    exact_terms_digest: cross_wallet.digest().unwrap(),
                    expected_input_class: Token::new("petal-subkey-v1").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: Some(cross_wallet),
                },
                10_150,
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::KeyrefMismatch
    );

    let mut browser_controlled = base_scope.clone();
    browser_controlled.custody_operation_id = operation("bc");
    assert_eq!(
        complete_petal_key_derivation(
            &service,
            &authenticator,
            browser_controlled,
            Some(serde_json::json!({
                "kind": "key_derive",
                "namespace_id": "browser-chosen",
                "grant": {
                    "authority_kind": "ceremony",
                    "namespace_id": "browser-chosen",
                    "canonical_prefix": "m/0",
                    "starting_index": "0",
                    "maximum_children": "1"
                },
                "authority_signature": Base64UrlBytes::from_bytes(&[0; 64]),
            })),
            10_175,
        )
        .unwrap_err()
        .code,
        ProtocolErrorCode::BackendInvalidRequest
    );

    let (first, first_complete) =
        complete_petal_key_derivation(&service, &authenticator, base_scope.clone(), None, 10_200)
            .unwrap();
    assert!(first.encrypted_browser_result.is_none());
    assert_eq!(first.public_key_refs.len(), 1);
    // Completion replay returns the same public receipt and never allocates a
    // second child for the same custody identity.
    assert_eq!(
        service.complete_custody(first_complete, 10_400).unwrap(),
        first
    );

    let mut second_scope = base_scope.clone();
    second_scope.custody_operation_id = operation("b4");
    let (second, _) =
        complete_petal_key_derivation(&service, &authenticator, second_scope, None, 10_500)
            .unwrap();
    assert_ne!(first.public_key_refs[0], second.public_key_refs[0]);
    let child = first.public_key_refs[0].clone();

    drop(service);
    drop(engine);
    // A fresh engine and empty registry restore both custody and the derived
    // key from Signer's durable records. The scope remains an independent
    // authorization boundary after restart.
    let restarted_registry = Arc::new(BackendRegistry::from_compiled(vec![]).unwrap());
    let restarted_engine = Arc::new(
        SignerEngine::open(
            &database,
            Token::new("broker-app-1").unwrap(),
            broker.verifying_key(),
            ceremony_key.verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            restarted_registry.clone(),
        )
        .unwrap(),
    );
    let restarted_service = SignerCeremonyService::new(
        restarted_engine.clone(),
        Token::new("signer-ceremony-key").unwrap(),
        ceremony_key,
    )
    .unwrap();
    let policy = restarted_engine.policy_snapshot(&wallet_id).unwrap();
    let epoch = restarted_engine
        .revocation_state(&wallet_id, 10_400)
        .unwrap()
        .wallet_revocation_epoch;
    let scoped_terms = SealedApprovalTerms {
        subject: ApprovalSubject::Petal {
            package_hash: base_scope.package_hash.clone(),
            route: base_scope.route.clone(),
            agent_id: base_scope.agent_id.clone(),
        },
        wallet_id: wallet_id.clone(),
        key_ref: child,
        allowed_crypto_suites: base_scope.allowed_crypto_suites.clone(),
        selector: ApprovalSelector::Exact {
            ordered_payload_digests: vec![digest("b5")],
            ordered_hashes: vec![digest("b6")],
        },
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(1),
            max_signatures: DecimalU64::new(1),
            operation_rate_limits: vec![],
            signature_rate_limits: vec![],
            value_limits: vec![],
        },
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: epoch,
        policy_version: policy.version,
        policy_digest: policy.policy_digest,
        provenance_digest: digest("b7"),
        request_nonce: RequestNonce::new("b8".repeat(16)).unwrap(),
        issued_at_ms: DecimalU64::new(10_400),
        not_before_ms: DecimalU64::new(10_400),
        expires_at_ms: DecimalU64::new(20_000),
        renewal_of: None,
    };

    let mut cli = scoped_terms.clone();
    cli.subject = ApprovalSubject::Cli {
        client_id: Token::new("bloom-cli").unwrap(),
        command_class: Token::new("wallet-sign").unwrap(),
    };
    assert_eq!(
        restarted_service
            .prepare_approval(
                CeremonyPrepareRequest {
                    activation_operation_id: operation("ba"),
                    terms: cli.clone(),
                    review_manifest_digest: digest("bb"),
                    exact_ordered_payload_digests: vec![digest("b5")],
                    exact_ordered_hashes: vec![digest("b6")],
                    replacement_approval_id: None,
                },
                10_400,
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::SelectorMismatch
    );
    assert_eq!(
        restarted_engine
            .install_approval_for_test(&cli)
            .unwrap_err()
            .code,
        ProtocolErrorCode::SelectorMismatch
    );
    let mut another_petal = scoped_terms.clone();
    another_petal.subject = ApprovalSubject::Petal {
        package_hash: digest("b9"),
        route: base_scope.route.clone(),
        agent_id: base_scope.agent_id.clone(),
    };
    assert_eq!(
        restarted_engine
            .install_approval_for_test(&another_petal)
            .unwrap_err()
            .code,
        ProtocolErrorCode::SelectorMismatch
    );
    let mut another_agent = scoped_terms.clone();
    another_agent.subject = ApprovalSubject::Petal {
        package_hash: base_scope.package_hash.clone(),
        route: base_scope.route.clone(),
        agent_id: Some("account-b".into()),
    };
    assert_eq!(
        restarted_engine
            .install_approval_for_test(&another_agent)
            .unwrap_err()
            .code,
        ProtocolErrorCode::SelectorMismatch
    );
    let mut another_wallet = scoped_terms.clone();
    another_wallet.wallet_id = Token::new("another-wallet").unwrap();
    assert_eq!(
        restarted_engine
            .install_approval_for_test(&another_wallet)
            .unwrap_err()
            .code,
        ProtocolErrorCode::KeyrefMismatch
    );
    let mut excessive_suite = scoped_terms.clone();
    excessive_suite.allowed_crypto_suites = vec![CryptoSuite::Secp256k1Keccak256Recoverable];
    assert_eq!(
        restarted_engine
            .install_approval_for_test(&excessive_suite)
            .unwrap_err()
            .code,
        ProtocolErrorCode::SuiteNotAllowed
    );
    let mut excessive_lifetime = scoped_terms.clone();
    excessive_lifetime.expires_at_ms = DecimalU64::new(31_000);
    assert_eq!(
        restarted_engine
            .install_approval_for_test(&excessive_lifetime)
            .unwrap_err()
            .code,
        ProtocolErrorCode::ApprovalExpired
    );
    let mut wrong_purpose = scoped_terms.clone();
    wrong_purpose.selector = ApprovalSelector::Petal {
        package_hash: base_scope.package_hash.clone(),
        route: base_scope.route.clone(),
        allowed_operation_classes: vec![Token::new("payment-key").unwrap()],
        required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
    };
    wrong_purpose.request_nonce = RequestNonce::new("ca".repeat(16)).unwrap();
    assert_eq!(
        restarted_engine
            .install_approval_for_test(&wrong_purpose)
            .unwrap_err()
            .code,
        ProtocolErrorCode::SelectorMismatch
    );
    let mut empty_purpose = wrong_purpose.clone();
    if let ApprovalSelector::Petal {
        allowed_operation_classes,
        ..
    } = &mut empty_purpose.selector
    {
        allowed_operation_classes.clear();
    }
    empty_purpose.request_nonce = RequestNonce::new("cf".repeat(16)).unwrap();
    assert_eq!(
        restarted_engine
            .install_approval_for_test(&empty_purpose)
            .unwrap_err()
            .code,
        ProtocolErrorCode::SelectorMismatch
    );

    let mut reusable = scoped_terms.clone();
    reusable.selector = ApprovalSelector::Petal {
        package_hash: base_scope.package_hash.clone(),
        route: base_scope.route.clone(),
        allowed_operation_classes: vec![base_scope.purpose.clone()],
        required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
    };
    reusable.request_nonce = RequestNonce::new("cb".repeat(16)).unwrap();
    restarted_engine
        .install_approval_for_test(&reusable)
        .unwrap();
    futures::executor::block_on(restarted_registry.activate_key(
        &reusable.key_ref,
        SecretBytes::new(authenticator.deterministic_prf().to_vec()),
    ))
    .unwrap();

    // Simulate a corrupt/replayed durable approval that bypassed activation.
    // authorize_sign must independently apply the scope-purpose check rather
    // than trusting the earlier activation decision.
    let mut corrupted = reusable.clone();
    if let ApprovalSelector::Petal {
        allowed_operation_classes,
        ..
    } = &mut corrupted.selector
    {
        *allowed_operation_classes = vec![Token::new("payment-key").unwrap()];
    }
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE approvals SET terms_jcs = ?2 WHERE approval_id = ?1",
            rusqlite::params![
                reusable.approval_id().unwrap().as_str(),
                serde_jcs::to_string(&corrupted).unwrap()
            ],
        )
        .unwrap();
    drop(connection);
    let signed = signed_petal_request(&reusable, &broker, operation("cc"));
    assert_eq!(
        restarted_engine
            .authorize_sign(
                &signed,
                &ClockDecision {
                    effective_now_ms: 10_500,
                    condition: ClockCondition::Healthy,
                    observed_utc_ms: Some(10_500),
                    monotonic_anchor_ns: 1_000_000,
                    boot_epoch: BootEpoch::new("cd".repeat(16)).unwrap(),
                },
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::SelectorMismatch
    );
    restarted_engine
        .install_approval_for_test(&scoped_terms)
        .unwrap();
}

#[test]
fn raw_webauthn_assertion_and_attestation_are_independently_verified() {
    let authenticator = VirtualAuthenticator::generate();
    let challenge = b"exact signed ceremony challenge";
    let credential = authenticator.credential(0);
    let assertion = authenticator.assertion(challenge, 1);
    let verified = verify_webauthn_assertion(&assertion, &credential, challenge, true).unwrap();
    assert_eq!(verified.sign_count, 1);

    let attestation = authenticator.attestation(challenge);
    let extracted = verify_webauthn_attestation(
        &attestation,
        challenge,
        credential.user_handle.clone(),
        credential.prf_salt.clone(),
    )
    .unwrap();
    assert_eq!(extracted.credential_id, credential.credential_id);
    verify_webauthn_assertion(&assertion, &extracted, challenge, true).unwrap();

    let mut wrong_origin = assertion;
    wrong_origin.client_data_json = Base64UrlBytes::from_bytes(
        br#"{"type":"webauthn.get","challenge":"ZXhhY3Qgc2lnbmVkIGNlcmVtb255IGNoYWxsZW5nZQ","origin":"http://127.0.0.1:18734","crossOrigin":false}"#,
    );
    assert_eq!(
        verify_webauthn_assertion(&wrong_origin, &credential, challenge, true)
            .unwrap_err()
            .code,
        ProtocolErrorCode::UnauthenticatedPeer
    );
}

#[test]
fn hpke_is_single_use_and_binds_info_aad_and_session() {
    let recipient = HpkeRecipient::generate();
    let public = recipient.public_key().clone();
    let envelope = seal_hpke(&public, LOCAL_PRF_INFO, b"aad-one", b"secret").unwrap();
    let plaintext = recipient
        .open(&envelope, LOCAL_PRF_INFO, b"aad-one")
        .unwrap();
    assert_eq!(plaintext.expose_to_backend(), b"secret");

    let wrong_aad = HpkeRecipient::generate();
    let envelope = seal_hpke(
        wrong_aad.public_key(),
        LOCAL_PRF_INFO,
        b"aad-one",
        b"secret",
    )
    .unwrap();
    assert_eq!(
        wrong_aad
            .open(&envelope, LOCAL_PRF_INFO, b"aad-two")
            .unwrap_err()
            .code,
        ProtocolErrorCode::UnauthenticatedPeer
    );

    let wrong_session = HpkeRecipient::generate();
    assert_eq!(
        wrong_session
            .open(&envelope, LOCAL_PRF_INFO, b"aad-one")
            .unwrap_err()
            .code,
        ProtocolErrorCode::UnauthenticatedPeer
    );
}

#[test]
fn hpke_matches_committed_reviewed_vector() {
    let vector: HpkeVector =
        serde_json::from_str(include_str!("../vectors/hpke-local-prf-v1.json")).unwrap();
    assert_eq!(
        vector.name,
        "rfc9180-x25519-hkdf-sha256-chacha20poly1305-v1"
    );
    let recipient =
        HpkeRecipient::from_private_key(SecretBytes::new(vector.recipient_private_key.decode()))
            .unwrap();
    assert_eq!(recipient.public_key(), &vector.recipient_public_key);
    let plaintext = recipient
        .open(
            &vector.envelope,
            &vector.info.decode(),
            &vector.aad.decode(),
        )
        .unwrap();
    assert_eq!(plaintext.expose_to_backend(), vector.plaintext.decode());
}

#[test]
fn approval_completion_verifies_raw_proof_decrypts_prf_and_is_idempotent() {
    let authenticator = VirtualAuthenticator::generate();
    let (service, key_ref, engine, _) = service(&authenticator);
    service
        .register_existing_credential(Token::new("wallet-1").unwrap(), authenticator.credential(0))
        .unwrap();
    let terms = terms(key_ref);
    let prepare_request = CeremonyPrepareRequest {
        activation_operation_id: operation("10"),
        terms: terms.clone(),
        review_manifest_digest: digest("77"),
        exact_ordered_payload_digests: vec![digest("22")],
        exact_ordered_hashes: vec![digest("33")],
        replacement_approval_id: None,
    };
    let prepared = service.prepare_approval(prepare_request, 2_000).unwrap();
    assert_eq!(
        prepared.contribution.allowed_crypto_suites,
        terms.allowed_crypto_suites
    );
    let assertion = authenticator.assertion(&prepared.challenges[0].canonical_bytes().unwrap(), 1);
    let aad = LocalPrfHpkeAad {
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        approval_id: terms.approval_id().unwrap(),
        approval_digest: terms.approval_digest().unwrap(),
        review_manifest_digest: digest("77"),
        key_ref: terms.key_ref.clone(),
        allowed_crypto_suites: terms.allowed_crypto_suites.clone(),
        credential_id: assertion.credential_id.clone(),
        activation_mode: terms.activation_mode.clone(),
        wallet_revocation_epoch: terms.wallet_revocation_epoch.clone(),
    }
    .canonical_bytes()
    .unwrap();
    let envelope = seal_hpke(
        prepared
            .contribution
            .ephemeral_encryption_public_key
            .as_ref()
            .unwrap(),
        LOCAL_PRF_INFO,
        &aad,
        &authenticator.deterministic_prf(),
    )
    .unwrap();
    let complete = CeremonyCompleteRequest {
        activation_operation_id: operation("10"),
        proof: WebAuthnCeremonyProof::Assertion { assertion },
        contribution: prepared.contribution,
        encrypted_local_prf: Some(envelope),
    };
    let receipt =
        futures::executor::block_on(service.complete_approval(complete.clone(), 2_500)).unwrap();
    let replay =
        futures::executor::block_on(service.complete_approval(complete.clone(), 2_600)).unwrap();
    assert_eq!(receipt, replay);
    assert_eq!(receipt.approval_id, terms.approval_id().unwrap());
    assert_eq!(receipt.allowed_crypto_suites, terms.allowed_crypto_suites);

    drop(service);
    let restarted = SignerCeremonyService::new(
        engine,
        Token::new("signer-ceremony-key").unwrap(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    let recovered =
        futures::executor::block_on(restarted.complete_approval(complete, 2_700)).unwrap();
    assert_eq!(receipt, recovered);
}

#[test]
fn custody_registration_restart_and_passkey_add_are_atomic_and_kind_bound() {
    let authenticator = VirtualAuthenticator::generate();
    let (service, _, engine, registry) = service(&authenticator);
    let prepare = CustodyPrepareRequest {
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation("20"),
        wallet_id: None,
        key_ref: None,
        exact_terms_digest: digest("88"),
        expected_input_class: Token::new("passkey-prf").unwrap(),
        browser_output_recipient_key: None,
        petal_key_scope: None,
    };
    let prepared = service.prepare_custody(prepare, 3_000).unwrap();
    let attestation = authenticator.attestation(&prepared.challenges[0].canonical_bytes().unwrap());
    let prf_assertion =
        authenticator.assertion(&prepared.challenges[1].canonical_bytes().unwrap(), 1);
    let aad = CustodyHpkeAad {
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation("20"),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        signer_contribution_digest: prepared.contribution.digest().unwrap(),
        wallet_id: prepared.contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(attestation.credential_id.clone()),
        expected_input_class: Token::new("passkey-prf").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let envelope = seal_hpke(
        &prepared.contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &authenticator.deterministic_prf(),
    )
    .unwrap();
    let mut complete = CustodyCompleteRequest {
        ceremony_kind: CeremonyKind::CredentialAdd,
        custody_operation_id: operation("20"),
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        proof: WebAuthnCeremonyProof::Registration {
            attestation: attestation.clone(),
            prf_assertion: Some(prf_assertion.clone()),
        },
        encrypted_input: Some(envelope.clone()),
        public_binding_digest: digest("88"),
    };
    assert_eq!(
        service
            .complete_custody(complete.clone(), 3_500)
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyKindMismatch
    );

    // Kind mismatch is terminal for that single-use ceremony. A fresh
    // operation is required and no partially registered wallet is visible.
    complete.custody_operation_id = operation("21");
    assert_eq!(
        service.complete_custody(complete, 3_500).unwrap_err().code,
        ProtocolErrorCode::CeremonyReplay
    );

    let retry = CustodyPrepareRequest {
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation("21"),
        wallet_id: None,
        key_ref: None,
        exact_terms_digest: digest("89"),
        expected_input_class: Token::new("passkey-prf").unwrap(),
        browser_output_recipient_key: None,
        petal_key_scope: None,
    };
    let prepared = service.prepare_custody(retry, 3_600).unwrap();
    let attestation = authenticator.attestation(&prepared.challenges[0].canonical_bytes().unwrap());
    let prf_assertion =
        authenticator.assertion(&prepared.challenges[1].canonical_bytes().unwrap(), 1);
    let aad = CustodyHpkeAad {
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation("21"),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        signer_contribution_digest: prepared.contribution.digest().unwrap(),
        wallet_id: prepared.contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(attestation.credential_id.clone()),
        expected_input_class: Token::new("passkey-prf").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let envelope = seal_hpke(
        &prepared.contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &authenticator.deterministic_prf(),
    )
    .unwrap();
    let registered_wallet_id = prepared.contribution.wallet_id.clone().unwrap();
    let successful_completion = CustodyCompleteRequest {
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation("21"),
        ceremony_id: prepared.contribution.ceremony_id,
        proof: WebAuthnCeremonyProof::Registration {
            attestation,
            prf_assertion: Some(prf_assertion),
        },
        encrypted_input: Some(envelope),
        public_binding_digest: digest("89"),
    };
    let result = service
        .complete_custody(successful_completion.clone(), 3_700)
        .unwrap();
    assert_eq!(result.public_status, CeremonyState::Completed);
    assert_eq!(result.public_key_refs.len(), 1);
    assert_eq!(result.public_key_refs[0].backend.as_str(), "local");
    assert_eq!(
        result.public_key_refs[0].backend_instance,
        registered_wallet_id
    );
    result.public_key_refs[0].validate().unwrap();
    let backend = registry
        .get(
            &result.public_key_refs[0].backend,
            &result.public_key_refs[0].backend_instance,
        )
        .unwrap();
    let description =
        futures::executor::block_on(backend.describe_key(&result.public_key_refs[0])).unwrap();
    assert_eq!(
        description.public_key_fingerprint,
        result.public_key_refs[0].public_key_fingerprint
    );
    let signature = futures::executor::block_on(backend.sign(BackendSignRequest {
        provider_attempt_id: digest("d4"),
        key_ref: result.public_key_refs[0].clone(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        input: BackendInput::Digest32 {
            digest: digest("d5"),
        },
        deadline_ms: DecimalU64::new(10_000),
    }))
    .unwrap();
    assert_eq!(signature.bytes.decode().len(), 65);

    let registered_root = result.public_key_refs[0].clone();
    drop(service);
    registry.remove_local_wallet_backend(&registered_root);
    assert!(
        registry
            .get(&registered_root.backend, &registered_root.backend_instance)
            .is_err()
    );
    let restarted = SignerCeremonyService::new(
        engine,
        Token::new("signer-ceremony-key").unwrap(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    assert!(!registry.key_is_available(&registered_root).unwrap());
    futures::executor::block_on(registry.activate_key(
        &registered_root,
        SecretBytes::new(authenticator.deterministic_prf().to_vec()),
    ))
    .unwrap();
    assert!(registry.key_is_available(&registered_root).unwrap());
    assert_eq!(
        restarted
            .complete_custody(successful_completion, 3_800)
            .unwrap(),
        result
    );
    let unlock_prepare = restarted
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation("22"),
                wallet_id: Some(registered_wallet_id.clone()),
                key_ref: None,
                exact_terms_digest: digest("90"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
            },
            3_900,
        )
        .unwrap();
    assert_eq!(unlock_prepare.webauthn_options.allowed_credentials.len(), 1);
    restarted.cancel(&operation("22")).unwrap();

    let second = VirtualAuthenticator::generate();
    let add = restarted
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::CredentialAdd,
                custody_operation_id: operation("23"),
                wallet_id: Some(registered_wallet_id.clone()),
                key_ref: None,
                exact_terms_digest: digest("91"),
                expected_input_class: Token::new("credential-change-prfs").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
            },
            4_000,
        )
        .unwrap();
    let authority_assertion =
        authenticator.assertion(&add.challenges[0].canonical_bytes().unwrap(), 2);
    let new_attestation = second.attestation(&add.challenges[1].canonical_bytes().unwrap());
    let new_prf_assertion = second.assertion(&add.challenges[2].canonical_bytes().unwrap(), 1);
    let add_aad = CustodyHpkeAad {
        ceremony_id: add.contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::CredentialAdd,
        custody_operation_id: operation("23"),
        signer_nonce: add.contribution.signer_nonce.clone(),
        signer_contribution_digest: add.contribution.digest().unwrap(),
        wallet_id: Some(registered_wallet_id.clone()),
        key_ref: None,
        credential_id: Some(new_attestation.credential_id.clone()),
        expected_input_class: Token::new("credential-change-prfs").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let add_plaintext = serde_jcs::to_vec(&serde_json::json!({
        "authority_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
        "new_credential_prf": Base64UrlBytes::from_bytes(&second.deterministic_prf())
    }))
    .unwrap();
    let add_envelope = seal_hpke(
        &add.contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &add_aad,
        &add_plaintext,
    )
    .unwrap();
    restarted
        .complete_custody(
            CustodyCompleteRequest {
                ceremony_kind: CeremonyKind::CredentialAdd,
                custody_operation_id: operation("23"),
                ceremony_id: add.contribution.ceremony_id,
                proof: WebAuthnCeremonyProof::AuthorityCredentialChange {
                    authority_assertion,
                    new_credential_attestation: new_attestation,
                    new_credential_prf_assertion: Some(new_prf_assertion),
                },
                encrypted_input: Some(add_envelope),
                public_binding_digest: digest("91"),
            },
            4_100,
        )
        .unwrap();
    let after_add = restarted
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletDelete,
                custody_operation_id: operation("24"),
                wallet_id: Some(registered_wallet_id),
                key_ref: None,
                exact_terms_digest: digest("92"),
                expected_input_class: Token::new("policy-document").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
            },
            4_200,
        )
        .unwrap();
    assert_eq!(after_add.webauthn_options.allowed_credentials.len(), 2);
}

#[test]
fn registration_returns_signed_public_projection_and_enables_one_time_recovery() {
    let authenticator = VirtualAuthenticator::generate();
    let replacement = VirtualAuthenticator::generate();
    let (service, _, _, _) = service(&authenticator);
    let output_recipient = HpkeRecipient::generate();
    let registration_operation = operation("a8");
    let (result, contribution) = complete_new_wallet(
        &service,
        &authenticator,
        CeremonyKind::WalletRegistration,
        registration_operation.clone(),
        None,
        Some(&output_recipient),
        5_000,
    );
    let wallet_id = result.wallet_id.clone().unwrap();
    assert_eq!(result.public_status, CeremonyState::Completed);
    assert_eq!(result.credential_summaries.len(), 1);
    assert_eq!(
        result.credential_summaries[0].credential_id,
        authenticator.credential(0).credential_id
    );
    let signature =
        ed25519_dalek::Signature::from_slice(&result.signer_signature.decode()).unwrap();
    ed25519_dalek::Verifier::verify(
        &SigningKey::from_bytes(&[9; 32]).verifying_key(),
        &[
            b"bloom-signer-ceremony-receipt/v1".as_slice(),
            &result.unsigned_canonical_bytes().unwrap(),
        ]
        .concat(),
        &signature,
    )
    .unwrap();

    let output_aad = CustodyOutputHpkeAad {
        ceremony_id: contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: registration_operation,
        signer_contribution_digest: contribution.digest().unwrap(),
        public_binding_digest: digest("d1"),
    }
    .canonical_bytes()
    .unwrap();
    let recovery_plaintext = output_recipient
        .open(
            result.encrypted_browser_result.as_ref().unwrap(),
            CUSTODY_OUTPUT_INFO,
            &output_aad,
        )
        .unwrap();
    let recovery: serde_json::Value =
        serde_json::from_slice(recovery_plaintext.expose_to_backend()).unwrap();

    let recovery_operation = operation("a9");
    let recovery_prepared = service
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletRecovery,
                custody_operation_id: recovery_operation.clone(),
                wallet_id: Some(wallet_id.clone()),
                key_ref: None,
                exact_terms_digest: digest("d2"),
                expected_input_class: Token::new("recovery-factor-v1").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
            },
            6_000,
        )
        .unwrap();
    let attestation =
        replacement.attestation(&recovery_prepared.challenges[0].canonical_bytes().unwrap());
    let prf_assertion = replacement.assertion(
        &recovery_prepared.challenges[1].canonical_bytes().unwrap(),
        1,
    );
    let recovery_input = serde_jcs::to_vec(&serde_json::json!({
        "recovery_id": recovery["recovery_id"],
        "recovery_secret": recovery["recovery_secret"],
        "new_credential_prf": Base64UrlBytes::from_bytes(&replacement.deterministic_prf()),
    }))
    .unwrap();
    let aad = CustodyHpkeAad {
        ceremony_id: recovery_prepared.contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletRecovery,
        custody_operation_id: recovery_operation.clone(),
        signer_nonce: recovery_prepared.contribution.signer_nonce.clone(),
        signer_contribution_digest: recovery_prepared.contribution.digest().unwrap(),
        wallet_id: Some(wallet_id.clone()),
        key_ref: None,
        credential_id: Some(attestation.credential_id.clone()),
        expected_input_class: Token::new("recovery-factor-v1").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
    let encrypted_input = seal_hpke(
        &recovery_prepared.contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        &recovery_input,
    )
    .unwrap();
    service
        .complete_custody(
            CustodyCompleteRequest {
                ceremony_kind: CeremonyKind::WalletRecovery,
                custody_operation_id: recovery_operation,
                ceremony_id: recovery_prepared.contribution.ceremony_id,
                proof: WebAuthnCeremonyProof::RecoveryCredentialChange {
                    new_credential_attestation: attestation,
                    new_credential_prf_assertion: Some(prf_assertion),
                },
                encrypted_input: Some(encrypted_input),
                public_binding_digest: digest("d2"),
            },
            6_100,
        )
        .unwrap();
    assert!(
        service
            .credential(&wallet_id, &replacement.credential(0).credential_id)
            .is_ok()
    );
    let forged_registration = service
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletRegistration,
                custody_operation_id: operation("ad"),
                wallet_id: None,
                key_ref: Some(result.public_key_refs[0].clone()),
                exact_terms_digest: digest("d3"),
                expected_input_class: Token::new("passkey-prf").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
            },
            7_000,
        )
        .unwrap_err();
    assert_eq!(forged_registration.code, ProtocolErrorCode::KeyrefMismatch);
}

#[test]
fn raw_private_key_import_creates_a_new_wallet_and_first_passkey() {
    let authenticator = VirtualAuthenticator::generate();
    let (service, _, _, registry) = service(&authenticator);
    let raw_private_key = [0x42; 32];
    let (result, _) = complete_new_wallet(
        &service,
        &authenticator,
        CeremonyKind::WalletImport,
        operation("aa"),
        Some(&raw_private_key),
        None,
        7_000,
    );
    let wallet_id = result.wallet_id.unwrap();
    assert_eq!(result.public_key_refs.len(), 1);
    assert_eq!(result.public_key_refs[0].backend_instance, wallet_id);
    let imported_signing_key = k256::ecdsa::SigningKey::from_slice(&raw_private_key).unwrap();
    let imported_public_key = k256::PublicKey::from_sec1_bytes(
        imported_signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
    .unwrap();
    let expected_fingerprint = Digest32::from_bytes(
        sha2::Sha256::digest(imported_public_key.to_public_key_der().unwrap().as_bytes()).into(),
    );
    assert_eq!(
        result.public_key_refs[0].public_key_fingerprint,
        expected_fingerprint
    );
    assert!(
        registry
            .key_is_available(&result.public_key_refs[0])
            .unwrap()
    );
    assert_eq!(result.credential_summaries.len(), 1);
    assert_eq!(
        service
            .credential(&wallet_id, &authenticator.credential(0).credential_id)
            .unwrap()
            .credential_id,
        authenticator.credential(0).credential_id
    );
}

#[test]
fn restart_tombstones_a_derived_key_allocated_before_custody_commit() {
    let authority_key = SigningKey::from_bytes(&[5; 32]);
    let backend = Arc::new(
        LocalSignerBackend::provision(
            Token::new("local-reconcile").unwrap(),
            Token::new("root-reconcile").unwrap(),
            SecretBytes::new((0_u8..16).collect()),
            SecretBytes::new(vec![3; 32]),
            authority_key.verifying_key(),
        )
        .unwrap(),
    );
    let root = backend.root_key_ref().unwrap();
    let namespace = Token::new("ethereum-reconcile").unwrap();
    let grant = DerivationGrant {
        authority_kind: Token::new("ceremony").unwrap(),
        namespace_id: namespace.clone(),
        canonical_prefix: "m/44'/60'/7'/0".into(),
        starting_index: DecimalU64::new(0),
        maximum_children: DecimalU64::new(2),
    };
    let mut message = b"bloom-key-derive-authority/v1".to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&grant).unwrap());
    let authority = DerivationAuthority::from_signed(
        grant,
        Base64UrlBytes::from_bytes(&authority_key.sign(&message).to_bytes()),
    );
    backend.configure_namespace(&authority).unwrap();
    let interrupted_operation = operation("ab");
    let interrupted_key = backend
        .allocate_derived_key_for_operation(&root, &namespace, &authority, &interrupted_operation)
        .unwrap()
        .key_ref;
    assert_eq!(backend.pending_derivations().len(), 1);

    let registry = Arc::new(
        BackendRegistry::from_compiled(vec![CompiledBackend::Local(backend.clone())]).unwrap(),
    );
    let engine = Arc::new(
        SignerEngine::open_in_memory(
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            registry.clone(),
        )
        .unwrap(),
    );
    SignerCeremonyService::new(
        engine.clone(),
        Token::new("signer-ceremony-key").unwrap(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();

    assert!(backend.pending_derivations().is_empty());
    assert!(!registry.key_is_registered(&interrupted_key).unwrap());
    let next = backend
        .allocate_derived_key(&root, &namespace, &authority)
        .unwrap();
    assert_ne!(next.key_ref, interrupted_key);
}

#[test]
fn generic_custody_export_policy_and_delete_apply_exact_typed_effects() {
    let authenticator = VirtualAuthenticator::generate();
    let (service, _, engine, _) = service(&authenticator);
    let (wallet_id, credential) = register_wallet(&service, &authenticator, operation("b0"), 5_000);

    let export_effect = serde_json::json!({"kind": "wallet_export"});
    let export_binding = Digest32::from_bytes(
        sha2::Sha256::digest(serde_jcs::to_vec(&export_effect).unwrap()).into(),
    );
    let output_recipient = HpkeRecipient::generate();
    let (export_result, export_contribution) = complete_generic(
        &service,
        &authenticator,
        &wallet_id,
        (CeremonyKind::WalletExport, operation("b1"), export_effect),
        Some(&output_recipient),
        6_000,
    )
    .unwrap();
    let output_aad = CustodyOutputHpkeAad {
        ceremony_id: export_contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletExport,
        custody_operation_id: operation("b1"),
        signer_contribution_digest: export_contribution.digest().unwrap(),
        public_binding_digest: export_binding,
    }
    .canonical_bytes()
    .unwrap();
    let exported = output_recipient
        .open(
            export_result.encrypted_browser_result.as_ref().unwrap(),
            CUSTODY_OUTPUT_INFO,
            &output_aad,
        )
        .unwrap();
    let bundle: serde_json::Value = serde_json::from_slice(exported.expose_to_backend()).unwrap();
    assert_eq!(bundle["wallet"]["wallet_id"], wallet_id.as_str());
    assert_eq!(bundle["credentials"].as_array().unwrap().len(), 1);

    let baseline_snapshot = engine.policy_snapshot(&wallet_id).unwrap();
    let mut proposed_policy: CanonicalWalletPolicy =
        serde_json::from_slice(&baseline_snapshot.canonical_policy.decode()).unwrap();
    proposed_policy.maximum_approval_lifetime_ms += 1;
    let proposed = Base64UrlBytes::from_bytes(&serde_jcs::to_vec(&proposed_policy).unwrap());
    let policy_operation = operation("b3");
    let update = PolicyUpdateRequest {
        operation_id: policy_operation,
        wallet_id: wallet_id.clone(),
        baseline_version: DecimalU64::new(1),
        baseline_digest: baseline_snapshot.policy_digest,
        proposed_canonical_policy: proposed.clone(),
        proposed_policy_digest: Digest32::from_bytes(
            sha2::Sha256::digest(proposed.decode()).into(),
        ),
        authority_diff_digest: digest("c1"),
        assurance_level: Token::new("user_verified").unwrap(),
    };
    let (policy_result, prepared) =
        complete_policy_update(&service, &authenticator, &wallet_id, update, 8_000).unwrap();
    assert_eq!(policy_result.public_status, CeremonyState::Succeeded);
    assert!(policy_result.encrypted_browser_result.is_none());
    assert_eq!(engine.policy_snapshot(&wallet_id).unwrap().version.get(), 1);
    let compare = PolicyCompareAndSwapRequest {
        update: prepared.update,
        ceremony_receipt: policy_result,
        broker_validation_receipt: prepared.broker_validation_receipt,
    };
    let mut altered = Vec::new();
    let mut changed = compare.clone();
    changed.update.baseline_version = DecimalU64::new(2);
    altered.push(changed);
    let mut changed = compare.clone();
    changed.update.baseline_digest = digest("c2");
    altered.push(changed);
    let mut changed = compare.clone();
    changed.update.proposed_canonical_policy = Base64UrlBytes::from_bytes(br#"{"version":3}"#);
    altered.push(changed);
    let mut changed = compare.clone();
    changed.update.proposed_policy_digest = digest("c4");
    altered.push(changed);
    let mut changed = compare.clone();
    changed.update.authority_diff_digest = digest("c5");
    altered.push(changed);
    let mut changed = compare.clone();
    changed.update.assurance_level = Token::new("machine_asserted").unwrap();
    altered.push(changed);
    let mut changed = compare.clone();
    changed.ceremony_receipt.receipt_digest = digest("c6");
    altered.push(changed);
    let mut changed = compare.clone();
    changed.broker_validation_receipt.review_manifest_digest = digest("c7");
    altered.push(changed);
    for changed in altered {
        assert!(
            engine.compare_and_swap_policy(&changed).is_err(),
            "every altered policy, baseline, receipt, and review binding must fail"
        );
    }
    let receipt = engine.compare_and_swap_policy(&compare).unwrap();
    assert_eq!(receipt.committed.version.get(), 2);
    assert_eq!(
        engine.policy_snapshot(&wallet_id).unwrap(),
        receipt.committed
    );
    assert_eq!(
        engine.compare_and_swap_policy(&compare).unwrap(),
        receipt,
        "same-operation replay returns the identical commit receipt"
    );

    let mismatch = complete_generic(
        &service,
        &authenticator,
        &wallet_id,
        (
            CeremonyKind::WalletDelete,
            operation("b4"),
            serde_json::json!({"kind": "wallet_export"}),
        ),
        None,
        9_000,
    )
    .unwrap_err();
    assert_eq!(mismatch.code, ProtocolErrorCode::CeremonyKindMismatch);
    assert!(
        service
            .credential(&wallet_id, &credential.credential_id)
            .is_ok()
    );

    complete_generic(
        &service,
        &authenticator,
        &wallet_id,
        (
            CeremonyKind::WalletDelete,
            operation("b5"),
            serde_json::json!({"kind": "wallet_delete"}),
        ),
        None,
        10_000,
    )
    .unwrap();
    assert!(
        service
            .credential(&wallet_id, &credential.credential_id)
            .is_err()
    );
}
