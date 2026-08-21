use bloom_signer::clock::{ClockCondition, ClockDecision};
use bloom_signer::custody::WalletCustody;
use bloom_signer::engine::{
    ApprovalCounterBackup, BackendEnrollmentBackup, SignAuthorization, SignerAuditKeys,
    SignerBackupSet, SignerEngine, SignerOperationEffect, WalletDerivationStatus,
};
use bloom_signer::registry::{BackendRegistry, CompiledBackend};
use bloom_signer_api::*;
use bloom_signer_backend_api::{SecretBytes, SignerBackendActivation};
use bloom_signer_backend_local::LocalSignerBackend;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, sync::Arc};

fn audit_keys() -> SignerAuditKeys {
    SignerAuditKeys {
        current_key_id: Token::new("signer-audit-key").unwrap(),
        current_signing_key: SigningKey::from_bytes(&[14; 32]),
        historical_verifying_keys: BTreeMap::new(),
    }
}

fn digest(byte: &str) -> Digest32 {
    Digest32::new(byte.repeat(32)).unwrap()
}

fn clock(effective_now_ms: u64) -> ClockDecision {
    ClockDecision {
        effective_now_ms,
        condition: ClockCondition::Healthy,
        observed_utc_ms: Some(effective_now_ms),
        monotonic_anchor_ns: 1_000_000,
        boot_epoch: BootEpoch::from_bytes([1; 16]),
    }
}

fn key_ref() -> KeyRef {
    local_backend().root_key_ref().unwrap()
}

fn local_backend() -> Arc<LocalSignerBackend> {
    Arc::new(
        LocalSignerBackend::provision_imported_secp256k1(
            Token::new("local-default").unwrap(),
            Token::new("root-1").unwrap(),
            SecretBytes::new((0_u8..32).collect()),
            SecretBytes::new(vec![7; 32]),
            SigningKey::from_bytes(&[5; 32]).verifying_key(),
        )
        .unwrap(),
    )
}

fn exact_terms() -> SealedApprovalTerms {
    SealedApprovalTerms {
        subject: ApprovalSubject::Cli {
            client_id: Token::new("bloom-cli").unwrap(),
            command_class: Token::new("wallet.sign").unwrap(),
        },
        wallet_id: Token::new("wallet-1").unwrap(),
        key_ref: key_ref(),
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Sha256Recoverable],
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
        wallet_revocation_epoch: DecimalU64::new(7),
        policy_version: DecimalU64::new(3),
        policy_digest: digest("44"),
        provenance_digest: digest("55"),
        request_nonce: RequestNonce::new("66".repeat(16)).unwrap(),
        issued_at_ms: DecimalU64::new(1_000),
        not_before_ms: DecimalU64::new(1_000),
        expires_at_ms: DecimalU64::new(10_000),
        renewal_of: None,
    }
}

fn petal_terms() -> SealedApprovalTerms {
    let mut terms = exact_terms();
    terms.subject = ApprovalSubject::Petal {
        package_hash: digest("77"),
        route: "/sign".into(),
        agent_id: None,
    };
    terms.selector = ApprovalSelector::Petal {
        package_hash: digest("77"),
        route: "/sign".into(),
        allowed_operation_classes: vec![Token::new("transfer").unwrap()],
        required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
    };
    terms
}

fn new_engine(broker: &SigningKey) -> SignerEngine {
    let registry = Arc::new(
        BackendRegistry::from_compiled(vec![CompiledBackend::Local(local_backend())]).unwrap(),
    );
    let engine = SignerEngine::open_in_memory(
        Token::new("broker-app-1").unwrap(),
        broker.verifying_key(),
        SigningKey::from_bytes(&[6; 32]).verifying_key(),
        Token::new("signer-revocation-key").unwrap(),
        SigningKey::from_bytes(&[4; 32]),
        audit_keys(),
        registry,
    )
    .unwrap();
    engine.enroll_key(&key_ref()).unwrap();
    engine
}

fn unsigned_request(terms: &SealedApprovalTerms, operation_byte: &str) -> UnsignedSignRequest {
    let (payloads, hashes, selector_kind) = match &terms.selector {
        ApprovalSelector::Exact {
            ordered_payload_digests,
            ordered_hashes,
        } => (
            ordered_payload_digests.clone(),
            ordered_hashes.clone(),
            SelectorKind::Exact,
        ),
        ApprovalSelector::Petal { .. } => {
            (vec![digest("22")], vec![digest("33")], SelectorKind::Petal)
        }
    };
    let claim_digest =
        matches!(&terms.selector, ApprovalSelector::Petal { .. }).then(|| digest("ab"));
    let assurance_digest =
        matches!(&terms.selector, ApprovalSelector::Petal { .. }).then(|| digest("ac"));
    let identity = SignOperationIdentity {
        operation_id: OperationId::new(operation_byte.repeat(32)).unwrap(),
        approval_id: terms.approval_id().unwrap(),
        key_ref: terms.key_ref.clone(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        ordered_payload_digests: payloads.clone(),
        ordered_hashes: hashes.clone(),
        petal_use_claim_digest: claim_digest.clone(),
        claim_assurance_digest: assurance_digest.clone(),
        policy_version: terms.policy_version.clone(),
        policy_digest: terms.policy_digest.clone(),
    };
    let mut request = UnsignedSignRequest {
        schema: Token::new("bloom.sign-request/1").unwrap(),
        attempt_id: digest("88"),
        operation_id: identity.operation_id.clone(),
        operation_digest: identity.digest().unwrap(),
        attempt_digest: digest("00"),
        audience: Token::new("bloom-signer").unwrap(),
        issuer_service_id: Token::new("bloom-broker").unwrap(),
        issuer_boot_epoch: BootEpoch::new("99".repeat(16)).unwrap(),
        broker_signing_key_id: Token::new("broker-app-1").unwrap(),
        approval_id: identity.approval_id,
        wallet_id: terms.wallet_id.clone(),
        key_ref: identity.key_ref,
        crypto_suite: identity.crypto_suite,
        selector_kind,
        ordered_payload_digests: payloads,
        ordered_hashes: hashes.clone(),
        signature_count: DecimalU64::new(hashes.len() as u64),
        petal_use_claim_digest: claim_digest,
        claim_assurance_digest: assurance_digest,
        policy_version: terms.policy_version.clone(),
        policy_digest: terms.policy_digest.clone(),
        validation_receipt_digest: digest("aa"),
        issued_at_ms: DecimalU64::new(2_000),
        not_before_ms: DecimalU64::new(2_000),
        expires_at_ms: DecimalU64::new(3_000),
    };
    request.attempt_digest = request.computed_attempt_digest().unwrap();
    request
}

fn signed(broker: &SigningKey, unsigned: UnsignedSignRequest) -> SignRequest {
    SignRequest {
        broker_signature: Base64UrlBytes::from_bytes(
            &broker
                .sign(&hex::decode(unsigned.attempt_digest.as_str()).unwrap())
                .to_bytes(),
        ),
        unsigned,
    }
}

fn resign(broker: &SigningKey, request: &mut SignRequest) {
    request.unsigned.operation_digest = request.unsigned.operation_identity().digest().unwrap();
    request.unsigned.attempt_digest = digest("00");
    request.unsigned.attempt_digest = request.unsigned.computed_attempt_digest().unwrap();
    request.broker_signature = Base64UrlBytes::from_bytes(
        &broker
            .sign(&hex::decode(request.unsigned.attempt_digest.as_str()).unwrap())
            .to_bytes(),
    );
}

#[test]
fn ac11_replay_retry_revocation_and_structural_failures_are_closed() {
    let broker = SigningKey::from_bytes(&[7; 32]);
    let mut terms = exact_terms();
    terms.limits.operation_rate_limits = vec![SlidingWindow {
        maximum: DecimalU64::new(1),
        duration_ms: DecimalU64::new(10_000),
    }];
    terms.limits.signature_rate_limits = vec![SlidingWindow {
        maximum: DecimalU64::new(1),
        duration_ms: DecimalU64::new(10_000),
    }];
    let engine = new_engine(&broker);
    let approval_id = engine.install_approval_for_test(&terms).unwrap();
    let request = signed(&broker, unsigned_request(&terms, "01"));
    assert_eq!(
        engine.authorize_sign(&request, &clock(2_500)).unwrap(),
        SignAuthorization::NewOperation
    );
    assert_eq!(
        engine
            .authorize_sign(&request, &clock(2_500))
            .unwrap_err()
            .code,
        ProtocolErrorCode::CeremonyReplay
    );

    let mut retry = request.clone();
    retry.unsigned.attempt_id = digest("89");
    retry.unsigned.issuer_boot_epoch = BootEpoch::new("98".repeat(16)).unwrap();
    retry.unsigned.expires_at_ms = DecimalU64::new(3_100);
    resign(&broker, &mut retry);
    assert_eq!(
        engine.authorize_sign(&retry, &clock(2_500)).unwrap(),
        SignAuthorization::SameOperationRetry
    );

    let revoke_operation = OperationId::new("f1".repeat(32)).unwrap();
    let tombstone = engine
        .revoke_approval(
            &approval_id,
            "operator panic revoke".into(),
            revoke_operation.clone(),
            2_600,
        )
        .unwrap();
    assert_eq!(tombstone.issuer_service_id.as_str(), "bloom-signer");
    assert_eq!(
        engine
            .revoke_approval(
                &approval_id,
                "operator panic revoke".into(),
                revoke_operation.clone(),
                2_600,
            )
            .unwrap(),
        tombstone
    );
    assert_eq!(
        engine
            .revoke_approval(
                &approval_id,
                "changed reason".into(),
                revoke_operation,
                2_600,
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::OperationIdConflict
    );
    let mut after_revoke = retry;
    after_revoke.unsigned.attempt_id = digest("8a");
    resign(&broker, &mut after_revoke);
    assert_eq!(
        engine
            .authorize_sign(&after_revoke, &clock(2_500))
            .unwrap_err()
            .code,
        ProtocolErrorCode::ApprovalRevoked
    );
}

#[test]
fn ac11_forged_expired_wrong_key_unsupported_and_excessive_requests_fail() {
    let broker = SigningKey::from_bytes(&[7; 32]);
    let terms = exact_terms();

    let engine = new_engine(&broker);
    engine.install_approval_for_test(&terms).unwrap();
    let mut forged = signed(&broker, unsigned_request(&terms, "02"));
    forged.broker_signature = Base64UrlBytes::from_bytes(&[0; 64]);
    assert_eq!(
        engine
            .authorize_sign(&forged, &clock(2_500))
            .unwrap_err()
            .code,
        ProtocolErrorCode::UnauthenticatedPeer
    );

    let engine = new_engine(&broker);
    engine.install_approval_for_test(&terms).unwrap();
    let expired = signed(&broker, unsigned_request(&terms, "03"));
    assert_eq!(
        engine
            .authorize_sign(&expired, &clock(3_001))
            .unwrap_err()
            .code,
        ProtocolErrorCode::ApprovalExpired
    );

    let engine = new_engine(&broker);
    engine.install_approval_for_test(&terms).unwrap();
    let mut wrong_key = signed(&broker, unsigned_request(&terms, "04"));
    wrong_key.unsigned.key_ref.locator = "other-key".into();
    resign(&broker, &mut wrong_key);
    assert_eq!(
        engine
            .authorize_sign(&wrong_key, &clock(2_500))
            .unwrap_err()
            .code,
        ProtocolErrorCode::KeyrefMismatch
    );

    let engine = new_engine(&broker);
    engine.install_approval_for_test(&terms).unwrap();
    let mut unsupported = signed(&broker, unsigned_request(&terms, "05"));
    unsupported.unsigned.crypto_suite = CryptoSuite::Secp256k1Keccak256Recoverable;
    resign(&broker, &mut unsupported);
    assert_eq!(
        engine
            .authorize_sign(&unsupported, &clock(2_500))
            .unwrap_err()
            .code,
        ProtocolErrorCode::SuiteNotAllowed
    );

    let petal = petal_terms();
    let engine = new_engine(&broker);
    engine.install_approval_for_test(&petal).unwrap();
    let mut excessive = signed(&broker, unsigned_request(&petal, "06"));
    excessive
        .unsigned
        .ordered_payload_digests
        .push(digest("23"));
    excessive.unsigned.ordered_hashes.push(digest("34"));
    excessive.unsigned.signature_count = DecimalU64::new(2);
    resign(&broker, &mut excessive);
    assert_eq!(
        engine
            .authorize_sign(&excessive, &clock(2_500))
            .unwrap_err()
            .code,
        ProtocolErrorCode::LimitExceededSignatures
    );
}

#[test]
fn ac11_approval_ceiling_selector_issuer_key_state_retry_and_release_are_closed() {
    let broker = SigningKey::from_bytes(&[7; 32]);

    let mut too_long = exact_terms();
    too_long.expires_at_ms =
        DecimalU64::new(too_long.not_before_ms.get() + 90 * 24 * 60 * 60 * 1_000 + 1);
    let engine = new_engine(&broker);
    assert_eq!(
        engine
            .install_approval_for_test(&too_long)
            .unwrap_err()
            .code,
        ProtocolErrorCode::ApprovalExpired
    );

    let mut terms = exact_terms();
    terms.limits.operation_rate_limits = vec![SlidingWindow {
        maximum: DecimalU64::new(1),
        duration_ms: DecimalU64::new(10_000),
    }];
    terms.limits.signature_rate_limits = vec![SlidingWindow {
        maximum: DecimalU64::new(1),
        duration_ms: DecimalU64::new(10_000),
    }];
    let engine = new_engine(&broker);
    engine.install_approval_for_test(&terms).unwrap();
    let mut wrong_issuer = signed(&broker, unsigned_request(&terms, "0a"));
    wrong_issuer.unsigned.issuer_service_id = Token::new("machine").unwrap();
    resign(&broker, &mut wrong_issuer);
    assert_eq!(
        engine
            .authorize_sign(&wrong_issuer, &clock(2_500))
            .unwrap_err()
            .code,
        ProtocolErrorCode::UnauthenticatedPeer
    );

    let mut wrong_selector = signed(&broker, unsigned_request(&terms, "0b"));
    wrong_selector.unsigned.selector_kind = SelectorKind::Petal;
    wrong_selector.unsigned.petal_use_claim_digest = Some(digest("ab"));
    wrong_selector.unsigned.claim_assurance_digest = Some(digest("ac"));
    resign(&broker, &mut wrong_selector);
    assert_eq!(
        engine
            .authorize_sign(&wrong_selector, &clock(2_500))
            .unwrap_err()
            .code,
        ProtocolErrorCode::SelectorMismatch
    );

    let inactive_backend = local_backend();
    futures::executor::block_on(inactive_backend.deactivate(&terms.key_ref)).unwrap();
    let inactive_engine = SignerEngine::open_in_memory(
        Token::new("broker-app-1").unwrap(),
        broker.verifying_key(),
        SigningKey::from_bytes(&[6; 32]).verifying_key(),
        Token::new("signer-revocation-key").unwrap(),
        SigningKey::from_bytes(&[4; 32]),
        audit_keys(),
        Arc::new(
            BackendRegistry::from_compiled(vec![CompiledBackend::Local(inactive_backend)]).unwrap(),
        ),
    )
    .unwrap();
    inactive_engine.enroll_key(&terms.key_ref).unwrap();
    inactive_engine.install_approval_for_test(&terms).unwrap();
    let inactive = signed(&broker, unsigned_request(&terms, "0c"));
    assert_eq!(
        inactive_engine
            .authorize_sign(&inactive, &clock(2_500))
            .unwrap_err()
            .code,
        ProtocolErrorCode::KeyrefMismatch
    );

    let accepted = signed(&broker, unsigned_request(&terms, "0d"));
    engine.authorize_sign(&accepted, &clock(2_500)).unwrap();
    let mut drifted = accepted.clone();
    drifted.unsigned.attempt_id = digest("8b");
    drifted.unsigned.validation_receipt_digest = digest("ad");
    resign(&broker, &mut drifted);
    assert_eq!(
        engine
            .authorize_sign(&drifted, &clock(2_500))
            .unwrap_err()
            .code,
        ProtocolErrorCode::OperationIdConflict
    );

    engine
        .finalize_operation(
            &accepted.unsigned.operation_id,
            SignerOperationEffect::Released,
        )
        .unwrap();
    let mut replacement = signed(&broker, unsigned_request(&terms, "0e"));
    replacement.unsigned.attempt_id = digest("8c");
    resign(&broker, &mut replacement);
    assert_eq!(
        engine.authorize_sign(&replacement, &clock(2_500)).unwrap(),
        SignAuthorization::NewOperation
    );
}

#[test]
fn policy_cas_fails_before_a_completed_policy_ceremony() {
    let broker = SigningKey::from_bytes(&[7; 32]);
    let engine = new_engine(&broker);
    let proposed = Base64UrlBytes::from_bytes(br#"{"limit":2}"#);
    let operation_id = OperationId::new("aa".repeat(32)).unwrap();
    let request = PolicyCompareAndSwapRequest {
        update: PolicyUpdateRequest {
            operation_id: operation_id.clone(),
            wallet_id: Token::new("wallet-1").unwrap(),
            baseline_version: DecimalU64::new(1),
            baseline_digest: digest("aa"),
            proposed_policy_digest: Digest32::from_bytes(Sha256::digest(proposed.decode()).into()),
            proposed_canonical_policy: proposed,
            authority_diff_digest: digest("bb"),
            assurance_level: Token::new("user_verified").unwrap(),
        },
        ceremony_receipt: CustodyResult {
            ceremony_kind: CeremonyKind::PolicyUpdate,
            custody_operation_id: operation_id,
            public_status: CeremonyState::Completed,
            wallet_id: Some(Token::new("wallet-1").unwrap()),
            public_key_refs: Vec::new(),
            credential_summaries: Vec::new(),
            initial_policy: None,
            receipt_digest: digest("cc"),
            encrypted_browser_result: None,
            signer_key_id: Token::new("signer-ceremony-key").unwrap(),
            signer_signature: Base64UrlBytes::from_bytes(&[1; 64]),
        },
        broker_validation_receipt: PolicyValidationReceipt {
            update_terms_digest: digest("dd"),
            review_manifest_digest: digest("ee"),
            broker_key_id: Token::new("broker-app-1").unwrap(),
            broker_signature: Base64UrlBytes::from_bytes(&[2; 64]),
        },
    };
    assert_eq!(
        engine.compare_and_swap_policy(&request).unwrap_err().code,
        ProtocolErrorCode::PolicyBaselineStale
    );
}

#[test]
fn ac32_backup_restore_refuses_missing_registry_for_derivation_and_lower_state() {
    let broker = SigningKey::from_bytes(&[7; 32]);
    let terms = exact_terms();
    let engine = new_engine(&broker);
    let approval_id = engine.install_approval_for_test(&terms).unwrap();
    let request = signed(&broker, unsigned_request(&terms, "07"));
    engine.authorize_sign(&request, &clock(2_500)).unwrap();
    let audit_backup = engine
        .export_backup(&terms.wallet_id, None, vec![])
        .unwrap();
    let audit_entries = audit_backup.audit_entries;
    let missing = SignerBackupSet {
        wallet_id: terms.wallet_id.clone(),
        wallet_revocation_epoch: terms.wallet_revocation_epoch.clone(),
        custody: None,
        derivation_registry: None,
        derivation_allocations: vec![],
        backend_enrollments: vec![],
        policy: None,
        petal_key_scopes: vec![],
        approvals: vec![],
        approval_tombstones: vec![],
        wallet_tombstone: None,
        operations: vec![],
        attempts: vec![],
        revocation_operations: vec![],
        approval_counters: vec![ApprovalCounterBackup {
            approval_id: approval_id.clone(),
            committed_operations: DecimalU64::new(1),
            committed_signatures: DecimalU64::new(1),
        }],
        audit_entries,
        audit_rotations: audit_backup.audit_rotations,
        audit_verifying_keys: audit_backup.audit_verifying_keys,
    };
    engine.restore_backup(&missing).unwrap();
    assert_eq!(
        engine.derivation_status(&terms.wallet_id).unwrap(),
        WalletDerivationStatus::DerivationRegistryMissing
    );
    assert!(engine.require_derivation_ready(&terms.wallet_id).is_err());
    let mut lower_epoch = missing.clone();
    lower_epoch.wallet_revocation_epoch = DecimalU64::new(6);
    assert_eq!(
        engine.restore_backup(&lower_epoch).unwrap_err().code,
        ProtocolErrorCode::RevocationEpochUnreconciled
    );
    let mut lower_counter = missing;
    lower_counter.approval_counters[0].committed_operations = DecimalU64::new(0);
    assert_eq!(
        engine.restore_backup(&lower_counter).unwrap_err().code,
        ProtocolErrorCode::RevocationEpochUnreconciled
    );
}

#[test]
fn signed_revocation_state_and_revoke_all_are_monotonic() {
    let broker = SigningKey::from_bytes(&[7; 32]);
    let terms = exact_terms();
    let engine = new_engine(&broker);
    engine.install_approval_for_test(&terms).unwrap();
    let revoke_all_operation = OperationId::new("e1".repeat(32)).unwrap();
    let state = engine
        .revoke_all(&terms.wallet_id, revoke_all_operation.clone(), 2_700)
        .unwrap();
    assert_eq!(state.wallet_revocation_epoch.get(), 8);
    assert!(state.wallet_tombstone.is_some());
    let signature: [u8; 64] = state.signature.decode().try_into().unwrap();
    let mut unsigned = state.clone();
    unsigned.signature = Base64UrlBytes::from_bytes(&[]);
    let mut message = b"bloom-revocation-state/v1".to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&unsigned).unwrap());
    SigningKey::from_bytes(&[4; 32])
        .verifying_key()
        .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&signature))
        .unwrap();
    assert_eq!(
        engine
            .revoke_all(&terms.wallet_id, revoke_all_operation.clone(), 2_700)
            .unwrap(),
        state
    );
    assert_eq!(
        engine
            .revoke_all(&terms.wallet_id, revoke_all_operation, 2_701)
            .unwrap_err()
            .code,
        ProtocolErrorCode::OperationIdConflict
    );

    let next = engine
        .revoke_all(
            &terms.wallet_id,
            OperationId::new("e2".repeat(32)).unwrap(),
            2_800,
        )
        .unwrap();
    assert_eq!(next.wallet_revocation_epoch.get(), 9);
    assert_eq!(
        engine
            .authorize_sign(
                &signed(&broker, unsigned_request(&terms, "0f")),
                &clock(2_500)
            )
            .unwrap_err()
            .code,
        ProtocolErrorCode::ApprovalRevoked
    );
}

#[test]
fn ac32_rotated_audit_export_restore_carries_custody_policy_registry_and_counters() {
    let broker = SigningKey::from_bytes(&[7; 32]);
    let terms = exact_terms();
    let engine = new_engine(&broker);
    engine.install_approval_for_test(&terms).unwrap();
    let custody = WalletCustody::register_imported_secp256k1(
        terms.wallet_id.clone(),
        SecretBytes::new(vec![1; 32]),
        SecretBytes::new(vec![8; 32]),
        SecretBytes::new(vec![2; 32]),
        Base64UrlBytes::from_bytes(b"credential-1"),
        SecretBytes::new(vec![3; 32]),
    )
    .unwrap();
    let unlocked = custody
        .unlock_with_credential(
            &Base64UrlBytes::from_bytes(b"credential-1"),
            &SecretBytes::new(vec![3; 32]),
        )
        .unwrap();
    engine
        .install_initial_policy(
            &terms.wallet_id,
            Base64UrlBytes::from_bytes(br#"{"limit":1}"#),
            Token::new("policy-key-1").unwrap(),
            &unlocked,
        )
        .unwrap();
    let authorized = signed(&broker, unsigned_request(&terms, "09"));
    engine.authorize_sign(&authorized, &clock(2_500)).unwrap();
    engine
        .commit_operation_result(
            &authorized.unsigned.operation_id,
            Base64UrlBytes::from_bytes(b"normalized-signature-result"),
        )
        .unwrap();
    let backup_backend = local_backend();
    let backend_record = backup_backend.encrypted_backup().unwrap();
    let backend_enrollment = BackendEnrollmentBackup {
        backend: Token::new("local").unwrap(),
        backend_instance: Token::new("local-default").unwrap(),
        encrypted_record: Base64UrlBytes::from_bytes(&serde_jcs::to_vec(&backend_record).unwrap()),
        pinned_keys: backend_record
            .pinned_root
            .clone()
            .into_iter()
            .collect::<Vec<_>>(),
    };
    let rotated_audit_key_id = Token::new("signer-audit-key-2").unwrap();
    let rotated_audit_key = SigningKey::from_bytes(&[15; 32]);
    engine
        .rotate_audit_key(rotated_audit_key_id.clone(), rotated_audit_key.clone())
        .unwrap();
    let exported = engine
        .export_backup(
            &terms.wallet_id,
            Some(custody.backup()),
            vec![backend_enrollment],
        )
        .unwrap();
    assert!(
        !exported.audit_entries.is_empty(),
        "normative export must carry the verified Signer audit chain"
    );
    assert_eq!(
        exported.audit_entries.last().unwrap().event_type,
        "custody.export",
        "the returned continuity chain must include its own export event"
    );
    // The imported-scalar fixture has no derivation namespace, so the export
    // carries no derivation registry.
    assert!(exported.derivation_registry.is_none());
    assert!(exported.custody.is_some());
    assert!(exported.policy.is_some());
    assert_eq!(
        exported.operations[0].normalized_result,
        Some(Base64UrlBytes::from_bytes(b"normalized-signature-result"))
    );
    assert_eq!(exported.approval_counters[0].committed_operations.get(), 1);
    assert_eq!(exported.audit_rotations.len(), 1);
    assert_eq!(exported.audit_rotations[0].new_key_id, rotated_audit_key_id);
    let mut legacy_backup_json = serde_json::to_value(&exported).unwrap();
    for operation in legacy_backup_json["operations"].as_array_mut().unwrap() {
        let operation = operation.as_object_mut().unwrap();
        operation.remove("observed_utc_ms");
        operation.remove("monotonic_anchor_ns");
        operation.remove("clock_boot_epoch");
    }
    let legacy_backup: SignerBackupSet = serde_json::from_value(legacy_backup_json).unwrap();
    assert_eq!(legacy_backup.operations[0].observed_utc_ms, None);
    assert_eq!(legacy_backup.operations[0].monotonic_anchor_ns.get(), 0);
    assert_eq!(
        legacy_backup.operations[0].clock_boot_epoch,
        BootEpoch::from_bytes([0; 16])
    );
    let mut stripped_audit_json = serde_json::to_value(&exported).unwrap();
    stripped_audit_json
        .as_object_mut()
        .unwrap()
        .remove("audit_entries");
    assert!(
        serde_json::from_value::<SignerBackupSet>(stripped_audit_json).is_err(),
        "ordinary restore input must not silently omit normative audit continuity"
    );
    let mut stripped_rotations_json = serde_json::to_value(&exported).unwrap();
    stripped_rotations_json
        .as_object_mut()
        .unwrap()
        .remove("audit_rotations");
    assert!(
        serde_json::from_value::<SignerBackupSet>(stripped_rotations_json).is_err(),
        "ordinary restore input must not silently omit audit-key rotation continuity"
    );
    let mut stripped_keys_json = serde_json::to_value(&exported).unwrap();
    stripped_keys_json
        .as_object_mut()
        .unwrap()
        .remove("audit_verifying_keys");
    assert!(
        serde_json::from_value::<SignerBackupSet>(stripped_keys_json).is_err(),
        "ordinary restore input must not omit pinned audit verification keys"
    );

    let restored_backend = Arc::new(
        exported
            .restore_local_backend(&Token::new("local-default").unwrap())
            .unwrap(),
    );
    futures::executor::block_on(
        restored_backend.activate(&terms.key_ref, SecretBytes::new(vec![7; 32])),
    )
    .unwrap();
    let mut historical_audit_keys = BTreeMap::new();
    historical_audit_keys.insert(
        Token::new("signer-audit-key").unwrap(),
        SigningKey::from_bytes(&[14; 32]).verifying_key(),
    );
    let restored = SignerEngine::open_in_memory(
        Token::new("broker-app-1").unwrap(),
        broker.verifying_key(),
        SigningKey::from_bytes(&[6; 32]).verifying_key(),
        Token::new("signer-revocation-key").unwrap(),
        SigningKey::from_bytes(&[4; 32]),
        SignerAuditKeys {
            current_key_id: rotated_audit_key_id,
            current_signing_key: rotated_audit_key,
            historical_verifying_keys: historical_audit_keys,
        },
        Arc::new(
            BackendRegistry::from_compiled(vec![CompiledBackend::Local(restored_backend)]).unwrap(),
        ),
    )
    .unwrap();
    let mut corrupt_audit = exported.clone();
    corrupt_audit.audit_entries[0].payload_jcs = "{}".into();
    assert_eq!(
        restored.restore_backup(&corrupt_audit).unwrap_err().code,
        ProtocolErrorCode::MalformedFrame
    );
    let mut duplicate_rotation = exported.clone();
    duplicate_rotation
        .audit_rotations
        .push(duplicate_rotation.audit_rotations[0].clone());
    assert_eq!(
        restored
            .restore_backup(&duplicate_rotation)
            .unwrap_err()
            .code,
        ProtocolErrorCode::MalformedFrame
    );
    let mut duplicate_transition = exported.clone();
    let mut repeated = duplicate_transition.audit_rotations[0].clone();
    repeated.first_new_sequence =
        DecimalU64::new(repeated.first_new_sequence.get().checked_add(10).unwrap());
    duplicate_transition.audit_rotations.push(repeated);
    assert_eq!(
        restored
            .restore_backup(&duplicate_transition)
            .unwrap_err()
            .code,
        ProtocolErrorCode::MalformedFrame
    );
    let mut tampered_rotation = exported.clone();
    tampered_rotation.audit_rotations[0].old_key_signature = Base64UrlBytes::from_bytes(&[0; 64]);
    assert_eq!(
        restored
            .restore_backup(&tampered_rotation)
            .unwrap_err()
            .code,
        ProtocolErrorCode::MalformedFrame
    );
    let mut missing_key_pin = exported.clone();
    missing_key_pin
        .audit_verifying_keys
        .retain(|key| key.key_id.as_str() != "signer-audit-key");
    assert_eq!(
        restored.restore_backup(&missing_key_pin).unwrap_err().code,
        ProtocolErrorCode::UnauthenticatedPeer
    );
    let mut substituted_key_pin = exported.clone();
    substituted_key_pin.audit_verifying_keys[0].verifying_key =
        Base64UrlBytes::from_bytes(&SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes());
    assert_eq!(
        restored
            .restore_backup(&substituted_key_pin)
            .unwrap_err()
            .code,
        ProtocolErrorCode::UnauthenticatedPeer
    );
    restored.restore_backup(&legacy_backup).unwrap();
    assert_eq!(
        restored.restore_backup(&exported).unwrap_err().code,
        ProtocolErrorCode::RevocationEpochUnreconciled,
        "restore must refuse an audit chain behind the durable import event"
    );
    let round_trip = restored
        .export_backup(
            &terms.wallet_id,
            exported.custody.clone(),
            exported.backend_enrollments.clone(),
        )
        .unwrap();
    assert_eq!(round_trip.approval_counters, exported.approval_counters);
    assert_eq!(round_trip.operations[0].monotonic_anchor_ns.get(), 0);
    assert_eq!(
        restored.derivation_status(&terms.wallet_id).unwrap(),
        WalletDerivationStatus::DerivationRegistryMissing
    );
    let mut retry = signed(&broker, unsigned_request(&terms, "09"));
    retry.unsigned.attempt_id = digest("8d");
    retry.unsigned.issuer_boot_epoch = BootEpoch::new("97".repeat(16)).unwrap();
    resign(&broker, &mut retry);
    assert_eq!(
        restored.authorize_sign(&retry, &clock(2_500)).unwrap(),
        SignAuthorization::SameOperationRetry
    );
    assert_eq!(
        restored
            .stored_operation_result(&retry.unsigned.operation_id)
            .unwrap(),
        Some(Base64UrlBytes::from_bytes(b"normalized-signature-result"))
    );
}

#[test]
fn backend_registry_accepts_only_compiled_variants() {
    let local = Arc::new(
        LocalSignerBackend::provision_imported_secp256k1(
            Token::new("local-default").unwrap(),
            Token::new("root-1").unwrap(),
            SecretBytes::new((0_u8..32).collect()),
            SecretBytes::new(vec![7; 32]),
            SigningKey::from_bytes(&[5; 32]).verifying_key(),
        )
        .unwrap(),
    );
    let other = Arc::new(
        LocalSignerBackend::provision_imported_secp256k1(
            Token::new("local-secondary").unwrap(),
            Token::new("root-2").unwrap(),
            SecretBytes::new((16_u8..48).collect()),
            SecretBytes::new(vec![8; 32]),
            SigningKey::from_bytes(&[5; 32]).verifying_key(),
        )
        .unwrap(),
    );
    let registry = BackendRegistry::from_compiled(vec![
        CompiledBackend::Local(local),
        CompiledBackend::Local(other),
    ])
    .unwrap();
    assert_eq!(registry.capabilities().len(), 2);
    assert!(
        registry
            .get(
                &Token::new("local").unwrap(),
                &Token::new("local-default").unwrap()
            )
            .is_ok()
    );
    assert!(
        registry
            .get(
                &Token::new("local").unwrap(),
                &Token::new("local-secondary").unwrap()
            )
            .is_ok()
    );
    assert_eq!(
        registry
            .get(
                &Token::new("runtime-plugin").unwrap(),
                &Token::new("runtime-default").unwrap()
            )
            .err()
            .unwrap()
            .code,
        ProtocolErrorCode::BackendUnsupported
    );
}

#[test]
fn production_visible_constructor_rejects_shared_revocation_audit_key() {
    let shared = SigningKey::from_bytes(&[4; 32]);
    let result = SignerEngine::open_in_memory(
        Token::new("broker-app-1").unwrap(),
        SigningKey::from_bytes(&[7; 32]).verifying_key(),
        SigningKey::from_bytes(&[6; 32]).verifying_key(),
        Token::new("signer-revocation-key").unwrap(),
        shared.clone(),
        SignerAuditKeys {
            current_key_id: Token::new("signer-audit-key").unwrap(),
            current_signing_key: shared,
            historical_verifying_keys: BTreeMap::new(),
        },
        Arc::new(BackendRegistry::from_compiled(vec![]).unwrap()),
    );
    assert_eq!(
        result.err().unwrap().code,
        ProtocolErrorCode::MalformedFrame
    );
}
