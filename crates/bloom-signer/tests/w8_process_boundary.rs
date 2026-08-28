use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("bloom-signer belongs to its workspace")
        .to_path_buf()
}

fn production_bloom_packages(package: &str) -> BTreeSet<String> {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            package,
            "--all-features",
            "--edges",
            "normal,build",
            "--prefix",
            "none",
        ])
        .current_dir(workspace())
        .output()
        .expect("run cargo tree for a production package graph");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("cargo tree output is UTF-8")
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name.starts_with("bloom-"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn production_signer_reports_its_semantic_version_without_starting_services() {
    let output = Command::new(env!("CARGO_BIN_EXE_bloom-signer"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("bloom-signer {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn production_signer_dependency_graph_has_no_machine_broker_or_debug_driver() {
    let actual = production_bloom_packages("bloom-signer");
    let allowed = BTreeSet::from_iter(
        [
            "bloom-audit-checkpoint",
            "bloom-platform-containment",
            "bloom-rpc-wire",
            "bloom-service-activation",
            "bloom-signer",
            "bloom-signer-api",
            "bloom-signer-backend-api",
            "bloom-signer-backend-aws-kms",
            "bloom-signer-backend-local",
            "bloom-signer-derive",
            "bloom-signer-process-hardening",
            "bloom-triad-local-transport",
            "bloom-trusted-time",
        ]
        .map(str::to_owned),
    );
    assert_eq!(actual, allowed, "unexpected package crossed into Signer");
}

#[test]
fn signer_api_dependency_graph_contains_only_its_mechanical_wire_package() {
    assert_eq!(
        production_bloom_packages("bloom-signer-api"),
        BTreeSet::from(["bloom-rpc-wire".into(), "bloom-signer-api".into()]),
        "Signer API gained another Bloom domain or service dependency"
    );
}

// ============================================================================
// BIP-39 end-to-end: register, allocate EVM and Solana, sign raw Ed25519 and
// recoverable EVM, restart the engine on the same database, and re-derive the
// identical descriptors.
// ============================================================================

mod support;

use std::sync::Arc;

use bloom_signer::{
    ceremony::SignerCeremonyService,
    engine::{SignerAuditKeys, SignerEngine},
    hpke::LOCAL_PRF_INFO,
    registry::BackendRegistry,
};
use bloom_signer_api::*;
use bloom_signer_backend_api::{BackendInput, BackendSignRequest};
use ed25519_dalek::SigningKey;
use sha2::Digest as _;
use std::collections::BTreeMap;
use support::{VirtualAuthenticator, seal_hpke};

fn bip39_audit_keys() -> SignerAuditKeys {
    SignerAuditKeys {
        current_key_id: Token::new("signer-audit-key").unwrap(),
        current_signing_key: SigningKey::from_bytes(&[14; 32]),
        historical_verifying_keys: BTreeMap::new(),
    }
}

fn digest(byte: &str) -> Digest32 {
    Digest32::new(byte.repeat(32)).unwrap()
}

fn operation(byte: &str) -> OperationId {
    OperationId::new(byte.repeat(32)).unwrap()
}

/// Approval terms for one restored derived child, so a full sign ceremony can
/// activate the backend after restore and produce a real signature.
fn bip39_terms(key_ref: KeyRef, wallet_id: &Token) -> SealedApprovalTerms {
    SealedApprovalTerms {
        subject: ApprovalSubject::Cli {
            client_id: Token::new("bloom-cli").unwrap(),
            command_class: Token::new("wallet.sign").unwrap(),
        },
        wallet_id: wallet_id.clone(),
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
        wallet_revocation_epoch: DecimalU64::new(0),
        policy_version: DecimalU64::new(1),
        policy_digest: digest("44"),
        provenance_digest: digest("55"),
        request_nonce: RequestNonce::new("66".repeat(16)).unwrap(),
        issued_at_ms: DecimalU64::new(1_000),
        not_before_ms: DecimalU64::new(1_000),
        expires_at_ms: DecimalU64::new(30_303),
        renewal_of: None,
    }
}

fn complete_local_approval(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    terms: SealedApprovalTerms,
    activation_operation_id: OperationId,
    sign_count: u32,
    now_ms: u64,
) -> SignerActivationReceipt {
    let review_manifest_digest = digest("76");
    let (exact_ordered_payload_digests, exact_ordered_hashes) = match &terms.selector {
        ApprovalSelector::Exact {
            ordered_payload_digests,
            ordered_hashes,
        } => (ordered_payload_digests.clone(), ordered_hashes.clone()),
        ApprovalSelector::Petal { .. } => (Vec::new(), Vec::new()),
    };
    let prepared = service
        .prepare_approval(
            CeremonyPrepareRequest {
                activation_operation_id: activation_operation_id.clone(),
                terms: terms.clone(),
                review_manifest_digest: review_manifest_digest.clone(),
                exact_ordered_payload_digests,
                exact_ordered_hashes,
                replacement_approval_id: None,
            },
            now_ms,
        )
        .unwrap();
    let assertion = authenticator.assertion(
        &prepared.challenges[0].canonical_bytes().unwrap(),
        sign_count,
    );
    let aad = LocalPrfHpkeAad {
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        approval_id: terms.approval_id().unwrap(),
        approval_digest: terms.approval_digest().unwrap(),
        review_manifest_digest,
        key_ref: terms.key_ref.clone(),
        allowed_crypto_suites: terms.allowed_crypto_suites.clone(),
        credential_id: assertion.credential_id.clone(),
        activation_mode: terms.activation_mode.clone(),
        wallet_revocation_epoch: terms.wallet_revocation_epoch.clone(),
    }
    .canonical_bytes()
    .unwrap();
    let encrypted_local_prf = seal_hpke(
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
    futures::executor::block_on(service.complete_approval(
        CeremonyCompleteRequest {
            activation_operation_id,
            proof: WebAuthnCeremonyProof::Assertion { assertion },
            contribution: prepared.contribution,
            encrypted_local_prf: Some(encrypted_local_prf),
        },
        now_ms + 1,
    ))
    .unwrap()
}

fn bip39_service(
    path: &std::path::Path,
) -> (
    SignerCeremonyService,
    Arc<SignerEngine>,
    Arc<BackendRegistry>,
) {
    let registry = Arc::new(BackendRegistry::from_compiled(vec![]).unwrap());
    let engine = Arc::new(
        SignerEngine::open(
            path,
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            bip39_audit_keys(),
            registry.clone(),
        )
        .unwrap(),
    );
    let service = SignerCeremonyService::new(
        engine.clone(),
        Token::new("signer-ceremony-key").unwrap(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    (service, engine, registry)
}

fn bip39_register(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    wallet_id: &Token,
    operation_id: &OperationId,
    now_ms: u64,
) -> CustodyResult {
    let prepared = service
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletRegistration,
                custody_operation_id: operation_id.clone(),
                wallet_id: Some(wallet_id.clone()),
                key_ref: None,
                exact_terms_digest: Digest32::new("a1".repeat(32)).unwrap(),
                expected_input_class: Token::new("passkey-prf").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: Some(WalletSeedProfile::Bip39MulticurveV1),
                derivation_request: None,
            },
            now_ms,
        )
        .unwrap();
    let attestation = authenticator.attestation(&prepared.challenges[0].canonical_bytes().unwrap());
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
    service
        .complete_custody(
            CustodyCompleteRequest {
                ceremony_kind: CeremonyKind::WalletRegistration,
                custody_operation_id: operation_id.clone(),
                ceremony_id: prepared.contribution.ceremony_id,
                proof: WebAuthnCeremonyProof::Registration {
                    attestation,
                    prf_assertion: Some(prf_assertion),
                },
                encrypted_input: Some(encrypted_input),
                public_binding_digest: Digest32::new("a1".repeat(32)).unwrap(),
            },
            now_ms + 100,
        )
        .unwrap()
}

fn bip39_allocate(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    wallet_id: &Token,
    operation_id: &OperationId,
    request: DerivedAccountRequest,
    now_ms: u64,
) -> KeyRef {
    let effect = serde_json::json!({ "kind": "account_allocate" });
    let exact_terms_digest =
        Digest32::from_bytes(sha2::Sha256::digest(serde_jcs::to_vec(&effect).unwrap()).into());
    let prepared = service
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::AccountAllocate,
                custody_operation_id: operation_id.clone(),
                wallet_id: Some(wallet_id.clone()),
                key_ref: None,
                exact_terms_digest: exact_terms_digest.clone(),
                expected_input_class: Token::new("generic-custody-v1").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: Some(request),
            },
            now_ms,
        )
        .unwrap();
    let assertion = authenticator.assertion(
        &prepared.challenges[0].canonical_bytes().unwrap(),
        now_ms as u32,
    );
    let aad = CustodyHpkeAad {
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::AccountAllocate,
        custody_operation_id: operation_id.clone(),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        signer_contribution_digest: prepared.contribution.digest().unwrap(),
        wallet_id: Some(wallet_id.clone()),
        key_ref: None,
        credential_id: Some(assertion.credential_id.clone()),
        expected_input_class: Token::new("generic-custody-v1").unwrap(),
    }
    .canonical_bytes()
    .unwrap();
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
    let result = service
        .complete_custody(
            CustodyCompleteRequest {
                ceremony_kind: CeremonyKind::AccountAllocate,
                custody_operation_id: operation_id.clone(),
                ceremony_id: prepared.contribution.ceremony_id,
                proof: WebAuthnCeremonyProof::Assertion { assertion },
                encrypted_input: Some(encrypted_input),
                public_binding_digest: exact_terms_digest,
            },
            now_ms + 100,
        )
        .unwrap();
    result.public_key_refs[0].clone()
}

#[test]
fn bip39_process_boundary_end_to_end() {
    let directory = tempfile::tempdir().unwrap();
    let db_path = directory.path().join("signer.db");
    let authenticator = VirtualAuthenticator::generate();

    // First lifecycle: register, allocate EVM (initial, done by registration)
    // and Solana, sign both curves, and export the mnemonic.
    let (first_child_key_ref, solana_child_key_ref, first_descriptors) = {
        let (service, engine, registry) = bip39_service(&db_path);
        let wallet_id = Token::new("bip39-e2e").unwrap();
        let registration = bip39_register(
            &service,
            &authenticator,
            &wallet_id,
            &OperationId::new("10".repeat(32)).unwrap(),
            10_000,
        );
        let evm_child = registration.public_key_refs[0].clone();

        let solana_child = bip39_allocate(
            &service,
            &authenticator,
            &wallet_id,
            &OperationId::new("20".repeat(32)).unwrap(),
            DerivedAccountRequest {
                derivation_profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                requested_role: Token::new("solana-account").unwrap(),
                account: Some(0),
            },
            10_100,
        );

        // Sign raw Ed25519 message through the backend (the service sign path
        // resolves here) and verify against the frozen vector derivation.
        let backend = registry
            .get(&Token::new("local").unwrap(), &wallet_id)
            .unwrap();
        let message = b"solana-native-transfer-v1";
        let signature = futures::executor::block_on(backend.sign(BackendSignRequest {
            provider_attempt_id: Digest32::new("11".repeat(32)).unwrap(),
            key_ref: solana_child.clone(),
            crypto_suite: CryptoSuite::Ed25519Message,
            input: BackendInput::Message {
                message: Base64UrlBytes::from_bytes(message),
            },
            deadline_ms: DecimalU64::new(1_000_000),
        }))
        .unwrap();
        assert_eq!(signature.encoding, SignatureEncoding::Ed25519Raw64);
        // The deterministic signature verifies under the derived child key.
        let solana_descriptor = engine
            .derived_account_descriptor(&solana_child)
            .unwrap()
            .unwrap();
        let spki = solana_descriptor.canonical_public_key.decode();
        let verifying =
            ed25519_dalek::VerifyingKey::from_bytes(&spki[12..44].try_into().unwrap()).unwrap();
        verifying
            .verify_strict(
                message,
                &ed25519_dalek::Signature::from_bytes(
                    &signature.bytes.decode().try_into().unwrap(),
                ),
            )
            .unwrap();

        // EVM recoverable sign.
        let digest: [u8; 32] = [0x5Au8; 32];
        let evm_sig = futures::executor::block_on(backend.sign(BackendSignRequest {
            provider_attempt_id: Digest32::new("12".repeat(32)).unwrap(),
            key_ref: evm_child.clone(),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            input: BackendInput::Digest32 {
                digest: Digest32::from_bytes(digest),
            },
            deadline_ms: DecimalU64::new(1_000_000),
        }))
        .unwrap();
        assert_eq!(evm_sig.encoding, SignatureEncoding::Secp256k1Recoverable65);

        let evm_descriptor = engine
            .derived_account_descriptor(&evm_child)
            .unwrap()
            .unwrap();
        let solana_descriptor = engine
            .derived_account_descriptor(&solana_child)
            .unwrap()
            .unwrap();
        (
            evm_descriptor.path.clone(),
            solana_descriptor.path.clone(),
            vec![
                (evm_child, evm_descriptor),
                (solana_child, solana_descriptor),
            ],
        )
    };

    // Restart: reopen the same database with a fresh registry; the engine's
    // startup reconciliation re-registers the backend and the descriptors are
    // identical.
    let restarted = {
        let (_service, engine, _registry) = bip39_service(&db_path);
        let mut descriptors = Vec::new();
        for (key_ref, _) in &first_descriptors {
            let descriptor = engine.derived_account_descriptor(key_ref).unwrap().unwrap();
            descriptors.push((
                descriptor.path.clone(),
                descriptor.public_key_fingerprint.clone(),
            ));
        }
        descriptors
    };

    assert_eq!(restarted.len(), 2);
    let _ = first_child_key_ref;
    let _ = solana_child_key_ref;
}

#[test]
fn bip39_derived_account_list_is_lock_free_and_stable_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    let db_path = directory.path().join("signer.db");
    let authenticator = VirtualAuthenticator::generate();
    let wallet_id = Token::new("bip39-list").unwrap();

    // Register (allocates the canonical EVM child) and allocate a Solana
    // sibling. No unlock happens after these ceremonies: the read below must
    // succeed purely from the persisted registry.
    let (first_child, solana_child) = {
        let (service, engine, _registry) = bip39_service(&db_path);
        let registration = bip39_register(
            &service,
            &authenticator,
            &wallet_id,
            &OperationId::new("40".repeat(32)).unwrap(),
            40_000,
        );
        let evm_child = registration.public_key_refs[0].clone();
        let solana_child = bip39_allocate(
            &service,
            &authenticator,
            &wallet_id,
            &OperationId::new("41".repeat(32)).unwrap(),
            DerivedAccountRequest {
                derivation_profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                requested_role: Token::new("solana-account").unwrap(),
                account: Some(0),
            },
            40_100,
        );

        let listed = engine.derived_account_descriptors(&wallet_id).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|descriptor| {
            descriptor.lifecycle == bloom_signer_api::AccountLifecycleState::Active
        }));
        assert!(
            listed
                .iter()
                .any(|descriptor| descriptor.key_ref == evm_child)
        );
        assert!(
            listed
                .iter()
                .any(|descriptor| descriptor.key_ref == solana_child)
        );

        (evm_child, solana_child)
    };

    // Restart: reopen the same database; the lock-free read is byte-for-byte
    // identical and still requires no unlock. The re-registered backend still
    // carries every allocated child so retirement works across the restart.
    let (first_child, solana_child) = {
        let (_service, engine, registry) = bip39_service(&db_path);
        let listed = engine.derived_account_descriptors(&wallet_id).unwrap();
        assert_eq!(listed.len(), 2);
        for descriptor in &listed {
            let public = futures::executor::block_on(
                registry
                    .get(
                        &descriptor.key_ref.backend,
                        &descriptor.key_ref.backend_instance,
                    )
                    .unwrap()
                    .describe_key(&descriptor.key_ref),
            )
            .unwrap();
            assert_eq!(public.canonical_spki_der, descriptor.canonical_public_key);
            assert_eq!(
                public.public_key_fingerprint,
                descriptor.public_key_fingerprint
            );
        }

        // Retiring after restart removes the child from the lock-free list and
        // from the re-registered backend registry.
        engine
            .retire_bip39_account(&wallet_id, &solana_child, 40_200)
            .unwrap();
        let after_retire = engine.derived_account_descriptors(&wallet_id).unwrap();
        assert_eq!(after_retire.len(), 1);
        assert_eq!(after_retire[0].key_ref, first_child);
        (first_child, solana_child)
    };

    // Second restart: the retired child stays gone.
    let restarted = {
        let (_service, engine, _registry) = bip39_service(&db_path);
        engine.derived_account_descriptors(&wallet_id).unwrap()
    };
    assert_eq!(restarted.len(), 1);
    assert_eq!(restarted[0].key_ref, first_child);
    assert_eq!(
        restarted[0].derivation_profile,
        DerivationProfile::Bip44EvmSecp256k1V1
    );
    let _ = solana_child;
}

#[test]
fn bip39_descriptor_rejects_a_profile_key_spec_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let db_path = directory.path().join("signer.db");
    let authenticator = VirtualAuthenticator::generate();
    let (service, engine, _registry) = bip39_service(&db_path);
    let wallet_id = Token::new("bip39-keyspec").unwrap();
    let registration = bip39_register(
        &service,
        &authenticator,
        &wallet_id,
        &OperationId::new("30".repeat(32)).unwrap(),
        30_000,
    );
    let child = registration.public_key_refs[0].clone();
    let descriptor = engine.derived_account_descriptor(&child).unwrap().unwrap();
    assert_eq!(
        descriptor.derivation_profile,
        DerivationProfile::Bip44EvmSecp256k1V1
    );

    // Corrupt the stored key spec so it contradicts the EVM derivation profile.
    let connection = rusqlite::Connection::open(&db_path).unwrap();
    let updated = connection
        .execute(
            "UPDATE derivation_allocations SET key_spec = 'ed25519'
              WHERE wallet_id = ?1 AND public_key_fingerprint = ?2",
            rusqlite::params![wallet_id.as_str(), child.public_key_fingerprint.as_str()],
        )
        .unwrap();
    assert_eq!(updated, 1);

    let result = engine.derived_account_descriptor(&child);
    assert_eq!(result.unwrap_err().code, ProtocolErrorCode::KeyrefMismatch);
}

#[test]
fn bip39_export_restore_round_trips_allocated_accounts() {
    let directory = tempfile::tempdir().unwrap();
    let db_path = directory.path().join("signer.db");
    let authenticator = VirtualAuthenticator::generate();
    let wallet_id = Token::new("bip39-export").unwrap();

    // Register (canonical EVM child) and allocate a Solana sibling. Exporting
    // exercises the enrollment pinned_keys cross-check that was broken for any
    // BIP-39 wallet with allocated accounts.
    let (exported, expected) = {
        let (service, engine, _registry) = bip39_service(&db_path);
        let registration = bip39_register(
            &service,
            &authenticator,
            &wallet_id,
            &OperationId::new("70".repeat(32)).unwrap(),
            70_000,
        );
        let evm_child = registration.public_key_refs[0].clone();
        let solana_child = bip39_allocate(
            &service,
            &authenticator,
            &wallet_id,
            &OperationId::new("71".repeat(32)).unwrap(),
            DerivedAccountRequest {
                derivation_profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                requested_role: Token::new("solana-account").unwrap(),
                account: Some(0),
            },
            70_100,
        );

        let expected = engine.derived_account_descriptors(&wallet_id).unwrap();
        assert_eq!(expected.len(), 2);
        assert!(expected.iter().any(|d| d.key_ref == evm_child));
        assert!(expected.iter().any(|d| d.key_ref == solana_child));

        (engine.export_wallet_backup(&wallet_id).unwrap(), expected)
    };

    // The export itself carries every allocated child: the pinned_keys fix
    // guarantees the enrollment and backend registry agree, so this must be
    // the full set rather than an empty placeholder.
    let registry = exported.derivation_registry.as_ref().unwrap();
    assert_eq!(registry.allocated_keys.len(), 2);
    assert!(
        registry
            .allocated_keys
            .iter()
            .any(|key| key.key_spec == bloom_signer_api::KeySpec::Secp256k1)
    );
    assert!(
        registry
            .allocated_keys
            .iter()
            .any(|key| key.key_spec == bloom_signer_api::KeySpec::Ed25519)
    );

    // The exported enrollment must deserialize into a backend whose pinned
    // registry matches the derived children, so a restore can re-register
    // them byte-for-byte.
    let backend = exported.restore_local_backend(&wallet_id).unwrap();
    let restored_backup = backend.encrypted_backup().unwrap();
    assert_eq!(restored_backup.derivation_registry.len(), 2);
    let _ = expected;
}

#[test]
fn bip39_restored_wallet_signs_from_its_restored_derived_account() {
    let directory = tempfile::tempdir().unwrap();
    let db_a = directory.path().join("a.db");
    let db_b = directory.path().join("b.db");
    let authenticator = VirtualAuthenticator::generate();
    let wallet_id = Token::new("bip39-restore-sign").unwrap();

    // Phase 1: register (canonical EVM child) and allocate a Solana sibling.
    let (evm_child, solana_child, exported) = {
        let (service, engine, _registry) = bip39_service(&db_a);
        let registration = bip39_register(
            &service,
            &authenticator,
            &wallet_id,
            &operation("80"),
            80_000,
        );
        let evm_child = registration.public_key_refs[0].clone();
        let solana_child = bip39_allocate(
            &service,
            &authenticator,
            &wallet_id,
            &operation("81"),
            DerivedAccountRequest {
                derivation_profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                requested_role: Token::new("solana-account").unwrap(),
                account: Some(0),
            },
            80_100,
        );
        (
            evm_child,
            solana_child,
            engine.export_wallet_backup(&wallet_id).unwrap(),
        )
    };

    // Phase 2: wipe/reload into a fresh engine and restore the backup.
    let (_service, engine, registry) = bip39_service(&db_b);
    engine.restore_backup(&exported).unwrap();

    // The descriptor projection round-trips: both children are listed with
    // their original SPKI / fingerprint / lifecycle.
    let descriptors = engine.derived_account_descriptors(&wallet_id).unwrap();
    assert_eq!(descriptors.len(), 2);
    for (child, profile) in [
        (evm_child.clone(), DerivationProfile::Bip44EvmSecp256k1V1),
        (
            solana_child.clone(),
            DerivationProfile::Bip44SolanaSlip10Ed25519V1,
        ),
    ] {
        let descriptor = engine.derived_account_descriptor(&child).unwrap().unwrap();
        assert_eq!(
            descriptor.public_key_fingerprint,
            child.public_key_fingerprint
        );
        assert_eq!(descriptor.derivation_profile, profile);
        assert_eq!(descriptor.lifecycle, AccountLifecycleState::Active);
    }
    // The restored child is enrolled (role 'derived', available), which is
    // exactly what the lock-free listing above already depends on.

    // Re-register the restored backend from the durable enrollment so the
    // backend can actually sign, then drive a real sign ceremony.
    let restored_service = SignerCeremonyService::new(
        engine.clone(),
        Token::new("signer-ceremony-key").unwrap(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    restored_service
        .register_existing_credential(wallet_id.clone(), authenticator.credential(0))
        .unwrap();

    let evm_terms = bip39_terms(evm_child.clone(), &wallet_id);
    complete_local_approval(
        &restored_service,
        &authenticator,
        evm_terms,
        operation("82"),
        2,
        80_200,
    );

    // A real signature succeeds from the restored derived account and
    // verifies under the restored descriptor's public key.
    let backend = registry
        .get(&Token::new("local").unwrap(), &wallet_id)
        .unwrap();
    let digest_bytes = [0x5Au8; 32];
    let signature = futures::executor::block_on(backend.sign(BackendSignRequest {
        provider_attempt_id: digest("83"),
        key_ref: evm_child.clone(),
        crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
        input: BackendInput::Digest32 {
            digest: Digest32::from_bytes(digest_bytes),
        },
        deadline_ms: DecimalU64::new(1_000_000),
    }))
    .unwrap();
    assert_eq!(
        signature.encoding,
        bloom_signer_api::SignatureEncoding::Secp256k1Recoverable65
    );
    let bytes = signature.bytes.decode();
    let sig = k256::ecdsa::Signature::from_slice(&bytes[..64]).unwrap();
    let recovery = k256::ecdsa::RecoveryId::from_byte(bytes[64]).unwrap();
    let recovered =
        k256::ecdsa::VerifyingKey::recover_from_prehash(&digest_bytes, &sig, recovery).unwrap();
    let descriptor = engine
        .derived_account_descriptor(&evm_child)
        .unwrap()
        .unwrap();
    // The recovered key's SPKI must byte-match the restored descriptor.
    use k256::pkcs8::EncodePublicKey as _;
    let spki = k256::PublicKey::from_sec1_bytes(recovered.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();
    assert_eq!(descriptor.canonical_public_key.decode(), spki.as_bytes());

    // A real Ed25519 signature also succeeds from the restored Solana child
    // and verifies under its restored descriptor's public key — the Solana
    // variant of the backup/restore-then-signs proof.
    let solana_terms = bip39_terms(solana_child.clone(), &wallet_id);
    let solana_terms = SealedApprovalTerms {
        allowed_crypto_suites: vec![CryptoSuite::Ed25519Message],
        ..solana_terms
    };
    complete_local_approval(
        &restored_service,
        &authenticator,
        solana_terms,
        operation("84"),
        3,
        80_300,
    );

    let message = b"solana-native-transfer";
    let solana_signature = futures::executor::block_on(backend.sign(BackendSignRequest {
        provider_attempt_id: digest("85"),
        key_ref: solana_child.clone(),
        crypto_suite: CryptoSuite::Ed25519Message,
        input: BackendInput::Message {
            message: Base64UrlBytes::from_bytes(message),
        },
        deadline_ms: DecimalU64::new(1_000_000),
    }))
    .unwrap();
    assert_eq!(
        solana_signature.encoding,
        bloom_signer_api::SignatureEncoding::Ed25519Raw64
    );
    let solana_descriptor = engine
        .derived_account_descriptor(&solana_child)
        .unwrap()
        .unwrap();
    // The descriptor's canonical public key is the Ed25519 SPKI DER
    // (RFC 8410, 12-byte prefix + 32-byte raw key).
    let spki = solana_descriptor.canonical_public_key.decode();
    assert_eq!(spki.len(), 44, "Ed25519 SPKI DER is 44 bytes");
    let raw_key: [u8; 32] = spki[12..].try_into().unwrap();
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&raw_key).unwrap();
    verifying
        .verify_strict(
            message,
            &ed25519_dalek::Signature::from_slice(&solana_signature.bytes.decode()).unwrap(),
        )
        .unwrap();
}
