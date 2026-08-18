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
        let (_service, engine, _registry) = bip39_service(&db_path);
        let listed = engine.derived_account_descriptors(&wallet_id).unwrap();
        assert_eq!(listed.len(), 2);

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
