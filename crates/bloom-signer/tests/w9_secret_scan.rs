mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bloom_signer::{
    ceremony::SignerCeremonyService,
    engine::{SignerAuditKeys, SignerEngine},
    hpke::HpkeRecipient,
    registry::BackendRegistry,
};
use bloom_signer_api::*;
use bloom_signer_backend_api::{BackendInput, BackendSignRequest};
use ed25519_dalek::SigningKey;
use sha2::Digest as _;
use support::{VirtualAuthenticator, seal_hpke};

fn audit_keys() -> SignerAuditKeys {
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
            audit_keys(),
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

fn import_mnemonic(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    wallet_id: &Token,
    operation_id: &OperationId,
    mnemonic: &str,
    now_ms: u64,
) -> CustodyResult {
    let prepared = service
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletImport,
                custody_operation_id: operation_id.clone(),
                wallet_id: Some(wallet_id.clone()),
                key_ref: None,
                exact_terms_digest: Digest32::new("a2".repeat(32)).unwrap(),
                expected_input_class: Token::new("bip39-mnemonic").unwrap(),
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
    let plaintext = serde_jcs::to_vec(&serde_json::json!({
        "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
        "mnemonic": mnemonic,
    }))
    .unwrap();
    let aad = CustodyHpkeAad {
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletImport,
        custody_operation_id: operation_id.clone(),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        signer_contribution_digest: prepared.contribution.digest().unwrap(),
        wallet_id: prepared.contribution.wallet_id.clone(),
        key_ref: None,
        credential_id: Some(attestation.credential_id.clone()),
        expected_input_class: Token::new("bip39-mnemonic").unwrap(),
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
    service
        .complete_custody(
            CustodyCompleteRequest {
                ceremony_kind: CeremonyKind::WalletImport,
                custody_operation_id: operation_id.clone(),
                ceremony_id: prepared.contribution.ceremony_id,
                proof: WebAuthnCeremonyProof::Registration {
                    attestation,
                    prf_assertion: Some(prf_assertion),
                },
                encrypted_input: Some(encrypted_input),
                public_binding_digest: Digest32::new("a2".repeat(32)).unwrap(),
            },
            now_ms + 100,
        )
        .unwrap()
}

fn allocate(
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

/// A tracing `MakeWriter` that appends every line to a shared buffer.
struct SharedWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl std::io::Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedWriter {
    type Writer = SharedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedWriter {
            buffer: self.buffer.clone(),
        }
    }
}

#[test]
fn bip39_secret_scan_is_empty_across_logs_audit_sqlite_and_responses() {
    let directory = tempfile::tempdir().unwrap();
    let db_path = directory.path().join("signer.db");
    let authenticator = VirtualAuthenticator::generate();

    // The frozen mnemonic and its frozen child scalars are the known secret
    // corpus; the PRF is deterministic for this authenticator.
    let mut secrets: Vec<Vec<u8>> = Vec::new();
    let mut add_secret_encodings = |secret: &[u8]| {
        secrets.push(secret.to_vec());
        secrets.push(
            Base64UrlBytes::from_bytes(secret)
                .encoded()
                .as_bytes()
                .to_vec(),
        );
    };
    add_secret_encodings(bloom_signer_vectors::BIP39_MNEMONIC.as_bytes());
    add_secret_encodings(bloom_signer_vectors::BIP39_ENTROPY_HEX.as_bytes());
    add_secret_encodings(&hex::decode(bloom_signer_vectors::BIP39_ENTROPY_HEX).unwrap());
    for scalar in [
        bloom_signer_vectors::BIP32_EVM_MASTER_PRIVATE_KEY_HEX,
        bloom_signer_vectors::BIP32_EVM_M44H_PRIVATE_KEY_HEX,
        bloom_signer_vectors::BIP32_EVM_M44H_60H_PRIVATE_KEY_HEX,
        bloom_signer_vectors::BIP32_EVM_ACCOUNT0_PRIVATE_KEY_HEX,
        bloom_signer_vectors::BIP32_EVM_CHANGE0_PRIVATE_KEY_HEX,
        bloom_signer_vectors::BIP32_EVM_TERMINAL_PRIVATE_KEY_HEX,
        bloom_signer_vectors::SLIP10_SOLANA_MASTER_PRIVATE_KEY_HEX,
        bloom_signer_vectors::SLIP10_SOLANA_M44H_PRIVATE_KEY_HEX,
        bloom_signer_vectors::SLIP10_SOLANA_M44H_501H_PRIVATE_KEY_HEX,
        bloom_signer_vectors::SLIP10_SOLANA_ACCOUNT0_PRIVATE_KEY_HEX,
        bloom_signer_vectors::SLIP10_SOLANA_TERMINAL_PRIVATE_KEY_HEX,
    ] {
        add_secret_encodings(scalar.as_bytes());
        add_secret_encodings(&hex::decode(scalar).unwrap());
    }
    add_secret_encodings(&authenticator.deterministic_prf());

    // (a) Capture tracing output.
    let log_buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer = SharedWriter {
        buffer: log_buffer.clone(),
    };
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // Run the E1/E2 flows with the frozen mnemonic: import, allocate the
    // Solana sibling, sign both curves, and export the words.
    let (service, engine, registry) = bip39_service(&db_path);
    let wallet_id = Token::new("bip39-secret-scan").unwrap();
    let import_result = import_mnemonic(
        &service,
        &authenticator,
        &wallet_id,
        &OperationId::new("40".repeat(32)).unwrap(),
        bloom_signer_vectors::BIP39_MNEMONIC,
        40_000,
    );
    let evm_child = import_result.public_key_refs[0].clone();
    let solana_child = allocate(
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

    let backend = registry
        .get(&Token::new("local").unwrap(), &wallet_id)
        .unwrap();
    futures::executor::block_on(backend.sign(BackendSignRequest {
        provider_attempt_id: Digest32::new("42".repeat(32)).unwrap(),
        key_ref: evm_child.clone(),
        crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
        input: BackendInput::Digest32 {
            digest: Digest32::from_bytes([0x5Au8; 32]),
        },
        deadline_ms: DecimalU64::new(1_000_000),
    }))
    .unwrap();
    futures::executor::block_on(backend.sign(BackendSignRequest {
        provider_attempt_id: Digest32::new("43".repeat(32)).unwrap(),
        key_ref: solana_child.clone(),
        crypto_suite: CryptoSuite::Ed25519Message,
        input: BackendInput::Message {
            message: Base64UrlBytes::from_bytes(b"solana-native-transfer-v1"),
        },
        deadline_ms: DecimalU64::new(1_000_000),
    }))
    .unwrap();

    // Export the mnemonic so the words pass through the sensitive-output path.
    let recipient = HpkeRecipient::generate();
    let effect = serde_json::json!({ "kind": "wallet_export", "format": "bip39_mnemonic24" });
    let exact_terms_digest =
        Digest32::from_bytes(sha2::Sha256::digest(serde_jcs::to_vec(&effect).unwrap()).into());
    service
        .prepare_custody(
            CustodyPrepareRequest {
                ceremony_kind: CeremonyKind::WalletExport,
                custody_operation_id: OperationId::new("44".repeat(32)).unwrap(),
                wallet_id: Some(wallet_id.clone()),
                key_ref: None,
                exact_terms_digest: exact_terms_digest.clone(),
                expected_input_class: Token::new("generic-custody-v1").unwrap(),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                wallet_seed_profile: None,
                derivation_request: None,
            },
            40_200,
        )
        .unwrap();
    let prepared = service
        .bind_custody_output_recipient(
            &OperationId::new("44".repeat(32)).unwrap(),
            recipient.public_key().clone(),
            40_201,
        )
        .unwrap();
    let assertion =
        authenticator.assertion(&prepared.challenges[0].canonical_bytes().unwrap(), 40_201);
    let aad = CustodyHpkeAad {
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::WalletExport,
        custody_operation_id: OperationId::new("44".repeat(32)).unwrap(),
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
    let export_result = service
        .complete_custody(
            CustodyCompleteRequest {
                ceremony_kind: CeremonyKind::WalletExport,
                custody_operation_id: OperationId::new("44".repeat(32)).unwrap(),
                ceremony_id: prepared.contribution.ceremony_id,
                proof: WebAuthnCeremonyProof::Assertion { assertion },
                encrypted_input: Some(encrypted_input),
                public_binding_digest: exact_terms_digest,
            },
            40_300,
        )
        .unwrap();

    let assert_clean = |surface: &str, bytes: &[u8]| {
        for secret in &secrets {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_slice()),
                "{surface} leaked a secret"
            );
        }
    };

    // (a) Captured logs.
    assert_clean("tracing logs", &log_buffer.lock().unwrap());

    // (b) audit_chain rows.
    let connection = rusqlite::Connection::open(&db_path).unwrap();
    let mut audit = Vec::new();
    {
        let mut statement = connection
            .prepare("SELECT payload_jcs FROM audit_chain ORDER BY sequence")
            .unwrap();
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap();
        for row in rows {
            audit.extend_from_slice(row.unwrap().as_bytes());
        }
    }
    assert_clean("audit_chain", &audit);

    // (c) SQLite dump excluding ciphertext columns.
    let mut dump = Vec::new();
    {
        // Ciphertext and opaque columns, plus the hash-chain link columns
        // (`previous_hash`/`entry_hash`) whose genesis row is legitimately the
        // all-zero digest. The all-zero frozen entropy must never appear
        // outside these structural columns.
        let excluded_columns = [
            "custody_jcs",
            "backup_set_jcs",
            "derivation_registry_jcs",
            "encrypted_record",
            "credential_jcs",
            "encrypted_root",
            "encrypted_policy_signing_key",
            "wrapped_wkek",
            "previous_hash",
            "entry_hash",
            "head_hash",
            "signature",
            "entry_signature",
        ];
        let mut tables = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap();
        let table_names: Vec<String> = tables
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|name| name.unwrap())
            .collect();
        for table in table_names {
            let mut columns = connection
                .prepare(&format!("PRAGMA table_info({table})"))
                .unwrap();
            let column_names: Vec<String> = columns
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .map(|name| name.unwrap())
                .filter(|name| !excluded_columns.contains(&name.as_str()))
                .collect();
            if column_names.is_empty() {
                continue;
            }
            let select = format!(
                "SELECT {} FROM {table}",
                column_names
                    .iter()
                    .map(|name| format!("\"{name}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let mut statement = connection.prepare(&select).unwrap();
            let mut rows = statement.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                for index in 0..column_names.len() {
                    match row.get_ref(index).unwrap() {
                        rusqlite::types::ValueRef::Text(value)
                        | rusqlite::types::ValueRef::Blob(value) => dump.extend_from_slice(value),
                        rusqlite::types::ValueRef::Null
                        | rusqlite::types::ValueRef::Integer(_)
                        | rusqlite::types::ValueRef::Real(_) => {}
                    }
                }
            }
        }
    }
    assert_clean("sqlite dump", &dump);

    // (d) Serialized responses.
    let mut responses = Vec::new();
    responses.extend_from_slice(&serde_jcs::to_vec(&import_result).unwrap());
    responses.extend_from_slice(&serde_jcs::to_vec(&export_result).unwrap());
    let evm_descriptor = engine
        .derived_account_descriptor(&evm_child)
        .unwrap()
        .unwrap();
    let solana_descriptor = engine
        .derived_account_descriptor(&solana_child)
        .unwrap()
        .unwrap();
    responses.extend_from_slice(&serde_jcs::to_vec(&evm_descriptor).unwrap());
    responses.extend_from_slice(&serde_jcs::to_vec(&solana_descriptor).unwrap());
    assert_clean("serialized responses", &responses);

    drop(connection);
}
