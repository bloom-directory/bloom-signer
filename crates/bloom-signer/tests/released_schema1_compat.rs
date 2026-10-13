mod support;

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use bloom_signer::{
    ceremony::{SignerCeremonyService, SignerCeremonyStatus},
    custody::{WalletCustody, WalletCustodyBackup},
    engine::{SignerAuditKeys, SignerEngine},
    registry::BackendRegistry,
    webauthn::verify_webauthn_assertion,
};
use bloom_signer_api::{
    Base64UrlBytes, CeremonyKind, CeremonyState, CustodyCompleteRequest, CustodyPrepareRequest,
    Digest32, OperationId, ProtocolErrorCode, Token, WebAuthnAttestation, WebAuthnCeremonyProof,
    legacy_local_surface,
};
use bloom_signer_backend_api::SecretBytes;
use ed25519_dalek::{Signature, SigningKey, Verifier as _};
use rusqlite::Connection;
use sha2::{Digest as _, Sha256};
use support::VirtualAuthenticator;

fn token(value: &str) -> Token {
    Token::new(value).unwrap()
}

fn digest(byte: u8) -> Digest32 {
    Digest32::from_bytes([byte; 32])
}

fn operation(byte: u8) -> OperationId {
    OperationId::from_bytes([byte; 32])
}

fn audit_keys() -> SignerAuditKeys {
    SignerAuditKeys {
        current_key_id: token("signer-audit-key"),
        current_signing_key: SigningKey::from_bytes(&[14; 32]),
        historical_verifying_keys: BTreeMap::new(),
    }
}

fn engine(path: &Path) -> Arc<SignerEngine> {
    Arc::new(
        SignerEngine::open(
            path,
            token("broker-app-1"),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
            token("signer-revocation-key"),
            SigningKey::from_bytes(&[4; 32]),
            audit_keys(),
            Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap()),
        )
        .unwrap(),
    )
}

fn fixture_path() -> (Option<tempfile::TempDir>, PathBuf) {
    if let Some(path) = env::var_os("BLOOM_RELEASED_SCHEMA1_DB") {
        return (None, path.into());
    }
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("released-schema1.sqlite3");
    fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/released-ccc9adb-schema1.sqlite3"
        ),
        &path,
    )
    .unwrap();
    (Some(temporary), path)
}

fn verify_receipt_signature(unsigned: &[u8], encoded: &Base64UrlBytes) {
    let signature = Signature::from_slice(&encoded.decode()).unwrap();
    SigningKey::from_bytes(&[9; 32])
        .verifying_key()
        .verify(
            &[b"bloom-signer-ceremony-receipt/v1".as_slice(), unsigned].concat(),
            &signature,
        )
        .unwrap();
}

fn completed_custody_retry(kind: CeremonyKind) -> CustodyCompleteRequest {
    CustodyCompleteRequest {
        ceremony_kind: kind,
        custody_operation_id: operation(31),
        ceremony_id: digest(43),
        proof: WebAuthnCeremonyProof::Registration {
            attestation: WebAuthnAttestation {
                credential_id: Base64UrlBytes::from_bytes(&[]),
                client_data_json: Base64UrlBytes::from_bytes(&[]),
                attestation_object: Base64UrlBytes::from_bytes(&[]),
                transports: Vec::new(),
            },
            prf_assertion: None,
        },
        encrypted_input: None,
        public_binding_digest: digest(44),
    }
}

#[test]
fn released_schema1_state_migrates_and_preserves_wallet_access() {
    let (_temporary, path) = fixture_path();
    let connection = Connection::open(&path).unwrap();
    let before: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(before, 0, "released package schema 1 used SQLite marker 0");
    let (custody_json, credential_json): (String, String) = connection
        .query_row(
            "SELECT w.custody_jcs, c.credential_jcs
             FROM ceremony_wallets w JOIN webauthn_credentials c USING (wallet_id)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(!custody_json.contains("credential_authority_generation"));
    assert!(custody_json.contains("released-recovery"));
    assert!(!credential_json.contains("surface"));
    drop(connection);

    let engine = engine(&path);
    let service = SignerCeremonyService::new(
        engine.clone(),
        token("signer-ceremony-key"),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();

    let credential = service
        .credential(
            &token("released-wallet"),
            &Base64UrlBytes::from_bytes(&[21; 32]),
        )
        .unwrap();
    assert_eq!(credential.surface, legacy_local_surface());
    assert_eq!(credential.sign_count.get(), 4);
    let authenticator = VirtualAuthenticator::from_test_material([30; 32], &[21; 32], &[28; 32]);
    let challenge = b"released-schema1-credential";
    let verified = verify_webauthn_assertion(
        &authenticator.assertion(challenge, 5),
        &credential,
        challenge,
        service.ceremony_origin(),
        true,
    )
    .unwrap();
    assert_eq!(verified.sign_count, 5);

    let custody = match service.status(&operation(31)).unwrap() {
        SignerCeremonyStatus::CompletedCustody(receipt) => receipt,
        status => panic!("released custody receipt was not restored: {status:?}"),
    };
    assert_eq!(custody.surface, None);
    assert_eq!(custody.credential_authority_generation, None);
    assert_eq!(custody.credential_summaries[0].surface, None);
    verify_receipt_signature(
        &custody.unsigned_canonical_bytes().unwrap(),
        &custody.signer_signature,
    );
    assert_eq!(
        service
            .complete_custody(
                completed_custody_retry(CeremonyKind::WalletRegistration),
                2_500
            )
            .unwrap(),
        *custody
    );
    assert_eq!(
        service
            .complete_custody(completed_custody_retry(CeremonyKind::WalletExport), 2_500)
            .unwrap_err()
            .code,
        ProtocolErrorCode::OperationIdConflict
    );

    let activation = match service.status(&operation(34)).unwrap() {
        SignerCeremonyStatus::CompletedApproval(receipt) => receipt,
        status => panic!("released activation receipt was not restored: {status:?}"),
    };
    assert_eq!(activation.surface, None);
    assert_eq!(activation.credential_authority_generation, None);
    verify_receipt_signature(
        &activation.unsigned_canonical_bytes().unwrap(),
        &activation.signer_signature,
    );
    assert!(matches!(
        service.status(&operation(40)).unwrap(),
        SignerCeremonyStatus::Terminal(CeremonyState::Failed)
    ));

    let pending = operation(41);
    service
        .prepare_custody(
            CustodyPrepareRequest {
                surface: legacy_local_surface(),
                ceremony_kind: CeremonyKind::WalletRecovery,
                custody_operation_id: pending.clone(),
                wallet_id: Some(token("released-wallet")),
                key_ref: None,
                exact_terms_digest: digest(42),
                expected_input_class: token("recovery-factor-v1"),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                derivation_requests: Vec::new(),
                wallet_seed_profile: None,
            },
            2_000,
        )
        .unwrap();
    assert!(matches!(
        service.status(&pending).unwrap(),
        SignerCeremonyStatus::Pending
    ));
    drop(service);
    let restarted = SignerCeremonyService::new(
        engine,
        token("signer-ceremony-key"),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    assert!(matches!(
        restarted.status(&pending).unwrap(),
        SignerCeremonyStatus::Missing
    ));
    let recovery_retry = restarted
        .prepare_custody(
            CustodyPrepareRequest {
                surface: legacy_local_surface(),
                ceremony_kind: CeremonyKind::WalletRecovery,
                custody_operation_id: pending,
                wallet_id: Some(token("released-wallet")),
                key_ref: None,
                exact_terms_digest: digest(42),
                expected_input_class: token("recovery-factor-v1"),
                browser_output_recipient_key: None,
                petal_key_scope: None,
                legacy_passkey_migration: None,
                derivation_requests: Vec::new(),
                wallet_seed_profile: None,
            },
            2_001,
        )
        .unwrap();
    assert_eq!(
        recovery_retry
            .contribution
            .credential_authority_generation
            .get(),
        0
    );

    let connection = Connection::open(path).unwrap();
    let after: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(after, 2);
    let generation_rows: u32 = connection
        .query_row(
            "SELECT count(*) FROM credential_authority_state",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(generation_rows, 0, "migration must not invent a revocation");
    let committed_at: String = connection
        .query_row(
            "SELECT committed_at_ms FROM ceremony_receipts WHERE operation_id = ?1",
            [operation(31).as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(committed_at, "0");
    let (migrated_custody_json, migrated_credential_json): (String, String) = connection
        .query_row(
            "SELECT w.custody_jcs, c.credential_jcs
             FROM ceremony_wallets w JOIN webauthn_credentials c USING (wallet_id)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(migrated_custody_json, custody_json);
    assert_eq!(migrated_credential_json, credential_json);
    let backup: WalletCustodyBackup = serde_json::from_str(&migrated_custody_json).unwrap();
    let custody = WalletCustody::restore(backup).unwrap();
    let credential_unlock = custody
        .unlock_with_credential(
            &Base64UrlBytes::from_bytes(&[21; 32]),
            &SecretBytes::new(vec![22; 32]),
        )
        .unwrap();
    let recovery_unlock = custody
        .unlock_with_recovery(&token("released-recovery"), &SecretBytes::new(vec![26; 32]))
        .unwrap();
    let expected_root = Digest32::from_bytes(Sha256::digest([23; 16]).into());
    assert_eq!(credential_unlock.root_fingerprint(), expected_root);
    assert_eq!(recovery_unlock.root_fingerprint(), expected_root);
    assert_eq!(
        credential_unlock.policy_verifying_key().unwrap(),
        recovery_unlock.policy_verifying_key().unwrap()
    );
}
