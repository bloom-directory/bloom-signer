//! Copied into the exact released Signer checkout by
//! `test-released-schema1-compat.sh`. Keep this source compatible with
//! ccc9adb3866b17b87d2774018dcfa015184b1918.

use std::{collections::BTreeMap, env, path::Path, sync::Arc};

use bloom_signer::{
    ceremony::SignerCeremonyService,
    custody::WalletCustody,
    engine::{SignerAuditKeys, SignerEngine},
    registry::BackendRegistry,
};
use bloom_signer_api::{
    ActivationMode, Base64UrlBytes, CeremonyKind, CeremonyState, CredentialSummary, CryptoSuite,
    DecimalU64, Digest32, OperationId, SignerActivationReceipt, Token,
    WebAuthnCredential,
};
use bloom_signer_backend_api::SecretBytes;
use ciborium::value::{Integer, Value};
use ed25519_dalek::{Signer as _, SigningKey};
use p256::ecdsa::SigningKey as P256SigningKey;
use rusqlite::{params, Connection};

const FIXTURE_COMMIT: &str = "ccc9adb3866b17b87d2774018dcfa015184b1918";

fn token(value: &str) -> Token {
    Token::new(value).unwrap()
}

fn digest(byte: u8) -> Digest32 {
    Digest32::from_bytes([byte; 32])
}

fn operation(byte: u8) -> OperationId {
    OperationId::from_bytes([byte; 32])
}

fn integer(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}

fn fixture_cose_public_key() -> Vec<u8> {
    let signing_key = P256SigningKey::from_slice(&[30; 32]).unwrap();
    let point = signing_key.verifying_key().to_sec1_point(false);
    let value = Value::Map(vec![
        (integer(1), integer(2)),
        (integer(3), integer(-7)),
        (integer(-1), integer(1)),
        (
            integer(-2),
            Value::Bytes(point.x().expect("P-256 x coordinate").to_vec()),
        ),
        (
            integer(-3),
            Value::Bytes(point.y().expect("P-256 y coordinate").to_vec()),
        ),
    ]);
    let mut encoded = Vec::new();
    ciborium::into_writer(&value, &mut encoded).unwrap();
    encoded
}

fn audit_keys() -> SignerAuditKeys {
    SignerAuditKeys {
        current_key_id: token("signer-audit-key"),
        current_signing_key: SigningKey::from_bytes(&[14; 32]),
        historical_verifying_keys: BTreeMap::new(),
    }
}

fn engine(path: &Path) -> SignerEngine {
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
    .unwrap()
}

fn generate(path: &Path) {
    assert_eq!(env!("RELEASED_SIGNER_COMMIT"), FIXTURE_COMMIT);
    let _ = std::fs::remove_file(path);
    drop(engine(path));

    let wallet_id = token("released-wallet");
    let credential_id = Base64UrlBytes::from_bytes(&[21; 32]);
    let credential_key = SecretBytes::new(vec![22; 32]);
    let custody = WalletCustody::register_bip39(
        wallet_id.clone(),
        SecretBytes::new(vec![23; 16]),
        SecretBytes::new(vec![24; 32]),
        SecretBytes::new(vec![25; 32]),
        credential_id.clone(),
        credential_key.clone(),
    )
    .unwrap();
    let unlocked = custody
        .unlock_with_credential(&credential_id, &credential_key)
        .unwrap();
    custody
        .set_recovery(
            &unlocked,
            token("released-recovery"),
            &SecretBytes::new(vec![26; 32]),
        )
        .unwrap();
    let backup = custody.backup();
    assert!(backup.recovery_wrap.is_some());

    let credential = WebAuthnCredential {
        credential_id: credential_id.clone(),
        cose_public_key: Base64UrlBytes::from_bytes(&fixture_cose_public_key()),
        user_handle: Base64UrlBytes::from_bytes(&[28; 32]),
        rp_id: token("localhost"),
        prf_salt: Base64UrlBytes::from_bytes(&[29; 32]),
        sign_count: DecimalU64::new(4),
    };

    let signer = SigningKey::from_bytes(&[9; 32]);
    let mut custody_receipt = bloom_signer_api::CustodyResult {
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation(31),
        public_status: CeremonyState::Completed,
        wallet_id: Some(wallet_id.clone()),
        public_key_refs: Vec::new(),
        credential_summaries: vec![CredentialSummary {
            credential_id: credential_id.clone(),
            rp_id: token("localhost"),
            active: true,
        }],
        initial_policy: None,
        receipt_digest: digest(32),
        encrypted_browser_result: None,
        signer_key_id: token("signer-ceremony-key"),
        signer_signature: Base64UrlBytes::from_bytes(&[]),
    };
    custody_receipt.signer_signature = Base64UrlBytes::from_bytes(
        &signer
            .sign(
                &[
                    b"bloom-signer-ceremony-receipt/v1".as_slice(),
                    &custody_receipt.unsigned_canonical_bytes().unwrap(),
                ]
                .concat(),
            )
            .to_bytes(),
    );

    let key_ref = bloom_signer_api::KeyRef {
        backend: token("local"),
        backend_instance: token("released-wallet"),
        locator: "root".into(),
        key_spec: bloom_signer_api::KeySpec::Secp256k1,
        public_key_fingerprint: digest(33),
        derivation: None,
    };
    let mut activation_receipt = SignerActivationReceipt {
        activation_operation_id: operation(34),
        ceremony_id: digest(35),
        approval_id: digest(36),
        approval_digest: digest(37),
        review_manifest_digest: digest(38),
        key_ref,
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Sha256Recoverable],
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: DecimalU64::new(1),
        replaced_approval_id: None,
        activated_at_ms: DecimalU64::new(1_000),
        expires_at_ms: DecimalU64::new(2_000),
        signer_key_id: token("signer-ceremony-key"),
        signer_signature: Base64UrlBytes::from_bytes(&[]),
    };
    activation_receipt.signer_signature = Base64UrlBytes::from_bytes(
        &signer
            .sign(
                &[
                    b"bloom-signer-ceremony-receipt/v1".as_slice(),
                    &activation_receipt.unsigned_canonical_bytes().unwrap(),
                ]
                .concat(),
            )
            .to_bytes(),
    );

    let connection = Connection::open(path).unwrap();
    connection
        .execute(
            "INSERT INTO ceremony_wallets(wallet_id, custody_jcs) VALUES (?1, ?2)",
            params![wallet_id.as_str(), serde_jcs::to_string(&backup).unwrap()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO webauthn_credentials(credential_id, wallet_id, credential_jcs, created_at_ms)
             VALUES (?1, ?2, ?3, '900')",
            params![
                credential_id.encoded(),
                wallet_id.as_str(),
                serde_jcs::to_string(&credential).unwrap()
            ],
        )
        .unwrap();
    for (operation_id, kind, receipt) in [
        (
            custody_receipt.custody_operation_id.as_str(),
            "custody",
            serde_jcs::to_string(&custody_receipt).unwrap(),
        ),
        (
            activation_receipt.activation_operation_id.as_str(),
            "sealed_approval",
            serde_jcs::to_string(&activation_receipt).unwrap(),
        ),
    ] {
        connection
            .execute(
                "INSERT INTO ceremony_receipts(operation_id, receipt_kind, receipt_jcs)
                 VALUES (?1, ?2, ?3)",
                params![operation_id, kind, receipt],
            )
            .unwrap();
    }
    let failed = serde_jcs::to_string(&bloom_signer_api::CeremonyPublicStatus {
        ceremony_id: digest(39),
        ceremony_kind: CeremonyKind::WalletExport,
        operation_id: operation(40),
        state: CeremonyState::Failed,
        expires_at_ms: DecimalU64::new(3_000),
        ceremony_url: None,
        receipt_digest: None,
    })
    .unwrap();
    connection
        .execute(
            "INSERT INTO ceremony_statuses(operation_id, status_jcs) VALUES (?1, ?2)",
            params![operation(40).as_str(), failed],
        )
        .unwrap();
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 0, "released package schema 1 used SQLite marker 0");
}

fn rollback_open(path: &Path) {
    assert_eq!(env!("RELEASED_SIGNER_COMMIT"), FIXTURE_COMMIT);
    let engine = Arc::new(engine(path));
    let service = SignerCeremonyService::new(
        engine,
        token("signer-ceremony-key"),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    assert!(service
        .credential(
            &token("released-wallet"),
            &Base64UrlBytes::from_bytes(&[21; 32])
        )
        .is_ok());
    assert!(matches!(
        service.status(&operation(31)).unwrap(),
        bloom_signer::ceremony::SignerCeremonyStatus::CompletedCustody(_)
    ));
}

#[test]
fn released_schema1_fixture_action() {
    let path = env::var_os("BLOOM_RELEASED_SCHEMA1_DB").expect("fixture database path");
    match env::var("BLOOM_RELEASED_SCHEMA1_ACTION").as_deref() {
        Ok("generate") => generate(Path::new(&path)),
        Ok("rollback-open") => rollback_open(Path::new(&path)),
        _ => panic!("unknown fixture action"),
    }
}
