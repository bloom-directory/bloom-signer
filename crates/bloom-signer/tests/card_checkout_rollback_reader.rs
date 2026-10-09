//! Run as an integration test against exactly the Signer shipped in v0.3.2.
//! Generate the released wallet here, add a card with the candidate Signer,
//! then reopen the same wallet with the exact released revision.
mod support;
use bloom_signer::{
    ceremony::SignerCeremonyService,
    custody::{WalletCustody, WalletCustodyBackup},
    engine::{SignerAuditKeys, SignerEngine},
    registry::BackendRegistry,
};
use bloom_signer_api::*;
use bloom_signer_backend_api::SecretBytes;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

#[test]
#[ignore = "requires an explicit retained fixture and execution against the released revision"]
fn released_signer_reopens_wallet_state_and_ignores_card_file() {
    let root = PathBuf::from(
        std::env::var("BLOOM_CARD_ROLLBACK_FIXTURE_DIR").expect("explicit fixture root required"),
    );
    let engine = Arc::new(
        SignerEngine::open(
            root.join("signer.sqlite3"),
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            SignerAuditKeys {
                current_key_id: Token::new("signer-audit-key").unwrap(),
                current_signing_key: SigningKey::from_bytes(&[14; 32]),
                historical_verifying_keys: BTreeMap::new(),
            },
            Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap()),
        )
        .unwrap(),
    );
    if std::env::var("BLOOM_CARD_ROLLBACK_ACTION").as_deref() == Ok("generate") {
        let auth = support::VirtualAuthenticator::generate();
        let credential = auth.credential(0);
        let wallet = WalletCustody::register_bip39(
            Token::new("rollback-wallet").unwrap(),
            SecretBytes::new(vec![2; 16]),
            SecretBytes::new(vec![3; 32]),
            SecretBytes::new(vec![4; 32]),
            credential.credential_id.clone(),
            SecretBytes::new(vec![6; 32]),
        )
        .unwrap();
        let unlocked = wallet
            .unlock_with_credential(&credential.credential_id, &SecretBytes::new(vec![6; 32]))
            .unwrap();
        std::fs::write(
            root.join("wallet-root-fingerprint.txt"),
            unlocked.root_fingerprint().as_str(),
        )
        .unwrap();
        let db = rusqlite::Connection::open(root.join("signer.sqlite3")).unwrap();
        db.execute(
            "INSERT INTO ceremony_wallets(wallet_id,custody_jcs) VALUES ('rollback-wallet',?1)",
            [serde_jcs::to_string(&wallet.backup()).unwrap()],
        )
        .unwrap();
        db.execute("INSERT INTO webauthn_credentials(credential_id,wallet_id,credential_jcs,created_at_ms) VALUES (?1,'rollback-wallet',?2,'1760000000000')",
            rusqlite::params![credential.credential_id.encoded(),serde_jcs::to_string(&credential).unwrap()]).unwrap();
        return;
    }
    let card_path = root.join("cards.sqlite3");
    let before = Sha256::digest(std::fs::read(&card_path).unwrap());
    let ceremony = SignerCeremonyService::new(
        engine,
        Token::new("signer-ceremony-key").unwrap(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    let connection = rusqlite::Connection::open(root.join("signer.sqlite3")).unwrap();
    let raw: String = connection
        .query_row(
            "SELECT custody_jcs FROM ceremony_wallets WHERE wallet_id='rollback-wallet'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let backup: WalletCustodyBackup = serde_json::from_str(&raw).unwrap();
    let credential_id = backup.credential_wraps[0].credential_id.clone();
    assert!(
        ceremony
            .credential(&Token::new("rollback-wallet").unwrap(), &credential_id)
            .is_ok()
    );
    let wallet = WalletCustody::restore(backup).unwrap();
    let unlocked = wallet
        .unlock_with_credential(&credential_id, &SecretBytes::new(vec![6; 32]))
        .unwrap();
    let expected = std::fs::read_to_string(root.join("wallet-root-fingerprint.txt")).unwrap();
    assert!(unlocked.root_fingerprint().as_str() == expected);
    assert!(Sha256::digest(std::fs::read(&card_path).unwrap()) == before);
}
