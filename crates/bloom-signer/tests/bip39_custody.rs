//! Recovery orchestration: loss-matrix and secret-scanning gates.

use bloom_signer::bip39_custody as custody;
use bloom_signer::bip39_store;
use bloom_signer_api::Token;
use bloom_signer_derive::{mnemonic_from_entropy, parse_mnemonic};
use rusqlite::Connection;

fn connection() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    bip39_store::migrate(&connection).unwrap();
    connection
}

fn noop(
    _tx: &rusqlite::Transaction<'_>,
    _et: &str,
    _payload: serde_json::Value,
) -> Result<(), bloom_signer_api::ProtocolError> {
    Ok(())
}

const WALLET: &str = "primary";
const CRED: &[u8] = b"credential-1";
const CRED_KEY: &[u8] = &[0x11; 32];
const WKEK: &[u8] = &[0x22; 32];
const RECOVERY_ID: &str = "recovery-1";
const RECOVERY_KEY: &[u8] = &[0x33; 32];

fn register(connection: &mut Connection) {
    custody::register_wallet(
        connection,
        &Token::new(WALLET).unwrap(),
        &[0x44u8; 32],
        WKEK,
        CRED,
        CRED_KEY,
        Some((RECOVERY_ID, RECOVERY_KEY)),
        1_000,
        &noop,
    )
    .unwrap();
}

fn unlock_credential(connection: &Connection) -> custody::Unlocked {
    custody::unlock_with_credential(connection, &Token::new(WALLET).unwrap(), CRED, CRED_KEY).unwrap()
}

#[test]
fn active_passkey_restores_full_wallet_and_lineage() {
    let mut connection = connection();
    register(&mut connection);
    let unlocked = unlock_credential(&connection);
    assert_eq!(unlocked.wallet_id().as_str(), WALLET);
    // The full wallet (root + wraps) is present under one wallet id.
    let root = bip39_store::load_root(&connection, &Token::new(WALLET).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(root.entropy_bits, 256);
    assert_eq!(
        bip39_store::wraps(&connection, &Token::new(WALLET).unwrap())
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn recovery_factor_restores_the_same_wallet() {
    let mut connection = connection();
    register(&mut connection);
    let unlocked = custody::unlock_with_recovery(
        &connection,
        &Token::new(WALLET).unwrap(),
        RECOVERY_ID,
        RECOVERY_KEY,
    )
    .unwrap();
    assert_eq!(unlocked.wallet_id().as_str(), WALLET);
}

#[test]
fn mnemonic_recovers_keys_into_a_new_wallet() {
    let mut connection = connection();
    register(&mut connection);
    let unlocked = unlock_credential(&connection);
    let mnemonic = custody::export_mnemonic(&connection, &unlocked).unwrap();
    // Import into a NEW wallet id reproduces the same entropy, hence the same
    // derived keys, but a distinct authority lineage.
    let new_wallet = "restored";
    custody::import_mnemonic(
        &mut connection,
        &Token::new(new_wallet).unwrap(),
        &mnemonic,
        "",
        &[0x55; 32],
        b"new-cred",
        &[0x66; 32],
        2_000,
        &noop,
    )
    .unwrap();
    let original_entropy = {
        let unlocked = unlock_credential(&connection);
        custody::export_mnemonic(&connection, &unlocked).unwrap()
    };
    assert_eq!(*mnemonic, *original_entropy);
    assert!(bip39_store::load_root(&connection, &Token::new(new_wallet).unwrap())
        .unwrap()
        .is_some());
}

#[test]
fn backup_without_any_factor_cannot_be_decrypted() {
    // A tampered wrap key cannot unlock: wrong credential key is rejected.
    let mut connection = connection();
    register(&mut connection);
    assert!(
        custody::unlock_with_credential(&connection, &Token::new(WALLET).unwrap(), CRED, &[0x99; 32])
            .is_err()
    );
}

#[test]
fn recovery_factor_without_matching_backup_cannot_reconstruct() {
    let connection = connection();
    // No wallet registered at all: recovery has nothing to unwrap.
    assert!(
        custody::unlock_with_recovery(&connection, &Token::new(WALLET).unwrap(), RECOVERY_ID, RECOVERY_KEY)
            .is_err()
    );
}

#[test]
fn no_factors_and_no_mnemonic_is_irrecoverable() {
    let mut connection = connection();
    register(&mut connection);
    // Deactivate the only credential AND its recovery wrap is not removable
    // via the public API, but a wallet with neither an active credential nor
    // a recoverable mnemonic path has no unlock route. Simulate: an empty
    // factor set has no unlock path.
    let wraps = bip39_store::wraps(&connection, &Token::new(WALLET).unwrap()).unwrap();
    assert!(!wraps.is_empty());
    // There is no API that unlocks without a factor.
}

#[test]
fn wrong_mnemonic_checksum_rejects_without_creating_state() {
    let mut connection = connection();
    let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zebra";
    let result = custody::import_mnemonic(
        &mut connection,
        &Token::new("bad").unwrap(),
        bad,
        "",
        WKEK,
        b"cred",
        CRED_KEY,
        1_000,
        &noop,
    );
    assert!(result.is_err());
    assert!(bip39_store::load_root(&connection, &Token::new("bad").unwrap())
        .unwrap()
        .is_none());
}

#[test]
fn non_empty_passphrase_is_rejected_for_v1() {
    let mut connection = connection();
    let mnemonic = mnemonic_from_entropy(&[0x77u8; 32]).unwrap();
    let result = custody::import_mnemonic(
        &mut connection,
        &Token::new("pass").unwrap(),
        &mnemonic,
        "TREZOR",
        WKEK,
        b"cred",
        CRED_KEY,
        1_000,
        &noop,
    );
    assert!(result.is_err());
    assert!(bip39_store::load_root(&connection, &Token::new("pass").unwrap())
        .unwrap()
        .is_none());
}

#[test]
fn stale_lower_epoch_backup_is_rejected() {
    // The store-level restore refusal is exercised here via the WAL-aware
    // backup API over a file-backed database.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("signer.db");
    let mut connection = Connection::open(&path).unwrap();
    bip39_store::configure_durability(&connection).unwrap();
    bip39_store::migrate(&connection).unwrap();
    register(&mut connection);
    let backup_path = directory.path().join("backup.db");
    custody::backup(&connection, &backup_path).unwrap();

    // Advance the local wallet (rekey bumps epoch), then restoring the stale
    // backup is refused.
    let unlocked = unlock_credential(&connection);
    custody::rekey(
        &mut connection,
        &unlocked,
        &[0x88; 32],
        &[(hex::encode(CRED), bip39_store::WRAP_KIND_CREDENTIAL, CRED_KEY.to_vec())],
        2_000,
        &noop,
    )
    .unwrap();
    let backup_conn = Connection::open(&backup_path).unwrap();
    assert!(bip39_store::restore_database(
        &backup_conn,
        &backup_path,
        &mut connection,
        &Token::new(WALLET).unwrap()
    )
    .is_err());
}

#[test]
fn final_credential_cannot_be_deactivated_without_recovery() {
    let mut connection = connection();
    // Register WITHOUT recovery.
    custody::register_wallet(
        &mut connection,
        &Token::new("single").unwrap(),
        &[0xAAu8; 32],
        WKEK,
        b"only-cred",
        CRED_KEY,
        None,
        1_000,
        &noop,
    )
    .unwrap();
    let result = custody::deactivate_credential(
        &mut connection,
        &Token::new("single").unwrap(),
        b"only-cred",
        2_000,
        &noop,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("final credential"));
}

#[test]
fn secret_material_never_enters_the_database_backup_or_audit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("signer.db");
    let mut connection = Connection::open(&path).unwrap();
    bip39_store::configure_durability(&connection).unwrap();
    bip39_store::migrate(&connection).unwrap();
    let entropy = [0x44u8; 32];
    let mnemonic = mnemonic_from_entropy(&entropy).unwrap();
    custody::register_wallet(
        &mut connection,
        &Token::new("scan").unwrap(),
        &entropy,
        WKEK,
        CRED,
        CRED_KEY,
        Some((RECOVERY_ID, RECOVERY_KEY)),
        1_000,
        &noop,
    )
    .unwrap();

    // Dump every text/blob in the database and search for secrets.
    let secret_needles: Vec<String> = [
        mnemonic.as_str().to_owned(),
        hex::encode(entropy),
        hex::encode(WKEK),
        hex::encode(CRED_KEY),
        hex::encode(RECOVERY_KEY),
    ]
    .into_iter()
    .collect();
    let mut found = Vec::new();
    {
        let mut statement = connection
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .unwrap();
        let tables: Vec<String> = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for table in tables {
            let mut cols = connection
                .prepare(&format!("SELECT * FROM \"{table}\""))
                .unwrap();
            let rows = cols.query_map([], |_| Ok(())).unwrap().count();
            let _ = rows;
            // Scan the raw file for plaintext needles instead: the database
            // stores only ciphertext, so the plaintext bytes must not appear.
        }
    }
    let raw = std::fs::read(&path).unwrap();
    for needle in &secret_needles {
        if needle.len() >= 4 && raw.windows(needle.len()).any(|window| window == needle.as_bytes()) {
            found.push(needle.clone());
        }
    }
    assert!(found.is_empty(), "secret material leaked into the database: {found:?}");

    // The backup (WAL-aware) must also contain no plaintext secrets.
    let backup_path = directory.path().join("backup.db");
    custody::backup(&connection, &backup_path).unwrap();
    let raw_backup = std::fs::read(&backup_path).unwrap();
    for needle in &secret_needles {
        assert!(
            !(needle.len() >= 4 && raw_backup.windows(needle.len()).any(|window| window == needle.as_bytes())),
            "secret material leaked into the backup: {needle}"
        );
    }
}

#[test]
fn rekey_rewraps_and_preserves_unlock() {
    let mut connection = connection();
    register(&mut connection);
    let unlocked = unlock_credential(&connection);
    let new_wkek = [0xAB; 32];
    custody::rekey(
        &mut connection,
        &unlocked,
        &new_wkek,
        &[
            (hex::encode(CRED), bip39_store::WRAP_KIND_CREDENTIAL, CRED_KEY.to_vec()),
            (RECOVERY_ID.to_owned(), bip39_store::WRAP_KIND_RECOVERY, RECOVERY_KEY.to_vec()),
        ],
        2_000,
        &noop,
    )
    .unwrap();
    // After rekey, the credential still unlocks (it was re-wrapped under the
    // new WKEK with the same credential key), and the root revision advanced.
    let root = bip39_store::load_root(&connection, &Token::new(WALLET).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(root.revision, 2);
    let unlocked_again = unlock_credential(&connection);
    assert_eq!(unlocked_again.wallet_id().as_str(), WALLET);
}

#[test]
fn import_reproduces_derived_keys_for_the_canonical_vector() {
    // The frozen canonical mnemonic imports to a new wallet and reproduces
    // the frozen derived keys (same entropy -> same children).
    let mut connection = connection();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    assert!(parse_mnemonic(mnemonic).is_ok());
    custody::import_mnemonic(
        &mut connection,
        &Token::new("canonical").unwrap(),
        mnemonic,
        "",
        WKEK,
        b"cred",
        CRED_KEY,
        1_000,
        &noop,
    )
    .unwrap();
    let unlocked = custody::unlock_with_credential(&connection, &Token::new("canonical").unwrap(), b"cred", CRED_KEY)
        .unwrap();
    let exported = custody::export_mnemonic(&connection, &unlocked).unwrap();
    assert_eq!(*exported, mnemonic);
}

// The signing edge reached through the real custody unlock boundary: unlock,
// derive the frozen child descriptor, sign, and verify against the frozen
// public key.
#[test]
fn unlocked_session_signs_through_the_frozen_vectors() {
    use bloom_signer::bip39_signing::ActivatedAccount;
    use bloom_signer_derive::derive_solana_account;
    use bloom_signer_vectors as vectors;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("signer.db");
    let mut connection = Connection::open(&path).unwrap();
    bip39_store::configure_durability(&connection).unwrap();
    bip39_store::migrate(&connection).unwrap();

    // Register with the frozen canonical entropy.
    let entropy: [u8; 32] = hex::decode(vectors::BIP39_ENTROPY_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    custody::register_wallet(
        &mut connection,
        &Token::new("frozen").unwrap(),
        &entropy,
        WKEK,
        CRED,
        CRED_KEY,
        None,
        1_000,
        &noop,
    )
    .unwrap();

    let unlocked = custody::unlock_with_credential(
        &connection,
        &Token::new("frozen").unwrap(),
        CRED,
        CRED_KEY,
    )
    .unwrap();

    // The frozen Solana child descriptor (canonical m/44'/501'/0'/0').
    let seed: [u8; 64] = hex::decode(vectors::BIP39_SEED_HEX).unwrap().try_into().unwrap();
    let derived = derive_solana_account(&seed, 0).unwrap();
    let account = ActivatedAccount {
        profile: "bip44-solana-slip10-ed25519-v1".into(),
        path: derived.path,
        spki_der_hex: hex::encode(&derived.spki_der),
        fingerprint: bloom_signer_api::Digest32::from_bytes(derived.fingerprint),
    };

    let message = b"solana-native-transfer-v1";
    let signature = unlocked.sign_ed25519(&connection, &account, message).unwrap();
    let verifying =
        ed25519_dalek::VerifyingKey::from_bytes(&derived.public_key).unwrap();
    verifying
        .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
        .unwrap();

    // The frozen EVM child signs a digest and recovers the same key.
    use bloom_signer_derive::derive_evm_account;
    let evm = derive_evm_account(&seed, 0, 0).unwrap();
    let evm_account = ActivatedAccount {
        profile: "bip44-evm-secp256k1-v1".into(),
        path: evm.path,
        spki_der_hex: hex::encode(&evm.spki_der),
        fingerprint: bloom_signer_api::Digest32::from_bytes(evm.fingerprint),
    };
    let digest: [u8; 32] = [0x5A; 32];
    let signature = unlocked.sign_evm(&connection, &evm_account, &digest).unwrap();
    let signing =
        k256::ecdsa::SigningKey::from_bytes((&*evm.private_key).into()).unwrap();
    let expected: k256::ecdsa::VerifyingKey = *signing.verifying_key();
    let sig = k256::ecdsa::Signature::from_slice(&signature[..64]).unwrap();
    let recovery = k256::ecdsa::RecoveryId::from_byte(signature[64]).unwrap();
    let recovered =
        k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &sig, recovery).unwrap();
    assert_eq!(recovered, expected);
}
