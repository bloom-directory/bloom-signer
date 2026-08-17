//! Custody loss-matrix after the reconciliation: the single custody path
//! serves both root-material profiles, with identical-children proof across
//! every factor for the BIP-39 profile.

use bloom_signer::custody::{RootMaterialProfile, WalletCustody, WalletCustodyBackup};
use bloom_signer_api::{Base64UrlBytes, Token};
use bloom_signer_backend_api::SecretBytes;
use bloom_signer_derive::{derive_solana_account, mnemonic_from_entropy, seed_from_mnemonic};
use bloom_signer_vectors as vectors;

fn key(byte: u8) -> SecretBytes {
    SecretBytes::new(vec![byte; 32])
}

fn cred(id: &str) -> Base64UrlBytes {
    Base64UrlBytes::from_bytes(id.as_bytes())
}

const WALLET: &str = "primary";
const RECOVERY: &str = "recovery-1";

fn solana_account(seed: &[u8; 64]) -> bloom_signer::bip39_signing::ActivatedAccount {
    let derived = derive_solana_account(seed, 0).unwrap();
    bloom_signer::bip39_signing::ActivatedAccount {
        profile: "bip44-solana-slip10-ed25519-v1".into(),
        path: derived.path,
        spki_der_hex: hex::encode(&derived.spki_der),
        fingerprint: bloom_signer_api::Digest32::from_bytes(derived.fingerprint),
    }
}

#[test]
fn bip39_two_passkeys_and_recovery_unlock_the_same_child() {
    let entropy = SecretBytes::new(hex::decode(vectors::BIP39_ENTROPY_HEX).unwrap());
    let custody = WalletCustody::register_bip39(
        Token::new(WALLET).unwrap(),
        entropy,
        key(0xAA), // policy signing seed
        key(0x11), // WKEK
        cred("cred-1"),
        key(0x22),
    )
    .unwrap();
    assert_eq!(
        custody.root_material_profile(),
        RootMaterialProfile::Bip39MulticurveV1
    );

    let unlocked_1 = custody
        .unlock_with_credential(&cred("cred-1"), &key(0x22))
        .unwrap();
    custody
        .add_credential(&unlocked_1, cred("cred-2"), &key(0x33))
        .unwrap();
    custody
        .set_recovery(&unlocked_1, Token::new(RECOVERY).unwrap(), &key(0x44))
        .unwrap();

    let seed: [u8; 64] = hex::decode(vectors::BIP39_SEED_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    let account = solana_account(&seed);
    let message = b"solana-native-transfer-v1";
    let sig_1 = unlocked_1.sign_ed25519(&account, message).unwrap();

    let unlocked_2 = custody
        .unlock_with_credential(&cred("cred-2"), &key(0x33))
        .unwrap();
    let sig_2 = unlocked_2.sign_ed25519(&account, message).unwrap();

    let unlocked_recovery = custody
        .unlock_with_recovery(&Token::new(RECOVERY).unwrap(), &key(0x44))
        .unwrap();
    let sig_recovery = unlocked_recovery.sign_ed25519(&account, message).unwrap();

    assert_eq!(sig_1, sig_2);
    assert_eq!(sig_1, sig_recovery);
}

#[test]
fn bip39_final_credential_cannot_be_removed_without_recovery() {
    let custody = WalletCustody::register_bip39(
        Token::new("single").unwrap(),
        SecretBytes::new(hex::decode(vectors::BIP39_ENTROPY_HEX).unwrap()),
        key(0xAA),
        key(0x11),
        cred("only"),
        key(0x22),
    )
    .unwrap();
    let result = custody.revoke_credential(&cred("only"));
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("final credential"));
}

#[test]
fn bip39_rekey_preserves_the_child_across_restart() {
    let entropy = SecretBytes::new(hex::decode(vectors::BIP39_ENTROPY_HEX).unwrap());
    let custody = WalletCustody::register_bip39(
        Token::new(WALLET).unwrap(),
        entropy,
        key(0xAA),
        key(0x11),
        cred("cred-1"),
        key(0x22),
    )
    .unwrap();
    let unlocked = custody
        .unlock_with_credential(&cred("cred-1"), &key(0x22))
        .unwrap();
    let seed: [u8; 64] = hex::decode(vectors::BIP39_SEED_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    let account = solana_account(&seed);
    let before = unlocked.sign_ed25519(&account, b"msg").unwrap();

    let mut keys = std::collections::BTreeMap::new();
    keys.insert(cred("cred-1").encoded().to_owned(), key(0x22));
    custody
        .rekey_wrap_format(&unlocked, 2, &keys, None)
        .unwrap();

    let unlocked_again = custody
        .unlock_with_credential(&cred("cred-1"), &key(0x22))
        .unwrap();
    let after = unlocked_again.sign_ed25519(&account, b"msg").unwrap();
    assert_eq!(before, after);
}

#[test]
fn bip39_mnemonic_export_reconstructs_the_frozen_words() {
    let custody = WalletCustody::register_bip39(
        Token::new(WALLET).unwrap(),
        SecretBytes::new(hex::decode(vectors::BIP39_ENTROPY_HEX).unwrap()),
        key(0xAA),
        key(0x11),
        cred("cred-1"),
        key(0x22),
    )
    .unwrap();
    let unlocked = custody
        .unlock_with_credential(&cred("cred-1"), &key(0x22))
        .unwrap();
    let mnemonic = custody.export_mnemonic(&unlocked).unwrap();
    assert_eq!(*mnemonic, vectors::BIP39_MNEMONIC);

    // The mnemonic round-trips to the same derived keys (portable recovery).
    let recovered_seed = seed_from_mnemonic(&mnemonic, "").unwrap();
    let expected: [u8; 64] = hex::decode(vectors::BIP39_SEED_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(*recovered_seed, expected);
}

#[test]
fn legacy_custody_rejects_mnemonic_export_and_keeps_its_path() {
    let custody = WalletCustody::register(
        Token::new("legacy").unwrap(),
        key(0x99), // 32-byte legacy seed
        key(0xAA),
        key(0x11),
        cred("cred-1"),
        key(0x22),
    )
    .unwrap();
    assert_eq!(
        custody.root_material_profile(),
        RootMaterialProfile::LegacySecp
    );
    let unlocked = custody
        .unlock_with_credential(&cred("cred-1"), &key(0x22))
        .unwrap();
    assert!(custody.export_mnemonic(&unlocked).is_err());

    // Legacy unlock still exposes a 32-byte root (BIP-32 seed) via the
    // backup round-trip, unchanged.
    let backup: WalletCustodyBackup = custody.backup();
    let restored = WalletCustody::restore(backup).unwrap();
    assert!(
        restored
            .unlock_with_credential(&cred("cred-1"), &key(0x22))
            .is_ok()
    );
}

#[test]
fn backup_round_trip_preserves_the_profile_and_unlocks() {
    let custody = WalletCustody::register_bip39(
        Token::new(WALLET).unwrap(),
        SecretBytes::new(hex::decode(vectors::BIP39_ENTROPY_HEX).unwrap()),
        key(0xAA),
        key(0x11),
        cred("cred-1"),
        key(0x22),
    )
    .unwrap();
    let backup: WalletCustodyBackup = custody.backup();
    let restored = WalletCustody::restore(backup).unwrap();
    assert_eq!(
        restored.root_material_profile(),
        RootMaterialProfile::Bip39MulticurveV1
    );
    let unlocked = restored
        .unlock_with_credential(&cred("cred-1"), &key(0x22))
        .unwrap();
    let mnemonic = restored.export_mnemonic(&unlocked).unwrap();
    assert_eq!(*mnemonic, vectors::BIP39_MNEMONIC);
}

#[test]
fn generated_entropy_wallet_is_a_valid_bip39_root() {
    let entropy = SecretBytes::new(vec![0x77u8; 32]);
    let custody = WalletCustody::register_bip39(
        Token::new("generated").unwrap(),
        entropy,
        key(0xAA),
        key(0x11),
        cred("cred-1"),
        key(0x22),
    )
    .unwrap();
    let unlocked = custody
        .unlock_with_credential(&cred("cred-1"), &key(0x22))
        .unwrap();
    let mnemonic = custody.export_mnemonic(&unlocked).unwrap();
    let canonical = mnemonic_from_entropy(&[0x77u8; 32]).unwrap();
    assert_eq!(*mnemonic, *canonical);
}
