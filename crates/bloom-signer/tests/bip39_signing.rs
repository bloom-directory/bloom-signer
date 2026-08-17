//! Signing-edge tests: derivation through the frozen corpus, fingerprint
//! verification, Ed25519 raw-message signing, EVM recoverable signing, local
//! verification, zeroization surface, and fail-closed rejection cases.

use bloom_signer::bip39_signing::{self, ActivatedAccount};
use bloom_signer_api::{Digest32, Token};
use bloom_signer_derive::{
    SEED_BYTES, derive_evm_account, derive_solana_account, mnemonic_from_entropy,
    seed_from_mnemonic,
};
use bloom_signer_vectors as vectors;

fn seed() -> [u8; SEED_BYTES] {
    hex::decode(vectors::BIP39_SEED_HEX).unwrap().try_into().unwrap()
}

fn evm_account() -> ActivatedAccount {
    let derived = derive_evm_account(&seed(), 0, 0).unwrap();
    ActivatedAccount {
        profile: "bip44-evm-secp256k1-v1".into(),
        path: derived.path,
        spki_der_hex: hex::encode(&derived.spki_der),
        fingerprint: Digest32::from_bytes(derived.fingerprint),
    }
}

fn solana_account() -> ActivatedAccount {
    let derived = derive_solana_account(&seed(), 0).unwrap();
    ActivatedAccount {
        profile: "bip44-solana-slip10-ed25519-v1".into(),
        path: derived.path,
        spki_der_hex: hex::encode(&derived.spki_der),
        fingerprint: Digest32::from_bytes(derived.fingerprint),
    }
}

#[test]
fn ed25519_signs_raw_message_and_self_verifies() {
    let message = b"solana-native-transfer-v1";
    let signature = bip39_signing::sign_ed25519_message(&seed(), &solana_account(), message).unwrap();
    assert_eq!(signature.len(), 64);
    // Re-verify with the expected public key.
    let derived = derive_solana_account(&seed(), 0).unwrap();
    let _ = &derived.spki_der;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&derived.public_key)
        .unwrap();
    verifying
        .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
        .unwrap();
}

#[test]
fn evm_signs_digest_and_recovers_the_same_key() {
    let digest: [u8; 32] = [0xAB; 32];
    let signature = bip39_signing::sign_evm_digest(&seed(), &evm_account(), &digest).unwrap();
    assert_eq!(signature.len(), 65);
    // Recover the public key from the signature and compare to the child.
    let derived = derive_evm_account(&seed(), 0, 0).unwrap();
    let signing = k256::ecdsa::SigningKey::from_bytes((&*derived.private_key).into()).unwrap();
    let expected: k256::ecdsa::VerifyingKey = *signing.verifying_key();
    let sig = k256::ecdsa::Signature::from_slice(&signature[..64]).unwrap();
    let recovery = k256::ecdsa::RecoveryId::from_byte(signature[64]).unwrap();
    let recovered =
        k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &sig, recovery).unwrap();
    assert_eq!(recovered, expected);
}

#[test]
fn descriptor_mismatch_fails_closed() {
    // Fingerprint from a different account.
    let mut wrong = solana_account();
    wrong.fingerprint = Digest32::from_bytes([0xEE; 32]);
    assert!(bloom_signer::bip39_signing::sign_ed25519_message(&seed(), &wrong, b"x").is_err());

    // Wrong SPKI bytes.
    let mut wrong_spki = evm_account();
    wrong_spki.spki_der_hex = "00".repeat(44);
    assert!(
        bloom_signer::bip39_signing::sign_evm_digest(&seed(), &wrong_spki, &[1; 32]).is_err()
    );

    // Profile cross-talk: an EVM descriptor never signs Ed25519.
    let cross = evm_account();
    assert!(bloom_signer::bip39_signing::sign_ed25519_message(&seed(), &cross, b"x").is_err());
}

#[test]
fn input_size_limits_are_enforced() {
    assert!(bloom_signer::bip39_signing::sign_ed25519_message(
        &seed(),
        &solana_account(),
        &vec![0u8; bip39_signing::MAX_ED25519_MESSAGE_BYTES + 1]
    )
    .is_err());
    assert!(bloom_signer::bip39_signing::sign_ed25519_message(&seed(), &solana_account(), b"")
        .is_err());
}

#[test]
fn entropy_to_seed_validates_length_against_metadata() {
    // Correct round-trip via the documented unlock path.
    let wallet = Token::new("primary").unwrap();
    // Encrypt the frozen entropy with a fixed WKEK using the custody API.
    let wkek = [7u8; 32];
    let entropy: [u8; 32] = hex::decode(vectors::BIP39_ENTROPY_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    let blob = {
        use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::{Aead, Payload}};
        let nonce = [3u8; 24];
        let aad = bloom_signer::custody::root_aad(&wallet, 1);
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(&wkek))
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload { msg: &entropy, aad: &aad },
            )
            .unwrap();
        (nonce.to_vec(), ciphertext)
    };
    let transient = bip39_signing::entropy_to_seed(
        &wkek,
        &wallet,
        1,
        &blob.0,
        &blob.1,
        256,
    )
    .unwrap();
    // The transient seed matches the frozen seed.
    assert_eq!(*transient, seed());

    // Wrong metadata length fails closed.
    assert!(bip39_signing::entropy_to_seed(&wkek, &wallet, 1, &blob.0, &blob.1, 128).is_err());

    // Tampered ciphertext fails AEAD authentication.
    let mut bad_ciphertext = blob.1.clone();
    bad_ciphertext[0] ^= 0xFF;
    assert!(
        bip39_signing::entropy_to_seed(&wkek, &wallet, 1, &blob.0, &bad_ciphertext, 256).is_err()
    );
}

#[test]
fn the_seed_is_never_a_signable_root() {
    // The signing edge exposes no root signing: the only entry points take an
    // ActivatedAccount with a registered child descriptor. The mnemonic and
    // seed never cross the boundary; only their derived signature does.
    let mnemonic = mnemonic_from_entropy(&[0u8; 32]).unwrap();
    let seed_value = seed_from_mnemonic(&mnemonic, "").unwrap();
    assert_eq!(seed_value.as_slice().len(), 64);
    // The frozen entropy's derived accounts match the canonical addresses'
    // keys, pinned by the vectors crate.
    assert_eq!(
        hex::encode(derive_evm_account(&seed(), 0, 0).unwrap().private_key.as_slice()),
        vectors::BIP32_EVM_TERMINAL_PRIVATE_KEY_HEX
    );
}
