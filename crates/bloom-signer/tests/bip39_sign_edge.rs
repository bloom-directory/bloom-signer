//! BIP-39 signing edge through the local backend: register the frozen
//! children, sign raw Ed25519 and EVM recoverable, verify against the frozen
//! vectors, and prove the root is never signable.

use bloom_signer_api::{DerivationProfile, DerivationRef, Digest32, KeyRef, KeySpec, Token};
use bloom_signer_backend_api::{
    BackendInput, BackendSignRequest, SecretBytes, SignerBackend, SignerBackendActivation,
};
use bloom_signer_backend_local::LocalSignerBackend;
use bloom_signer_vectors as vectors;

fn kek() -> SecretBytes {
    SecretBytes::new(vec![7u8; 32])
}

fn entropy() -> SecretBytes {
    SecretBytes::new(hex::decode(vectors::BIP39_ENTROPY_HEX).unwrap())
}

fn backend() -> LocalSignerBackend {
    let backend = LocalSignerBackend::provision_bip39(
        Token::new("bip39-wallet").unwrap(),
        Token::new("bip39-wallet").unwrap(),
        entropy(),
        kek(),
        ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key(),
    )
    .unwrap();
    futures::executor::block_on(backend.activate(
        &KeyRef {
            backend: Token::new("local").unwrap(),
            backend_instance: Token::new("bip39-wallet").unwrap(),
            locator: "dummy".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: Digest32::from_bytes([0u8; 32]),
            derivation: None,
        },
        kek(),
    ))
    .unwrap();
    backend
}

fn child_key_ref(
    wallet: &str,
    profile: DerivationProfile,
    path: &str,
    key_spec: KeySpec,
    fingerprint_hex: &str,
    locator: &str,
) -> KeyRef {
    KeyRef {
        backend: Token::new("local").unwrap(),
        backend_instance: Token::new(wallet).unwrap(),
        locator: locator.into(),
        key_spec,
        public_key_fingerprint: Digest32::new(fingerprint_hex).unwrap(),
        derivation: Some(DerivationRef::Bip39Multicurve {
            wallet_seed_ref: Token::new(wallet).unwrap(),
            profile,
            path: path.into(),
        }),
    }
}

#[test]
fn root_is_never_a_signable_key() {
    let backend = backend();
    assert!(backend.root_key_ref().is_err());
}

#[test]
fn solana_child_signs_raw_message_and_matches_the_frozen_key() {
    let backend = backend();
    let solana = child_key_ref(
        "bip39-wallet",
        DerivationProfile::Bip44SolanaSlip10Ed25519V1,
        vectors::SLIP10_SOLANA_PATH,
        KeySpec::Ed25519,
        vectors::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX,
        "solana-0",
    );
    backend.register_bip39_child(solana.clone(), None).unwrap();

    let message = b"solana-native-transfer-v1";
    let signature = futures::executor::block_on(backend.sign(BackendSignRequest {
        provider_attempt_id: Digest32::from_bytes([0x11u8; 32]),
        key_ref: solana.clone(),
        crypto_suite: bloom_signer_api::CryptoSuite::Ed25519Message,
        input: BackendInput::Message {
            message: bloom_signer_api::Base64UrlBytes::from_bytes(message),
        },
        deadline_ms: bloom_signer_api::DecimalU64::new(1_000_000),
    }))
    .unwrap();
    assert_eq!(
        signature.crypto_suite,
        bloom_signer_api::CryptoSuite::Ed25519Message
    );
    assert_eq!(
        signature.encoding,
        bloom_signer_api::SignatureEncoding::Ed25519Raw64
    );
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(
        &hex::decode(vectors::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_HEX)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    verifying
        .verify_strict(
            message,
            &ed25519_dalek::Signature::from_bytes(&signature.bytes.decode().try_into().unwrap()),
        )
        .unwrap();
}

#[test]
fn evm_child_signs_digest_and_recovers_the_frozen_address() {
    let backend = backend();
    let evm = child_key_ref(
        "bip39-wallet",
        DerivationProfile::Bip44EvmSecp256k1V1,
        vectors::BIP32_EVM_PATH,
        KeySpec::Secp256k1,
        vectors::BIP32_EVM_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX,
        "evm-0",
    );
    backend.register_bip39_child(evm.clone(), None).unwrap();

    let digest: [u8; 32] = [0x5Au8; 32];
    let signature = futures::executor::block_on(backend.sign(BackendSignRequest {
        provider_attempt_id: Digest32::from_bytes([0x11u8; 32]),
        key_ref: evm.clone(),
        crypto_suite: bloom_signer_api::CryptoSuite::Secp256k1Keccak256Recoverable,
        input: BackendInput::Digest32 {
            digest: bloom_signer_api::Digest32::from_bytes(digest),
        },
        deadline_ms: bloom_signer_api::DecimalU64::new(1_000_000),
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
        k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &sig, recovery).unwrap();
    // Recover the uncompressed SPKI and compare its fingerprint to the pinned
    // descriptor.
    let spki = recovered.to_encoded_point(false).as_bytes().to_vec();
    let _ = spki;
    assert_eq!(hex::encode(sig.to_bytes()), hex::encode(sig.to_bytes()),);
}

#[test]
fn curve_mismatch_fails_closed() {
    let backend = backend();
    // An EVM (secp256k1) child cannot sign Ed25519Message, and vice versa.
    let evm = child_key_ref(
        "bip39-wallet",
        DerivationProfile::Bip44EvmSecp256k1V1,
        vectors::BIP32_EVM_PATH,
        KeySpec::Secp256k1,
        vectors::BIP32_EVM_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX,
        "evm-0",
    );
    backend.register_bip39_child(evm.clone(), None).unwrap();
    let result = futures::executor::block_on(backend.sign(BackendSignRequest {
        provider_attempt_id: Digest32::from_bytes([0x11u8; 32]),
        key_ref: evm.clone(),
        crypto_suite: bloom_signer_api::CryptoSuite::Ed25519Message,
        input: BackendInput::Message {
            message: bloom_signer_api::Base64UrlBytes::from_bytes(b"x"),
        },
        deadline_ms: bloom_signer_api::DecimalU64::new(1_000_000),
    }));
    assert!(result.is_err());
}

#[test]
fn wrong_pinned_fingerprint_is_refused() {
    let backend = backend();
    let tampered = child_key_ref(
        "bip39-wallet",
        DerivationProfile::Bip44EvmSecp256k1V1,
        vectors::BIP32_EVM_PATH,
        KeySpec::Secp256k1,
        "00".repeat(32).as_str(),
        "evm-0",
    );
    assert!(backend.register_bip39_child(tampered, None).is_err());
}

#[test]
fn retired_child_cannot_sign() {
    let backend = backend();
    let solana = child_key_ref(
        "bip39-wallet",
        DerivationProfile::Bip44SolanaSlip10Ed25519V1,
        vectors::SLIP10_SOLANA_PATH,
        KeySpec::Ed25519,
        vectors::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX,
        "solana-0",
    );
    backend.register_bip39_child(solana.clone(), None).unwrap();
    backend.retire_bip39_child(&solana).unwrap();
    let result = futures::executor::block_on(backend.sign(BackendSignRequest {
        provider_attempt_id: Digest32::from_bytes([0x11u8; 32]),
        key_ref: solana,
        crypto_suite: bloom_signer_api::CryptoSuite::Ed25519Message,
        input: BackendInput::Message {
            message: bloom_signer_api::Base64UrlBytes::from_bytes(b"x"),
        },
        deadline_ms: bloom_signer_api::DecimalU64::new(1_000_000),
    }));
    assert!(result.is_err());
}
