use bloom_signer_api::{CryptoInputKind, CryptoSuite, SignatureEncoding};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier as _, VerifyingKey as Ed25519Key};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::Deserialize;
use sha3::{Digest as _, Keccak256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureVector {
    name: String,
    crypto_suite: CryptoSuite,
    input_kind: CryptoInputKind,
    digest_hex: String,
    compressed_public_key_hex: String,
    encoding: SignatureEncoding,
    normalized_signature_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeccakSignatureVector {
    name: String,
    crypto_suite: CryptoSuite,
    input_kind: CryptoInputKind,
    message_hex: String,
    digest_hex: String,
    compressed_public_key_hex: String,
    encoding: SignatureEncoding,
    normalized_signature_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ed25519SignatureVector {
    name: String,
    crypto_suite: CryptoSuite,
    input_kind: CryptoInputKind,
    message_hex: String,
    public_key_hex: String,
    encoding: SignatureEncoding,
    normalized_signature_hex: String,
}

#[test]
fn normalized_recoverable_signature_matches_reviewed_artifact() {
    let vector: SignatureVector =
        serde_json::from_str(include_str!("../vectors/secp256k1-recoverable-v1.json")).unwrap();
    assert_eq!(vector.name, "secp256k1-sha256-recoverable-v1");
    assert_eq!(vector.crypto_suite, CryptoSuite::Secp256k1Sha256Recoverable);
    assert_eq!(vector.input_kind, vector.crypto_suite.input_kind());
    assert_eq!(vector.encoding, vector.crypto_suite.signature_encoding());

    let digest: [u8; 32] = hex::decode(vector.digest_hex).unwrap().try_into().unwrap();
    let normalized = hex::decode(vector.normalized_signature_hex).unwrap();
    assert_eq!(normalized.len(), 65);
    let signature = Signature::from_slice(&normalized[..64]).unwrap();
    assert!(
        signature.normalize_s().is_none(),
        "golden signature must already use low s"
    );
    let recovery_id = RecoveryId::from_byte(normalized[64]).unwrap();
    let recovered = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id).unwrap();
    assert_eq!(
        hex::encode(recovered.to_encoded_point(true).as_bytes()),
        vector.compressed_public_key_hex
    );
}

#[test]
fn normalized_keccak_recoverable_signature_matches_reviewed_artifact() {
    let vector: KeccakSignatureVector = serde_json::from_str(include_str!(
        "../vectors/secp256k1-keccak256-recoverable-v1.json"
    ))
    .unwrap();
    assert_eq!(vector.name, "secp256k1-keccak256-recoverable-v1");
    assert_eq!(
        vector.crypto_suite,
        CryptoSuite::Secp256k1Keccak256Recoverable
    );
    assert_eq!(vector.input_kind, vector.crypto_suite.input_kind());
    assert_eq!(vector.encoding, vector.crypto_suite.signature_encoding());
    let message = hex::decode(vector.message_hex).unwrap();
    let digest: [u8; 32] = Keccak256::digest(message).into();
    assert_eq!(hex::encode(digest), vector.digest_hex);
    let normalized = hex::decode(vector.normalized_signature_hex).unwrap();
    let signature = Signature::from_slice(&normalized[..64]).unwrap();
    assert!(signature.normalize_s().is_none());
    let recovery_id = RecoveryId::from_byte(normalized[64]).unwrap();
    let recovered = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id).unwrap();
    assert_eq!(
        hex::encode(recovered.to_encoded_point(true).as_bytes()),
        vector.compressed_public_key_hex
    );
}

#[test]
fn normalized_ed25519_message_signature_matches_reviewed_artifact() {
    let vector: Ed25519SignatureVector =
        serde_json::from_str(include_str!("../vectors/ed25519-message-v1.json")).unwrap();
    assert_eq!(vector.name, "ed25519-message-v1");
    assert_eq!(vector.crypto_suite, CryptoSuite::Ed25519Message);
    assert_eq!(vector.input_kind, vector.crypto_suite.input_kind());
    assert_eq!(vector.encoding, vector.crypto_suite.signature_encoding());
    let message = hex::decode(vector.message_hex).unwrap();
    let public_key: [u8; 32] = hex::decode(vector.public_key_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let signature_bytes: [u8; 64] = hex::decode(vector.normalized_signature_hex)
        .unwrap()
        .try_into()
        .unwrap();
    Ed25519Key::from_bytes(&public_key)
        .unwrap()
        .verify(&message, &Ed25519Signature::from_bytes(&signature_bytes))
        .unwrap();
}
