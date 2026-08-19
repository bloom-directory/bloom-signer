use bloom_signer_api::{Base64UrlBytes, CryptoSuite, DecimalU64, Digest32, Token};
use bloom_signer_backend_api::{
    ActivationStatus, BackendError, BackendInput, BackendSignRequest, SecretBytes, SignerBackend,
    SignerBackendActivation, SignerBackendDerivation,
};
use bloom_signer_backend_local::{EncryptedLocalBackup, LocalSignerBackend};
use ed25519_dalek::SigningKey as Ed25519SigningKey;

fn backend(private_key: [u8; 32]) -> LocalSignerBackend {
    LocalSignerBackend::provision_imported_secp256k1(
        Token::new("local-default").unwrap(),
        Token::new("root-1").unwrap(),
        SecretBytes::new(private_key.to_vec()),
        SecretBytes::new(vec![7; 32]),
        Ed25519SigningKey::from_bytes(&[5; 32]).verifying_key(),
    )
    .unwrap()
}

#[test]
fn imported_scalar_roots_sign_deactivate_and_restart() {
    let backend = backend([1_u8; 32]);
    let root = backend.root_key_ref().unwrap();
    assert!(root.derivation.is_none());

    let request = BackendSignRequest {
        provider_attempt_id: Digest32::new("11".repeat(32)).unwrap(),
        key_ref: root.clone(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        input: BackendInput::Digest32 {
            digest: Digest32::new("22".repeat(32)).unwrap(),
        },
        deadline_ms: DecimalU64::new(100),
    };
    let signature = futures::executor::block_on(backend.sign(request.clone())).unwrap();
    assert_eq!(signature.bytes.decode().len(), 65);

    futures::executor::block_on(backend.deactivate(&root)).unwrap();
    assert_eq!(
        futures::executor::block_on(backend.activation_status(&root)).unwrap(),
        ActivationStatus::Inactive
    );
    assert!(futures::executor::block_on(backend.sign(request.clone())).is_err());

    let backup: EncryptedLocalBackup = backend.encrypted_backup().unwrap();
    let restarted =
        LocalSignerBackend::restore(Token::new("local-default").unwrap(), backup).unwrap();
    assert!(futures::executor::block_on(restarted.sign(request)).is_err());
}

#[test]
fn restarted_public_projection_rejects_an_spki_fingerprint_mismatch() {
    let backend = backend([2_u8; 32]);
    let root = backend.root_key_ref().unwrap();
    let mut backup = backend.encrypted_backup().unwrap();
    backup.public_descriptions[0].canonical_spki_der = Base64UrlBytes::from_bytes(&[9; 33]);
    let restored =
        LocalSignerBackend::restore(Token::new("local-default").unwrap(), backup).unwrap();
    assert!(futures::executor::block_on(restored.describe_key(&root)).is_err());
}

#[test]
fn imported_scalar_roots_reject_derivation_namespaces() {
    // The imported-scalar profile is a single key, not a seed: it can never
    // host a derivation namespace.
    let backend = backend([3_u8; 32]);
    let root = backend.root_key_ref().unwrap();
    assert!(matches!(
        futures::executor::block_on(backend.derive_public(&root, "m/44'/60'/0'/0/0")),
        Err(BackendError::InvalidRequest)
    ));
}

#[test]
fn pre_rename_secp256k1_scalar_backups_still_parse() {
    // The permanent imported-scalar profile must keep reading on-disk backups
    // written before the `Secp256k1Scalar` -> `ImportedSecp256k1Scalar` rename.
    let backend = backend([4_u8; 32]);
    let backup: EncryptedLocalBackup = backend.encrypted_backup().unwrap();
    let mut encoded = serde_json::to_string(&backup).unwrap();
    assert!(
        encoded.contains("imported_secp256k1_scalar"),
        "fixture should serialize the current tag: {encoded}"
    );
    encoded = encoded.replace("imported_secp256k1_scalar", "secp256k1_scalar");
    let parsed: EncryptedLocalBackup = serde_json::from_str(&encoded).unwrap();
    assert!(matches!(
        parsed.root_material_kind,
        bloom_signer_backend_local::LocalRootMaterialKind::ImportedSecp256k1Scalar
    ));
    // The restored backend still resolves its root from the pinned record.
    let restored =
        LocalSignerBackend::restore(Token::new("local-default").unwrap(), parsed).unwrap();
    let root = restored.root_key_ref().unwrap();
    assert_eq!(root, backend.root_key_ref().unwrap());
}
