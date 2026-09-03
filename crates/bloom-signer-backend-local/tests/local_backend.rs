use bloom_signer_api::{
    Base64UrlBytes, CryptoSuite, DecimalU64, DerivationProfile, DerivationRef, Digest32, KeyRef,
    KeySpec, Token,
};
use bloom_signer_backend_api::{
    ActivationStatus, BackendError, BackendInput, BackendSignRequest, SecretBytes, SignerBackend,
    SignerBackendActivation, SignerBackendDerivation,
};
use bloom_signer_backend_local::{EncryptedLocalBackup, LocalSignerBackend};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use k256::pkcs8::EncodePublicKey as _;
use sha2::Digest as _;
use std::str::FromStr as _;

fn spki_fingerprint(verifying: &k256::ecdsa::VerifyingKey) -> (Vec<u8>, Digest32) {
    let public =
        k256::PublicKey::from_sec1_bytes(verifying.to_encoded_point(false).as_bytes()).unwrap();
    let spki = public.to_public_key_der().unwrap().as_bytes().to_vec();
    let fingerprint = Digest32::from_bytes(sha2::Sha256::digest(&spki).into());
    (spki, fingerprint)
}

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

fn bip39_backend() -> (LocalSignerBackend, Vec<u8>) {
    let entropy = vec![0_u8; 32];
    let backend = LocalSignerBackend::provision_bip39(
        Token::new("bip39-restart-test").unwrap(),
        Token::new("bip39-restart-test").unwrap(),
        SecretBytes::new(entropy.clone()),
        SecretBytes::new(vec![7; 32]),
        Ed25519SigningKey::from_bytes(&[5; 32]).verifying_key(),
    )
    .unwrap();
    (backend, entropy)
}

fn bip39_child(entropy: &[u8], profile: DerivationProfile) -> (KeyRef, Vec<u8>, Vec<CryptoSuite>) {
    let mnemonic = bloom_signer_derive::mnemonic_from_entropy(entropy).unwrap();
    let seed = bloom_signer_derive::seed_from_mnemonic(&mnemonic).unwrap();
    let (path, key_spec, spki, fingerprint, suites) = match profile {
        DerivationProfile::Bip44EvmSecp256k1V1 => {
            let derived = bloom_signer_derive::derive_evm_account(&seed, 0, 0).unwrap();
            (
                "m/44'/60'/0'/0/0",
                KeySpec::Secp256k1,
                derived.spki_der,
                derived.fingerprint,
                vec![
                    CryptoSuite::Secp256k1Keccak256Recoverable,
                    CryptoSuite::Secp256k1Sha256Recoverable,
                ],
            )
        }
        DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
            let derived = bloom_signer_derive::derive_solana_account(&seed, 0).unwrap();
            (
                "m/44'/501'/0'/0'",
                KeySpec::Ed25519,
                derived.spki_der,
                derived.fingerprint,
                vec![CryptoSuite::Ed25519Message],
            )
        }
    };
    let key_ref = KeyRef {
        backend: Token::new("local").unwrap(),
        backend_instance: Token::new("bip39-restart-test").unwrap(),
        locator: hex::encode(sha2::Sha256::digest(
            [b"bip39-restart-test".as_slice(), path.as_bytes()].concat(),
        )),
        key_spec,
        public_key_fingerprint: Digest32::from_bytes(fingerprint),
        derivation: Some(DerivationRef::Bip39Multicurve {
            wallet_seed_ref: Token::new("bip39-restart-test").unwrap(),
            profile,
            path: path.into(),
        }),
    };
    (key_ref, spki, suites)
}

#[test]
fn bip39_public_descriptions_survive_a_locked_restart() {
    let (backend, entropy) = bip39_backend();
    let evm = bip39_child(&entropy, DerivationProfile::Bip44EvmSecp256k1V1);
    let solana = bip39_child(&entropy, DerivationProfile::Bip44SolanaSlip10Ed25519V1);
    backend.register_bip39_child(evm.0.clone(), None).unwrap();
    backend
        .register_bip39_child(solana.0.clone(), None)
        .unwrap();

    let backup = backend.encrypted_backup().unwrap();
    assert_eq!(backup.public_descriptions.len(), 2);
    let restarted =
        LocalSignerBackend::restore(Token::new("bip39-restart-test").unwrap(), backup).unwrap();

    for (key_ref, spki, suites) in [evm, solana] {
        let description = futures::executor::block_on(restarted.describe_key(&key_ref)).unwrap();
        assert_eq!(description.canonical_spki_der.decode(), spki);
        assert_eq!(description.supported_crypto_suites, suites);
    }
    assert!(
        futures::executor::block_on(restarted.sign(BackendSignRequest {
            provider_attempt_id: Digest32::new("11".repeat(32)).unwrap(),
            key_ref: bip39_child(&entropy, DerivationProfile::Bip44EvmSecp256k1V1).0,
            crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
            input: BackendInput::Digest32 {
                digest: Digest32::new("22".repeat(32)).unwrap(),
            },
            deadline_ms: DecimalU64::new(100),
        }))
        .is_err(),
        "public projection must not unlock signing"
    );
}

#[test]
fn failed_bip39_child_can_be_tombstoned_without_reusing_its_path() {
    let (backend, entropy) = bip39_backend();
    let child = bip39_child(&entropy, DerivationProfile::Bip44SolanaSlip10Ed25519V1).0;
    backend
        .register_bip39_child(
            child.clone(),
            Some(bloom_signer_api::OperationId::from_bytes([9; 32])),
        )
        .unwrap();

    backend.tombstone_derived_key(&child).unwrap();
    let backup = backend.encrypted_backup().unwrap();
    assert!(!backup.derivation_registry.contains(&child));
    assert!(
        backup
            .public_descriptions
            .iter()
            .all(|item| item.key_ref != child)
    );
    assert!(
        backup
            .derivation_tombstones
            .contains(&"m/44'/501'/0'/0'".into())
    );
    assert!(backup.pending_derivations.is_empty());
    assert!(futures::executor::block_on(backend.describe_key(&child)).is_err());

    let restarted =
        LocalSignerBackend::restore(Token::new("bip39-restart-test").unwrap(), backup).unwrap();
    assert!(futures::executor::block_on(restarted.describe_key(&child)).is_err());
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
    let mut backup = backend.encrypted_backup().unwrap();
    backup.public_descriptions[0].canonical_spki_der = Base64UrlBytes::from_bytes(&[9; 33]);
    assert!(matches!(
        LocalSignerBackend::restore(Token::new("local-default").unwrap(), backup),
        Err(BackendError::InvalidRequest)
    ));
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

/// Construct a legacy BIP-32-seed backend the way an existing wallet's on-disk
/// enrollment would: an encrypted seed plus a pinned root, restored from the
/// `EncryptedLocalBackup` (there is no creation entry point anymore).
fn bip32_seed_backend(seed: &[u8], kek: &[u8]) -> LocalSignerBackend {
    use bip32::{DerivationPath, XPrv};
    use chacha20poly1305::{
        Key as CKey, XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    };
    use k256::ecdsa::SigningKey as K256SigningKey;

    let instance = Token::new("bip32-seed-test").unwrap();
    let root_id = Token::new("root-1").unwrap();
    let aad = [
        b"bloom-local-root-wrap/v1".as_slice(),
        instance.as_str().as_bytes(),
        root_id.as_str().as_bytes(),
        &1_u32.to_be_bytes(),
    ]
    .concat();
    let nonce = [0_u8; 24];
    let ciphertext = XChaCha20Poly1305::new(CKey::from_slice(kek))
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: seed,
                aad: &aad,
            },
        )
        .unwrap();

    // Master key at "m" and its SPKI fingerprint, mirroring describe_path.
    let master: K256SigningKey =
        XPrv::derive_from_path(seed, &DerivationPath::from_str("m").unwrap())
            .unwrap()
            .into();
    let (spki, fingerprint) = spki_fingerprint(master.verifying_key());

    let root = KeyRef {
        backend: Token::new("local").unwrap(),
        backend_instance: instance.clone(),
        locator: format!("root:{}", root_id.as_str()),
        key_spec: KeySpec::Secp256k1,
        public_key_fingerprint: fingerprint.clone(),
        derivation: None,
    };
    let backup = EncryptedLocalBackup {
        root_key_id: root_id.clone(),
        root_material_kind: bloom_signer_backend_local::LocalRootMaterialKind::Bip32Seed,
        pinned_root: Some(root.clone()),
        wrap_format_version: 1,
        nonce: Base64UrlBytes::from_bytes(&nonce),
        encrypted_seed: Base64UrlBytes::from_bytes(&ciphertext),
        authority_verifying_key: Base64UrlBytes::from_bytes(
            &Ed25519SigningKey::from_bytes(&[5; 32])
                .verifying_key()
                .to_bytes(),
        ),
        public_descriptions: vec![bloom_signer_backend_api::KeyDescription {
            key_ref: root.clone(),
            canonical_spki_der: Base64UrlBytes::from_bytes(&spki),
            public_key_fingerprint: fingerprint,
            supported_crypto_suites: vec![
                CryptoSuite::Secp256k1Keccak256Recoverable,
                CryptoSuite::Secp256k1Sha256Recoverable,
            ],
        }],
        derivation_registry: vec![],
        derivation_namespaces: vec![],
        derivation_tombstones: vec![],
        pending_derivations: Default::default(),
    };
    LocalSignerBackend::restore(instance, backup).unwrap()
}

#[test]
fn bip32_seed_backup_deserializes_to_the_bip32_seed_kind() {
    let backend = bip32_seed_backend(&[9_u8; 32], &[7_u8; 32]);
    let backup = backend.encrypted_backup().unwrap();
    assert!(matches!(
        backup.root_material_kind,
        bloom_signer_backend_local::LocalRootMaterialKind::Bip32Seed
    ));
    // The on-disk tag is literally the original "bip32_seed".
    let encoded = serde_json::to_string(&backup).unwrap();
    assert!(encoded.contains("\"root_material_kind\":\"bip32_seed\""));
    let reparsed: EncryptedLocalBackup = serde_json::from_str(&encoded).unwrap();
    assert!(matches!(
        reparsed.root_material_kind,
        bloom_signer_backend_local::LocalRootMaterialKind::Bip32Seed
    ));
}

#[test]
fn bip32_seed_wallet_unlocks_derives_signs_and_round_trips() {
    use bip32::{DerivationPath, XPrv};
    use sha2::Digest as _;

    let seed = [0xAB_u8; 32];
    let kek = [7_u8; 32];
    let backend = bip32_seed_backend(&seed, &kek);
    let root = backend.root_key_ref().unwrap();

    // Unlock (activate) with the KEK.
    futures::executor::block_on(backend.activate(&root, SecretBytes::new(kek.to_vec()))).unwrap();

    // The root and a derived child both sign.
    let root_sig = futures::executor::block_on(backend.sign(BackendSignRequest {
        provider_attempt_id: Digest32::new("aa".repeat(32)).unwrap(),
        key_ref: root.clone(),
        crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
        input: BackendInput::Digest32 {
            digest: Digest32::new("bb".repeat(32)).unwrap(),
        },
        deadline_ms: DecimalU64::new(1_000_000),
    }))
    .unwrap();
    assert_eq!(root_sig.bytes.decode().len(), 65);

    // Derive two children and confirm they differ and are both signable.
    let child_path = "m/0";
    let child_sk: k256::ecdsa::SigningKey = XPrv::derive_from_path(
        seed.as_slice(),
        &DerivationPath::from_str(child_path).unwrap(),
    )
    .unwrap()
    .into();
    let (_child_spki, child_fingerprint) = spki_fingerprint(child_sk.verifying_key());
    let child = KeyRef {
        backend: Token::new("local").unwrap(),
        backend_instance: Token::new("bip32-seed-test").unwrap(),
        locator: hex::encode(sha2::Sha256::digest(b"root-1m/0")),
        key_spec: KeySpec::Secp256k1,
        public_key_fingerprint: child_fingerprint,
        derivation: Some(DerivationRef::Bip32Secp256k1 {
            root_key_id: Token::new("root-1").unwrap(),
            path: child_path.into(),
        }),
    };
    // Register the child in the backend's durable registry and sign with it.
    backend.register_bip39_child(child.clone(), None).unwrap();
    let child_sig = futures::executor::block_on(backend.sign(BackendSignRequest {
        provider_attempt_id: Digest32::new("cc".repeat(32)).unwrap(),
        key_ref: child.clone(),
        crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
        input: BackendInput::Digest32 {
            digest: Digest32::new("dd".repeat(32)).unwrap(),
        },
        deadline_ms: DecimalU64::new(1_000_000),
    }))
    .unwrap();
    assert_eq!(child_sig.bytes.decode().len(), 65);
    assert_ne!(root.public_key_fingerprint, child.public_key_fingerprint);

    // Backup round-trip preserves the root and its derived child.
    let exported = backend.encrypted_backup().unwrap();
    let restored =
        LocalSignerBackend::restore(Token::new("bip32-seed-test").unwrap(), exported).unwrap();
    assert_eq!(restored.root_key_ref().unwrap(), root);
    // Re-lock check: before unlocking, derived-child description is refused.
    assert_eq!(
        futures::executor::block_on(restored.describe_key(&child)).unwrap_err(),
        BackendError::DefinitiveRejected
    );
    futures::executor::block_on(restored.activate(&root, SecretBytes::new(kek.to_vec()))).unwrap();
    let description = futures::executor::block_on(restored.describe_key(&child)).unwrap();
    assert_eq!(
        description.public_key_fingerprint,
        child.public_key_fingerprint
    );
}
