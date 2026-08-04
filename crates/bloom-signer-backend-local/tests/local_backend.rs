use bloom_signer_api::{Base64UrlBytes, CryptoSuite, DecimalU64, Digest32, Token};
use bloom_signer_backend_api::{
    ActivationStatus, BackendInput, BackendSignRequest, SecretBytes, SignerBackend,
    SignerBackendActivation,
};
use bloom_signer_backend_local::{
    DerivationAuthority, DerivationGrant, EncryptedLocalBackup, LocalSignerBackend,
};
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use k256::pkcs8::DecodePublicKey;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bip32Vector {
    name: String,
    seed_hex: String,
    path: String,
    compressed_public_key_hex: String,
    canonical_spki_der: Base64UrlBytes,
    public_key_fingerprint: Digest32,
    locator: String,
}

fn authority(prefix: &str, starting_index: u64, maximum_children: u64) -> DerivationAuthority {
    let grant = DerivationGrant {
        authority_kind: Token::new("ceremony").unwrap(),
        namespace_id: Token::new("ethereum-account-0").unwrap(),
        canonical_prefix: prefix.into(),
        starting_index: DecimalU64::new(starting_index),
        maximum_children: DecimalU64::new(maximum_children),
    };
    let mut message = b"bloom-key-derive-authority/v1".to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&grant).unwrap());
    let signature = Ed25519SigningKey::from_bytes(&[5; 32]).sign(&message);
    DerivationAuthority::from_signed(grant, Base64UrlBytes::from_bytes(&signature.to_bytes()))
}

fn backend(seed: Vec<u8>) -> LocalSignerBackend {
    LocalSignerBackend::provision(
        Token::new("local-default").unwrap(),
        Token::new("root-1").unwrap(),
        SecretBytes::new(seed),
        SecretBytes::new(vec![7; 32]),
        Ed25519SigningKey::from_bytes(&[5; 32]).verifying_key(),
    )
    .unwrap()
}

#[test]
fn ac25_bip32_derivation_and_registry_match_reviewed_vector() {
    let vector: Bip32Vector =
        serde_json::from_str(include_str!("../vectors/bip32-vector-1-final.json")).unwrap();
    assert_eq!(vector.name, "bip32-vector-1-final");
    let backend = backend(hex::decode(&vector.seed_hex).unwrap());
    let root = backend.root_key_ref().unwrap();
    let authority = authority("m/0'/1/2'/2", 1_000_000_000, 2);
    backend.configure_namespace(&authority).unwrap();
    let first = backend
        .allocate_derived_key(
            &root,
            &Token::new("ethereum-account-0").unwrap(),
            &authority,
        )
        .unwrap();
    assert_eq!(vector.path, "m/0'/1/2'/2/1000000000");
    assert_eq!(first.key_ref.locator, vector.locator);
    assert_eq!(first.public_key_fingerprint, vector.public_key_fingerprint);
    assert_eq!(first.canonical_spki_der, vector.canonical_spki_der);
    let public = k256::PublicKey::from_public_key_der(&first.canonical_spki_der.decode()).unwrap();
    assert_eq!(
        hex::encode(public.to_sec1_bytes()),
        vector.compressed_public_key_hex
    );

    let backup = backend.encrypted_backup().unwrap();
    assert_eq!(backup.derivation_registry, vec![first.key_ref.clone()]);
    assert!(
        !serde_json::to_string(&backup)
            .unwrap()
            .contains(&vector.seed_hex)
    );

    let restored =
        LocalSignerBackend::restore(Token::new("local-default").unwrap(), backup).unwrap();
    assert_eq!(
        futures::executor::block_on(restored.activation_status(&first.key_ref)).unwrap(),
        ActivationStatus::Inactive
    );
    assert_eq!(
        futures::executor::block_on(restored.describe_key(&first.key_ref)).unwrap(),
        first,
        "public projection must not require custody activation after restart"
    );
    futures::executor::block_on(restored.activate(&first.key_ref, SecretBytes::new(vec![7; 32])))
        .unwrap();
    assert_eq!(
        futures::executor::block_on(restored.describe_key(&first.key_ref)).unwrap(),
        first
    );
}

#[test]
fn ac15_deactivation_and_restart_remove_plaintext_key_availability() {
    let backend = backend((0_u8..16).collect());
    let root = backend.root_key_ref().unwrap();
    let authority = authority("m/44'/60'/0'/0", 0, 2);
    backend.configure_namespace(&authority).unwrap();
    let key = backend
        .allocate_derived_key(
            &root,
            &Token::new("ethereum-account-0").unwrap(),
            &authority,
        )
        .unwrap()
        .key_ref;
    let request = BackendSignRequest {
        provider_attempt_id: Digest32::new("11".repeat(32)).unwrap(),
        key_ref: key.clone(),
        crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
        input: BackendInput::Digest32 {
            digest: Digest32::new("22".repeat(32)).unwrap(),
        },
        deadline_ms: DecimalU64::new(100),
    };
    let signature = futures::executor::block_on(backend.sign(request.clone())).unwrap();
    assert_eq!(signature.bytes.decode().len(), 65);
    futures::executor::block_on(backend.deactivate(&key)).unwrap();
    assert_eq!(
        futures::executor::block_on(backend.activation_status(&key)).unwrap(),
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
    let backend = backend((0_u8..32).collect());
    let root = backend.root_key_ref().unwrap();
    let mut backup = backend.encrypted_backup().unwrap();
    backup.public_descriptions[0].canonical_spki_der = Base64UrlBytes::from_bytes(&[9; 33]);
    let restored =
        LocalSignerBackend::restore(Token::new("local-default").unwrap(), backup).unwrap();
    assert!(futures::executor::block_on(restored.describe_key(&root)).is_err());
}

#[test]
fn derivation_registry_is_restart_safe_and_tombstoned_paths_are_not_reused() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "bloom-local-backend-{}-{unique}.json",
        std::process::id()
    ));
    let backend = LocalSignerBackend::provision_at(
        &path,
        Token::new("local-default").unwrap(),
        Token::new("root-1").unwrap(),
        SecretBytes::new((0_u8..16).collect()),
        SecretBytes::new(vec![7; 32]),
        Ed25519SigningKey::from_bytes(&[5; 32]).verifying_key(),
    )
    .unwrap();
    let root = backend.root_key_ref().unwrap();
    let namespace = Token::new("ethereum-account-0").unwrap();
    let authority = authority("m/44'/60'/0'/0", 0, 3);
    backend.configure_namespace(&authority).unwrap();
    let first = backend
        .allocate_derived_key(&root, &namespace, &authority)
        .unwrap();
    backend.tombstone_derived_key(&first.key_ref).unwrap();
    drop(backend);

    let restarted =
        LocalSignerBackend::open_at(&path, Token::new("local-default").unwrap()).unwrap();
    futures::executor::block_on(restarted.activate(&first.key_ref, SecretBytes::new(vec![7; 32])))
        .unwrap();
    let root = restarted.root_key_ref().unwrap();
    let second = restarted
        .allocate_derived_key(&root, &namespace, &authority)
        .unwrap();
    assert!(matches!(
        second.key_ref.derivation,
        Some(bloom_signer_api::DerivationRef::Bip32Secp256k1 { ref path, .. })
            if path == "m/44'/60'/0'/0/1"
    ));
    let backup = restarted.encrypted_backup().unwrap();
    assert_eq!(backup.derivation_namespaces[0].next_index.get(), 2);
    assert_eq!(backup.derivation_tombstones, vec!["m/44'/60'/0'/0/0"]);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn namespace_configuration_rejects_unauthenticated_authority() {
    let backend = backend((0_u8..16).collect());
    let grant = DerivationGrant {
        authority_kind: Token::new("policy").unwrap(),
        namespace_id: Token::new("ethereum-account-0").unwrap(),
        canonical_prefix: "m/44'/60'/0'/0".into(),
        starting_index: DecimalU64::new(0),
        maximum_children: DecimalU64::new(10),
    };
    let forged = DerivationAuthority::from_signed(
        grant,
        Base64UrlBytes::from_bytes(
            &Ed25519SigningKey::from_bytes(&[6; 32])
                .sign(b"forged")
                .to_bytes(),
        ),
    );
    assert!(backend.configure_namespace(&forged).is_err());
}
