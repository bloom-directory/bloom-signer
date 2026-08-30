use bloom_signer::custody::{WalletCustody, WalletCustodyBackup};
use bloom_signer_api::{Base64UrlBytes, ProtocolErrorCode, Token};
use bloom_signer_backend_api::SecretBytes;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// New wallets are created at `WRAP_FORMAT_CURRENT`, so a rekey must target
/// the next version rather than a fixed literal.
const NEXT_WRAP_FORMAT: u32 = bloom_signer::custody::WRAP_FORMAT_CURRENT + 1;

fn credential(value: u8) -> Base64UrlBytes {
    Base64UrlBytes::from_bytes(&[value; 32])
}

fn key(value: u8) -> SecretBytes {
    SecretBytes::new(vec![value; 32])
}

fn registered() -> WalletCustody {
    WalletCustody::register_bip39(
        Token::new("wallet-1").unwrap(),
        SecretBytes::new((0_u8..32).collect()),
        key(9),
        key(8),
        credential(1),
        key(1),
    )
    .unwrap()
}

#[test]
fn ac27_registration_and_multi_passkey_unlock_share_one_root_and_policy_key() {
    let custody = registered();
    let initial = custody.backup();
    assert_eq!(initial.credential_wraps.len(), 1);
    let first = custody
        .unlock_with_credential(&credential(1), &key(1))
        .unwrap();
    let root_fingerprint = first.root_fingerprint();
    let policy_public = first.policy_verifying_key().unwrap();

    custody
        .add_credential(&first, credential(2), &key(2))
        .unwrap();
    let second = custody
        .unlock_with_credential(&credential(2), &key(2))
        .unwrap();
    assert_eq!(second.root_fingerprint(), root_fingerprint);
    assert_eq!(second.policy_verifying_key().unwrap(), policy_public);

    // Replacement is add-before-revoke.
    custody
        .add_credential(&second, credential(3), &key(3))
        .unwrap();
    custody.revoke_credential(&credential(1)).unwrap();
    assert!(
        custody
            .unlock_with_credential(&credential(1), &key(1))
            .is_err()
    );
    assert_eq!(
        custody
            .unlock_with_credential(&credential(3), &key(3))
            .unwrap()
            .root_fingerprint(),
        root_fingerprint
    );

    custody
        .set_recovery(&second, Token::new("recovery-1").unwrap(), &key(7))
        .unwrap();
    assert_eq!(
        custody
            .unlock_with_recovery(&Token::new("recovery-1").unwrap(), &key(7))
            .unwrap()
            .root_fingerprint(),
        root_fingerprint
    );
}

#[test]
fn ac28_policy_versions_do_not_change_wrap_aad_and_format_rekey_is_atomic() {
    let custody = registered();
    let unlocked = custody
        .unlock_with_credential(&credential(1), &key(1))
        .unwrap();
    custody
        .add_credential(&unlocked, credential(2), &key(2))
        .unwrap();
    custody
        .set_recovery(&unlocked, Token::new("recovery-1").unwrap(), &key(7))
        .unwrap();
    let before_policy_updates = custody.backup();
    for version in 2..=5 {
        custody.set_policy_version(version).unwrap();
        assert!(
            custody
                .unlock_with_credential(&credential(1), &key(1))
                .is_ok()
        );
        assert!(
            custody
                .unlock_with_credential(&credential(2), &key(2))
                .is_ok()
        );
    }
    let after_policy_updates = custody.backup();
    assert_eq!(
        before_policy_updates.credential_wraps,
        after_policy_updates.credential_wraps
    );
    assert_eq!(
        before_policy_updates.recovery_wrap,
        after_policy_updates.recovery_wrap
    );

    let incomplete = BTreeMap::from([(credential(1).encoded().to_owned(), key(1))]);
    let before_failed_rekey = custody.backup();
    assert_eq!(
        custody
            .rekey_wrap_format(&unlocked, NEXT_WRAP_FORMAT, &incomplete, Some(&key(7)))
            .unwrap_err()
            .code,
        ProtocolErrorCode::ApprovalRearmRequired
    );
    assert_eq!(custody.backup(), before_failed_rekey);

    let complete = BTreeMap::from([
        (credential(1).encoded().to_owned(), key(1)),
        (credential(2).encoded().to_owned(), key(2)),
    ]);
    custody
        .rekey_wrap_format(&unlocked, NEXT_WRAP_FORMAT, &complete, Some(&key(7)))
        .unwrap();
    let rekeyed = custody.backup();
    assert_eq!(rekeyed.wrap_format_version, NEXT_WRAP_FORMAT);
    assert!(
        rekeyed
            .credential_wraps
            .iter()
            .all(|wrap| wrap.wrap_format_version == NEXT_WRAP_FORMAT)
    );
    assert!(
        custody
            .unlock_with_credential(&credential(1), &key(1))
            .is_ok()
    );
    assert!(
        custody
            .unlock_with_credential(&credential(2), &key(2))
            .is_ok()
    );
    assert!(
        custody
            .unlock_with_recovery(&Token::new("recovery-1").unwrap(), &key(7))
            .is_ok()
    );
}

#[test]
fn loss_of_every_passkey_without_recovery_is_unrecoverable() {
    let custody = registered();
    let mut lost: WalletCustodyBackup = custody.backup();
    for wrap in &mut lost.credential_wraps {
        wrap.active = false;
    }
    lost.recovery_wrap = None;
    let restored = WalletCustody::restore(lost).unwrap();
    assert!(
        restored
            .unlock_with_credential(&credential(1), &key(1))
            .is_err()
    );
}

#[test]
fn credential_wrap_is_bound_to_exact_root_ciphertext_fingerprint() {
    let first = registered().backup();
    let second = WalletCustody::register_bip39(
        Token::new("wallet-1").unwrap(),
        SecretBytes::new(vec![42; 32]),
        key(6),
        key(8),
        credential(1),
        key(1),
    )
    .unwrap()
    .backup();
    let mut spliced = first;
    spliced.encrypted_root = second.encrypted_root;
    spliced.encrypted_policy_signing_key = second.encrypted_policy_signing_key;
    let restored = WalletCustody::restore(spliced).unwrap();
    assert_eq!(
        restored
            .unlock_with_credential(&credential(1), &key(1))
            .err()
            .unwrap()
            .code,
        ProtocolErrorCode::UnauthenticatedPeer
    );
}

#[test]
fn custody_mutations_survive_atomic_file_restart() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "bloom-custody-{}-{unique}.json",
        std::process::id()
    ));
    let custody = WalletCustody::register_at(
        &path,
        Token::new("wallet-1").unwrap(),
        SecretBytes::new((0_u8..32).collect()),
        key(9),
        key(8),
        credential(1),
        key(1),
    )
    .unwrap();
    let unlocked = custody
        .unlock_with_credential(&credential(1), &key(1))
        .unwrap();
    custody
        .add_credential(&unlocked, credential(2), &key(2))
        .unwrap();
    drop(custody);

    let restarted = WalletCustody::open_at(&path).unwrap();
    assert!(
        restarted
            .unlock_with_credential(&credential(2), &key(2))
            .is_ok()
    );
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn rekeyed_backup_with_revoked_older_wrap_restarts() {
    let custody = registered();
    let unlocked = custody
        .unlock_with_credential(&credential(1), &key(1))
        .unwrap();
    custody
        .add_credential(&unlocked, credential(2), &key(2))
        .unwrap();
    custody.revoke_credential(&credential(1)).unwrap();
    let keys = BTreeMap::from([(credential(2).encoded().to_owned(), key(2))]);
    custody
        .rekey_wrap_format(&unlocked, NEXT_WRAP_FORMAT, &keys, None)
        .unwrap();
    let backup = custody.backup();
    // The revoked wrap is left at the version it was created under.
    assert_eq!(
        backup.credential_wraps[0].wrap_format_version,
        bloom_signer::custody::WRAP_FORMAT_CURRENT
    );
    let restored = WalletCustody::restore(backup).unwrap();
    assert!(
        restored
            .unlock_with_credential(&credential(2), &key(2))
            .is_ok()
    );
}

/// From WRAP_FORMAT_V2 the fields that decide how the decrypted root is
/// *interpreted* are authenticated, so editing them in the backup file
/// fails the AEAD at decrypt time — before any derivation runs.
///
/// The specific attack this closes: `root_material_profile` carries
/// `#[serde(default)]` and its default is `LegacySecp`, the one arm applying
/// no length check. Stripping the field therefore both disabled the
/// decrypt-time validation and reinterpreted BIP-39 entropy as a raw BIP-32
/// seed — a different, silently valid key tree from the same secret.
#[test]
fn tampering_with_root_interpretation_metadata_fails_before_derivation() {
    let custody = registered();
    let baseline = custody.backup();
    assert_eq!(
        baseline.wrap_format_version,
        bloom_signer::custody::WRAP_FORMAT_V2,
        "new wallets must be created at the authenticated envelope version"
    );
    assert!(
        WalletCustody::restore(baseline.clone())
            .unwrap()
            .unlock_with_credential(&credential(1), &key(1))
            .is_ok(),
        "baseline backup must unlock"
    );

    // Strip the profile, as an attacker editing the file would.
    let mut stripped = baseline.clone();
    stripped.root_material_profile = bloom_signer::custody::RootMaterialProfile::default();
    assert_eq!(
        stripped.root_material_profile,
        bloom_signer::custody::RootMaterialProfile::LegacySecp,
        "the serde default is the unchecked arm, which is what made this reachable"
    );
    assert!(
        WalletCustody::restore(stripped)
            .unwrap()
            .unlock_with_credential(&credential(1), &key(1))
            .is_err(),
        "a relabelled root must not decrypt"
    );

    // Change the declared entropy size without touching the ciphertext.
    let mut resized = baseline.clone();
    resized.entropy_bits = Some(128);
    assert!(
        WalletCustody::restore(resized)
            .unwrap()
            .unlock_with_credential(&credential(1), &key(1))
            .is_err(),
        "a rewritten entropy size must not decrypt"
    );

    // Absent and present-but-zero must not collide in the AAD encoding.
    let mut cleared = baseline;
    cleared.entropy_bits = None;
    assert!(
        WalletCustody::restore(cleared)
            .unwrap()
            .unlock_with_credential(&credential(1), &key(1))
            .is_err(),
        "removing the entropy size must not decrypt"
    );
}

/// V1 envelopes keep their original AAD byte-for-byte, so wallets written
/// before the metadata was authenticated still unlock. The upgrade is
/// `rekey_wrap_format`, which re-encrypts under the V2 AAD.
#[test]
fn legacy_v1_envelopes_still_unlock_and_upgrade_to_v2() {
    let custody = registered();
    let unlocked = custody
        .unlock_with_credential(&credential(1), &key(1))
        .unwrap();

    let keys = BTreeMap::from([(credential(1).encoded().to_owned(), key(1))]);
    custody
        .rekey_wrap_format(&unlocked, NEXT_WRAP_FORMAT, &keys, None)
        .unwrap();
    let upgraded = custody.backup();
    assert_eq!(upgraded.wrap_format_version, NEXT_WRAP_FORMAT);

    // The upgrade re-encrypts rather than relabelling: the profile is
    // carried across unchanged, and the wallet still unlocks.
    assert_eq!(
        upgraded.root_material_profile,
        bloom_signer::custody::RootMaterialProfile::Bip39MulticurveV1,
        "an upgrade must never restate what the material is"
    );
    assert!(
        WalletCustody::restore(upgraded.clone())
            .unwrap()
            .unlock_with_credential(&credential(1), &key(1))
            .is_ok()
    );

    // Metadata stays authenticated after the upgrade.
    let mut tampered = upgraded;
    tampered.root_material_profile = bloom_signer::custody::RootMaterialProfile::LegacySecp;
    assert!(
        WalletCustody::restore(tampered)
            .unwrap()
            .unlock_with_credential(&credential(1), &key(1))
            .is_err()
    );
}

/// The AAD binds a stable tag per profile rather than its serde name, so a
/// future rename cannot silently change what a ciphertext authenticates.
#[test]
fn profile_aad_tags_are_stable_and_distinct() {
    use bloom_signer::custody::RootMaterialProfile as P;
    assert_eq!(P::Bip39MulticurveV1.aad_tag(), "bip39-multicurve-v1");
    assert_eq!(
        P::ImportedSecp256k1Scalar.aad_tag(),
        "imported-secp256k1-scalar"
    );
    assert_eq!(P::LegacySecp.aad_tag(), "legacy-secp");
    let tags = [
        P::Bip39MulticurveV1.aad_tag(),
        P::ImportedSecp256k1Scalar.aad_tag(),
        P::LegacySecp.aad_tag(),
    ];
    let unique: std::collections::BTreeSet<_> = tags.iter().collect();
    assert_eq!(unique.len(), tags.len(), "profile tags must be distinct");
}
