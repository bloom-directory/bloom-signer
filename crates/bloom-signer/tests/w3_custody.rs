use bloom_signer::custody::{WalletCustody, WalletCustodyBackup};
use bloom_signer_api::{Base64UrlBytes, ProtocolErrorCode, Token};
use bloom_signer_backend_api::SecretBytes;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
            .rekey_wrap_format(&unlocked, 2, &incomplete, Some(&key(7)))
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
        .rekey_wrap_format(&unlocked, 2, &complete, Some(&key(7)))
        .unwrap();
    let rekeyed = custody.backup();
    assert_eq!(rekeyed.wrap_format_version, 2);
    assert!(
        rekeyed
            .credential_wraps
            .iter()
            .all(|wrap| wrap.wrap_format_version == 2)
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
        .rekey_wrap_format(&unlocked, 2, &keys, None)
        .unwrap();
    let backup = custody.backup();
    assert_eq!(backup.credential_wraps[0].wrap_format_version, 1);
    let restored = WalletCustody::restore(backup).unwrap();
    assert!(
        restored
            .unlock_with_credential(&credential(2), &key(2))
            .is_ok()
    );
}
