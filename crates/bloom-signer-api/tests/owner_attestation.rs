use bloom_signer_api::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

fn token(value: &str) -> Token {
    Token::new(value).unwrap()
}

fn digest(value: u8) -> Digest32 {
    Digest32::from_bytes([value; 32])
}

fn operation(value: u8) -> OperationId {
    OperationId::from_bytes([value; 32])
}

fn terms() -> OwnerAttestationTerms {
    OwnerAttestationTerms {
        schema: token("bloom.owner-attestation/1"),
        operation_id: operation(0x11),
        owner_wallet_id: token("wallet-owner"),
        authority_edge_digest: digest(0x22),
        context_digest: digest(0x33),
        subject_digest: digest(0x44),
    }
}

fn receipt() -> OwnerAttestationReceipt {
    OwnerAttestationReceipt {
        operation_id: operation(0x11),
        ceremony_id: digest(0x55),
        owner_wallet_id: token("wallet-owner"),
        authority_edge_digest: digest(0x22),
        context_digest: digest(0x33),
        subject_digest: digest(0x44),
        receipt_digest: digest(0x66),
        signer_key_id: token("signer-key"),
        signer_signature: Base64UrlBytes::from_bytes(&[]),
    }
}

#[test]
fn terms_round_trip_through_canonical_json() {
    let original = terms();
    let canonical = serde_jcs::to_vec(&original).unwrap();
    let decoded: OwnerAttestationTerms = serde_json::from_slice(&canonical).unwrap();

    assert_eq!(decoded, original);
    assert_eq!(
        decoded.digest().unwrap().as_str(),
        "355516224f5e84baffe571df2c79cac3738de9fd48bb6b45455890d467f383e9"
    );
    assert_eq!(decoded.digest().unwrap(), original.digest().unwrap());
}

#[test]
fn terms_digest_changes_when_subject_digest_changes() {
    let original = terms();
    let mut changed = original.clone();
    changed.subject_digest = digest(0x45);

    assert_ne!(changed.digest().unwrap(), original.digest().unwrap());
}

#[test]
fn terms_reject_unknown_fields() {
    let mut value = serde_json::to_value(terms()).unwrap();
    value["unreviewed"] = json!(true);

    assert!(serde_json::from_value::<OwnerAttestationTerms>(value).is_err());
}

#[test]
fn receipt_signature_bytes_bind_every_unsigned_public_field() {
    let original = receipt();
    let key = SigningKey::from_bytes(&[0x77; 32]);
    let signature = key.sign(&original.signature_message().unwrap());
    key.verifying_key()
        .verify_strict(&original.signature_message().unwrap(), &signature)
        .unwrap();

    let mut changes = Vec::new();
    let mut changed = original.clone();
    changed.operation_id = operation(0x12);
    changes.push(changed);
    let mut changed = original.clone();
    changed.ceremony_id = digest(0x56);
    changes.push(changed);
    let mut changed = original.clone();
    changed.owner_wallet_id = token("wallet-other");
    changes.push(changed);
    let mut changed = original.clone();
    changed.authority_edge_digest = digest(0x23);
    changes.push(changed);
    let mut changed = original.clone();
    changed.context_digest = digest(0x34);
    changes.push(changed);
    let mut changed = original.clone();
    changed.subject_digest = digest(0x45);
    changes.push(changed);
    let mut changed = original.clone();
    changed.receipt_digest = digest(0x67);
    changes.push(changed);
    let mut changed = original.clone();
    changed.signer_key_id = token("other-signer-key");
    changes.push(changed);

    for changed in changes {
        assert!(
            key.verifying_key()
                .verify_strict(&changed.signature_message().unwrap(), &signature)
                .is_err()
        );
    }
}
