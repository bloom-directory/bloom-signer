use bloom_signer_api::*;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::json;

#[test]
fn registration_requires_the_connected_1_5_authority_edge() {
    assert!(SIGNER_API_RANGE.contains(ProtocolVersion::new(1, 5)));
    assert!(!SIGNER_API_RANGE.contains(ProtocolVersion::new(1, 4)));
    assert!(!SIGNER_API_RANGE.contains(ProtocolVersion::new(1, 6)));
}

fn terms() -> PetalRegistrationTerms {
    serde_json::from_value(json!({
        "schema": "bloom.petal-registration/1",
        "operation_id": "11".repeat(32),
        "enrollment_digest": "22".repeat(32),
        "owner_wallet_id": "wallet-owner",
        "package_hash": "33".repeat(32),
        "manifest_digest": "44".repeat(32),
        "permissions_digest": "55".repeat(32),
        "lineage_id": format!("pln1_{}", "a".repeat(52)),
    }))
    .unwrap()
}

fn receipt() -> CustodyResult {
    serde_json::from_value(json!({
        "ceremony_kind": "petal_registration",
        "custody_operation_id": "11".repeat(32),
        "public_status": "SUCCEEDED",
        "wallet_id": "wallet-owner",
        "public_key_refs": [], "credential_summaries": [], "initial_policy": null,
        "receipt_digest": "66".repeat(32),
        "petal_registration_terms_digest": terms().digest().unwrap(),
        "encrypted_browser_result": null,
        "signer_key_id": "signer-key", "signer_signature": ""
    }))
    .unwrap()
}

#[test]
fn terms_digest_binds_every_exact_field_and_matches_independent_vector() {
    let original = terms();
    let digest = original.digest().unwrap();
    assert_eq!(
        digest.as_str(),
        "0697036022c3e2830c782aac96c0d7fd53302dc2da11e4c93bd08f6b6934f744"
    );
    let original_json = serde_json::to_value(&original).unwrap();
    for (field, value) in [
        ("operation_id", json!("77".repeat(32))),
        ("enrollment_digest", json!("77".repeat(32))),
        ("owner_wallet_id", json!("another-owner")),
        ("package_hash", json!("77".repeat(32))),
        ("manifest_digest", json!("77".repeat(32))),
        ("permissions_digest", json!("77".repeat(32))),
        (
            "lineage_id",
            json!(format!("pln1_{}", "b".repeat(51) + "a")),
        ),
    ] {
        let mut changed = original_json.clone();
        changed[field] = value;
        let changed: PetalRegistrationTerms = serde_json::from_value(changed).unwrap();
        assert_ne!(changed.digest().unwrap(), digest, "{field}");
    }
    assert_eq!(
        serde_json::from_value::<PetalRegistrationTerms>(original_json).unwrap(),
        original
    );
}

#[test]
fn terms_reject_unknown_fields_and_wrong_schema() {
    let mut value = serde_json::to_value(terms()).unwrap();
    value["unreviewed"] = json!(true);
    assert!(serde_json::from_value::<PetalRegistrationTerms>(value).is_err());
    let mut value = serde_json::to_value(terms()).unwrap();
    value["schema"] = json!("bloom.petal-registration/0");
    assert!(serde_json::from_value::<PetalRegistrationTerms>(value).is_err());
    let mut wrong = terms();
    wrong.schema = Token::new("bloom.petal-registration/0").unwrap();
    assert!(wrong.digest().is_err());
}

fn public(hex: &str) -> VerifyingKey {
    VerifyingKey::from_bytes(&hex::decode(hex).unwrap().try_into().unwrap()).unwrap()
}

#[test]
fn enrollment_binds_both_key_ids_and_validated_public_bytes() {
    let broker_id = Token::new("broker-key").unwrap();
    let signer_id = Token::new("signer-key").unwrap();
    let broker = public("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signer = public("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let digest =
        petal_registration_enrollment_digest(&broker_id, &broker, &signer_id, &signer).unwrap();
    assert_eq!(
        digest.as_str(),
        "6e6973cef8feb7f45b68ba33ca474a8ef80e3dad5ff94396c11b28ee4afab34a"
    );
    let other = Token::new("other-key").unwrap();
    for changed in [
        petal_registration_enrollment_digest(&other, &broker, &signer_id, &signer),
        petal_registration_enrollment_digest(&broker_id, &signer, &signer_id, &signer),
        petal_registration_enrollment_digest(&broker_id, &broker, &other, &signer),
        petal_registration_enrollment_digest(&broker_id, &broker, &signer_id, &broker),
    ] {
        assert_ne!(changed.unwrap(), digest);
    }
}

#[test]
fn receipt_requires_exact_registration_binding_and_success_shape() {
    let original = receipt();
    original
        .validate_petal_registration_binding(&terms())
        .unwrap();
    assert_eq!(
        CeremonyKind::PetalRegistration.successful_terminal_state(),
        Some(CeremonyState::Succeeded)
    );
    for (field, value) in [
        ("ceremony_kind", json!("policy_update")),
        ("custody_operation_id", json!("77".repeat(32))),
        ("public_status", json!("COMPLETED")),
        ("wallet_id", json!("other-owner")),
        ("petal_registration_terms_digest", json!("77".repeat(32))),
        ("petal_registration_terms_digest", json!(null)),
        (
            "credential_summaries",
            json!([{"credential_id":"AQ", "rp_id":"localhost", "active":true}]),
        ),
    ] {
        let mut changed = serde_json::to_value(&original).unwrap();
        changed[field] = value;
        let changed: CustodyResult = serde_json::from_value(changed).unwrap();
        assert!(
            changed
                .validate_petal_registration_binding(&terms())
                .is_err(),
            "{field}"
        );
    }
    let mut missing = original.clone();
    missing.petal_registration_terms_digest = None;
    assert!(missing.unsigned_canonical_bytes().is_err());
    let mut cross_kind = original;
    cross_kind.ceremony_kind = CeremonyKind::PolicyUpdate;
    assert!(cross_kind.unsigned_canonical_bytes().is_err());
}

#[test]
fn receipt_signature_covers_registration_binding_and_old_kinds_keep_their_bytes() {
    let original = receipt();
    let key = SigningKey::from_bytes(&[9; 32]);
    let bytes = original.unsigned_canonical_bytes().unwrap();
    let signature = key.sign(&bytes);
    key.verifying_key()
        .verify_strict(&bytes, &signature)
        .unwrap();
    let mut changed = original.clone();
    changed.petal_registration_terms_digest = Some(Digest32::from_bytes([9; 32]));
    assert!(
        key.verifying_key()
            .verify_strict(&changed.unsigned_canonical_bytes().unwrap(), &signature)
            .is_err()
    );
    let mut old = original;
    old.ceremony_kind = CeremonyKind::PolicyUpdate;
    old.petal_registration_terms_digest = None;
    let mut legacy = serde_json::to_value(&old).unwrap();
    assert!(legacy.get("petal_registration_terms_digest").is_none());
    legacy.as_object_mut().unwrap().remove("signer_signature");
    assert_eq!(
        old.unsigned_canonical_bytes().unwrap(),
        serde_jcs::to_vec(&legacy).unwrap()
    );
}

#[test]
fn typed_prepare_and_complete_preserve_registration_kind_and_operation() {
    let exact = terms();
    let request = PetalRegistrationCeremonyPrepareRequest {
        custody: CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::PetalRegistration,
            custody_operation_id: exact.operation_id.clone(),
            wallet_id: Some(exact.owner_wallet_id.clone()),
            key_ref: None,
            exact_terms_digest: exact.digest().unwrap(),
            expected_input_class: Token::new(PETAL_REGISTRATION_INPUT_CLASS).unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: None,
            legacy_passkey_migration: None,
        },
        terms: exact.clone(),
    };
    request.validate_binding().unwrap();
    let wire = serde_json::to_value(SignerCeremonyPrepareRequest::PetalRegistration(Box::new(
        request.clone(),
    )))
    .unwrap();
    assert_eq!(wire["ceremony_kind"], "petal_registration");
    let parsed: SignerCeremonyPrepareRequest = serde_json::from_value(wire).unwrap();
    let envelope = BrokerSignerRequest::CeremonyPrepare(parsed);
    assert_eq!(envelope.operation_id().unwrap(), Some(exact.operation_id));
    for (field, value) in [
        ("ceremony_kind", json!("policy_update")),
        ("custody_operation_id", json!("77".repeat(32))),
        ("wallet_id", json!("other-owner")),
        ("exact_terms_digest", json!("77".repeat(32))),
        ("expected_input_class", json!("passkey-prf")),
        ("browser_output_recipient_key", json!("AQ")),
    ] {
        let mut changed = serde_json::to_value(&request).unwrap();
        changed["custody"][field] = value;
        let changed: PetalRegistrationCeremonyPrepareRequest =
            serde_json::from_value(changed).unwrap();
        assert!(changed.validate_binding().is_err(), "{field}");
    }
    let response = SignerCeremonyCompleteResponse::PetalRegistration(Box::new(receipt()));
    let encoded = serde_json::to_value(response).unwrap();
    assert_eq!(encoded["ceremony_kind"], "petal_registration");
}
