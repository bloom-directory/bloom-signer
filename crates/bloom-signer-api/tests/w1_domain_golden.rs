use bloom_signer_api::*;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalVector {
    name: String,
    terms: SealedApprovalTerms,
    canonical_jcs: String,
    approval_digest: Digest32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRefVector {
    name: String,
    key_ref: KeyRef,
    canonical_jcs: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignOperationVector {
    name: String,
    operation_identity: SignOperationIdentity,
    operation_canonical_jcs: String,
    operation_digest: Digest32,
    unsigned_request: UnsignedSignRequest,
    attempt_canonical_jcs: String,
    attempt_digest: Digest32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CeremonyVector {
    name: String,
    challenge: CeremonyChallenge,
    challenge_canonical_jcs: String,
    challenge_base64url: Base64UrlBytes,
    challenge_digest: Digest32,
    local_prf_aad: LocalPrfHpkeAad,
    local_prf_aad_canonical_jcs: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeGoldenBody {
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalHeadEnvelopeVector {
    name: String,
    unsigned_envelope: UnsignedEnvelope<EnvelopeGoldenBody>,
    canonical_jcs: String,
    head_signature_message_base64url: Base64UrlBytes,
}

#[test]
fn keyref_jcs_and_exact_equality_match_reviewed_artifact() {
    let vector: KeyRefVector =
        serde_json::from_str(include_str!("../vectors/keyref-local-bip32-v1.json")).unwrap();
    assert_eq!(vector.name, "local-bip32-v1");
    vector.key_ref.validate().unwrap();
    assert_eq!(
        String::from_utf8(serde_jcs::to_vec(&vector.key_ref).unwrap()).unwrap(),
        vector.canonical_jcs
    );

    let mut changed = vector.key_ref.clone();
    changed.backend_instance = Token::new("local-other").unwrap();
    assert_ne!(changed, vector.key_ref);
    let mut changed = vector.key_ref.clone();
    changed.public_key_fingerprint = Digest32::new("aa".repeat(32)).unwrap();
    assert_ne!(changed, vector.key_ref);
    let mut changed = vector.key_ref.clone();
    changed.derivation = None;
    assert_ne!(changed, vector.key_ref);
}

#[test]
fn approval_jcs_and_digest_match_reviewed_artifact() {
    let vector: ApprovalVector = serde_json::from_str(include_str!(
        "../vectors/approval-exact-local-bip32-v1.json"
    ))
    .unwrap();
    assert_eq!(vector.name, "exact-local-bip32-v1");
    assert_eq!(
        String::from_utf8(vector.terms.canonical_bytes().unwrap()).unwrap(),
        vector.canonical_jcs
    );
    assert_eq!(
        vector.terms.approval_digest().unwrap(),
        vector.approval_digest
    );
    assert_eq!(vector.terms.approval_id().unwrap(), vector.approval_digest);
    for excluded in [
        "approval_id",
        "review_manifest_digest",
        "state",
        "activation_receipt",
        "created_at",
        "updated_at",
    ] {
        assert!(!vector.canonical_jcs.contains(excluded));
    }
}

#[test]
fn every_immutable_authority_field_changes_the_approval_digest() {
    let vector: ApprovalVector = serde_json::from_str(include_str!(
        "../vectors/approval-exact-local-bip32-v1.json"
    ))
    .unwrap();
    let baseline = vector.approval_digest;
    let mut mutations = Vec::new();

    let mut changed = vector.terms.clone();
    changed.subject = ApprovalSubject::Cli {
        client_id: Token::new("other-cli").unwrap(),
        command_class: Token::new("wallet.sign").unwrap(),
    };
    mutations.push(("subject", changed));

    let mut changed = vector.terms.clone();
    changed.key_ref.locator = "key-2".into();
    mutations.push(("KeyRef", changed));

    let mut changed = vector.terms.clone();
    changed
        .allowed_crypto_suites
        .push(CryptoSuite::Secp256k1Sha256Recoverable);
    mutations.push(("allowed_crypto_suites", changed));

    let mut changed = vector.terms.clone();
    changed.selector = ApprovalSelector::Exact {
        ordered_payload_digests: vec![Digest32::new("66".repeat(32)).unwrap()],
        ordered_hashes: vec![Digest32::new("33".repeat(32)).unwrap()],
    };
    mutations.push(("selector", changed));

    let mut changed = vector.terms.clone();
    changed.limits.operation_rate_limits.push(SlidingWindow {
        maximum: DecimalU64::new(1),
        duration_ms: DecimalU64::new(60_000),
    });
    mutations.push(("limits", changed));

    let mut changed = vector.terms.clone();
    changed.activation_mode = ActivationMode::BackendManaged;
    mutations.push(("activation_mode", changed));

    let mut changed = vector.terms.clone();
    changed.wallet_revocation_epoch = DecimalU64::new(8);
    mutations.push(("wallet_revocation_epoch", changed));

    let mut changed = vector.terms.clone();
    changed.policy_version = DecimalU64::new(4);
    changed.policy_digest = Digest32::new("77".repeat(32)).unwrap();
    mutations.push(("policy", changed));

    let mut changed = vector.terms.clone();
    changed.provenance_digest = Digest32::new("88".repeat(32)).unwrap();
    mutations.push(("provenance", changed));

    let mut changed = vector.terms.clone();
    changed.request_nonce = RequestNonce::new("99".repeat(16)).unwrap();
    mutations.push(("request_nonce", changed));

    let mut changed = vector.terms.clone();
    changed.expires_at_ms = DecimalU64::new(1_900_000_700_000);
    mutations.push(("validity", changed));

    for (field, terms) in mutations {
        assert_ne!(terms.approval_digest().unwrap(), baseline, "{field}");
    }
}

#[test]
fn identical_terms_with_distinct_request_nonces_have_distinct_ids() {
    let vector: ApprovalVector = serde_json::from_str(include_str!(
        "../vectors/approval-exact-local-bip32-v1.json"
    ))
    .unwrap();
    let mut second = vector.terms.clone();
    second.request_nonce = RequestNonce::new("01".repeat(16)).unwrap();
    assert_ne!(
        vector.terms.approval_id().unwrap(),
        second.approval_id().unwrap()
    );
}

#[test]
fn operation_and_attempt_digests_match_reviewed_artifact() {
    let vector: SignOperationVector =
        serde_json::from_str(include_str!("../vectors/sign-operation-local-v1.json")).unwrap();
    assert_eq!(vector.name, "local-secp256k1-keccak256-v1");
    assert_eq!(
        String::from_utf8(serde_jcs::to_vec(&vector.operation_identity).unwrap()).unwrap(),
        vector.operation_canonical_jcs
    );
    assert_eq!(
        vector.operation_identity.digest().unwrap(),
        vector.operation_digest
    );
    assert_eq!(
        String::from_utf8(
            vector
                .unsigned_request
                .canonical_attempt_preimage()
                .unwrap()
        )
        .unwrap(),
        vector.attempt_canonical_jcs
    );
    assert_eq!(
        vector.unsigned_request.computed_attempt_digest().unwrap(),
        vector.attempt_digest
    );
}

#[test]
fn ceremony_challenge_and_hpke_aad_match_reviewed_artifact() {
    let vector: CeremonyVector =
        serde_json::from_str(include_str!("../vectors/ceremony-local-prf-v1.json")).unwrap();
    assert_eq!(vector.name, "sealed-approval-local-prf-v1");
    assert_eq!(
        String::from_utf8(vector.challenge.canonical_bytes().unwrap()).unwrap(),
        vector.challenge_canonical_jcs
    );
    assert_eq!(
        vector.challenge.webauthn_challenge().unwrap(),
        vector.challenge_base64url
    );
    assert_eq!(vector.challenge.digest().unwrap(), vector.challenge_digest);
    assert_eq!(
        String::from_utf8(vector.local_prf_aad.canonical_bytes().unwrap()).unwrap(),
        vector.local_prf_aad_canonical_jcs
    );
}

#[test]
fn broker_signer_journal_head_envelope_matches_reviewed_artifact() {
    let vector: JournalHeadEnvelopeVector = serde_json::from_str(include_str!(
        "../vectors/broker-signer-journal-head-v1.json"
    ))
    .unwrap();
    assert_eq!(vector.name, "broker-signer-journal-head-minor-1");
    assert_eq!(
        String::from_utf8(vector.unsigned_envelope.canonical_bytes().unwrap()).unwrap(),
        vector.canonical_jcs
    );
    let head = vector.unsigned_envelope.sender_journal_head.unwrap();
    assert_eq!(
        Base64UrlBytes::from_bytes(&head.signature_message()),
        vector.head_signature_message_base64url
    );
}

#[test]
fn operation_identity_excludes_attempt_only_fields() {
    let vector: SignOperationVector =
        serde_json::from_str(include_str!("../vectors/sign-operation-local-v1.json")).unwrap();
    let baseline_operation = vector
        .unsigned_request
        .operation_identity()
        .digest()
        .unwrap();
    let baseline_attempt = vector.unsigned_request.computed_attempt_digest().unwrap();

    for mut changed in [
        {
            let mut value = vector.unsigned_request.clone();
            value.attempt_id = Digest32::new("aa".repeat(32)).unwrap();
            value
        },
        {
            let mut value = vector.unsigned_request.clone();
            value.issuer_boot_epoch = BootEpoch::new("bb".repeat(16)).unwrap();
            value
        },
        {
            let mut value = vector.unsigned_request.clone();
            value.expires_at_ms = DecimalU64::new(1_900_000_029_000);
            value
        },
    ] {
        assert_eq!(
            changed.operation_identity().digest().unwrap(),
            baseline_operation
        );
        changed.attempt_digest = Digest32::new("00".repeat(32)).unwrap();
        assert_ne!(changed.computed_attempt_digest().unwrap(), baseline_attempt);
    }

    let mut changed = vector.operation_identity;
    changed.policy_version = DecimalU64::new(8);
    assert_ne!(changed.digest().unwrap(), baseline_operation);
}

#[test]
fn sign_request_rejects_issue_time_after_expiry() {
    let vector: SignOperationVector =
        serde_json::from_str(include_str!("../vectors/sign-operation-local-v1.json")).unwrap();
    let mut unsigned = vector.unsigned_request;
    unsigned.issued_at_ms = DecimalU64::new(unsigned.expires_at_ms.get() + 1);
    unsigned.attempt_digest = Digest32::new("00".repeat(32)).unwrap();
    unsigned.attempt_digest = unsigned.computed_attempt_digest().unwrap();
    let request = SignRequest {
        unsigned,
        broker_signature: Base64UrlBytes::from_bytes(&[0; 64]),
    };
    assert_eq!(
        request.validate_shape().unwrap_err().code,
        ProtocolErrorCode::MalformedFrame
    );
}

#[test]
fn ed25519_sign_request_rejects_empty_and_oversized_messages() {
    let vector: SignOperationVector =
        serde_json::from_str(include_str!("../vectors/sign-operation-local-v1.json")).unwrap();

    for message in [
        Vec::new(),
        vec![0u8; MAX_ED25519_MESSAGE_BYTES.saturating_add(1)],
    ] {
        let digest = Digest32::from_bytes(sha2::Sha256::digest(&message).into());
        let mut unsigned = vector.unsigned_request.clone();
        unsigned.crypto_suite = CryptoSuite::Ed25519Message;
        unsigned.ordered_messages = vec![Base64UrlBytes::from_bytes(&message)];
        unsigned.ordered_hashes = vec![digest.clone()];
        unsigned.ordered_payload_digests = vec![digest];
        unsigned.signature_count = DecimalU64::new(1);
        unsigned.operation_digest = unsigned.operation_identity().digest().unwrap();
        unsigned.attempt_digest = Digest32::new("00".repeat(32)).unwrap();
        unsigned.attempt_digest = unsigned.computed_attempt_digest().unwrap();
        let request = SignRequest {
            unsigned,
            broker_signature: Base64UrlBytes::from_bytes(&[0; 64]),
        };
        assert_eq!(
            request.validate_shape().unwrap_err().code,
            ProtocolErrorCode::MalformedFrame
        );
    }
}

#[test]
fn broker_validation_receipt_signature_and_digest_golden() {
    let receipt = BrokerValidationReceipt {
        approval_id: Digest32::new("11".repeat(32)).unwrap(),
        approval_digest: Digest32::new("12".repeat(32)).unwrap(),
        operation_digest: Digest32::new("13".repeat(32)).unwrap(),
        policy_version: DecimalU64::new(7),
        policy_digest: Digest32::new("14".repeat(32)).unwrap(),
        claim_digest: Some(Digest32::new("15".repeat(32)).unwrap()),
        assurance_digest: Some(Digest32::new("16".repeat(32)).unwrap()),
        reservation_ids: vec![Digest32::new("17".repeat(32)).unwrap()],
        effective_claim_assurance: Some(SignerClaimAssurance::MachineAsserted),
        broker_key_id: Token::new("broker-app-v1").unwrap(),
        broker_signature: Base64UrlBytes::from_bytes(&[0x18; 64]),
    };
    let unsigned = String::from_utf8(receipt.unsigned_canonical_bytes().unwrap()).unwrap();
    assert!(!unsigned.contains("broker_signature"));
    assert_eq!(
        unsigned,
        "{\"approval_digest\":\"1212121212121212121212121212121212121212121212121212121212121212\",\"approval_id\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"assurance_digest\":\"1616161616161616161616161616161616161616161616161616161616161616\",\"broker_key_id\":\"broker-app-v1\",\"claim_digest\":\"1515151515151515151515151515151515151515151515151515151515151515\",\"effective_claim_assurance\":{\"kind\":\"machine_asserted\"},\"operation_digest\":\"1313131313131313131313131313131313131313131313131313131313131313\",\"policy_digest\":\"1414141414141414141414141414141414141414141414141414141414141414\",\"policy_version\":\"7\",\"reservation_ids\":[\"1717171717171717171717171717171717171717171717171717171717171717\"]}"
    );
    assert_eq!(
        receipt.digest().unwrap().as_str(),
        "18291199bc67c8e91afd52e6d872fffc3108e618608c18b44019094433bbf776"
    );
    assert!(
        receipt
            .signature_message()
            .unwrap()
            .starts_with(BROKER_VALIDATION_RECEIPT_SIGNATURE_DOMAIN)
    );

    let baseline_message = receipt.signature_message().unwrap();
    let baseline_digest = receipt.digest().unwrap();
    let mut changes = Vec::new();
    let mut changed = receipt.clone();
    changed.approval_id = Digest32::new("21".repeat(32)).unwrap();
    changes.push(changed);
    let mut changed = receipt.clone();
    changed.approval_digest = Digest32::new("22".repeat(32)).unwrap();
    changes.push(changed);
    let mut changed = receipt.clone();
    changed.operation_digest = Digest32::new("23".repeat(32)).unwrap();
    changes.push(changed);
    let mut changed = receipt.clone();
    changed.policy_version = DecimalU64::new(8);
    changes.push(changed);
    let mut changed = receipt.clone();
    changed.policy_digest = Digest32::new("24".repeat(32)).unwrap();
    changes.push(changed);
    let mut changed = receipt.clone();
    changed.claim_digest = None;
    changes.push(changed);
    let mut changed = receipt.clone();
    changed.assurance_digest = None;
    changes.push(changed);
    let mut changed = receipt.clone();
    changed
        .reservation_ids
        .push(Digest32::new("25".repeat(32)).unwrap());
    changes.push(changed);
    let mut changed = receipt.clone();
    changed.effective_claim_assurance = None;
    changes.push(changed);
    let mut changed = receipt.clone();
    changed.broker_key_id = Token::new("broker-app-v2").unwrap();
    changes.push(changed);
    for changed in changes {
        assert_ne!(changed.signature_message().unwrap(), baseline_message);
        assert_ne!(changed.digest().unwrap(), baseline_digest);
    }
    let mut signature_changed = receipt;
    signature_changed.broker_signature = Base64UrlBytes::from_bytes(&[0x19; 64]);
    assert_eq!(
        signature_changed.signature_message().unwrap(),
        baseline_message
    );
    assert_ne!(signature_changed.digest().unwrap(), baseline_digest);
}
