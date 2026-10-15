mod support;
use bloom_signer::{
    cards::CardCeremonies,
    hpke::{CUSTODY_INPUT_INFO, CUSTODY_OUTPUT_INFO, HpkeRecipient},
};
use bloom_signer_api::*;
use ed25519_dalek::SigningKey;
use std::sync::Arc;
use support::{VirtualAuthenticator, seal_hpke};
const NOW: u64 = 1_760_000_000_000;

fn traveler_input(auth: &VirtualAuthenticator, given: &str) -> serde_json::Value {
    let mut input = private(auth, false, false);
    input["traveler"] = serde_json::json!({"given_name":given,"family_name":"SyntheticFamily",
        "born_on":"1992-02-29","gender":"female","nationality":"CA","email":"fixture@example.com",
        "phone":"+12505550123","document_kind":"passport","document_number":"SYNTHETIC-DOC-123",
        "document_country":"CA","document_expiry":"2030-12-31"});
    input
}

fn save_traveler(op: u8, id: &str, label: &str) -> CardPrepareRequest {
    request(
        op,
        CardEffect::SaveTraveler {
            traveler_id: Token::new(id).unwrap(),
            label: label.into(),
        },
    )
}

#[test]
fn travelers_are_independent_encrypted_records_with_private_scoped_output() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("custody.sqlite3");
    let cards = service();
    cards.open_storage(&path).unwrap();
    let auth = enroll(&cards);
    for (op, id, label, name) in [
        (2, "wife", "Wife", "SyntheticWife"),
        (3, "self", "Me", "SyntheticSelf"),
    ] {
        let p = cards
            .prepare(save_traveler(op, id, label), NOW + 2)
            .unwrap();
        let result = cards
            .complete(
                complete(&auth, &p, traveler_input(&auth, name), op.into()),
                NOW + 3,
            )
            .unwrap();
        assert!(result.encrypted_browser_result.is_none());
    }
    let public = serde_json::to_string(&cards.travelers().unwrap()).unwrap();
    assert!(public.contains("Wife") && public.contains("Me"));
    for secret in [
        "SyntheticWife",
        "SyntheticSelf",
        "SyntheticFamily",
        "1992-02-29",
        "fixture@example.com",
        "SYNTHETIC-DOC-123",
    ] {
        assert!(!public.contains(secret));
        assert!(!String::from_utf8_lossy(&std::fs::read(&path).unwrap()).contains(secret));
    }
    let recipient = HpkeRecipient::generate();
    let effect = CardEffect::FillTraveler {
        traveler_id: Token::new("wife").unwrap(),
        scope: TravelerFillScope {
            origin: "https://airline.example".into(),
            frame_origins: vec!["https://airline.example".into()],
            document_binding: Digest32::from_bytes([33; 32]),
            fields: vec![TravelerField::GivenName, TravelerField::FamilyName],
        },
        recipient_key: recipient.public_key().clone(),
    };
    let p = cards.prepare(request(4, effect.clone()), NOW + 4).unwrap();
    let mut changed = effect;
    if let CardEffect::FillTraveler { scope, .. } = &mut changed {
        scope.origin = "https://other.example".into();
    }
    assert!(cards.prepare(request(4, changed), NOW + 4).is_err());
    let completed = complete(&auth, &p, private(&auth, false, false), 4);
    let result = cards.complete(completed.clone(), NOW + 5).unwrap();
    assert!(cards.complete(completed, NOW + 6).is_err());
    let aad = CustodyOutputHpkeAad {
        surface: p.contribution.surface.clone(),
        ceremony_id: p.contribution.ceremony_id.clone(),
        ceremony_kind: p.contribution.ceremony_kind,
        custody_operation_id: p.contribution.custody_operation_id.clone(),
        signer_contribution_digest: p.contribution.digest().unwrap(),
        public_binding_digest: p.contribution.review_manifest_digest.clone(),
    };
    let encrypted = result.encrypted_browser_result.as_ref().unwrap();
    assert!(
        HpkeRecipient::generate()
            .open(
                encrypted,
                CUSTODY_OUTPUT_INFO,
                &aad.canonical_bytes().unwrap()
            )
            .is_err()
    );
    let released = recipient
        .open(
            encrypted,
            CUSTODY_OUTPUT_INFO,
            &aad.canonical_bytes().unwrap(),
        )
        .unwrap();
    let fields: serde_json::Value = serde_json::from_slice(released.expose_to_backend()).unwrap();
    assert_eq!(
        fields,
        serde_json::json!({"given_name":"SyntheticWife","family_name":"SyntheticFamily"})
    );
    let reopened = service();
    reopened.open_storage(&path).unwrap();
    assert_eq!(reopened.travelers().unwrap().len(), 2);
    let p = reopened
        .prepare(
            request(
                5,
                CardEffect::DeleteTraveler {
                    traveler_id: Token::new("wife").unwrap(),
                },
            ),
            NOW + 7,
        )
        .unwrap();
    reopened
        .complete(
            complete(&auth, &p, private(&auth, false, false), 5),
            NOW + 8,
        )
        .unwrap();
    assert_eq!(
        reopened.travelers().unwrap()[0].traveler_id.as_str(),
        "self"
    );
    assert_eq!(reopened.list().unwrap().len(), 1);
}

#[test]
fn travelers_can_enroll_without_a_card_and_reject_mixed_or_invalid_input() {
    let cards = service();
    let auth = VirtualAuthenticator::generate();
    let p = cards
        .prepare(save_traveler(1, "wife", "Wife"), NOW)
        .unwrap();
    cards
        .complete(
            complete(&auth, &p, traveler_input(&auth, "SyntheticWife"), 1),
            NOW + 1,
        )
        .unwrap();
    assert!(cards.list().unwrap().is_empty());
    let p = cards
        .prepare(save_traveler(2, "wife", "Wife"), NOW + 2)
        .unwrap();
    let mut input = traveler_input(&auth, "Replacement");
    input["cvc"] = serde_json::json!("123");
    assert!(
        cards
            .complete(complete(&auth, &p, input, 2), NOW + 3)
            .is_err()
    );
    let p = cards
        .prepare(save_traveler(3, "wife", "Wife"), NOW + 4)
        .unwrap();
    let mut input = traveler_input(&auth, "Replacement");
    input["traveler"]["born_on"] = serde_json::json!("1993-02-29");
    assert!(
        cards
            .complete(complete(&auth, &p, input, 3), NOW + 5)
            .is_err()
    );
    assert_eq!(cards.travelers().unwrap().len(), 1);
    let p = cards
        .prepare(save_traveler(4, "self", "Me"), NOW + 6)
        .unwrap();
    assert!(
        cards
            .complete(
                complete(&auth, &p, traveler_input(&auth, "Late"), 4),
                NOW + 900_007
            )
            .is_err()
    );
}

#[test]
fn manual_checkout_authorizes_view_without_release_and_rejects_cvc() {
    let cards = service();
    let auth = enroll(&cards);
    let p = cards
        .prepare(
            request(
                2,
                CardEffect::ManualCheckout {
                    card_id: Some(Token::new("card-one").unwrap()),
                    agent_description: "Unverified checkout".into(),
                },
            ),
            NOW + 2,
        )
        .unwrap();
    assert!(p.contribution.browser_output_recipient_key.is_none());
    let result = cards
        .complete(
            complete(&auth, &p, private(&auth, false, false), 2),
            NOW + 3,
        )
        .unwrap();
    assert!(result.encrypted_browser_result.is_none());
    let p = cards
        .prepare(
            request(
                3,
                CardEffect::ManualCheckout {
                    card_id: Some(Token::new("card-one").unwrap()),
                    agent_description: "Unverified checkout".into(),
                },
            ),
            NOW + 4,
        )
        .unwrap();
    assert!(
        cards
            .complete(complete(&auth, &p, private(&auth, false, true), 3), NOW + 5)
            .is_err()
    );
    assert_eq!(cards.list().unwrap().len(), 1);
}

#[test]
fn takeover_and_site_checkout_release_nothing_and_reject_card_input() {
    let cards = service();
    let auth = enroll(&cards);
    let site = || CardEffect::SiteCheckout {
        facts: CheckoutFacts {
            origin: "https://shop.example".into(),
            payment_frame_origins: vec![],
            total_minor: 4990,
            currency: "CHF".into(),
            installments: 1,
            recurring: false,
        },
        agent_description: "Order with the shop's saved card".into(),
    };
    let takeover = CardEffect::ManualCheckout {
        card_id: None,
        agent_description: "Log in to the shop".into(),
    };
    for (op, effect) in [(2, takeover), (3, site())] {
        let p = cards.prepare(request(op, effect), NOW + 2).unwrap();
        assert!(p.contribution.browser_output_recipient_key.is_none());
        let result = cards
            .complete(
                complete(&auth, &p, private(&auth, false, false), op.into()),
                NOW + 3,
            )
            .unwrap();
        assert!(result.encrypted_browser_result.is_none());
    }
    let p = cards.prepare(request(4, site()), NOW + 4).unwrap();
    assert!(
        cards
            .complete(complete(&auth, &p, private(&auth, false, true), 4), NOW + 5)
            .is_err()
    );
    let mut framed = site();
    if let CardEffect::SiteCheckout { facts, .. } = &mut framed {
        facts.payment_frame_origins = vec!["https://js.stripe.com".into()];
    }
    assert!(cards.prepare(request(5, framed), NOW + 6).is_err());
    assert_eq!(cards.list().unwrap().len(), 1);
}

#[test]
#[ignore = "generates an explicit retained fixture for released-revision rollback testing"]
fn prepare_released_rollback_fixture() {
    use bloom_signer::{
        ceremony::SignerCeremonyService,
        engine::{SignerAuditKeys, SignerEngine},
        registry::BackendRegistry,
    };
    use std::collections::BTreeMap;
    let root = std::path::PathBuf::from(std::env::var("BLOOM_CARD_ROLLBACK_FIXTURE_DIR").unwrap());
    assert!(
        root.join("signer.sqlite3").is_file(),
        "generate the wallet fixture with the released revision first"
    );
    let engine = SignerEngine::open(
        root.join("signer.sqlite3"),
        Token::new("broker-app-1").unwrap(),
        SigningKey::from_bytes(&[7; 32]).verifying_key(),
        SigningKey::from_bytes(&[9; 32]).verifying_key(),
        Token::new("signer-revocation-key").unwrap(),
        SigningKey::from_bytes(&[4; 32]),
        SignerAuditKeys {
            current_key_id: Token::new("signer-audit-key").unwrap(),
            current_signing_key: SigningKey::from_bytes(&[14; 32]),
            historical_verifying_keys: BTreeMap::new(),
        },
        Arc::new(BackendRegistry::from_compiled(Vec::new()).unwrap()),
    )
    .unwrap();
    let _ceremony = SignerCeremonyService::new(
        Arc::new(engine),
        Token::new("signer-ceremony-key").unwrap(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    let db = rusqlite::Connection::open(root.join("signer.sqlite3")).unwrap();
    let before: String = db
        .query_row(
            "SELECT custody_jcs FROM ceremony_wallets WHERE wallet_id='rollback-wallet'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let cards = service();
    cards.open_storage(&root.join("cards.sqlite3")).unwrap();
    let auth = enroll(&cards);
    let (prepared, _) = checkout(&cards, 2);
    cards
        .complete(
            complete(&auth, &prepared, private(&auth, false, true), 2),
            NOW + 3,
        )
        .unwrap();
    assert!(cards.list().unwrap().len() == 1);
    let after: String = db
        .query_row(
            "SELECT custody_jcs FROM ceremony_wallets WHERE wallet_id='rollback-wallet'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(before == after);
}
fn service() -> CardCeremonies {
    CardCeremonies::new(
        SigningKey::from_bytes(&[7; 32]),
        Token::new("card-signer").unwrap(),
        bloom_signer::webauthn::configured_ceremony_origin().expect("test origin"),
    )
    .unwrap()
}
fn request(op: u8, effect: CardEffect) -> CardPrepareRequest {
    CardPrepareRequest {
        surface: legacy_local_surface(),
        operation_id: OperationId::from_bytes([op; 32]),
        effect,
    }
}
fn add(op: u8, id: &str) -> CardPrepareRequest {
    request(
        op,
        CardEffect::Add {
            card_id: Token::new(id).unwrap(),
            label: "Test card".into(),
        },
    )
}
fn private(auth: &VirtualAuthenticator, card: bool, cvc: bool) -> serde_json::Value {
    let mut v =
        serde_json::json!({"credential_prf":Base64UrlBytes::from_bytes(&auth.deterministic_prf())});
    if card {
        v["card"] = serde_json::json!({"number":"4242424242424242","expiry_month":12,"expiry_year":2034,"name":"Synthetic Test"});
    }
    if cvc {
        v["cvc"] = serde_json::json!("123");
    }
    v
}
fn complete(
    auth: &VirtualAuthenticator,
    p: &SignerPreparedCustody,
    input: serde_json::Value,
    count: u32,
) -> CustodyCompleteRequest {
    let c = &p.contribution;
    let credential_id = auth.credential(0).credential_id;
    let proof = if p.webauthn_options.registration_user_handle.is_some() {
        WebAuthnCeremonyProof::Registration {
            attestation: auth.attestation(&p.challenges[0].canonical_bytes().unwrap()),
            prf_assertion: Some(auth.assertion(&p.challenges[1].canonical_bytes().unwrap(), count)),
        }
    } else {
        WebAuthnCeremonyProof::Assertion {
            assertion: auth.assertion(&p.challenges[0].canonical_bytes().unwrap(), count),
        }
    };
    let aad = CustodyHpkeAad {
        surface: c.surface.clone(),
        ceremony_id: c.ceremony_id.clone(),
        ceremony_kind: c.ceremony_kind,
        custody_operation_id: c.custody_operation_id.clone(),
        signer_nonce: c.signer_nonce.clone(),
        signer_contribution_digest: c.digest().unwrap(),
        wallet_id: None,
        key_ref: None,
        credential_id: Some(credential_id),
        expected_input_class: c.expected_input_class.clone(),
    };
    CustodyCompleteRequest {
        ceremony_kind: c.ceremony_kind,
        custody_operation_id: c.custody_operation_id.clone(),
        ceremony_id: c.ceremony_id.clone(),
        proof,
        encrypted_input: Some(
            seal_hpke(
                &c.hpke_recipient_key,
                CUSTODY_INPUT_INFO,
                &aad.canonical_bytes().unwrap(),
                &serde_json::to_vec(&input).unwrap(),
            )
            .unwrap(),
        ),
        public_binding_digest: c.review_manifest_digest.clone(),
    }
}
fn enroll(s: &CardCeremonies) -> VirtualAuthenticator {
    let p = s.prepare(add(1, "card-one"), NOW).unwrap();
    let auth = VirtualAuthenticator::generate_with_user_handle(
        &p.webauthn_options
            .registration_user_handle
            .as_ref()
            .unwrap()
            .decode(),
    );
    s.complete(complete(&auth, &p, private(&auth, true, false), 1), NOW + 1)
        .unwrap();
    auth
}
fn checkout(s: &CardCeremonies, op: u8) -> (SignerPreparedCustody, HpkeRecipient) {
    let recipient = HpkeRecipient::generate();
    let p = s
        .prepare(
            request(
                op,
                CardEffect::Checkout {
                    card_id: Token::new("card-one").unwrap(),
                    facts: CheckoutFacts {
                        origin: "https://merchant.example".into(),
                        payment_frame_origins: vec!["https://payments.example".into()],
                        total_minor: 199,
                        currency: "USD".into(),
                        installments: 1,
                        recurring: false,
                    },
                    recipient_key: recipient.public_key().clone(),
                    agent_description: "Digital test item".into(),
                },
            ),
            NOW + 2,
        )
        .unwrap();
    (p, recipient)
}
#[test]
fn approved_release_is_bound_encrypted_and_single_use() {
    let s = service();
    let auth = enroll(&s);
    let (p, recipient) = checkout(&s, 2);
    let completed = complete(&auth, &p, private(&auth, false, true), 2);
    let result = s.complete(completed.clone(), NOW + 3).unwrap();
    let aad = CustodyOutputHpkeAad {
        surface: p.contribution.surface.clone(),
        ceremony_id: p.contribution.ceremony_id.clone(),
        ceremony_kind: CeremonyKind::CardCheckout,
        custody_operation_id: p.contribution.custody_operation_id.clone(),
        signer_contribution_digest: p.contribution.digest().unwrap(),
        public_binding_digest: p.contribution.review_manifest_digest.clone(),
    };
    let plaintext = recipient
        .open(
            result.encrypted_browser_result.as_ref().unwrap(),
            CUSTODY_OUTPUT_INFO,
            &aad.canonical_bytes().unwrap(),
        )
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(plaintext.expose_to_backend()).unwrap();
    assert!(value["number"] == "4242424242424242" && value["cvc"] == "123");
    assert!(s.complete(completed, NOW + 4).is_err());
    let projection = serde_json::to_string(&s.list().unwrap()).unwrap();
    assert!(
        !projection.contains("4242424242424242")
            && !projection.contains("expiry")
            && !projection.contains("cvc")
    );
}
#[test]
fn wrong_credential_missing_uv_and_tampering_never_release() {
    for case in 0..5 {
        let s = service();
        let auth = enroll(&s);
        let (p, _) = checkout(&s, 2);
        let mut c = if case == 0 {
            let other = VirtualAuthenticator::generate();
            complete(&other, &p, private(&other, false, true), 2)
        } else {
            complete(&auth, &p, private(&auth, false, true), 2)
        };
        match case {
            1 => {
                c.proof = WebAuthnCeremonyProof::Assertion {
                    assertion: auth
                        .assertion_without_uv(&p.challenges[0].canonical_bytes().unwrap(), 2),
                }
            }
            2 => {
                let envelope = c.encrypted_input.as_mut().unwrap();
                let mut bytes = envelope.ciphertext.decode();
                bytes[0] ^= 1;
                envelope.ciphertext = Base64UrlBytes::from_bytes(&bytes);
            }
            3 => {
                c.encrypted_input.as_mut().unwrap().ciphertext =
                    Base64UrlBytes::from_bytes(&vec![0; 4097])
            }
            4 => c.public_binding_digest = Digest32::from_bytes([9; 32]),
            _ => {}
        }
        assert!(s.complete(c.clone(), NOW + 3).is_err());
        assert!(s.complete(c, NOW + 4).is_err());
    }
}
#[test]
fn expired_checkout_cannot_release() {
    let s = service();
    let auth = enroll(&s);
    let (p, _) = checkout(&s, 2);
    assert!(
        s.complete(
            complete(&auth, &p, private(&auth, false, true), 2),
            NOW + 122_002
        )
        .is_err()
    );
}

#[test]
fn cancellation_and_restart_close_pending_approvals() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("cards.sqlite3");
    let s = service();
    s.open_storage(&path).unwrap();
    let auth = enroll(&s);
    let (p, _) = checkout(&s, 2);
    let c = complete(&auth, &p, private(&auth, false, true), 2);
    assert!(
        s.cancel(&p.contribution.custody_operation_id, NOW + 3)
            .unwrap()
            .state
            == CardOperationState::Cancelled
    );
    assert!(s.complete(c, NOW + 4).is_err());
    let (p, _) = checkout(&s, 3);
    let c = complete(&auth, &p, private(&auth, false, true), 2);
    drop(s);
    let s = service();
    s.open_storage(&path).unwrap();
    assert!(
        s.status(&p.contribution.custody_operation_id, NOW + 4)
            .unwrap()
            .state
            == CardOperationState::Failed
    );
    assert!(s.complete(c, NOW + 4).is_err());
}
#[test]
fn invalid_luhn_expiry_and_cvc_enrollment_are_rejected() {
    for case in 0..3 {
        let s = service();
        let p = s.prepare(add(1, "card-one"), NOW).unwrap();
        let auth = VirtualAuthenticator::generate_with_user_handle(
            &p.webauthn_options
                .registration_user_handle
                .as_ref()
                .unwrap()
                .decode(),
        );
        let mut input = private(&auth, true, case == 2);
        if case == 0 {
            input["card"]["number"] = serde_json::json!("4242424242424241");
        }
        if case == 1 {
            input["card"]["expiry_year"] = serde_json::json!(2020);
        }
        assert!(s.complete(complete(&auth, &p, input, 1), NOW + 1).is_err());
        assert!(s.list().unwrap().is_empty());
    }
}
#[test]
fn restart_preserves_cards_and_replay_consumption_and_delete_keeps_container() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("cards.sqlite3");
    let s = service();
    s.open_storage(&path).unwrap();
    let auth = enroll(&s);
    let (p, _) = checkout(&s, 2);
    let c = complete(&auth, &p, private(&auth, false, true), 2);
    s.complete(c.clone(), NOW + 3).unwrap();
    drop(s);
    let reopened = service();
    reopened.open_storage(&path).unwrap();
    assert!(reopened.list().unwrap().len() == 1);
    assert!(reopened.complete(c, NOW + 4).is_err());
    let p = reopened
        .prepare(
            request(
                3,
                CardEffect::Delete {
                    card_id: Token::new("card-one").unwrap(),
                },
            ),
            NOW + 4,
        )
        .unwrap();
    reopened
        .complete(
            complete(&auth, &p, private(&auth, false, false), 3),
            NOW + 5,
        )
        .unwrap();
    assert!(reopened.list().unwrap().is_empty());
    let p = reopened.prepare(add(4, "card-two"), NOW + 6).unwrap();
    assert!(p.webauthn_options.registration_user_handle.is_none());
    let bytes = std::fs::read(path).unwrap();
    assert!(!bytes.windows(16).any(|w| w == b"4242424242424242"));
}
#[test]
fn exactly_one_concurrent_release_succeeds() {
    let s = Arc::new(service());
    let auth = enroll(&s);
    let (p, _) = checkout(&s, 2);
    let c = complete(&auth, &p, private(&auth, false, true), 2);
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let handles = (0..8)
        .map(|_| {
            let s = s.clone();
            let c = c.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                s.complete(c, NOW + 3).is_ok()
            })
        })
        .collect::<Vec<_>>();
    assert!(
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count()
            == 1
    );
}
#[test]
fn interrupted_storage_write_does_not_mutate_cards_or_reuse_approval() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("cards.sqlite3");
    let s = service();
    s.open_storage(&path).unwrap();
    let auth = enroll(&s);
    let (p, _) = checkout(&s, 2);
    let c = complete(&auth, &p, private(&auth, false, true), 2);
    let blocker = rusqlite::Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    assert!(s.complete(c.clone(), NOW + 3).is_err());
    blocker.execute_batch("ROLLBACK").unwrap();
    assert!(s.list().unwrap().len() == 1);
    assert!(s.complete(c, NOW + 4).is_err());
}
#[test]
fn adding_under_an_existing_id_replaces_that_card() {
    let s = service();
    let auth = enroll(&s);
    let p = s.prepare(add(2, "card-one"), NOW + 2).unwrap();
    let mut input = private(&auth, true, false);
    input["card"]["number"] = serde_json::json!("5555555555554444");
    s.complete(complete(&auth, &p, input, 2), NOW + 3).unwrap();
    let cards = s.list().unwrap();
    assert_eq!(cards.len(), 1);
    assert_eq!(
        (cards[0].brand.as_str(), cards[0].last4.as_str()),
        ("Mastercard", "4444")
    );
}
