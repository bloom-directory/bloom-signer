//! Fail-closed backend support for the BIP-39 profile.
//!
//! BIP-39 derivation requires the local derivation backend; an artifact built
//! without it (for example `--no-default-features --features aws-kms`) must
//! reject a bip39 registration prepare with `BackendUnsupported` rather than
//! reach an unimplemented provisioning path.
#![cfg(not(feature = "local"))]

use bloom_signer::{
    ceremony::SignerCeremonyService,
    engine::{SignerAuditKeys, SignerEngine},
    registry::BackendRegistry,
};
use bloom_signer_api::{
    CeremonyKind, CustodyPrepareRequest, Digest32, OperationId, ProtocolErrorCode, Token,
    WalletSeedProfile,
};
use ed25519_dalek::SigningKey;
use std::{collections::BTreeMap, sync::Arc};

fn audit_keys() -> SignerAuditKeys {
    SignerAuditKeys {
        current_key_id: Token::new("signer-audit-key").unwrap(),
        current_signing_key: SigningKey::from_bytes(&[14; 32]),
        historical_verifying_keys: BTreeMap::new(),
    }
}

#[test]
fn bip39_registration_prepare_is_backend_unsupported_without_local() {
    let registry = Arc::new(BackendRegistry::from_compiled(vec![]).unwrap());
    let engine = Arc::new(
        SignerEngine::open_in_memory(
            Token::new("broker-app-1").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
            Token::new("signer-revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            audit_keys(),
            registry.clone(),
        )
        .unwrap(),
    );
    let service = SignerCeremonyService::new(
        engine.clone(),
        Token::new("signer-ceremony-key").unwrap(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();

    let result = service.prepare_custody(
        CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::WalletRegistration,
            custody_operation_id: OperationId::new("a1".repeat(32)).unwrap(),
            wallet_id: Some(Token::new("bip39-no-local").unwrap()),
            key_ref: None,
            exact_terms_digest: Digest32::new("a1".repeat(32)).unwrap(),
            expected_input_class: Token::new("passkey-prf").unwrap(),
            browser_output_recipient_key: None,
            petal_key_scope: None,
            legacy_passkey_migration: None,
            wallet_seed_profile: Some(WalletSeedProfile::Bip39MulticurveV1),
            derivation_request: None,
        },
        10_000,
    );
    assert_eq!(
        result.unwrap_err().code,
        ProtocolErrorCode::BackendUnsupported
    );
}
