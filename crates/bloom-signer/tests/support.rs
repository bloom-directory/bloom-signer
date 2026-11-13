#![allow(dead_code)]
//! Test-only driver for Signer ceremony surfaces.
//!
//! This module is not linked by production Signer artifacts. It
//! produces genuine ES256 WebAuthn bytes and RFC 9180 HPKE envelopes so tests
//! exercise the same public contracts as a browser.

use std::{collections::BTreeMap, path::Path, sync::Arc};

use bloom_signer::{
    ceremony::{PreparedCustodyCeremony, SignerCeremonyService},
    engine::{SignerAuditKeys, SignerEngine},
    hpke::{HpkeRecipient, LOCAL_PRF_INFO},
    registry::BackendRegistry,
};
use bloom_signer_api::{
    ActivationMode, ApprovalLimits, ApprovalSelector, ApprovalSubject, Base64UrlBytes,
    CeremonyCompleteRequest, CeremonyKind, CeremonyPrepareRequest, CryptoSuite,
    CustodyCompleteRequest, CustodyHpkeAad, CustodyPrepareRequest, CustodyResult,
    CustodySignerContribution, DecimalU64, DerivationProfile, DerivedAccountRequest, Digest32,
    HpkeEnvelope, KeyRef, LocalPrfHpkeAad, OperationId, ProtocolError, ProtocolErrorCode,
    RequestNonce, SealedApprovalTerms, SignerActivationReceipt, Token, WalletSeedProfile,
    WebAuthnAssertion, WebAuthnAttestation, WebAuthnCeremonyProof, WebAuthnCredential,
};
use ciborium::value::{Integer, Value};
use ed25519_dalek::SigningKey as Ed25519Key;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, setup_sender,
};
use p256::{
    ecdsa::{SigningKey, signature::Signer as _},
    elliptic_curve::Generate as _,
};
use rand::{TryRng as _, rngs::SysRng};
use sha2::{Digest as _, Sha256};

type BloomKem = X25519HkdfSha256;

pub struct VirtualAuthenticator {
    signing_key: SigningKey,
    credential_id: Base64UrlBytes,
    user_handle: Base64UrlBytes,
    origin: String,
    rp_id: String,
}

impl VirtualAuthenticator {
    pub fn generate() -> Self {
        let mut credential_id = [0_u8; 32];
        let mut user_handle = [0_u8; 32];
        SysRng
            .try_fill_bytes(&mut credential_id)
            .expect("OS randomness unavailable");
        SysRng
            .try_fill_bytes(&mut user_handle)
            .expect("OS randomness unavailable");
        Self {
            signing_key: SigningKey::generate(),
            credential_id: Base64UrlBytes::from_bytes(&credential_id),
            user_handle: Base64UrlBytes::from_bytes(&user_handle),
            origin: bloom_signer::webauthn::configured_ceremony_origin().expect("test origin"),
            rp_id: "localhost".into(),
        }
    }

    pub fn generate_with_user_handle(user_handle: &[u8]) -> Self {
        let mut authenticator = Self::generate();
        authenticator.user_handle = Base64UrlBytes::from_bytes(user_handle);
        authenticator
    }

    pub fn from_test_material(
        signing_key: [u8; 32],
        credential_id: &[u8],
        user_handle: &[u8],
    ) -> Self {
        Self {
            signing_key: SigningKey::from_slice(&signing_key).expect("valid test signing key"),
            credential_id: Base64UrlBytes::from_bytes(credential_id),
            user_handle: Base64UrlBytes::from_bytes(user_handle),
            origin: bloom_signer::webauthn::configured_ceremony_origin().expect("test origin"),
            rp_id: "localhost".into(),
        }
    }

    pub fn generate_for_surface(user_handle: &[u8], origin: &str, rp_id: &str) -> Self {
        let mut authenticator = Self::generate_with_user_handle(user_handle);
        authenticator.origin = origin.to_owned();
        authenticator.rp_id = rp_id.to_owned();
        authenticator
    }

    pub fn credential(&self, sign_count: u32) -> WebAuthnCredential {
        WebAuthnCredential {
            surface: bloom_signer_api::legacy_local_surface(),
            credential_id: self.credential_id.clone(),
            cose_public_key: Base64UrlBytes::from_bytes(
                &self.cose_public_key().expect("generated key encodes"),
            ),
            user_handle: self.user_handle.clone(),
            rp_id: bloom_signer_api::RpId::new(self.rp_id.clone()).expect("test RP ID"),
            prf_salt: Base64UrlBytes::from_bytes(&Sha256::digest(
                [
                    b"bloom-debug-driver-salt/v1".as_slice(),
                    self.credential_id.decode().as_slice(),
                ]
                .concat(),
            )),
            sign_count: DecimalU64::new(u64::from(sign_count)),
        }
    }

    pub fn assertion(&self, challenge: &[u8], sign_count: u32) -> WebAuthnAssertion {
        self.assertion_with_origin(challenge, sign_count, &self.origin)
    }

    /// Correctly signed assertion binding an explicit origin, for
    /// wrong-origin rejection tests: the signature stays valid so only the
    /// origin check can fail.
    pub fn assertion_with_origin(
        &self,
        challenge: &[u8],
        sign_count: u32,
        origin: &str,
    ) -> WebAuthnAssertion {
        let client_data = client_data_with_origin("webauthn.get", challenge, origin);
        let authenticator_data = authenticator_data(0x05, sign_count, &self.rp_id);
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        let signature: p256::ecdsa::Signature = self.signing_key.sign(&message);
        WebAuthnAssertion {
            credential_id: self.credential_id.clone(),
            authenticator_data: Base64UrlBytes::from_bytes(&authenticator_data),
            client_data_json: Base64UrlBytes::from_bytes(&client_data),
            signature: Base64UrlBytes::from_bytes(signature.to_der().as_bytes()),
            user_handle: Some(self.user_handle.clone()),
        }
    }

    pub fn attestation(&self, challenge: &[u8]) -> WebAuthnAttestation {
        self.attestation_with_origin(challenge, &self.origin)
    }

    /// Correctly formed attestation binding an explicit origin, for
    /// wrong-origin rejection tests.
    pub fn attestation_with_origin(&self, challenge: &[u8], origin: &str) -> WebAuthnAttestation {
        let mut auth_data = authenticator_data(0x45, 0, &self.rp_id);
        auth_data.extend_from_slice(&[0_u8; 16]);
        let credential_id = self.credential_id.decode();
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&credential_id);
        auth_data.extend_from_slice(&self.cose_public_key().expect("generated key encodes"));
        let object = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(Vec::new())),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&object, &mut encoded).expect("attestation encodes");
        WebAuthnAttestation {
            credential_id: self.credential_id.clone(),
            client_data_json: Base64UrlBytes::from_bytes(&client_data_with_origin(
                "webauthn.create",
                challenge,
                origin,
            )),
            attestation_object: Base64UrlBytes::from_bytes(&encoded),
            transports: vec![Token::new("internal").expect("static transport token")],
        }
    }

    pub fn deterministic_prf(&self) -> [u8; 32] {
        Sha256::digest(
            [
                b"bloom-debug-driver-prf/v1".as_slice(),
                self.credential_id.decode().as_slice(),
            ]
            .concat(),
        )
        .into()
    }

    fn cose_public_key(&self) -> Result<Vec<u8>, ProtocolError> {
        let point = self.signing_key.verifying_key().to_sec1_point(false);
        let x = point.x().ok_or_else(driver_error)?;
        let y = point.y().ok_or_else(driver_error)?;
        let value = Value::Map(vec![
            (integer(1), integer(2)),
            (integer(3), integer(-7)),
            (integer(-1), integer(1)),
            (integer(-2), Value::Bytes(x.to_vec())),
            (integer(-3), Value::Bytes(y.to_vec())),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&value, &mut encoded).map_err(|_| driver_error())?;
        Ok(encoded)
    }
}

pub fn seal_hpke(
    recipient_public_key: &Base64UrlBytes,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeEnvelope, ProtocolError> {
    let public_key = <BloomKem as KemTrait>::PublicKey::from_bytes(&recipient_public_key.decode())
        .map_err(|_| driver_error())?;
    let (encapped, mut context) =
        setup_sender::<ChaCha20Poly1305, HkdfSha256, BloomKem>(&OpModeS::Base, &public_key, info)
            .map_err(|_| driver_error())?;
    let ciphertext = context.seal(plaintext, aad).map_err(|_| driver_error())?;
    Ok(HpkeEnvelope {
        kem_output: Base64UrlBytes::from_bytes(&encapped.to_bytes()),
        ciphertext: Base64UrlBytes::from_bytes(&ciphertext),
    })
}

fn client_data_with_origin(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type": kind,
        "challenge": Base64UrlBytes::from_bytes(challenge),
        "origin": origin,
        "crossOrigin": false
    }))
    .expect("client data serializes")
}

fn authenticator_data(flags: u8, sign_count: u32, rp_id: &str) -> Vec<u8> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    data
}

fn integer(value: i128) -> Value {
    Value::Integer(Integer::try_from(value).expect("small COSE integer"))
}

fn driver_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::BackendInvalidRequest,
        "debug driver could not construct standards-compliant proof",
    )
}

pub fn digest(byte: &str) -> Digest32 {
    Digest32::new(byte.repeat(32)).unwrap()
}

pub fn operation(byte: &str) -> OperationId {
    OperationId::new(byte.repeat(32)).unwrap()
}

pub fn audit_keys() -> SignerAuditKeys {
    SignerAuditKeys {
        current_key_id: Token::new("signer-audit-key").unwrap(),
        current_signing_key: Ed25519Key::from_bytes(&[14; 32]),
        historical_verifying_keys: BTreeMap::new(),
    }
}

/// Opens an engine with the test Broker ([7; 32]), ceremony ([9; 32]) and
/// revocation ([4; 32]) keys; `None` opens it in memory.
pub fn open_engine(path: Option<&Path>, registry: Arc<BackendRegistry>) -> Arc<SignerEngine> {
    let broker_key_id = Token::new("broker-app-1").unwrap();
    let broker = Ed25519Key::from_bytes(&[7; 32]).verifying_key();
    let ceremony = Ed25519Key::from_bytes(&[9; 32]).verifying_key();
    let revocation_key_id = Token::new("signer-revocation-key").unwrap();
    let revocation = Ed25519Key::from_bytes(&[4; 32]);
    let engine = match path {
        Some(path) => SignerEngine::open(
            path,
            broker_key_id,
            broker,
            ceremony,
            revocation_key_id,
            revocation,
            audit_keys(),
            registry,
        ),
        None => SignerEngine::open_in_memory(
            broker_key_id,
            broker,
            ceremony,
            revocation_key_id,
            revocation,
            audit_keys(),
            registry,
        ),
    };
    Arc::new(engine.unwrap())
}

pub fn ceremony_service(engine: Arc<SignerEngine>) -> Result<SignerCeremonyService, ProtocolError> {
    SignerCeremonyService::new(
        engine,
        Token::new("signer-ceremony-key").unwrap(),
        Ed25519Key::from_bytes(&[9; 32]),
    )
}

/// A file-backed service with no compiled backend, as BIP-39 wallets use.
pub fn bip39_service(
    path: &Path,
) -> (
    SignerCeremonyService,
    Arc<SignerEngine>,
    Arc<BackendRegistry>,
) {
    bip39_service_at(Some(path))
}

pub fn bip39_memory_service() -> (
    SignerCeremonyService,
    Arc<SignerEngine>,
    Arc<BackendRegistry>,
) {
    bip39_service_at(None)
}

fn bip39_service_at(
    path: Option<&Path>,
) -> (
    SignerCeremonyService,
    Arc<SignerEngine>,
    Arc<BackendRegistry>,
) {
    let registry = Arc::new(BackendRegistry::from_compiled(vec![]).unwrap());
    let engine = open_engine(path, registry.clone());
    (ceremony_service(engine.clone()).unwrap(), engine, registry)
}

/// Exact single-operation CLI approval terms for `key_ref` in `wallet-1`.
pub fn terms(key_ref: KeyRef) -> SealedApprovalTerms {
    SealedApprovalTerms {
        subject: ApprovalSubject::Cli {
            client_id: Token::new("bloom-cli").unwrap(),
            command_class: Token::new("wallet.sign").unwrap(),
        },
        wallet_id: Token::new("wallet-1").unwrap(),
        key_ref,
        allowed_crypto_suites: vec![
            CryptoSuite::Secp256k1Sha256Recoverable,
            CryptoSuite::Secp256k1Keccak256Recoverable,
        ],
        selector: ApprovalSelector::Exact {
            ordered_payload_digests: vec![digest("22")],
            ordered_hashes: vec![digest("33")],
        },
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(1),
            max_signatures: DecimalU64::new(1),
            operation_rate_limits: vec![],
            signature_rate_limits: vec![],
            value_limits: vec![],
        },
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: DecimalU64::new(1),
        policy_version: DecimalU64::new(1),
        policy_digest: digest("44"),
        provenance_digest: digest("55"),
        request_nonce: RequestNonce::new("66".repeat(16)).unwrap(),
        issued_at_ms: DecimalU64::new(1_000),
        not_before_ms: DecimalU64::new(1_000),
        // Exactly the persisted child-scope boundary (derivation committed at
        // 10_300 plus maximum_lifetime_ms 20_000).
        expires_at_ms: DecimalU64::new(30_300),
        renewal_of: None,
    }
}

/// Runs an approval ceremony for `terms` with a local-PRF assertion.
pub fn try_complete_local_approval(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    terms: SealedApprovalTerms,
    activation_operation_id: OperationId,
    sign_count: u32,
    now_ms: u64,
) -> Result<SignerActivationReceipt, ProtocolError> {
    let review_manifest_digest = digest("76");
    let (exact_ordered_payload_digests, exact_ordered_hashes) = match &terms.selector {
        ApprovalSelector::Exact {
            ordered_payload_digests,
            ordered_hashes,
        } => (ordered_payload_digests.clone(), ordered_hashes.clone()),
        ApprovalSelector::Petal { .. } => (Vec::new(), Vec::new()),
    };
    let prepared = service.prepare_approval(
        CeremonyPrepareRequest {
            surface: bloom_signer_api::legacy_local_surface(),
            activation_operation_id: activation_operation_id.clone(),
            terms: terms.clone(),
            review_manifest_digest: review_manifest_digest.clone(),
            exact_ordered_payload_digests,
            exact_ordered_hashes,
            replacement_approval_id: None,
        },
        now_ms,
    )?;
    let assertion = authenticator.assertion(
        &prepared.challenges[0].canonical_bytes().unwrap(),
        sign_count,
    );
    let aad = LocalPrfHpkeAad {
        surface: bloom_signer_api::legacy_local_surface(),
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        approval_id: terms.approval_id().unwrap(),
        approval_digest: terms.approval_digest().unwrap(),
        review_manifest_digest,
        key_ref: terms.key_ref.clone(),
        allowed_crypto_suites: terms.allowed_crypto_suites.clone(),
        credential_id: assertion.credential_id.clone(),
        activation_mode: terms.activation_mode.clone(),
        wallet_revocation_epoch: terms.wallet_revocation_epoch.clone(),
    }
    .canonical_bytes()
    .unwrap();
    let encrypted_local_prf = seal_hpke(
        prepared
            .contribution
            .ephemeral_encryption_public_key
            .as_ref()
            .unwrap(),
        LOCAL_PRF_INFO,
        &aad,
        &authenticator.deterministic_prf(),
    )
    .unwrap();
    futures::executor::block_on(service.complete_approval(
        CeremonyCompleteRequest {
            activation_operation_id,
            proof: WebAuthnCeremonyProof::Assertion { assertion },
            contribution: prepared.contribution,
            encrypted_local_prf: Some(encrypted_local_prf),
        },
        now_ms + 1,
    ))
}

pub fn complete_local_approval(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    terms: SealedApprovalTerms,
    activation_operation_id: OperationId,
    sign_count: u32,
    now_ms: u64,
) -> SignerActivationReceipt {
    try_complete_local_approval(
        service,
        authenticator,
        terms,
        activation_operation_id,
        sign_count,
        now_ms,
    )
    .unwrap()
}

/// A custody prepare request with every optional field empty.
pub fn custody_prepare(
    kind: CeremonyKind,
    operation_id: &OperationId,
    wallet_id: &Token,
    key_ref: Option<KeyRef>,
    exact_terms_digest: Digest32,
    input_class: &str,
) -> CustodyPrepareRequest {
    CustodyPrepareRequest {
        surface: bloom_signer_api::legacy_local_surface(),
        ceremony_kind: kind,
        custody_operation_id: operation_id.clone(),
        wallet_id: Some(wallet_id.clone()),
        key_ref,
        exact_terms_digest,
        expected_input_class: Token::new(input_class).unwrap(),
        browser_output_recipient_key: None,
        petal_key_scope: None,
        legacy_passkey_migration: None,
        wallet_seed_profile: None,
        derivation_requests: Vec::new(),
    }
}

/// A `generic-custody-v1` prepare request bound to the JCS digest of `effect`.
pub fn generic_prepare(
    kind: CeremonyKind,
    operation_id: &OperationId,
    wallet_id: &Token,
    key_ref: Option<KeyRef>,
    effect: &serde_json::Value,
) -> CustodyPrepareRequest {
    let exact_terms_digest =
        Digest32::from_bytes(Sha256::digest(serde_jcs::to_vec(effect).unwrap()).into());
    custody_prepare(
        kind,
        operation_id,
        wallet_id,
        key_ref,
        exact_terms_digest,
        "generic-custody-v1",
    )
}

/// The BIP-39 wallet registration request (terms digest `a1`).
pub fn bip39_registration_request(
    wallet_id: &Token,
    operation_id: &OperationId,
) -> CustodyPrepareRequest {
    CustodyPrepareRequest {
        wallet_seed_profile: Some(WalletSeedProfile::Bip39MulticurveV1),
        ..custody_prepare(
            CeremonyKind::WalletRegistration,
            operation_id,
            wallet_id,
            None,
            digest("a1"),
            "passkey-prf",
        )
    }
}

fn prepare_custody(
    service: &SignerCeremonyService,
    request: &CustodyPrepareRequest,
    output_recipient: Option<&HpkeRecipient>,
    now_ms: u64,
) -> PreparedCustodyCeremony {
    let prepared = service.prepare_custody(request.clone(), now_ms).unwrap();
    match output_recipient {
        Some(recipient) => service
            .bind_custody_output_recipient(
                &request.custody_operation_id,
                recipient.public_key().clone(),
                now_ms + 1,
            )
            .unwrap(),
        None => prepared,
    }
}

/// Prepares `request`, authorizes it with one assertion carrying
/// `{credential_prf, effect}`, and completes it.
pub fn assertion_custody(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    request: CustodyPrepareRequest,
    effect: serde_json::Value,
    output_recipient: Option<&HpkeRecipient>,
    now_ms: u64,
) -> Result<(CustodyResult, CustodySignerContribution), ProtocolError> {
    let prepared = prepare_custody(service, &request, output_recipient, now_ms);
    let assertion = authenticator.assertion(
        &prepared.challenges[0].canonical_bytes().unwrap(),
        now_ms as u32,
    );
    let plaintext = serde_jcs::to_vec(&serde_json::json!({
        "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
        "effect": effect,
    }))
    .unwrap();
    let wallet_id = request.wallet_id.clone();
    seal_and_complete(
        service,
        &request,
        prepared,
        wallet_id,
        WebAuthnCeremonyProof::Assertion { assertion },
        &plaintext,
        now_ms,
    )
}

/// Prepares `request` and completes it with a new-credential attestation and
/// PRF assertion, sealing `plaintext` as the custody input.
pub fn registration_custody(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    request: CustodyPrepareRequest,
    plaintext: &[u8],
    output_recipient: Option<&HpkeRecipient>,
    now_ms: u64,
) -> Result<(CustodyResult, CustodySignerContribution), ProtocolError> {
    let prepared = prepare_custody(service, &request, output_recipient, now_ms);
    let attestation = authenticator.attestation(&prepared.challenges[0].canonical_bytes().unwrap());
    let prf_assertion =
        authenticator.assertion(&prepared.challenges[1].canonical_bytes().unwrap(), 1);
    let wallet_id = prepared.contribution.wallet_id.clone();
    seal_and_complete(
        service,
        &request,
        prepared,
        wallet_id,
        WebAuthnCeremonyProof::Registration {
            attestation,
            prf_assertion: Some(prf_assertion),
        },
        plaintext,
        now_ms,
    )
}

fn seal_and_complete(
    service: &SignerCeremonyService,
    request: &CustodyPrepareRequest,
    prepared: PreparedCustodyCeremony,
    wallet_id: Option<Token>,
    proof: WebAuthnCeremonyProof,
    plaintext: &[u8],
    now_ms: u64,
) -> Result<(CustodyResult, CustodySignerContribution), ProtocolError> {
    let credential_id = match &proof {
        WebAuthnCeremonyProof::Assertion { assertion } => assertion.credential_id.clone(),
        WebAuthnCeremonyProof::Registration { attestation, .. } => {
            attestation.credential_id.clone()
        }
        _ => unreachable!("test driver only builds assertion or registration proofs"),
    };
    let aad = CustodyHpkeAad {
        surface: request.surface.clone(),
        ceremony_id: prepared.contribution.ceremony_id.clone(),
        ceremony_kind: request.ceremony_kind,
        custody_operation_id: request.custody_operation_id.clone(),
        signer_nonce: prepared.contribution.signer_nonce.clone(),
        signer_contribution_digest: prepared.contribution.digest().unwrap(),
        wallet_id,
        key_ref: request.key_ref.clone(),
        credential_id: Some(credential_id),
        expected_input_class: request.expected_input_class.clone(),
    }
    .canonical_bytes()
    .unwrap();
    let encrypted_input = seal_hpke(
        &prepared.contribution.hpke_recipient_key,
        b"bloom-custody-input/v1",
        &aad,
        plaintext,
    )
    .unwrap();
    let result = service.complete_custody(
        CustodyCompleteRequest {
            ceremony_kind: request.ceremony_kind,
            custody_operation_id: request.custody_operation_id.clone(),
            ceremony_id: prepared.contribution.ceremony_id.clone(),
            proof,
            encrypted_input: Some(encrypted_input),
            public_binding_digest: request.exact_terms_digest.clone(),
        },
        now_ms + 100,
    )?;
    Ok((result, prepared.contribution))
}

pub fn try_complete_bip39_registration(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    wallet_id: &Token,
    operation_id: &OperationId,
    now_ms: u64,
) -> Result<CustodyResult, ProtocolError> {
    registration_custody(
        service,
        authenticator,
        bip39_registration_request(wallet_id, operation_id),
        &authenticator.deterministic_prf(),
        None,
        now_ms,
    )
    .map(|(result, _)| result)
}

pub fn complete_bip39_registration(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    wallet_id: &Token,
    operation_id: &OperationId,
    now_ms: u64,
) -> CustodyResult {
    try_complete_bip39_registration(service, authenticator, wallet_id, operation_id, now_ms)
        .unwrap()
}

/// Imports `mnemonic` as a new BIP-39 wallet (terms digest `a2`), optionally
/// smuggling a `passphrase` field into the sealed input.
pub fn attempt_bip39_mnemonic_import(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    wallet_id: &Token,
    operation_id: &OperationId,
    mnemonic: &str,
    passphrase_field: Option<&str>,
    now_ms: u64,
) -> Result<CustodyResult, ProtocolError> {
    let request = CustodyPrepareRequest {
        wallet_seed_profile: Some(WalletSeedProfile::Bip39MulticurveV1),
        ..custody_prepare(
            CeremonyKind::WalletImport,
            operation_id,
            wallet_id,
            None,
            digest("a2"),
            "bip39-mnemonic",
        )
    };
    let mut input = serde_json::json!({
        "credential_prf": Base64UrlBytes::from_bytes(&authenticator.deterministic_prf()),
        "mnemonic": mnemonic,
    });
    if let Some(passphrase) = passphrase_field {
        input["passphrase"] = serde_json::json!(passphrase);
    }
    let plaintext = serde_jcs::to_vec(&input).unwrap();
    registration_custody(service, authenticator, request, &plaintext, None, now_ms)
        .map(|(result, _)| result)
}

pub fn complete_bip39_mnemonic_import(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    wallet_id: &Token,
    operation_id: &OperationId,
    mnemonic: &str,
    now_ms: u64,
) -> CustodyResult {
    attempt_bip39_mnemonic_import(
        service,
        authenticator,
        wallet_id,
        operation_id,
        mnemonic,
        None,
        now_ms,
    )
    .unwrap()
}

pub fn evm_request(account: Option<u32>) -> DerivedAccountRequest {
    DerivedAccountRequest {
        derivation_profile: DerivationProfile::Bip44EvmSecp256k1V1,
        requested_role: Token::new("evm-account").unwrap(),
        account,
    }
}

pub fn solana_request(account: Option<u32>) -> DerivedAccountRequest {
    DerivedAccountRequest {
        derivation_profile: DerivationProfile::Bip44SolanaSlip10Ed25519V1,
        requested_role: Token::new("solana-account").unwrap(),
        account,
    }
}

/// One allocation ceremony for `requests` under one Signer-chosen number.
pub fn try_complete_account_allocate(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    wallet_id: &Token,
    operation_id: &OperationId,
    requests: Vec<DerivedAccountRequest>,
    now_ms: u64,
) -> Result<(CustodyResult, CustodySignerContribution), ProtocolError> {
    let effect = serde_json::json!({ "kind": "account_allocate" });
    let request = CustodyPrepareRequest {
        derivation_requests: requests,
        ..generic_prepare(
            CeremonyKind::AccountAllocate,
            operation_id,
            wallet_id,
            None,
            &effect,
        )
    };
    assertion_custody(service, authenticator, request, effect, None, now_ms)
}

pub fn complete_account_retire(
    service: &SignerCeremonyService,
    authenticator: &VirtualAuthenticator,
    wallet_id: &Token,
    child: &KeyRef,
    operation_id: &OperationId,
    now_ms: u64,
) -> CustodyResult {
    let effect = serde_json::json!({ "kind": "account_retire" });
    let request = generic_prepare(
        CeremonyKind::AccountRetire,
        operation_id,
        wallet_id,
        Some(child.clone()),
        &effect,
    );
    assertion_custody(service, authenticator, request, effect, None, now_ms)
        .unwrap()
        .0
}
