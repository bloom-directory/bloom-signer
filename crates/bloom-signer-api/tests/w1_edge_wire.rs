use bloom_signer_api::*;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::fmt::Debug;

fn token(value: &str) -> Token {
    Token::new(value).unwrap()
}

fn digest(value: u8) -> Digest32 {
    Digest32::from_bytes([value; 32])
}

fn operation(value: u8) -> OperationId {
    OperationId::from_bytes([value; 32])
}

fn key_ref() -> KeyRef {
    KeyRef {
        backend: token("local"),
        backend_instance: token("default"),
        locator: "key-1".into(),
        key_spec: KeySpec::Secp256k1,
        public_key_fingerprint: digest(1),
        derivation: None,
    }
}

fn approval_terms() -> SealedApprovalTerms {
    SealedApprovalTerms {
        subject: ApprovalSubject::Cli {
            client_id: token("cli"),
            command_class: token("wallet.sign"),
        },
        wallet_id: token("wallet"),
        key_ref: key_ref(),
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
        selector: ApprovalSelector::Exact {
            ordered_payload_digests: vec![digest(2)],
            ordered_hashes: vec![digest(3)],
        },
        limits: ApprovalLimits {
            max_operations: DecimalU64::new(1),
            max_signatures: DecimalU64::new(1),
            operation_rate_limits: Vec::new(),
            signature_rate_limits: Vec::new(),
            value_limits: Vec::new(),
        },
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: DecimalU64::new(0),
        policy_version: DecimalU64::new(1),
        policy_digest: digest(4),
        provenance_digest: digest(5),
        request_nonce: RequestNonce::from_bytes([6; 16]),
        issued_at_ms: DecimalU64::new(10),
        not_before_ms: DecimalU64::new(10),
        expires_at_ms: DecimalU64::new(20),
        renewal_of: None,
    }
}

fn hello() -> HelloChallenge {
    HelloChallenge {
        service_id: token("bloom-machine"),
        boot_epoch: BootEpoch::from_bytes([7; 16]),
        protocol: SIGNER_API_CURRENT,
        challenge: digest(8),
        application_key_id: token("app-key"),
        signature: Base64UrlBytes::from_bytes(&[9; 64]),
    }
}

fn readiness() -> Readiness {
    Readiness {
        service_id: token("bloom-broker"),
        service_version: "0.1.0".into(),
        build_digest: digest(10),
        boot_epoch: BootEpoch::from_bytes([11; 16]),
        state: ReadinessState::Ready,
        conditions: Vec::new(),
    }
}

fn capabilities() -> ServiceCapabilities {
    ServiceCapabilities {
        service_id: token("bloom-broker"),
        service_version: "0.1.0".into(),
        build_digest: digest(12),
        protocol_major: SIGNER_API_MAJOR,
        protocol_minor_min: SIGNER_API_MINOR_MIN,
        protocol_minor_max: SIGNER_API_MINOR_MAX,
        methods: vec![token("system.hello")],
        schemas: vec![token("bloom.rpc-envelope.1")],
        backends: vec![BackendPublicCapability {
            backend_id: token("local"),
            backend_instance_id: token("default"),
            crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            derivation_schemes: vec![token("bip32")],
            networked: false,
            wallet_seed_profiles: vec![],
            derivation_profiles: vec![],
            mnemonic_export: false,
            derivation_namespace_limits: vec![],
        }],
        assurance_verifiers: vec![VerifierPublicCapability {
            verifier_id: token("webauthn"),
            verifier_digest: digest(13),
        }],
        frame_max_bytes: DecimalU64::new(FRAME_MAX_BYTES as u64),
    }
}

fn custody_prepare() -> CustodyPrepareRequest {
    CustodyPrepareRequest {
        surface: bloom_signer_api::legacy_local_surface(),
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation(14),
        wallet_id: Some(token("wallet")),
        key_ref: Some(key_ref()),
        exact_terms_digest: digest(15),
        expected_input_class: token("none"),
        browser_output_recipient_key: None,
        petal_key_scope: None,
        legacy_passkey_migration: None,
        derivation_requests: Vec::new(),
        wallet_seed_profile: None,
    }
}

fn derived_account_descriptor() -> DerivedAccountDescriptor {
    DerivedAccountDescriptor {
        key_ref: KeyRef {
            backend: token("local"),
            backend_instance: token("default"),
            locator: "key-child-1".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: digest(2),
            derivation: Some(DerivationRef::Bip39Multicurve {
                wallet_seed_ref: token("wallet"),
                profile: DerivationProfile::Bip44EvmSecp256k1V1,
                path: "m/44'/60'/0'/0/0".into(),
            }),
        },
        wallet_seed_ref: WalletSeedRef {
            wallet_id: token("wallet"),
            profile: WalletSeedProfile::Bip39MulticurveV1,
            entropy_bits: 256,
        },
        derivation_profile: DerivationProfile::Bip44EvmSecp256k1V1,
        path: "m/44'/60'/0'/0/0".into(),
        canonical_public_key: Base64UrlBytes::from_bytes(&[3; 33]),
        public_key_encoding: PublicKeyEncoding::Secp256k1SpkiDer,
        public_key_fingerprint: digest(2),
        supported_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
        lifecycle: AccountLifecycleState::Active,
    }
}

fn policy_snapshot() -> SignedPolicySnapshot {
    SignedPolicySnapshot {
        wallet_id: token("wallet"),
        version: DecimalU64::new(1),
        canonical_policy: Base64UrlBytes::from_bytes(b"{}"),
        policy_digest: digest(16),
        policy_signing_key_id: token("policy-key"),
        policy_verifying_key: Base64UrlBytes::from_bytes(&[17; 32]),
        signer_signature: Base64UrlBytes::from_bytes(&[18; 64]),
    }
}

fn custody_result() -> CustodyResult {
    CustodyResult {
        surface: Some(bloom_signer_api::legacy_local_surface()),
        credential_authority_generation: Some(DecimalU64::new(0)),
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation(14),
        public_status: CeremonyState::Completed,
        wallet_id: Some(token("wallet")),
        public_key_refs: vec![key_ref()],
        credential_summaries: vec![CredentialSummary {
            surface: Some(bloom_signer_api::legacy_local_surface()),
            credential_id: Base64UrlBytes::from_bytes(&[19]),
            rp_id: RpId::new("localhost").unwrap(),
            active: true,
        }],
        initial_policy: Some(policy_snapshot()),
        receipt_digest: digest(20),
        encrypted_browser_result: None,
        signer_key_id: token("signer-key"),
        signer_signature: Base64UrlBytes::from_bytes(&[21; 64]),
    }
}

fn policy_update() -> PolicyUpdateRequest {
    PolicyUpdateRequest {
        operation_id: operation(22),
        wallet_id: token("wallet"),
        baseline_version: DecimalU64::new(1),
        baseline_digest: digest(23),
        proposed_canonical_policy: Base64UrlBytes::from_bytes(b"{}"),
        proposed_policy_digest: digest(24),
        authority_diff_digest: digest(25),
        assurance_level: token("hardened"),
    }
}

fn policy_validation_receipt() -> PolicyValidationReceipt {
    PolicyValidationReceipt {
        update_terms_digest: digest(26),
        review_manifest_digest: digest(27),
        broker_key_id: token("broker-key"),
        broker_signature: Base64UrlBytes::from_bytes(&[28; 64]),
    }
}

fn policy_commit_receipt() -> PolicyCommitReceipt {
    PolicyCommitReceipt {
        operation_id: operation(22),
        wallet_id: token("wallet"),
        previous_version: DecimalU64::new(1),
        committed: policy_snapshot(),
        authority_diff_digest: digest(25),
        signer_key_id: token("signer-key"),
        signer_signature: Base64UrlBytes::from_bytes(&[29; 64]),
    }
}

fn signing_result() -> SigningResult {
    SigningResult {
        operation_id: operation(30),
        operation_digest: digest(31),
        signatures: vec![NormalizedSignature {
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            bytes: Base64UrlBytes::from_bytes(&[32; 65]),
        }],
        signer_receipt_digest: digest(33),
        broker_receipt_digest: digest(34),
    }
}

fn sign_request() -> SignRequest {
    SignRequest {
        unsigned: UnsignedSignRequest {
            schema: token("bloom.sign-request/1"),
            attempt_id: digest(37),
            operation_id: operation(30),
            operation_digest: digest(31),
            attempt_digest: digest(38),
            audience: token("bloom-signer"),
            issuer_service_id: token("bloom-broker"),
            issuer_boot_epoch: BootEpoch::from_bytes([39; 16]),
            broker_signing_key_id: token("broker-key"),
            approval_id: digest(35),
            wallet_id: token("wallet"),
            key_ref: key_ref(),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            selector_kind: SelectorKind::Exact,
            ordered_payload_digests: vec![digest(40)],
            ordered_hashes: vec![digest(41)],
            ordered_messages: Vec::new(),
            signature_count: DecimalU64::new(1),
            petal_use_claim_digest: None,
            claim_assurance_digest: None,
            policy_version: DecimalU64::new(1),
            policy_digest: digest(16),
            validation_receipt_digest: digest(42),
            issued_at_ms: DecimalU64::new(10),
            not_before_ms: DecimalU64::new(10),
            expires_at_ms: DecimalU64::new(20),
        },
        broker_signature: Base64UrlBytes::from_bytes(&[43; 64]),
    }
}

fn approval_status() -> ApprovalPublicStatus {
    ApprovalPublicStatus {
        approval_id: digest(35),
        wallet_id: token("wallet"),
        state: ApprovalLifecycleState::Active,
        effective_claim_assurance: Some(ClaimAssuranceLevel::MachineAsserted),
        ceremony_url: None,
        ceremony_expires_at_ms: None,
    }
}

fn revocation_state() -> RevocationState {
    RevocationState {
        wallet_id: token("wallet"),
        wallet_revocation_epoch: DecimalU64::new(1),
        wallet_tombstone: None,
        approval_tombstone_digest: digest(44),
        approval_tombstone_count: DecimalU64::new(0),
        observed_at_ms: DecimalU64::new(10),
        issuer_service_id: token("bloom-signer"),
        key_id: token("signer-key"),
        signature: Base64UrlBytes::from_bytes(&[45; 64]),
    }
}

fn ceremony_status() -> CeremonyPublicStatus {
    CeremonyPublicStatus {
        ceremony_id: digest(46),
        ceremony_kind: CeremonyKind::WalletRegistration,
        operation_id: operation(14),
        state: CeremonyState::AwaitingUser,
        expires_at_ms: DecimalU64::new(20),
        ceremony_url: Some("http://localhost:18734/ceremony/token".into()),
        receipt_digest: None,
    }
}

fn webauthn_assertion() -> WebAuthnAssertion {
    WebAuthnAssertion {
        credential_id: Base64UrlBytes::from_bytes(&[47]),
        authenticator_data: Base64UrlBytes::from_bytes(&[48]),
        client_data_json: Base64UrlBytes::from_bytes(b"{}"),
        signature: Base64UrlBytes::from_bytes(&[49; 64]),
        user_handle: None,
    }
}

fn webauthn_attestation() -> WebAuthnAttestation {
    WebAuthnAttestation {
        credential_id: Base64UrlBytes::from_bytes(&[47]),
        client_data_json: Base64UrlBytes::from_bytes(b"{}"),
        attestation_object: Base64UrlBytes::from_bytes(&[48; 32]),
        transports: vec![token("internal")],
    }
}

fn custody_complete() -> CustodyCompleteRequest {
    CustodyCompleteRequest {
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation(14),
        ceremony_id: digest(46),
        proof: WebAuthnCeremonyProof::Assertion {
            assertion: webauthn_assertion(),
        },
        encrypted_input: None,
        public_binding_digest: digest(50),
    }
}

fn signer_contribution() -> SignerCeremonyContribution {
    SignerCeremonyContribution {
        surface: bloom_signer_api::legacy_local_surface(),
        credential_authority_generation: DecimalU64::new(0),
        ceremony_id: digest(46),
        signer_nonce: digest(51),
        approval_digest: digest(52),
        review_manifest_digest: digest(27),
        key_ref: key_ref(),
        allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
        activation_mode: ActivationMode::BootBound,
        wallet_revocation_epoch: DecimalU64::new(0),
        required_user_verification: true,
        ephemeral_encryption_public_key: None,
        expires_at_ms: DecimalU64::new(20),
        signer_key_id: token("signer-key"),
        signer_signature: Base64UrlBytes::from_bytes(&[53; 64]),
    }
}

fn ceremony_challenge() -> CeremonyChallenge {
    CeremonyChallenge {
        surface: bloom_signer_api::legacy_local_surface(),
        schema: token("bloom.ceremony-challenge/1"),
        ceremony_id: digest(46),
        ceremony_kind: CeremonyKind::SealedApproval,
        operation_id: operation(54),
        signer_nonce: digest(51),
        review_manifest_digest: digest(27),
        signer_contribution_digest: digest(55),
        exact_terms_digest: digest(52),
        phase: CeremonyPhase::Approve,
    }
}

fn prepared_approval() -> SignerPreparedApproval {
    SignerPreparedApproval {
        contribution: signer_contribution(),
        challenges: vec![ceremony_challenge()],
        webauthn_options: CeremonyWebAuthnOptions {
            allowed_credentials: Vec::new(),
            registration_user_handle: None,
            registration_prf_salt: None,
        },
        verification_credentials: Vec::new(),
    }
}

fn custody_contribution() -> CustodySignerContribution {
    CustodySignerContribution {
        surface: bloom_signer_api::legacy_local_surface(),
        credential_authority_generation: DecimalU64::new(0),
        ceremony_id: digest(46),
        ceremony_kind: CeremonyKind::WalletRegistration,
        custody_operation_id: operation(14),
        signer_nonce: digest(51),
        review_manifest_digest: digest(27),
        wallet_id: Some(token("wallet")),
        key_ref: Some(key_ref()),
        expected_input_class: token("none"),
        required_user_verification: true,
        hpke_recipient_key: Base64UrlBytes::from_bytes(&[56; 32]),
        browser_output_recipient_key: None,
        petal_key_scope: None,
        wallet_seed_profile: None,
        expires_at_ms: DecimalU64::new(20),
        signer_key_id: token("signer-key"),
        signer_signature: Base64UrlBytes::from_bytes(&[57; 64]),
    }
}

fn prepared_custody() -> SignerPreparedCustody {
    SignerPreparedCustody {
        contribution: custody_contribution(),
        challenges: vec![ceremony_challenge()],
        webauthn_options: CeremonyWebAuthnOptions {
            allowed_credentials: Vec::new(),
            registration_user_handle: None,
            registration_prf_salt: None,
        },
        verification_credentials: Vec::new(),
    }
}

fn key_public() -> KeyPublic {
    KeyPublic {
        key_ref: key_ref(),
        role: KeyRole::WalletRoot,
        canonical_public_key: Base64UrlBytes::from_bytes(&[63; 33]),
        addresses: vec!["0x1".into()],
        supported_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
        derived_account: None,
        petal_scope_expires_at_ms: None,
    }
}

fn credential_public() -> CredentialPublic {
    CredentialPublic {
        credential_id: Base64UrlBytes::from_bytes(&[64]),
        wallet_id: token("wallet"),
        surface: bloom_signer_api::legacy_local_surface(),
        created_at_ms: DecimalU64::new(10),
        state: CredentialState::Active,
    }
}

fn remote_surface() -> SurfaceRef {
    SurfaceIdentity::remote("abcdefghijklmnopqrstuv2345.relay.bloom.directory", 10)
        .unwrap()
        .reference()
        .unwrap()
}

fn surface_status() -> SurfaceStatus {
    let local = SurfaceIdentity::local(0);
    let remote =
        SurfaceIdentity::remote("abcdefghijklmnopqrstuv2345.relay.bloom.directory", 10).unwrap();
    SurfaceStatus {
        surfaces: vec![
            SurfaceDescriptor {
                identity_digest: local.reference().unwrap().identity_digest,
                identity: local,
                lifecycle: SurfaceLifecycle::Active,
                lifecycle_revision: DecimalU64::new(0),
            },
            SurfaceDescriptor {
                identity_digest: remote.reference().unwrap().identity_digest,
                identity: remote,
                lifecycle: SurfaceLifecycle::Disabled,
                lifecycle_revision: DecimalU64::new(0),
            },
        ],
        installation_id: Some("00000000-0000-4000-8000-000000000001".into()),
        installation_admin_key_sha256: Some(digest(89)),
        desired_mode: ExposureMode::RemoteEnabled,
        desired_revision: DecimalU64::new(2),
        effective_mode: ExposureMode::LocalhostOnly,
        effective_revision: DecimalU64::new(1),
        remote_tls_ready: false,
        remote_routing_ready: false,
    }
}

fn cross_pairing() -> CrossSurfacePairing {
    CrossSurfacePairing {
        pairing_id: digest(90),
        destination_surface: remote_surface(),
        operation_id: operation(91),
        exact_terms_digest: digest(92),
        destination_hpke_public_key: Base64UrlBytes::from_bytes(&[93; 32]),
        destination_challenge: digest(94),
        confirmation_code: "123456".into(),
        expires_at_ms: DecimalU64::new(600_000),
    }
}

fn cross_prepared() -> CrossSurfaceSourcePrepared {
    let mut source_challenge = ceremony_challenge();
    source_challenge.ceremony_kind = CeremonyKind::CredentialAdd;
    source_challenge.operation_id = operation(91);
    let mut destination_challenge = source_challenge.clone();
    destination_challenge.surface = remote_surface();
    destination_challenge.phase = CeremonyPhase::RegisterCredential;
    CrossSurfaceSourcePrepared {
        pairing: cross_pairing(),
        source_surface: legacy_local_surface(),
        wallet_id: token("wallet"),
        source_challenge,
        destination_challenges: vec![destination_challenge],
        source_credentials: Vec::new(),
        source_prf_inputs: Vec::new(),
        destination_user_handle: Base64UrlBytes::from_bytes(&[95; 32]),
        destination_prf_salt: Base64UrlBytes::from_bytes(&[96; 32]),
        source_hpke_recipient_key: Base64UrlBytes::from_bytes(&[97; 32]),
        destination_hpke_recipient_key: Base64UrlBytes::from_bytes(&[98; 32]),
        credential_authority_generation: DecimalU64::new(0),
        signer_signature: Base64UrlBytes::from_bytes(&[99; 64]),
    }
}

fn signer_requests() -> Vec<BrokerSignerRequest> {
    let wallet = WalletRequest {
        wallet_id: token("wallet"),
    };
    let key = KeyRequest { key_ref: key_ref() };
    let operation_request = OperationRequest {
        operation_id: operation(30),
    };
    let id = IdRequest { id: digest(46) };
    vec![
        BrokerSignerRequest::SystemHello(hello()),
        BrokerSignerRequest::SignerReadiness(Empty {}),
        BrokerSignerRequest::SignerCapabilities(Empty {}),
        BrokerSignerRequest::SurfaceStatus(Empty {}),
        BrokerSignerRequest::SurfaceReportEffective(SurfaceEffectiveReport {
            desired_revision: DecimalU64::new(2),
            remote_tls_ready: true,
            remote_routing_ready: true,
            remote_closed: false,
        }),
        BrokerSignerRequest::CrossSurfacePairStart(CrossSurfacePairStartRequest {
            destination_surface: remote_surface(),
            operation_id: operation(91),
            exact_terms_digest: digest(92),
            destination_hpke_public_key: Base64UrlBytes::from_bytes(&[93; 32]),
        }),
        BrokerSignerRequest::CrossSurfacePrepareSource(CrossSurfacePrepareSourceRequest {
            pairing_id: digest(90),
            operation_id: operation(91),
            source_surface: legacy_local_surface(),
            wallet_id: token("wallet"),
            exact_terms_digest: digest(92),
        }),
        BrokerSignerRequest::CrossSurfaceCompleteSource(CrossSurfaceCompleteSourceRequest {
            pairing_id: digest(90),
            operation_id: operation(91),
            authority_assertion: webauthn_assertion(),
            encrypted_authority_prf: HpkeEnvelope {
                kem_output: Base64UrlBytes::from_bytes(&[100; 32]),
                ciphertext: Base64UrlBytes::from_bytes(&[101; 48]),
            },
        }),
        BrokerSignerRequest::CrossSurfaceCompleteDestination(
            CrossSurfaceCompleteDestinationRequest {
                pairing_id: digest(90),
                operation_id: operation(91),
                capability: Base64UrlBytes::from_bytes(&[102; 32]),
                attestation: webauthn_attestation(),
                prf_assertion: webauthn_assertion(),
                encrypted_new_prf: HpkeEnvelope {
                    kem_output: Base64UrlBytes::from_bytes(&[103; 32]),
                    ciphertext: Base64UrlBytes::from_bytes(&[104; 48]),
                },
            },
        ),
        BrokerSignerRequest::KeyGetPublic(key.clone()),
        BrokerSignerRequest::KeyListPublic(wallet.clone()),
        BrokerSignerRequest::KeyDerivationCapabilities(key.clone()),
        BrokerSignerRequest::KeyDerivePrepare(custody_prepare()),
        BrokerSignerRequest::KeyListDerived(key),
        BrokerSignerRequest::DerivedAccountList(wallet.clone()),
        BrokerSignerRequest::KeyEnrollPrepare(custody_prepare()),
        BrokerSignerRequest::KeyEnrollStatus(operation_request.clone()),
        BrokerSignerRequest::CeremonyPrepare(SignerCeremonyPrepareRequest::SealedApproval(
            Box::new(CeremonyPrepareRequest {
                surface: bloom_signer_api::legacy_local_surface(),
                activation_operation_id: operation(54),
                terms: approval_terms(),
                review_manifest_digest: digest(27),
                exact_ordered_payload_digests: vec![digest(2)],
                exact_ordered_hashes: vec![digest(3)],
                replacement_approval_id: None,
            }),
        )),
        BrokerSignerRequest::CeremonyComplete(SignerCeremonyCompleteRequest::SealedApproval(
            Box::new(CeremonyCompleteRequest {
                activation_operation_id: operation(54),
                proof: WebAuthnCeremonyProof::Assertion {
                    assertion: webauthn_assertion(),
                },
                contribution: signer_contribution(),
                encrypted_local_prf: None,
            }),
        )),
        BrokerSignerRequest::CeremonyStatus(id.clone()),
        BrokerSignerRequest::CeremonyCancel(id.clone()),
        BrokerSignerRequest::SealedApprovalStatus(IdRequest { id: digest(35) }),
        BrokerSignerRequest::SealedApprovalRevoke(RevokeRequest {
            operation_id: operation(60),
            approval_id: digest(35),
            wallet_id: token("wallet"),
            reason: "reviewed".into(),
        }),
        BrokerSignerRequest::SealedApprovalRevokeAll(WalletOperationRequest {
            operation_id: operation(61),
            wallet_id: token("wallet"),
        }),
        BrokerSignerRequest::RevocationState(wallet.clone()),
        BrokerSignerRequest::SignerSign(sign_request()),
        BrokerSignerRequest::SignerSignBatch(sign_request()),
        BrokerSignerRequest::OperationStatus(operation_request.clone()),
        BrokerSignerRequest::PolicyRead(wallet.clone()),
        BrokerSignerRequest::PolicyCompareAndSwap(PolicyCompareAndSwapRequest {
            update: policy_update(),
            ceremony_receipt: custody_result(),
            broker_validation_receipt: policy_validation_receipt(),
        }),
        BrokerSignerRequest::WalletRegistrationPrepare(custody_prepare()),
        BrokerSignerRequest::WalletRegistrationStatus(operation_request.clone()),
        BrokerSignerRequest::WalletUnlockPrepare(custody_prepare()),
        BrokerSignerRequest::WalletImportPrepare(custody_prepare()),
        BrokerSignerRequest::WalletExportPrepare(custody_prepare()),
        BrokerSignerRequest::WalletDeletePrepare(custody_prepare()),
        BrokerSignerRequest::CredentialListPublic(wallet),
        BrokerSignerRequest::CredentialAddPrepare(custody_prepare()),
        BrokerSignerRequest::CredentialRemovePrepare(custody_prepare()),
        BrokerSignerRequest::CredentialReplacePrepare(custody_prepare()),
        BrokerSignerRequest::RecoveryPrepare(custody_prepare()),
        BrokerSignerRequest::CustodyBindOutputRecipient(CustodyBindOutputRecipientRequest {
            operation_id: operation(14),
            recipient_key: Base64UrlBytes::from_bytes(&[65; 32]),
        }),
        BrokerSignerRequest::CustodyComplete(custody_complete()),
        BrokerSignerRequest::CustodyResult(operation_request.clone()),
        BrokerSignerRequest::CustodyStatus(operation_request),
    ]
}

fn signer_responses() -> Vec<BrokerSignerResponse> {
    let custody_prepared = prepared_custody();
    let operation_status = OperationPublicStatus {
        operation_id: operation(30),
        operation_digest: digest(31),
        state: OperationState::Succeeded,
        result: Some(signing_result()),
        error: None,
    };
    vec![
        BrokerSignerResponse::SystemHello(hello()),
        BrokerSignerResponse::SignerReadiness(readiness()),
        BrokerSignerResponse::SignerCapabilities(capabilities()),
        BrokerSignerResponse::SurfaceStatus(surface_status()),
        BrokerSignerResponse::SurfaceReportEffective(surface_status()),
        BrokerSignerResponse::CrossSurfacePairStart(cross_pairing()),
        BrokerSignerResponse::CrossSurfacePrepareSource(cross_prepared()),
        BrokerSignerResponse::CrossSurfaceCompleteSource(CrossSurfaceHandoff {
            pairing_id: digest(90),
            encrypted_capability: HpkeEnvelope {
                kem_output: Base64UrlBytes::from_bytes(&[105; 32]),
                ciphertext: Base64UrlBytes::from_bytes(&[106; 48]),
            },
            expires_at_ms: DecimalU64::new(600_000),
        }),
        BrokerSignerResponse::CrossSurfaceCompleteDestination(custody_result()),
        BrokerSignerResponse::KeyGetPublic(key_public()),
        BrokerSignerResponse::KeyListPublic(vec![key_public()]),
        BrokerSignerResponse::KeyDerivationCapabilities(vec![token("bip32")]),
        BrokerSignerResponse::KeyDerivePrepare(custody_prepared.clone()),
        BrokerSignerResponse::KeyListDerived(vec![key_public()]),
        BrokerSignerResponse::DerivedAccountList(vec![derived_account_descriptor()]),
        BrokerSignerResponse::KeyEnrollPrepare(custody_prepared.clone()),
        BrokerSignerResponse::KeyEnrollStatus(ceremony_status()),
        BrokerSignerResponse::CeremonyPrepare(SignerCeremonyPrepareResponse::SealedApproval(
            prepared_approval(),
        )),
        BrokerSignerResponse::CeremonyComplete(SignerCeremonyCompleteResponse::SealedApproval(
            Box::new(SignerActivationReceipt {
                surface: Some(bloom_signer_api::legacy_local_surface()),
                credential_authority_generation: Some(DecimalU64::new(0)),
                activation_operation_id: operation(54),
                ceremony_id: digest(46),
                approval_id: digest(35),
                approval_digest: digest(52),
                review_manifest_digest: digest(27),
                key_ref: key_ref(),
                allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
                activation_mode: ActivationMode::BootBound,
                wallet_revocation_epoch: DecimalU64::new(0),
                replaced_approval_id: None,
                activated_at_ms: DecimalU64::new(10),
                expires_at_ms: DecimalU64::new(20),
                signer_key_id: token("signer-key"),
                signer_signature: Base64UrlBytes::from_bytes(&[66; 64]),
            }),
        )),
        BrokerSignerResponse::CeremonyCancel(ceremony_status()),
        BrokerSignerResponse::OperationStatus(operation_status),
        BrokerSignerResponse::CeremonyStatus(SignerCeremonyStatus::Pending),
        BrokerSignerResponse::CeremonyStatus(SignerCeremonyStatus::Terminal(CeremonyState::Failed)),
        BrokerSignerResponse::SealedApprovalStatus(approval_status()),
        BrokerSignerResponse::SealedApprovalRevoke(approval_status()),
        BrokerSignerResponse::SealedApprovalRevokeAll(revocation_state()),
        BrokerSignerResponse::RevocationState(RevocationSnapshot {
            state: revocation_state(),
            approval_tombstones: Vec::new(),
        }),
        BrokerSignerResponse::SignerSign(signing_result()),
        BrokerSignerResponse::SignerSignBatch(signing_result()),
        BrokerSignerResponse::PolicyRead(policy_snapshot()),
        BrokerSignerResponse::PolicyCompareAndSwap(policy_commit_receipt()),
        BrokerSignerResponse::WalletRegistrationPrepare(custody_prepared.clone()),
        BrokerSignerResponse::WalletRegistrationStatus(ceremony_status()),
        BrokerSignerResponse::WalletUnlockPrepare(custody_prepared.clone()),
        BrokerSignerResponse::WalletImportPrepare(custody_prepared.clone()),
        BrokerSignerResponse::WalletExportPrepare(custody_prepared.clone()),
        BrokerSignerResponse::WalletDeletePrepare(custody_prepared.clone()),
        BrokerSignerResponse::CredentialListPublic(vec![credential_public()]),
        BrokerSignerResponse::CredentialAddPrepare(custody_prepared.clone()),
        BrokerSignerResponse::CredentialRemovePrepare(custody_prepared.clone()),
        BrokerSignerResponse::CredentialReplacePrepare(custody_prepared.clone()),
        BrokerSignerResponse::RecoveryPrepare(custody_prepared.clone()),
        BrokerSignerResponse::CustodyComplete(custody_result()),
        BrokerSignerResponse::CustodyBindOutputRecipient(custody_prepared),
        BrokerSignerResponse::CustodyResult(custody_result()),
        BrokerSignerResponse::CustodyStatus(ceremony_status()),
    ]
}

fn control_requests() -> Vec<ControlRequest> {
    vec![
        ControlRequest::Revoke(RevokeRequest {
            operation_id: operation(60),
            approval_id: digest(35),
            wallet_id: token("wallet"),
            reason: "reviewed".into(),
        }),
        ControlRequest::RevokeAll(WalletOperationRequest {
            operation_id: operation(61),
            wallet_id: token("wallet"),
        }),
        ControlRequest::Status(WalletRequest {
            wallet_id: token("wallet"),
        }),
    ]
}

fn control_responses() -> Vec<ControlResponse> {
    vec![
        ControlResponse::Revoke(approval_status()),
        ControlResponse::RevokeAll(revocation_state()),
        ControlResponse::Status(revocation_state()),
    ]
}

fn assert_wire_digest<T>(name: &str, values: Vec<T>, expected: &str)
where
    T: Clone + Debug + DeserializeOwned + Eq + Serialize,
{
    let mut aggregate = Sha256::new();
    for value in values {
        let frame = encode_frame(&value).unwrap();
        assert_eq!(decode_frame::<T>(&frame).unwrap(), value, "{name}");
        aggregate.update(frame);
    }
    assert_eq!(hex::encode(aggregate.finalize()), expected, "{name}");
}

#[test]
fn every_edge_request_and_response_variant_matches_frozen_v1_frames() {
    // The v1.6 signer frame sets include exact surface status and the four
    // cross-surface operations. These digests freeze every authority variant
    // together with the strict v1.6 protocol range.
    assert_wire_digest(
        "signer requests",
        signer_requests(),
        "a64eb396809eb2eb7896c57efa3956a2c096ef9c8bedd5d3d89f38aa646ae3fe",
    );
    assert_wire_digest(
        "signer responses",
        signer_responses(),
        "53c5ff1b20e8d720bb9e702b8c551949bcdbd6f0c4337c4a63865b239218b3c2",
    );
    assert_wire_digest(
        "control requests",
        control_requests(),
        "64f459f07b9f308b3225cd3cac7a91aab5c16c20f94089ce27090f1dfde9d286",
    );
    assert_wire_digest(
        "control responses",
        control_responses(),
        "4645f9050601fa8d966346c30a01c0f6dd44f3777dd9c7b56585c4ed453665b7",
    );
}

#[test]
fn pre_surface_signed_receipts_keep_their_original_canonical_bytes() {
    let signer = SigningKey::from_bytes(&[47; 32]);
    let mut custody = custody_result();
    custody.surface = None;
    custody.credential_authority_generation = None;
    for summary in &mut custody.credential_summaries {
        summary.surface = None;
    }
    let mut historical = serde_json::to_value(&custody).unwrap();
    historical
        .as_object_mut()
        .unwrap()
        .remove("signer_signature");
    let old_unsigned = serde_jcs::to_vec(&historical).unwrap();
    assert_eq!(custody.unsigned_canonical_bytes().unwrap(), old_unsigned);
    let signature = signer.sign(
        &[
            b"bloom-signer-ceremony-receipt/v1".as_slice(),
            &old_unsigned,
        ]
        .concat(),
    );
    custody.signer_signature = Base64UrlBytes::from_bytes(&signature.to_bytes());
    let restored: CustodyResult =
        serde_json::from_value(serde_json::to_value(&custody).unwrap()).unwrap();
    signer
        .verifying_key()
        .verify(
            &[
                b"bloom-signer-ceremony-receipt/v1".as_slice(),
                &restored.unsigned_canonical_bytes().unwrap(),
            ]
            .concat(),
            &signature,
        )
        .unwrap();
    assert_eq!(restored.surface, None);

    let mut activation = signer_responses()
        .into_iter()
        .find_map(|response| match response {
            BrokerSignerResponse::CeremonyComplete(
                SignerCeremonyCompleteResponse::SealedApproval(receipt),
            ) => Some(*receipt),
            _ => None,
        })
        .unwrap();
    activation.surface = None;
    activation.credential_authority_generation = None;
    let mut historical = serde_json::to_value(&activation).unwrap();
    historical
        .as_object_mut()
        .unwrap()
        .remove("signer_signature");
    let old_unsigned = serde_jcs::to_vec(&historical).unwrap();
    assert_eq!(activation.unsigned_canonical_bytes().unwrap(), old_unsigned);
    let signature = signer.sign(
        &[
            b"bloom-signer-ceremony-receipt/v1".as_slice(),
            &old_unsigned,
        ]
        .concat(),
    );
    activation.signer_signature = Base64UrlBytes::from_bytes(&signature.to_bytes());
    let restored: SignerActivationReceipt =
        serde_json::from_value(serde_json::to_value(&activation).unwrap()).unwrap();
    signer
        .verifying_key()
        .verify(
            &[
                b"bloom-signer-ceremony-receipt/v1".as_slice(),
                &restored.unsigned_canonical_bytes().unwrap(),
            ]
            .concat(),
            &signature,
        )
        .unwrap();
    assert_eq!(restored.surface, None);
}
