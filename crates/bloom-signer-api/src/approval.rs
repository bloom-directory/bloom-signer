use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;

use crate::{
    CryptoSuite, DecimalU64, DecimalU256, Digest32, KeyRef, KeySpec, ProtocolError,
    ProtocolErrorCode, RequestNonce, Token,
};

const APPROVAL_DOMAIN: &[u8] = b"bloom-sealed-approval-terms/v1";

/// The only System subject that may seal a blockhash-normalized approval.
const NORMALIZED_TRANSFER_COMPONENT_ID: &str = "bloom-machine";
/// The action class carried by the subject of a normalized native transfer.
const NORMALIZED_TRANSFER_ACTION_CLASS: &str = "solana.transfer.confirm";
/// The one asset a normalized native transfer may debit.
const NORMALIZED_TRANSFER_ASSET_CHAIN: &str = "solana";
const NORMALIZED_TRANSFER_ASSET: &str = "native";
/// Longest validity interval a normalized approval may seal. The extra
/// temporal authority this mode grants is bounded here and nowhere else.
const NORMALIZED_TRANSFER_MAX_VALIDITY_MS: u64 = 300_000;

/// Serialized length of the one supported canonical native-transfer message.
const NATIVE_TRANSFER_MESSAGE_LEN: usize = 150;
/// Message header plus account count: one required signature, no read-only
/// signed accounts, one read-only unsigned account, three account keys.
const NATIVE_TRANSFER_PREFIX: [u8; 4] = [1, 0, 1, 3];
/// One instruction on program index 2 over accounts 0 and 1, whose twelve data
/// bytes open with the System `transfer` discriminator.
const NATIVE_TRANSFER_INSTRUCTION: [u8; 10] = [1, 2, 2, 0, 1, 12, 2, 0, 0, 0];
/// Offsets of the recent blockhash inside the canonical message. These are the
/// only bytes a normalized approval leaves uncommitted.
const NATIVE_TRANSFER_BLOCKHASH: std::ops::Range<usize> = 100..132;

/// Approval-matching mode for [`ApprovalSelector::Exact`].
///
/// Absent (the default) the approved digests commit to the exact payload
/// bytes. The one defined mode normalizes a Solana native-transfer message's
/// recent blockhash before matching, so an owner-approved transfer may still
/// be signed after the staged blockhash expires. Matching is the only thing
/// normalized: sign requests, operation digests, evidence, retry bindings and
/// the bytes handed to the backend all remain raw.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactMessageNormalization {
    SolanaNativeTransferBlockhashV1,
}

/// SHA-256 over the one supported canonical native-transfer message with its
/// 32-byte recent blockhash replaced by zeroes.
///
/// This is a fixed-layout normalizer, not a parser and not a semantic transfer
/// validator. It checks length, header prefix and instruction suffix only;
/// every other byte, including the account keys, program ID and amount, stays
/// inside the digest, so changing one changes the approval commitment. Whether
/// those bytes describe an acceptable transfer stays the Broker verifier's
/// responsibility.
pub fn solana_native_transfer_approval_digest(message: &[u8]) -> Result<Digest32, ProtocolError> {
    if message.len() != NATIVE_TRANSFER_MESSAGE_LEN
        || message[..NATIVE_TRANSFER_PREFIX.len()] != NATIVE_TRANSFER_PREFIX
        || message[NATIVE_TRANSFER_BLOCKHASH.end
            ..NATIVE_TRANSFER_BLOCKHASH.end + NATIVE_TRANSFER_INSTRUCTION.len()]
            != NATIVE_TRANSFER_INSTRUCTION
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::SelectorMismatch,
            "message is not the supported canonical Solana native-transfer layout",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(&message[..NATIVE_TRANSFER_BLOCKHASH.start]);
    hasher.update([0u8; 32]);
    hasher.update(&message[NATIVE_TRANSFER_BLOCKHASH.end..]);
    Ok(Digest32::from_bytes(hasher.finalize().into()))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalSubject {
    Petal {
        package_hash: Digest32,
        route: String,
        agent_id: Option<String>,
    },
    Cli {
        client_id: Token,
        command_class: Token,
    },
    System {
        component_id: Token,
        operation_class: Token,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimAssuranceLevel {
    MachineAsserted,
    ProofVerified,
    InvariantAttested,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApprovalSelector {
    Exact {
        ordered_payload_digests: Vec<Digest32>,
        ordered_hashes: Vec<Digest32>,
        /// How the approved digests are matched against a sign request.
        /// Absent means raw payload bytes, the v1 behavior; old terms
        /// therefore keep their exact canonical bytes and approval IDs.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message_normalization: Option<ExactMessageNormalization>,
    },
    Petal {
        package_hash: Digest32,
        route: String,
        allowed_operation_classes: Vec<Token>,
        /// Complete route-specific grant set for the immutable package.
        /// Empty preserves the v1 singleton `route` semantics. When nonempty,
        /// it must include a grant identical to the legacy route, classes, and
        /// top-level provenance digest.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        route_grants: Vec<PetalRouteGrant>,
        required_claim_assurance: ClaimAssuranceLevel,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalRouteGrant {
    pub route: String,
    pub allowed_operation_classes: Vec<Token>,
    pub provenance_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlidingWindow {
    pub maximum: DecimalU64,
    pub duration_ms: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetId {
    pub chain: Token,
    pub asset: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValueLimit {
    pub asset: AssetId,
    pub lifetime: DecimalU256,
    pub rolling_windows: Vec<ValueWindow>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValueWindow {
    pub maximum: DecimalU256,
    pub duration_ms: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLimits {
    pub max_operations: DecimalU64,
    pub max_signatures: DecimalU64,
    pub operation_rate_limits: Vec<SlidingWindow>,
    pub signature_rate_limits: Vec<SlidingWindow>,
    pub value_limits: Vec<ValueLimit>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActivationMode {
    BootBound,
    DurableLocal {
        provider_tier: Token,
        maximum_rearm_until_ms: DecimalU64,
    },
    BackendManaged,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedApprovalTerms {
    pub subject: ApprovalSubject,
    pub wallet_id: Token,
    pub key_ref: KeyRef,
    pub allowed_crypto_suites: Vec<CryptoSuite>,
    pub selector: ApprovalSelector,
    pub limits: ApprovalLimits,
    pub activation_mode: ActivationMode,
    pub wallet_revocation_epoch: DecimalU64,
    pub policy_version: DecimalU64,
    pub policy_digest: Digest32,
    pub provenance_digest: Digest32,
    pub request_nonce: RequestNonce,
    pub issued_at_ms: DecimalU64,
    pub not_before_ms: DecimalU64,
    pub expires_at_ms: DecimalU64,
    pub renewal_of: Option<Digest32>,
}

impl SealedApprovalTerms {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.key_ref.validate()?;
        validate_suites(&self.allowed_crypto_suites, self.key_ref.key_spec)?;
        validate_limits(&self.limits)?;

        if self.expires_at_ms.get() <= self.not_before_ms.get()
            || self.issued_at_ms.get() > self.expires_at_ms.get()
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "approval validity interval is invalid",
            ));
        }

        match (&self.subject, &self.selector) {
            (
                ApprovalSubject::Petal {
                    package_hash,
                    route,
                    ..
                },
                ApprovalSelector::Petal {
                    package_hash: selector_hash,
                    route: selector_route,
                    allowed_operation_classes,
                    route_grants,
                    ..
                },
            ) if package_hash == selector_hash
                && route == selector_route
                && classes_are_canonical(allowed_operation_classes)
                && valid_route_grants(
                    route_grants,
                    selector_route,
                    allowed_operation_classes,
                    &self.provenance_digest,
                ) => {}
            (
                _,
                ApprovalSelector::Exact {
                    ordered_payload_digests,
                    ordered_hashes,
                    ..
                },
            ) if !ordered_payload_digests.is_empty()
                && !ordered_hashes.is_empty()
                && self.limits.max_operations.get() == 1
                && self.limits.max_signatures.get() == ordered_hashes.len() as u64 => {}
            _ => {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::SelectorMismatch,
                    "subject, selector, and count constraints are inconsistent",
                ));
            }
        }

        if let ApprovalSelector::Exact {
            ordered_payload_digests,
            ordered_hashes,
            message_normalization: Some(ExactMessageNormalization::SolanaNativeTransferBlockhashV1),
        } = &self.selector
        {
            self.validate_normalized_native_transfer(ordered_payload_digests, ordered_hashes)?;
        }

        Ok(())
    }

    /// A normalized approval leaves 32 message bytes uncommitted, so it is
    /// admitted only for the one narrow shape it was designed for. Everything
    /// here is checked on the sealed terms themselves, independently of any
    /// claim the Broker may also require.
    fn validate_normalized_native_transfer(
        &self,
        ordered_payload_digests: &[Digest32],
        ordered_hashes: &[Digest32],
    ) -> Result<(), ProtocolError> {
        let ApprovalSubject::System {
            component_id,
            operation_class,
        } = &self.subject
        else {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SelectorMismatch,
                "blockhash-normalized Exact requires a System approval subject",
            ));
        };
        if component_id.as_str() != NORMALIZED_TRANSFER_COMPONENT_ID
            || operation_class.as_str() != NORMALIZED_TRANSFER_ACTION_CLASS
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SelectorMismatch,
                "blockhash-normalized Exact is limited to the Machine native-transfer confirm action",
            ));
        }
        if self.key_ref.key_spec != KeySpec::Ed25519
            || self.allowed_crypto_suites != [CryptoSuite::Ed25519Message]
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SuiteNotAllowed,
                "blockhash-normalized Exact requires an Ed25519 key and exactly the Ed25519 message suite",
            ));
        }
        if ordered_payload_digests.len() != 1
            || ordered_hashes.len() != 1
            || ordered_payload_digests[0] != ordered_hashes[0]
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SelectorMismatch,
                "blockhash-normalized Exact commits to exactly one normalized message digest",
            ));
        }
        if self.limits.max_operations.get() != 1
            || self.limits.max_signatures.get() != 1
            || !self.limits.operation_rate_limits.is_empty()
            || !self.limits.signature_rate_limits.is_empty()
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::LimitExceededOperations,
                "blockhash-normalized Exact allows one operation and one signature with no rate windows",
            ));
        }
        match self.limits.value_limits.as_slice() {
            [limit]
                if limit.asset.chain.as_str() == NORMALIZED_TRANSFER_ASSET_CHAIN
                    && limit.asset.asset == NORMALIZED_TRANSFER_ASSET
                    && limit.lifetime.as_str() != "0"
                    && limit.rolling_windows.is_empty() => {}
            _ => {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::LimitExceededValue,
                    "blockhash-normalized Exact requires one positive solana:native lifetime ceiling and no rolling windows",
                ));
            }
        }
        if self
            .expires_at_ms
            .get()
            .checked_sub(self.not_before_ms.get())
            .is_none_or(|window| window > NORMALIZED_TRANSFER_MAX_VALIDITY_MS)
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ApprovalExpired,
                "blockhash-normalized Exact may not be valid for longer than five minutes",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("approval JCS encoding failed: {error}"),
            )
        })
    }

    pub fn approval_digest(&self) -> Result<Digest32, ProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(APPROVAL_DOMAIN);
        hasher.update(self.canonical_bytes()?);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }

    pub fn approval_id(&self) -> Result<Digest32, ProtocolError> {
        self.approval_digest()
    }
}

fn valid_route_grants(
    grants: &[PetalRouteGrant],
    primary_route: &str,
    primary_classes: &[Token],
    primary_provenance: &Digest32,
) -> bool {
    grants.is_empty()
        || grants.iter().all(|grant| {
            !grant.route.is_empty() && classes_are_canonical(&grant.allowed_operation_classes)
        }) && grants
            .windows(2)
            .all(|pair| pair[0].route.as_bytes() < pair[1].route.as_bytes())
            && grants.iter().any(|grant| {
                grant.route == primary_route
                    && grant.allowed_operation_classes == primary_classes
                    && &grant.provenance_digest == primary_provenance
            })
}

fn classes_are_canonical(classes: &[Token]) -> bool {
    !classes.is_empty()
        && classes
            .windows(2)
            .all(|pair| pair[0].as_str().as_bytes() < pair[1].as_str().as_bytes())
}

fn validate_suites(suites: &[CryptoSuite], key_spec: crate::KeySpec) -> Result<(), ProtocolError> {
    if suites.is_empty()
        || suites.len() > 4
        || !unique(suites)
        || suites.iter().any(|suite| suite.key_spec() != key_spec)
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::SuiteNotAllowed,
            "allowed CryptoSuites must contain 1-4 unique suites compatible with the KeyRef",
        ));
    }
    Ok(())
}

fn validate_limits(limits: &ApprovalLimits) -> Result<(), ProtocolError> {
    if limits.max_operations.get() == 0 || limits.max_signatures.get() == 0 {
        return Err(ProtocolError::new(
            ProtocolErrorCode::LimitExceededOperations,
            "operation and signature limits must be greater than zero",
        ));
    }
    if limits
        .operation_rate_limits
        .iter()
        .chain(&limits.signature_rate_limits)
        .any(|window| window.maximum.get() == 0 || window.duration_ms.get() == 0)
        || limits.value_limits.iter().any(|limit| {
            limit.asset.asset.is_empty()
                || limit
                    .rolling_windows
                    .iter()
                    .any(|window| window.duration_ms.get() == 0)
        })
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::LimitExceededRate,
            "rate limits require positive maxima and durations",
        ));
    }
    Ok(())
}

fn unique<T: Eq + std::hash::Hash>(values: &[T]) -> bool {
    let mut seen = HashSet::with_capacity(values.len());
    values.iter().all(|value| seen.insert(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DerivationRef, KeySpec};

    fn exact_terms(nonce: &str) -> SealedApprovalTerms {
        SealedApprovalTerms {
            subject: ApprovalSubject::Cli {
                client_id: Token::new("bloom-cli").unwrap(),
                command_class: Token::new("wallet.sign").unwrap(),
            },
            wallet_id: Token::new("wallet-1").unwrap(),
            key_ref: KeyRef {
                backend: Token::new("local").unwrap(),
                backend_instance: Token::new("local-default").unwrap(),
                locator: "key-1".into(),
                key_spec: KeySpec::Secp256k1,
                public_key_fingerprint: Digest32::new("11".repeat(32)).unwrap(),
                derivation: Some(DerivationRef::Bip32Secp256k1 {
                    root_key_id: Token::new("root-1").unwrap(),
                    path: "m/44'/60'/0'/0/0".into(),
                }),
            },
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            selector: ApprovalSelector::Exact {
                ordered_payload_digests: vec![Digest32::new("22".repeat(32)).unwrap()],
                ordered_hashes: vec![Digest32::new("33".repeat(32)).unwrap()],
                message_normalization: None,
            },
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(1),
                max_signatures: DecimalU64::new(1),
                operation_rate_limits: vec![],
                signature_rate_limits: vec![],
                value_limits: vec![],
            },
            activation_mode: ActivationMode::BootBound,
            wallet_revocation_epoch: DecimalU64::new(7),
            policy_version: DecimalU64::new(3),
            policy_digest: Digest32::new("44".repeat(32)).unwrap(),
            provenance_digest: Digest32::new("55".repeat(32)).unwrap(),
            request_nonce: RequestNonce::new(nonce).unwrap(),
            issued_at_ms: DecimalU64::new(1_900_000_000_000),
            not_before_ms: DecimalU64::new(1_900_000_000_000),
            expires_at_ms: DecimalU64::new(1_900_000_600_000),
            renewal_of: None,
        }
    }

    #[test]
    fn approval_digest_excludes_lifecycle_and_nonce_distinguishes_identical_requests() {
        let first = exact_terms("00".repeat(16).as_str());
        let second = exact_terms("01".repeat(16).as_str());
        assert_ne!(first.approval_id().unwrap(), second.approval_id().unwrap());
    }

    #[test]
    fn exact_selector_count_consistency_is_fail_closed() {
        let mut terms = exact_terms("00".repeat(16).as_str());
        terms.limits.max_signatures = DecimalU64::new(2);
        assert_eq!(
            terms.validate().unwrap_err().code,
            ProtocolErrorCode::SelectorMismatch
        );
    }

    #[test]
    fn petal_route_grants_are_canonical_and_legacy_singletons_decode() {
        let mut terms = exact_terms("02".repeat(16).as_str());
        let package_hash = Digest32::new("66".repeat(32)).unwrap();
        terms.subject = ApprovalSubject::Petal {
            package_hash: package_hash.clone(),
            route: "r000001".into(),
            agent_id: None,
        };
        terms.selector = ApprovalSelector::Petal {
            package_hash,
            route: "r000001".into(),
            allowed_operation_classes: vec![Token::new("session.create").unwrap()],
            route_grants: vec![
                PetalRouteGrant {
                    route: "r000001".into(),
                    allowed_operation_classes: vec![Token::new("session.create").unwrap()],
                    provenance_digest: terms.provenance_digest.clone(),
                },
                PetalRouteGrant {
                    route: "r000002".into(),
                    allowed_operation_classes: vec![Token::new("order.place").unwrap()],
                    provenance_digest: Digest32::new("77".repeat(32)).unwrap(),
                },
                PetalRouteGrant {
                    route: "r000003".into(),
                    allowed_operation_classes: vec![Token::new("order.cancel").unwrap()],
                    provenance_digest: Digest32::new("88".repeat(32)).unwrap(),
                },
            ],
            required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
        };
        terms.limits.max_operations = DecimalU64::new(10);
        terms.validate().unwrap();

        let mut reversed = terms.clone();
        if let ApprovalSelector::Petal { route_grants, .. } = &mut reversed.selector {
            route_grants.reverse();
        }
        assert_eq!(
            reversed.validate().unwrap_err().code,
            ProtocolErrorCode::SelectorMismatch
        );

        let mut missing_primary = terms.clone();
        if let ApprovalSelector::Petal { route_grants, .. } = &mut missing_primary.selector {
            route_grants.remove(0);
        }
        assert_eq!(
            missing_primary.validate().unwrap_err().code,
            ProtocolErrorCode::SelectorMismatch
        );

        let mut unsorted_classes = terms.clone();
        if let ApprovalSelector::Petal { route_grants, .. } = &mut unsorted_classes.selector {
            route_grants[1].allowed_operation_classes = vec![
                Token::new("order.place").unwrap(),
                Token::new("order.cancel").unwrap(),
            ];
        }
        assert_eq!(
            unsorted_classes.validate().unwrap_err().code,
            ProtocolErrorCode::SelectorMismatch
        );

        if let ApprovalSelector::Petal { route_grants, .. } = &mut terms.selector {
            route_grants.clear();
        }
        let encoded = serde_json::to_value(&terms).unwrap();
        assert!(encoded["selector"].get("route_grants").is_none());
        serde_json::from_value::<SealedApprovalTerms>(encoded)
            .unwrap()
            .validate()
            .unwrap();
    }

    /// The public Solana native-transfer golden message, mirrored from
    /// `bloom_broker_api::solana_vectors`. Signer must normalize the same
    /// bytes the Broker verifier and the Machine constructor agree on, but it
    /// deliberately takes no dependency on a Solana SDK to do so, so the
    /// vector is duplicated here and pinned by the digests below.
    const GOLDEN_MESSAGE_HEX: &str = "0100010303a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8abababababababababababababababababababababababababababababababab0000000000000000000000000000000000000000000000000000000000000000424242424242424242424242424242424242424242424242424242424242424201020200010c0200000000ca9a3b00000000";
    /// SHA-256 of the raw golden message: the digest ordinary Exact commits to.
    const GOLDEN_RAW_DIGEST: &str =
        "d7770e6c7f805e94d5ed24b4b0d8ca93bdd7de4081ccb230fa257096b7dc5ec5";
    /// SHA-256 of the golden message with bytes 100..132 zeroed.
    const GOLDEN_NORMALIZED_DIGEST: &str =
        "e122e4d638a825d599932132b53f5939bd9f2d3f53118fa960c51ecbc819c80c";

    fn golden_message() -> Vec<u8> {
        (0..GOLDEN_MESSAGE_HEX.len() / 2)
            .map(|index| {
                u8::from_str_radix(&GOLDEN_MESSAGE_HEX[index * 2..index * 2 + 2], 16).unwrap()
            })
            .collect()
    }

    fn normalized_terms(message: &[u8]) -> SealedApprovalTerms {
        let normalized = solana_native_transfer_approval_digest(message).unwrap();
        let mut terms = exact_terms("10".repeat(16).as_str());
        terms.subject = ApprovalSubject::System {
            component_id: Token::new("bloom-machine").unwrap(),
            operation_class: Token::new("solana.transfer.confirm").unwrap(),
        };
        terms.key_ref.key_spec = KeySpec::Ed25519;
        terms.key_ref.derivation = None;
        terms.allowed_crypto_suites = vec![CryptoSuite::Ed25519Message];
        terms.selector = ApprovalSelector::Exact {
            ordered_payload_digests: vec![normalized.clone()],
            ordered_hashes: vec![normalized],
            message_normalization: Some(ExactMessageNormalization::SolanaNativeTransferBlockhashV1),
        };
        terms.limits.value_limits = vec![ValueLimit {
            asset: AssetId {
                chain: Token::new("solana").unwrap(),
                asset: "native".into(),
            },
            lifetime: DecimalU256::parse("1000005000").unwrap(),
            rolling_windows: Vec::new(),
        }];
        terms.expires_at_ms = DecimalU64::new(terms.not_before_ms.get() + 300_000);
        terms
    }

    #[test]
    fn unmarked_exact_terms_keep_their_v1_bytes_and_approval_id() {
        let terms = exact_terms("00".repeat(16).as_str());
        let encoded = serde_json::to_value(&terms).unwrap();
        assert!(encoded["selector"].get("message_normalization").is_none());
        assert_eq!(
            terms.approval_id().unwrap().as_str(),
            "ee43cae12df068751c9aee67c6f260d343aa851319ede8fb54d8cfbd1862b4ef",
            "the frozen v1 approval ID must not move when the optional field is absent"
        );
        // An old peer's terms, which never carried the field at all, still decode.
        serde_json::from_value::<SealedApprovalTerms>(encoded)
            .unwrap()
            .validate()
            .unwrap();
    }

    #[test]
    fn the_marker_is_sealed_into_the_approval_identity() {
        let message = golden_message();
        let marked = normalized_terms(&message);
        marked.validate().unwrap();
        let mut unmarked = marked.clone();
        let ApprovalSelector::Exact {
            message_normalization,
            ..
        } = &mut unmarked.selector
        else {
            unreachable!("fixture is exact")
        };
        *message_normalization = None;
        assert_ne!(
            marked.approval_id().unwrap(),
            unmarked.approval_id().unwrap(),
            "a normalized approval must not share an identity with a raw one"
        );
        assert!(
            serde_json::to_string(&marked)
                .unwrap()
                .contains("solana_native_transfer_blockhash_v1")
        );
    }

    #[test]
    fn an_unknown_normalization_mode_fails_decoding() {
        let message = golden_message();
        let mut encoded = serde_json::to_value(normalized_terms(&message)).unwrap();
        encoded["selector"]["message_normalization"] =
            serde_json::Value::String("solana_native_transfer_blockhash_v2".into());
        assert!(serde_json::from_value::<SealedApprovalTerms>(encoded).is_err());
    }

    #[test]
    fn the_normalizer_matches_the_public_golden_vector() {
        let message = golden_message();
        assert_eq!(message.len(), 150);
        assert_eq!(
            Digest32::from_bytes(Sha256::digest(&message).into()).as_str(),
            GOLDEN_RAW_DIGEST,
            "the raw payload commitment must be untouched by this change"
        );
        assert_eq!(
            solana_native_transfer_approval_digest(&message)
                .unwrap()
                .as_str(),
            GOLDEN_NORMALIZED_DIGEST
        );
    }

    #[test]
    fn only_the_recent_blockhash_bytes_leave_the_normalized_digest() {
        let message = golden_message();
        let baseline = solana_native_transfer_approval_digest(&message).unwrap();
        let mut preserved = 0usize;
        for offset in 0..message.len() {
            for delta in 1..=u8::MAX {
                let mut mutated = message.clone();
                mutated[offset] = mutated[offset].wrapping_add(delta);
                match solana_native_transfer_approval_digest(&mutated) {
                    Ok(digest) => {
                        // Structurally valid changes to the program ID, the
                        // account keys or the amount must still normalize and
                        // must still change N. Only the blockhash may move.
                        assert_eq!(
                            digest == baseline,
                            NATIVE_TRANSFER_BLOCKHASH.contains(&offset),
                            "byte {offset} changed the wrong way"
                        );
                        preserved += usize::from(digest == baseline);
                    }
                    Err(error) => {
                        assert!(
                            offset < NATIVE_TRANSFER_PREFIX.len()
                                || (NATIVE_TRANSFER_BLOCKHASH.end
                                    ..NATIVE_TRANSFER_BLOCKHASH.end
                                        + NATIVE_TRANSFER_INSTRUCTION.len())
                                    .contains(&offset),
                            "byte {offset} must not be structural"
                        );
                        assert_eq!(error.code, ProtocolErrorCode::SelectorMismatch);
                    }
                }
            }
        }
        assert_eq!(preserved, 32 * usize::from(u8::MAX));
    }

    #[test]
    fn other_message_layouts_are_refused() {
        let message = golden_message();
        let mut refused: Vec<Vec<u8>> = Vec::new();
        // Every truncation, including the empty message.
        for length in 0..message.len() {
            refused.push(message[..length].to_vec());
        }
        // Trailing data after the one instruction, and a doubled instruction,
        // which is how a priority-fee or nonce-advance message would differ.
        let mut trailing = message.clone();
        trailing.push(0);
        refused.push(trailing);
        let mut two_instructions = message.clone();
        two_instructions[3] = 4;
        two_instructions.extend_from_slice(&message[132..]);
        refused.push(two_instructions);
        // A noncanonical account count and a versioned (v0) message prefix.
        let mut noncanonical = message.clone();
        noncanonical[3] = 4;
        refused.push(noncanonical);
        let mut versioned = message.clone();
        versioned[0] = 0x80;
        refused.push(versioned);
        for candidate in refused {
            let error = solana_native_transfer_approval_digest(&candidate)
                .expect_err("layout must be refused");
            assert_eq!(error.code, ProtocolErrorCode::SelectorMismatch);
        }
    }

    #[test]
    fn marked_terms_admit_only_the_native_transfer_confirm_shape() {
        let message = golden_message();
        let baseline = normalized_terms(&message);
        baseline.validate().unwrap();

        let mut wrong_subject_kind = baseline.clone();
        wrong_subject_kind.subject = ApprovalSubject::Cli {
            client_id: Token::new("bloom-cli").unwrap(),
            command_class: Token::new("wallet.sign").unwrap(),
        };
        let mut wrong_component = baseline.clone();
        wrong_component.subject = ApprovalSubject::System {
            component_id: Token::new("bloom-daemon").unwrap(),
            operation_class: Token::new("solana.transfer.confirm").unwrap(),
        };
        let mut wrong_action = baseline.clone();
        wrong_action.subject = ApprovalSubject::System {
            component_id: Token::new("bloom-machine").unwrap(),
            operation_class: Token::new("solana.token-transfer.confirm").unwrap(),
        };
        for (label, terms) in [
            ("non-System subject", wrong_subject_kind),
            ("other component", wrong_component),
            ("other action class", wrong_action),
        ] {
            assert_eq!(
                terms.validate().unwrap_err().code,
                ProtocolErrorCode::SelectorMismatch,
                "{label}"
            );
        }

        let mut secp_key = baseline.clone();
        secp_key.key_ref.key_spec = KeySpec::Secp256k1;
        secp_key.allowed_crypto_suites = vec![CryptoSuite::Secp256k1Sha256Recoverable];
        let mut extra_suite = baseline.clone();
        extra_suite.allowed_crypto_suites = vec![CryptoSuite::Ed25519Message; 1];
        extra_suite.key_ref.key_spec = KeySpec::Ed25519;
        extra_suite.allowed_crypto_suites.clear();
        for (label, terms) in [("secp256k1 key", secp_key), ("no suite", extra_suite)] {
            assert_eq!(
                terms.validate().unwrap_err().code,
                ProtocolErrorCode::SuiteNotAllowed,
                "{label}"
            );
        }

        let normalized = solana_native_transfer_approval_digest(&message).unwrap();
        let mut two_messages = baseline.clone();
        two_messages.selector = ApprovalSelector::Exact {
            ordered_payload_digests: vec![normalized.clone(), normalized.clone()],
            ordered_hashes: vec![normalized.clone(), normalized.clone()],
            message_normalization: Some(ExactMessageNormalization::SolanaNativeTransferBlockhashV1),
        };
        two_messages.limits.max_signatures = DecimalU64::new(2);
        let mut split_digests = baseline.clone();
        split_digests.selector = ApprovalSelector::Exact {
            ordered_payload_digests: vec![normalized.clone()],
            ordered_hashes: vec![Digest32::new("77".repeat(32)).unwrap()],
            message_normalization: Some(ExactMessageNormalization::SolanaNativeTransferBlockhashV1),
        };
        for (label, terms) in [
            ("two messages", two_messages),
            ("payload digest unequal to hash", split_digests),
        ] {
            assert_eq!(
                terms.validate().unwrap_err().code,
                ProtocolErrorCode::SelectorMismatch,
                "{label}"
            );
        }

        let mut rate_window = baseline.clone();
        rate_window.limits.signature_rate_limits = vec![SlidingWindow {
            maximum: DecimalU64::new(1),
            duration_ms: DecimalU64::new(60_000),
        }];
        assert_eq!(
            rate_window.validate().unwrap_err().code,
            ProtocolErrorCode::LimitExceededOperations
        );

        let mut no_budget = baseline.clone();
        no_budget.limits.value_limits.clear();
        let mut zero_budget = baseline.clone();
        zero_budget.limits.value_limits[0].lifetime = DecimalU256::parse("0").unwrap();
        let mut wrong_asset = baseline.clone();
        wrong_asset.limits.value_limits[0].asset.asset = "usdc".into();
        let mut rolling_budget = baseline.clone();
        rolling_budget.limits.value_limits[0].rolling_windows = vec![ValueWindow {
            maximum: DecimalU256::parse("1").unwrap(),
            duration_ms: DecimalU64::new(60_000),
        }];
        for (label, terms) in [
            ("missing budget", no_budget),
            ("zero budget", zero_budget),
            ("other asset", wrong_asset),
            ("rolling window", rolling_budget),
        ] {
            assert_eq!(
                terms.validate().unwrap_err().code,
                ProtocolErrorCode::LimitExceededValue,
                "{label}"
            );
        }

        let mut too_long = baseline.clone();
        too_long.expires_at_ms = DecimalU64::new(too_long.not_before_ms.get() + 300_001);
        assert_eq!(
            too_long.validate().unwrap_err().code,
            ProtocolErrorCode::ApprovalExpired
        );
        let mut exactly_five_minutes = baseline;
        exactly_five_minutes.expires_at_ms =
            DecimalU64::new(exactly_five_minutes.not_before_ms.get() + 300_000);
        exactly_five_minutes.validate().unwrap();
    }
}
