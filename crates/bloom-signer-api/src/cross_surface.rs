//! Authority-first passkey addition across the two Signer-owned origins.

use serde::{Deserialize, Serialize};

use crate::{
    Base64UrlBytes, CeremonyChallenge, CredentialPrfInput, DecimalU64, Digest32, HpkeEnvelope,
    OperationId, SurfaceRef, Token, WebAuthnAssertion, WebAuthnAttestation, WebAuthnCredential,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSurfacePairStartRequest {
    pub destination_surface: SurfaceRef,
    pub operation_id: OperationId,
    pub exact_terms_digest: Digest32,
    pub destination_hpke_public_key: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSurfacePairing {
    pub pairing_id: Digest32,
    pub destination_surface: SurfaceRef,
    pub operation_id: OperationId,
    pub exact_terms_digest: Digest32,
    pub destination_hpke_public_key: Base64UrlBytes,
    pub destination_challenge: Digest32,
    /// A six-digit comparison code displayed on both origins. It confers no authority.
    pub confirmation_code: String,
    pub expires_at_ms: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSurfacePrepareSourceRequest {
    pub pairing_id: Digest32,
    pub operation_id: OperationId,
    pub source_surface: SurfaceRef,
    pub wallet_id: Token,
    pub exact_terms_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSurfaceSourcePrepared {
    pub pairing: CrossSurfacePairing,
    pub source_surface: SurfaceRef,
    pub wallet_id: Token,
    pub source_challenge: CeremonyChallenge,
    pub destination_challenges: Vec<CeremonyChallenge>,
    pub source_credentials: Vec<WebAuthnCredential>,
    pub source_prf_inputs: Vec<CredentialPrfInput>,
    pub destination_user_handle: Base64UrlBytes,
    pub destination_prf_salt: Base64UrlBytes,
    pub source_hpke_recipient_key: Base64UrlBytes,
    pub destination_hpke_recipient_key: Base64UrlBytes,
    pub credential_authority_generation: DecimalU64,
    pub signer_signature: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSurfaceCompleteSourceRequest {
    pub pairing_id: Digest32,
    pub operation_id: OperationId,
    pub authority_assertion: WebAuthnAssertion,
    pub encrypted_authority_prf: HpkeEnvelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSurfaceHandoff {
    pub pairing_id: Digest32,
    pub encrypted_capability: HpkeEnvelope,
    pub expires_at_ms: DecimalU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSurfaceCompleteDestinationRequest {
    pub pairing_id: Digest32,
    pub operation_id: OperationId,
    pub capability: Base64UrlBytes,
    pub attestation: WebAuthnAttestation,
    pub prf_assertion: WebAuthnAssertion,
    pub encrypted_new_prf: HpkeEnvelope,
}

/// The same canonical pair AAD is used with distinct HPKE info strings for
/// source and destination PRF input; the handoff has a third info string.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSurfaceHpkeAad {
    pub pairing_id: Digest32,
    pub operation_id: OperationId,
    pub wallet_id: Token,
    pub source_surface: SurfaceRef,
    pub destination_surface: SurfaceRef,
    pub exact_terms_digest: Digest32,
    pub destination_challenge: Digest32,
    pub phase: Token,
}

impl CrossSurfaceHpkeAad {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, crate::ProtocolError> {
        serde_jcs::to_vec(self).map_err(|error| {
            crate::ProtocolError::new(crate::ProtocolErrorCode::MalformedFrame, error.to_string())
        })
    }
}
