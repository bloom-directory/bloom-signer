use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    Base64UrlBytes, CeremonyWebAuthnOptions, Digest32, OperationId, ProtocolError,
    ProtocolErrorCode, Token, WebAuthnCeremonyProof, WebAuthnCredential,
};

pub const OWNER_ATTESTATION_SCHEMA: &str = "bloom.owner-attestation/1";
pub const OWNER_ATTESTATION_TERMS_DOMAIN: &[u8] = b"bloom-owner-attestation-terms/v1\0";
pub const OWNER_ATTESTATION_RECEIPT_SIGNATURE_DOMAIN: &[u8] =
    b"bloom-owner-attestation-receipt/v1\0";
pub const OWNER_ATTESTATION_CONTRIBUTION_SIGNATURE_DOMAIN: &[u8] =
    b"bloom-owner-attestation-contribution/v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAttestationTerms {
    #[serde(deserialize_with = "deserialize_schema")]
    pub schema: Token,
    pub operation_id: OperationId,
    pub owner_wallet_id: Token,
    pub authority_edge_digest: Digest32,
    pub context_digest: Digest32,
    pub subject_digest: Digest32,
}

impl OwnerAttestationTerms {
    pub fn validate_shape(&self) -> Result<(), ProtocolError> {
        if self.schema.as_str() != OWNER_ATTESTATION_SCHEMA {
            return Err(ProtocolError::new(
                ProtocolErrorCode::UnsupportedVersion,
                "unsupported owner attestation schema",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        self.validate_shape()?;
        digest(OWNER_ATTESTATION_TERMS_DOMAIN, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAttestationPrepareRequest {
    pub terms: OwnerAttestationTerms,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAttestationCompleteRequest {
    pub operation_id: OperationId,
    pub ceremony_id: Digest32,
    pub public_binding_digest: Digest32,
    pub browser_proof: WebAuthnCeremonyProof,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAttestationSignerContribution {
    pub ceremony_id: Digest32,
    pub operation_id: OperationId,
    pub terms_digest: Digest32,
    pub public_binding_digest: Digest32,
    pub signer_key_id: Token,
    pub signer_signature: Base64UrlBytes,
}

impl OwnerAttestationSignerContribution {
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            ceremony_id: &'a Digest32,
            operation_id: &'a OperationId,
            terms_digest: &'a Digest32,
            public_binding_digest: &'a Digest32,
            signer_key_id: &'a Token,
        }

        serde_jcs::to_vec(&Unsigned {
            ceremony_id: &self.ceremony_id,
            operation_id: &self.operation_id,
            terms_digest: &self.terms_digest,
            public_binding_digest: &self.public_binding_digest,
            signer_key_id: &self.signer_key_id,
        })
        .map_err(canonical_error)
    }

    pub fn signature_message(&self) -> Result<Vec<u8>, ProtocolError> {
        Ok([
            OWNER_ATTESTATION_CONTRIBUTION_SIGNATURE_DOMAIN,
            self.unsigned_canonical_bytes()?.as_slice(),
        ]
        .concat())
    }

    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        digest(&[], self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAttestationChallenge {
    pub ceremony_id: Digest32,
    pub operation_id: OperationId,
    pub terms_digest: Digest32,
    pub public_binding_digest: Digest32,
    pub signer_contribution_digest: Digest32,
}

impl OwnerAttestationChallenge {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        serde_jcs::to_vec(self).map_err(canonical_error)
    }

    pub fn webauthn_challenge(&self) -> Result<Base64UrlBytes, ProtocolError> {
        Ok(Base64UrlBytes::from_bytes(&self.canonical_bytes()?))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedOwnerAttestation {
    pub contribution: OwnerAttestationSignerContribution,
    pub challenges: Vec<OwnerAttestationChallenge>,
    pub webauthn_options: CeremonyWebAuthnOptions,
    pub verification_credentials: Vec<WebAuthnCredential>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAttestationReceipt {
    pub operation_id: OperationId,
    pub ceremony_id: Digest32,
    pub owner_wallet_id: Token,
    pub authority_edge_digest: Digest32,
    pub context_digest: Digest32,
    pub subject_digest: Digest32,
    pub receipt_digest: Digest32,
    pub signer_key_id: Token,
    pub signer_signature: Base64UrlBytes,
}

impl OwnerAttestationReceipt {
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            operation_id: &'a OperationId,
            ceremony_id: &'a Digest32,
            owner_wallet_id: &'a Token,
            authority_edge_digest: &'a Digest32,
            context_digest: &'a Digest32,
            subject_digest: &'a Digest32,
            receipt_digest: &'a Digest32,
            signer_key_id: &'a Token,
        }

        serde_jcs::to_vec(&Unsigned {
            operation_id: &self.operation_id,
            ceremony_id: &self.ceremony_id,
            owner_wallet_id: &self.owner_wallet_id,
            authority_edge_digest: &self.authority_edge_digest,
            context_digest: &self.context_digest,
            subject_digest: &self.subject_digest,
            receipt_digest: &self.receipt_digest,
            signer_key_id: &self.signer_key_id,
        })
        .map_err(canonical_error)
    }

    pub fn signature_message(&self) -> Result<Vec<u8>, ProtocolError> {
        Ok([
            OWNER_ATTESTATION_RECEIPT_SIGNATURE_DOMAIN,
            self.unsigned_canonical_bytes()?.as_slice(),
        ]
        .concat())
    }
}

fn deserialize_schema<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Token, D::Error> {
    let schema = Token::deserialize(deserializer)?;
    if schema.as_str() != OWNER_ATTESTATION_SCHEMA {
        return Err(serde::de::Error::custom(
            "unsupported owner attestation schema",
        ));
    }
    Ok(schema)
}

fn digest(domain: &[u8], value: &impl Serialize) -> Result<Digest32, ProtocolError> {
    let bytes = serde_jcs::to_vec(value).map_err(canonical_error)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Ok(Digest32::from_bytes(hasher.finalize().into()))
}

fn canonical_error(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::MalformedFrame,
        format!("owner attestation canonicalization failed: {error}"),
    )
}
