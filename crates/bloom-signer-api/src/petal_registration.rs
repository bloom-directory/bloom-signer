//! Exact owner-consent terms for a package registration. These terms confer no
//! wallet, key-derivation, or signing authority.
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    Base64UrlBytes, CeremonyKind, CeremonyState, CustodyPrepareRequest, CustodyResult, Digest32,
    OperationId, ProtocolError, ProtocolErrorCode, Token,
};

pub const PETAL_REGISTRATION_SCHEMA: &str = "bloom.petal-registration/1";
pub const PETAL_REGISTRATION_INPUT_CLASS: &str = "petal_registration";
const TERMS_DOMAIN: &[u8] = b"bloom.petal-registration-terms/v1\0";
const ENROLLMENT_DOMAIN: &[u8] = b"bloom.petal-registration-enrollment/v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalRegistrationTerms {
    #[serde(deserialize_with = "deserialize_schema")]
    pub schema: Token,
    pub operation_id: OperationId,
    pub enrollment_digest: Digest32,
    pub owner_wallet_id: Token,
    pub package_hash: Digest32,
    pub manifest_digest: Digest32,
    pub permissions_digest: Digest32,
    pub lineage_id: String,
}

impl PetalRegistrationTerms {
    pub fn validate_shape(&self) -> Result<(), ProtocolError> {
        if self.schema.as_str() != PETAL_REGISTRATION_SCHEMA {
            return Err(ProtocolError::new(
                ProtocolErrorCode::UnsupportedVersion,
                "unsupported Petal registration schema",
            ));
        }
        crate::validate_lineage_id(&self.lineage_id)
    }

    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        self.validate_shape()?;
        digest(TERMS_DOMAIN, self)
    }
}

/// Identifies the locally configured persistent custody pair, independent of
/// boot epochs, transport rotation, or release versions. Callers must use their
/// actual local key and configured peer verification pin, never request input.
pub fn petal_registration_enrollment_digest(
    broker_key_id: &Token,
    broker_public_key: &VerifyingKey,
    signer_key_id: &Token,
    signer_public_key: &VerifyingKey,
) -> Result<Digest32, ProtocolError> {
    #[derive(Serialize)]
    struct Identity<'a> {
        service_id: &'static str,
        key_role: &'static str,
        key_id: &'a Token,
        public_key: Base64UrlBytes,
    }
    #[derive(Serialize)]
    struct Enrollment<'a> {
        broker: Identity<'a>,
        signer: Identity<'a>,
    }
    digest(
        ENROLLMENT_DOMAIN,
        &Enrollment {
            broker: Identity {
                service_id: "bloom-broker",
                key_role: "broker_signing",
                key_id: broker_key_id,
                public_key: Base64UrlBytes::from_bytes(&broker_public_key.to_bytes()),
            },
            signer: Identity {
                service_id: "bloom-signer",
                key_role: "signer_ceremony",
                key_id: signer_key_id,
                public_key: Base64UrlBytes::from_bytes(&signer_public_key.to_bytes()),
            },
        },
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PetalRegistrationCeremonyPrepareRequest {
    pub custody: CustodyPrepareRequest,
    pub terms: PetalRegistrationTerms,
}

impl PetalRegistrationCeremonyPrepareRequest {
    /// Check exact typed binding. Enrollment still requires an independent
    /// comparison against the recipient service's locally configured identity.
    pub fn validate_binding(&self) -> Result<(), ProtocolError> {
        if self.custody.ceremony_kind != CeremonyKind::PetalRegistration
            || self.custody.custody_operation_id != self.terms.operation_id
            || self.custody.wallet_id.as_ref() != Some(&self.terms.owner_wallet_id)
            || self.custody.exact_terms_digest != self.terms.digest()?
            || self.custody.expected_input_class.as_str() != PETAL_REGISTRATION_INPUT_CLASS
            || self.custody.key_ref.is_some()
            || self.custody.browser_output_recipient_key.is_some()
            || self.custody.petal_key_scope.is_some()
            || self.custody.legacy_passkey_migration.is_some()
        {
            return Err(binding_error());
        }
        Ok(())
    }
}

impl CustodyResult {
    /// Enforce the registration-specific signed field on all receipt kinds.
    /// Existing receipt kinds keep their canonical bytes with an absent field.
    pub fn validate_petal_registration_shape(&self) -> Result<(), ProtocolError> {
        if self.ceremony_kind == CeremonyKind::PetalRegistration {
            if self.petal_registration_terms_digest.is_none()
                || self.public_status != CeremonyState::Succeeded
                || self.wallet_id.is_none()
                || !self.public_key_refs.is_empty()
                || !self.credential_summaries.is_empty()
                || self.initial_policy.is_some()
                || self.encrypted_browser_result.is_some()
            {
                return Err(binding_error());
            }
        } else if self.petal_registration_terms_digest.is_some() {
            return Err(binding_error());
        }
        Ok(())
    }

    /// Exact public terms binding; signature and local enrollment verification
    /// remain mandatory for any consumer adopting this receipt as authority.
    pub fn validate_petal_registration_binding(
        &self,
        terms: &PetalRegistrationTerms,
    ) -> Result<(), ProtocolError> {
        self.validate_petal_registration_shape()?;
        if self.ceremony_kind != CeremonyKind::PetalRegistration
            || self.custody_operation_id != terms.operation_id
            || self.wallet_id.as_ref() != Some(&terms.owner_wallet_id)
            || self.petal_registration_terms_digest.as_ref() != Some(&terms.digest()?)
        {
            return Err(binding_error());
        }
        Ok(())
    }
}

fn binding_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::CeremonyKindMismatch,
        "Petal registration binding mismatch",
    )
}
fn deserialize_schema<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Token, D::Error> {
    let schema = Token::deserialize(deserializer)?;
    if schema.as_str() != PETAL_REGISTRATION_SCHEMA {
        return Err(serde::de::Error::custom(
            "unsupported Petal registration schema",
        ));
    }
    Ok(schema)
}
fn digest(domain: &[u8], value: &impl Serialize) -> Result<Digest32, ProtocolError> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| {
        ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Ok(Digest32::from_bytes(hasher.finalize().into()))
}
