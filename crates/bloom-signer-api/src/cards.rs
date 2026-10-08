//! Public card metadata and typed ceremony terms. No card plaintext on RPC.
use crate::{
    Base64UrlBytes, CeremonyKind, Digest32, OperationId, ProtocolError, ProtocolErrorCode,
    SurfaceRef, Token,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardPublic {
    pub card_id: Token,
    pub label: String,
    pub brand: String,
    pub last4: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CardOperationState {
    Prepared,
    Consumed,
    Succeeded,
    Failed,
    Cancelled,
    Expired,
    Missing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardOperationStatus {
    pub operation_id: OperationId,
    pub state: CardOperationState,
}

/// Supplied by the authenticated checkout principal, then independently bound
/// in Signer's contribution and WebAuthn challenges. Amounts are minor units.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutFacts {
    pub origin: String,
    pub payment_frame_origins: Vec<String>,
    pub total_minor: u64,
    pub currency: String,
    pub installments: u16,
    pub recurring: bool,
}

impl CheckoutFacts {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        fn valid_origin(value: &str) -> bool {
            url::Url::parse(value).is_ok_and(|u| {
                u.scheme() == "https"
                    && u.host_str().is_some()
                    && u.username().is_empty()
                    && u.password().is_none()
                    && u.origin().ascii_serialization() == value
            })
        }
        if self.origin.len() > 256
            || !valid_origin(&self.origin)
            || self.payment_frame_origins.len() > 8
            || self
                .payment_frame_origins
                .iter()
                .any(|s| s.len() > 256 || !valid_origin(s))
            || self.currency.len() != 3
            || !self.currency.bytes().all(|b| b.is_ascii_uppercase())
            || self.installments == 0
            || self.installments > 60
            || self.total_minor == 0
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "invalid checkout facts",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CardEffect {
    Add {
        card_id: Token,
        label: String,
    },
    Delete {
        card_id: Token,
    },
    Checkout {
        card_id: Token,
        facts: CheckoutFacts,
        recipient_key: Base64UrlBytes,
        agent_description: String,
    },
}
impl CardEffect {
    pub fn ceremony_kind(&self) -> CeremonyKind {
        match self {
            Self::Add { .. } => CeremonyKind::CardAdd,
            Self::Delete { .. } => CeremonyKind::CardDelete,
            Self::Checkout { .. } => CeremonyKind::CardCheckout,
        }
    }
    pub fn card_id(&self) -> &Token {
        match self {
            Self::Add { card_id, .. }
            | Self::Delete { card_id }
            | Self::Checkout { card_id, .. } => card_id,
        }
    }
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Add { label, .. }
                if label.is_empty() || label.len() > 64 || label.chars().any(char::is_control) =>
            {
                Err(ProtocolError::new(
                    ProtocolErrorCode::MalformedFrame,
                    "invalid card label",
                ))
            }
            Self::Checkout {
                facts,
                recipient_key,
                agent_description,
                ..
            } => {
                facts.validate()?;
                if recipient_key.decode().len() != 32 || agent_description.len() > 1024 {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::MalformedFrame,
                        "invalid checkout binding",
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CardPrepareRequest {
    pub surface: SurfaceRef,
    pub operation_id: OperationId,
    pub effect: CardEffect,
}
impl CardPrepareRequest {
    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        self.effect.validate()?;
        let bytes = serde_jcs::to_vec(self).map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "card terms cannot be canonicalized",
            )
        })?;
        let mut hash = Sha256::new();
        hash.update(b"bloom-card-terms/v1\0");
        hash.update(bytes);
        Ok(Digest32::from_bytes(hash.finalize().into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn facts() -> CheckoutFacts {
        CheckoutFacts {
            origin: "https://shop.example".into(),
            payment_frame_origins: vec!["https://payment.example".into()],
            total_minor: 34200,
            currency: "BRL".into(),
            installments: 6,
            recurring: false,
        }
    }
    fn request(facts: CheckoutFacts, key: u8) -> CardPrepareRequest {
        CardPrepareRequest {
            surface: crate::legacy_local_surface(),
            operation_id: OperationId::from_bytes([1; 32]),
            effect: CardEffect::Checkout {
                card_id: Token::new("card-one").unwrap(),
                facts,
                recipient_key: Base64UrlBytes::from_bytes(&[key; 32]),
                agent_description: "Unverified item description".into(),
            },
        }
    }
    #[test]
    fn every_payment_term_and_recipient_changes_the_binding() {
        let original = request(facts(), 2).digest().unwrap();
        for index in 0..7 {
            let mut f = facts();
            let mut key = 2;
            match index {
                0 => f.origin = "https://other.example".into(),
                1 => f.payment_frame_origins = vec!["https://other.example".into()],
                2 => f.total_minor += 1,
                3 => f.currency = "USD".into(),
                4 => f.installments += 1,
                5 => f.recurring = true,
                _ => key = 3,
            }
            assert!(request(f, key).digest().unwrap() != original);
        }
    }
    #[test]
    fn ambiguous_origins_and_invalid_payment_terms_are_rejected() {
        for origin in [
            "http://shop.example",
            "https://shop.example/path",
            "https://user@shop.example",
            "https://shop.example?token=1",
            "https://shop.example#fragment",
        ] {
            let mut f = facts();
            f.origin = origin.into();
            assert!(f.validate().is_err());
        }
        let mut f = facts();
        f.installments = 0;
        assert!(f.validate().is_err());
        let mut f = facts();
        f.currency = "usd".into();
        assert!(f.validate().is_err());
    }
}
