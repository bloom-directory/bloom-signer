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
    /// What each later charge costs, when the page states a price today's
    /// charge does not show: a trial or introductory offer. In the same
    /// currency; the person approves it with the rest of the facts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_minor: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_period: Option<RenewalPeriod>,
    /// The first date that price applies, `YYYY-MM-DD`, when the page states
    /// one unambiguously.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_starts_on: Option<String>,
}

/// How often a subscription renews.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RenewalPeriod {
    Day,
    Week,
    Month,
    Year,
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
            // A checkout with nothing to charge today is only meaningful as a
            // subscription that starts later: the person is approving the
            // renewal terms, not a payment. Without them there is no amount
            // to approve at all.
            || (self.total_minor == 0 && self.renewal_minor.is_none())
            // A renewal price means a price and how often it recurs, on a
            // checkout that says it recurs at all. A date without a price
            // would be a claim the review cannot put an amount against.
            || self.renewal_minor.is_some() != self.renewal_period.is_some()
            || self.renewal_minor.is_some_and(|minor| minor == 0)
            || (self.renewal_minor.is_none() && self.renewal_starts_on.is_some())
            || (self.renewal_minor.is_some() && !self.recurring)
            || self
                .renewal_starts_on
                .as_ref()
                .is_some_and(|date| !is_calendar_date(date))
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "invalid checkout facts",
            ));
        }
        Ok(())
    }
}

/// `YYYY-MM-DD`, and a date that exists. The review shows this to the person
/// as the day the renewal price starts, so "2026-02-31" must not reach it.
fn is_calendar_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        value
            .get(range)
            .filter(|part| part.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|part| part.parse().ok())
    };
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let length = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=length).contains(&day)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CardEffect {
    SaveTraveler {
        traveler_id: Token,
        label: String,
    },
    DeleteTraveler {
        traveler_id: Token,
    },
    FillTraveler {
        traveler_id: Token,
        scope: crate::TravelerFillScope,
        recipient_key: Base64UrlBytes,
    },
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
    /// Authorize the private human view only. Never release a saved card.
    /// Without a card, the human takes over the browser for a step such as a
    /// login or a verification code.
    ManualCheckout {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        card_id: Option<Token>,
        agent_description: String,
    },
    /// Click the merchant's pay button once; the merchant charges the payment
    /// method saved in the buyer's account there. No saved card is released.
    SiteCheckout {
        facts: CheckoutFacts,
        agent_description: String,
    },
}
impl CardEffect {
    pub fn ceremony_kind(&self) -> CeremonyKind {
        match self {
            Self::SaveTraveler { .. } => CeremonyKind::CardAdd,
            Self::DeleteTraveler { .. } => CeremonyKind::CardDelete,
            Self::FillTraveler { .. } => CeremonyKind::CardCheckout,
            Self::Add { .. } => CeremonyKind::CardAdd,
            Self::Delete { .. } => CeremonyKind::CardDelete,
            Self::Checkout { .. } | Self::ManualCheckout { .. } | Self::SiteCheckout { .. } => {
                CeremonyKind::CardCheckout
            }
        }
    }
    pub fn card_id(&self) -> Option<&Token> {
        match self {
            Self::Add { card_id, .. }
            | Self::Delete { card_id }
            | Self::Checkout { card_id, .. } => Some(card_id),
            Self::ManualCheckout { card_id, .. } => card_id.as_ref(),
            Self::SiteCheckout { .. }
            | Self::SaveTraveler { .. }
            | Self::DeleteTraveler { .. }
            | Self::FillTraveler { .. } => None,
        }
    }
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::SaveTraveler { label, .. }
                if label.is_empty() || label.len() > 64 || label.chars().any(char::is_control) =>
            {
                Err(ProtocolError::new(
                    ProtocolErrorCode::MalformedFrame,
                    "invalid traveler label",
                ))
            }
            Self::FillTraveler {
                scope,
                recipient_key,
                ..
            } => {
                scope.validate()?;
                if recipient_key.decode().len() != 32 {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::MalformedFrame,
                        "invalid traveler recipient",
                    ));
                }
                Ok(())
            }
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
            Self::SiteCheckout {
                facts,
                agent_description,
            } => {
                facts.validate()?;
                if !facts.payment_frame_origins.is_empty() || agent_description.len() > 1024 {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::MalformedFrame,
                        "invalid site checkout binding",
                    ));
                }
                Ok(())
            }
            Self::ManualCheckout {
                agent_description, ..
            } if agent_description.len() > 1024 => Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "manual checkout description too long",
            )),
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
            renewal_minor: None,
            renewal_period: None,
            renewal_starts_on: None,
        }
    }
    fn subscription() -> CheckoutFacts {
        CheckoutFacts {
            total_minor: 100,
            currency: "USD".into(),
            installments: 1,
            recurring: true,
            renewal_minor: Some(1299),
            renewal_period: Some(RenewalPeriod::Month),
            renewal_starts_on: Some("2026-11-25".into()),
            ..facts()
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
    /// What the subscription costs later is approved, not advisory: the
    /// person's signature covers the renewal price, how often it recurs and
    /// the day it starts.
    #[test]
    fn every_renewal_term_changes_the_binding() {
        let original = request(subscription(), 2).digest().unwrap();
        let mut seen = std::collections::HashSet::from([original]);
        for index in 0..4 {
            let mut f = subscription();
            match index {
                0 => f.renewal_minor = Some(1399),
                1 => f.renewal_period = Some(RenewalPeriod::Year),
                2 => f.renewal_starts_on = Some("2026-12-25".into()),
                _ => {
                    f.renewal_minor = None;
                    f.renewal_period = None;
                    f.renewal_starts_on = None;
                }
            }
            assert!(seen.insert(request(f, 2).digest().unwrap()), "{index}");
        }
    }
    /// Spotify's headline offer charges nothing today and $12.99 a month from
    /// a stated date. That is approvable: the renewal terms are the whole
    /// substance of it, and they are bound into the operation.
    #[test]
    fn a_free_trial_is_approvable_only_with_its_renewal_terms() {
        let mut trial = subscription();
        trial.total_minor = 0;
        assert!(trial.validate().is_ok());
        // The same page without readable renewal terms has no amount at all.
        let mut empty = trial.clone();
        empty.renewal_minor = None;
        empty.renewal_period = None;
        empty.renewal_starts_on = None;
        assert!(empty.validate().is_err());
        // Nothing today and nothing later is not a subscription either.
        let mut free_forever = trial.clone();
        free_forever.renewal_minor = Some(0);
        assert!(free_forever.validate().is_err());
        // The trial's terms stay bound: a different later price is a
        // different operation.
        let mut dearer = trial.clone();
        dearer.renewal_minor = Some(1999);
        assert_ne!(
            request(trial, 2).digest().unwrap(),
            request(dearer, 2).digest().unwrap()
        );
    }

    #[test]
    fn a_renewal_needs_a_price_a_period_and_a_real_date() {
        assert!(subscription().validate().is_ok());
        let mut f = subscription();
        f.renewal_period = None;
        assert!(f.validate().is_err());
        let mut f = subscription();
        f.renewal_minor = Some(0);
        assert!(f.validate().is_err());
        // A date with no price it belongs to.
        let mut f = subscription();
        f.renewal_minor = None;
        f.renewal_period = None;
        assert!(f.validate().is_err());
        // A later price on a checkout that says it does not recur.
        let mut f = subscription();
        f.recurring = false;
        assert!(f.validate().is_err());
        for date in [
            "2026-11-5",
            "26-11-05",
            "2026/11/05",
            "2026-13-01",
            "2026-02-30",
            "2026-00-10",
            "2026-11-00",
            "2026-11-05 ",
            "two thousand",
        ] {
            let mut f = subscription();
            f.renewal_starts_on = Some(date.into());
            assert!(f.validate().is_err(), "{date}");
        }
        for date in ["2026-02-29", "2024-02-29", "2026-12-31", "2026-11-25"] {
            let mut f = subscription();
            f.renewal_starts_on = Some(date.into());
            assert_eq!(f.validate().is_ok(), date != "2026-02-29", "{date}");
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
