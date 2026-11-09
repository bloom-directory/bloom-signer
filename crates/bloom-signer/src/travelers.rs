//! Traveler plaintext exists only inside custody or encrypted browser output.
use bloom_signer_api::{ProtocolError, ProtocolErrorCode, TravelerField};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct TravelerDetails {
    pub given_name: String,
    pub family_name: String,
    pub born_on: Option<String>,
    pub gender: Option<String>,
    pub nationality: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub document_kind: Option<String>,
    pub document_number: Option<String>,
    pub document_country: Option<String>,
    pub document_expiry: Option<String>,
}

fn valid_date(s: &str) -> bool {
    bloom_signer_api::is_calendar_date(s)
        && s.get(..4)
            .and_then(|year| year.parse::<u32>().ok())
            .is_some_and(|year| year >= 1900)
}

impl TravelerDetails {
    pub fn value(&self, field: TravelerField) -> Option<&str> {
        use TravelerField::*;
        match field {
            GivenName => Some(&self.given_name),
            FamilyName => Some(&self.family_name),
            BornOn => self.born_on.as_deref(),
            Gender => self.gender.as_deref(),
            Nationality => self.nationality.as_deref(),
            Email => self.email.as_deref(),
            Phone => self.phone.as_deref(),
            DocumentKind => self.document_kind.as_deref(),
            DocumentNumber => self.document_number.as_deref(),
            DocumentCountry => self.document_country.as_deref(),
            DocumentExpiry => self.document_expiry.as_deref(),
        }
    }
    pub fn fields(&self) -> Vec<TravelerField> {
        use TravelerField::*;
        [
            GivenName,
            FamilyName,
            BornOn,
            Gender,
            Nationality,
            Email,
            Phone,
            DocumentKind,
            DocumentNumber,
            DocumentCountry,
            DocumentExpiry,
        ]
        .into_iter()
        .filter(|field| self.value(*field).is_some())
        .collect()
    }
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let country = |s: &str| s.len() == 2 && s.bytes().all(|b| b.is_ascii_uppercase());
        if self.given_name.trim().is_empty()
            || self.family_name.trim().is_empty()
            || self.fields().iter().any(|field| {
                self.value(*field).is_some_and(|s| {
                    s.trim().is_empty() || s.len() > 320 || s.chars().any(char::is_control)
                })
            })
            || self.given_name.len() > 128
            || self.family_name.len() > 128
            || self.born_on.as_deref().is_some_and(|s| !valid_date(s))
            || self
                .document_expiry
                .as_deref()
                .is_some_and(|s| !valid_date(s))
            || self.nationality.as_deref().is_some_and(|s| !country(s))
            || self
                .document_country
                .as_deref()
                .is_some_and(|s| !country(s))
            || self
                .gender
                .as_deref()
                .is_some_and(|s| !matches!(s, "female" | "male" | "unspecified"))
            || self
                .document_kind
                .as_deref()
                .is_some_and(|s| !matches!(s, "passport" | "national_id"))
            || self
                .document_number
                .as_deref()
                .is_some_and(|s| s.len() > 64)
            || (self.document_number.is_some() && self.document_kind.is_none())
            || self.email.as_deref().is_some_and(|s| !s.contains('@'))
            || self.phone.as_deref().is_some_and(|s| s.len() > 48)
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "invalid private traveler details",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn date_validation_rejects_normalized_impossible_dates() {
        assert!(valid_date("1992-02-29"));
        for value in [
            "1993-02-29",
            "2000-04-31",
            "2000-00-01",
            "2000-01-00",
            "2000-1-01",
        ] {
            assert!(!valid_date(value));
        }
    }
}
