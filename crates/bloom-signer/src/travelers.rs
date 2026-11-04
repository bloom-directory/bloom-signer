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
    if s.len() != 10
        || !s.is_ascii()
        || &s[4..5] != "-"
        || &s[7..8] != "-"
        || !s
            .bytes()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
    {
        return false;
    }
    let (Ok(y), Ok(m), Ok(d)) = (
        s[..4].parse::<u32>(),
        s[5..7].parse::<u32>(),
        s[8..].parse::<u32>(),
    ) else {
        return false;
    };
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    };
    y >= 1900 && (1..=days).contains(&d)
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
