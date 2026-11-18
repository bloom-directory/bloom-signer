//! Agent-visible traveler handles and exact private release terms.
use crate::{Digest32, ProtocolError, ProtocolErrorCode, Token};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TravelerField {
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
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TravelerPublic {
    pub traveler_id: Token,
    pub label: String,
    pub fields: Vec<TravelerField>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TravelerFillScope {
    pub origin: String,
    pub frame_origins: Vec<String>,
    /// Fresh private-browser document/mapping binding, not an agent URL.
    pub document_binding: Digest32,
    pub fields: Vec<TravelerField>,
}

impl TravelerFillScope {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let origin = |s: &str| {
            s.len() <= 256
                && url::Url::parse(s).is_ok_and(|u| {
                    u.scheme() == "https"
                        && u.host_str().is_some()
                        && u.username().is_empty()
                        && u.password().is_none()
                        && u.origin().ascii_serialization() == s
                })
        };
        let fields: std::collections::BTreeSet<_> = self.fields.iter().collect();
        let frames: std::collections::BTreeSet<_> = self.frame_origins.iter().collect();
        if !origin(&self.origin)
            || self.frame_origins.is_empty()
            || self.frame_origins.len() > 8
            || frames.len() != self.frame_origins.len()
            || self.frame_origins.iter().any(|s| !origin(s))
            || self.fields.is_empty()
            || self.fields.len() > 11
            || fields.len() != self.fields.len()
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "invalid traveler fill scope",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_rejects_duplicate_fields_and_non_origin_urls() {
        let base = TravelerFillScope {
            origin: "https://airline.example".into(),
            frame_origins: vec!["https://airline.example".into()],
            document_binding: Digest32::from_bytes([1; 32]),
            fields: vec![TravelerField::GivenName],
        };
        assert!(base.validate().is_ok());
        for origin in [
            "http://airline.example",
            "https://airline.example/path",
            "https://user@airline.example",
            "https://airline.example?token=private",
        ] {
            let mut s = base.clone();
            s.origin = origin.into();
            assert!(s.validate().is_err());
        }
        let mut s = base.clone();
        s.fields.push(TravelerField::GivenName);
        assert!(s.validate().is_err());
        let mut s = base.clone();
        s.frame_origins.clear();
        assert!(s.validate().is_err());
        let mut s = base;
        s.frame_origins.push("https://airline.example".into());
        assert!(s.validate().is_err());
    }
}
