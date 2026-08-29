use serde::{Deserialize, Serialize};

use crate::{Digest32, ProtocolError, ProtocolErrorCode, Token};

pub const KEYREF_LOCATOR_MAX_BYTES: usize = 2 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeySpec {
    Secp256k1,
    Ed25519,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoSuite {
    Secp256k1Keccak256Recoverable,
    Secp256k1Sha256Recoverable,
    Ed25519Message,
}

impl CryptoSuite {
    pub const ALL: [Self; 3] = [
        Self::Secp256k1Keccak256Recoverable,
        Self::Secp256k1Sha256Recoverable,
        Self::Ed25519Message,
    ];

    pub const fn key_spec(self) -> KeySpec {
        match self {
            Self::Secp256k1Keccak256Recoverable | Self::Secp256k1Sha256Recoverable => {
                KeySpec::Secp256k1
            }
            Self::Ed25519Message => KeySpec::Ed25519,
        }
    }

    pub const fn input_kind(self) -> CryptoInputKind {
        match self {
            Self::Secp256k1Keccak256Recoverable | Self::Secp256k1Sha256Recoverable => {
                CryptoInputKind::Digest32
            }
            Self::Ed25519Message => CryptoInputKind::Message,
        }
    }

    pub const fn signature_encoding(self) -> SignatureEncoding {
        match self {
            Self::Secp256k1Keccak256Recoverable | Self::Secp256k1Sha256Recoverable => {
                SignatureEncoding::Secp256k1Recoverable65
            }
            Self::Ed25519Message => SignatureEncoding::Ed25519Raw64,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoInputKind {
    Digest32,
    Message,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureEncoding {
    Secp256k1Recoverable65,
    Ed25519Raw64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "scheme", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DerivationRef {
    Bip32Secp256k1 { root_key_id: Token, path: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRef {
    pub backend: Token,
    pub backend_instance: Token,
    pub locator: String,
    pub key_spec: KeySpec,
    pub public_key_fingerprint: Digest32,
    pub derivation: Option<DerivationRef>,
}

impl<'de> Deserialize<'de> for KeyRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unchecked {
            backend: Token,
            backend_instance: Token,
            locator: String,
            key_spec: KeySpec,
            public_key_fingerprint: Digest32,
            derivation: Option<DerivationRef>,
        }

        let unchecked = Unchecked::deserialize(deserializer)?;
        let key_ref = Self {
            backend: unchecked.backend,
            backend_instance: unchecked.backend_instance,
            locator: unchecked.locator,
            key_spec: unchecked.key_spec,
            public_key_fingerprint: unchecked.public_key_fingerprint,
            derivation: unchecked.derivation,
        };
        key_ref.validate().map_err(serde::de::Error::custom)?;
        Ok(key_ref)
    }
}

impl KeyRef {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.locator.is_empty() || self.locator.len() > KEYREF_LOCATOR_MAX_BYTES {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "KeyRef locator must contain 1-2048 UTF-8 bytes",
            ));
        }
        match (&self.key_spec, &self.derivation) {
            (KeySpec::Secp256k1, Some(DerivationRef::Bip32Secp256k1 { path, .. })) => {
                validate_bip32_path(path)
            }
            (_, None) => Ok(()),
            _ => Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "derivation scheme is incompatible with key specification",
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolledKeyBinding {
    pub key_ref: KeyRef,
    pub supported_crypto_suites: Vec<CryptoSuite>,
}

impl EnrolledKeyBinding {
    pub fn authorize(
        &self,
        requested_key: &KeyRef,
        requested_suite: CryptoSuite,
    ) -> Result<(), ProtocolError> {
        self.key_ref.validate()?;
        requested_key.validate()?;
        if requested_key != &self.key_ref {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "requested KeyRef does not exactly match enrollment",
            ));
        }
        if !self.supported_crypto_suites.contains(&requested_suite)
            || requested_suite.key_spec() != requested_key.key_spec
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SuiteNotAllowed,
                "requested CryptoSuite is not pinned for this KeyRef",
            ));
        }
        Ok(())
    }
}

fn validate_bip32_path(path: &str) -> Result<(), ProtocolError> {
    let mut parts = path.split('/');
    if parts.next() != Some("m") {
        return Err(invalid_path());
    }
    let children: Vec<_> = parts.collect();
    if children.is_empty() || children.len() > 10 {
        return Err(invalid_path());
    }
    for child in children {
        let index = child.strip_suffix('\'').unwrap_or(child);
        if index.is_empty()
            || (index.len() > 1 && index.starts_with('0'))
            || index
                .parse::<u32>()
                .ok()
                .filter(|value| *value < (1 << 31))
                .is_none()
        {
            return Err(invalid_path());
        }
    }
    Ok(())
}

fn invalid_path() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::KeyrefMismatch,
        "noncanonical or unsupported BIP32 path",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_key() -> KeyRef {
        KeyRef {
            backend: Token::new("local").unwrap(),
            backend_instance: Token::new("local-default").unwrap(),
            locator: "018f6a40-7b63-7f4d-a64a-0cf3d5f0d8b1".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: Digest32::new("a".repeat(64)).unwrap(),
            derivation: None,
        }
    }

    #[test]
    fn keyref_validates_locator_and_derivation() {
        assert!(base_key().validate().is_ok());
        let mut key = base_key();
        key.derivation = Some(DerivationRef::Bip32Secp256k1 {
            root_key_id: Token::new("root-1").unwrap(),
            path: "m/44'/60'/0'/0/0".into(),
        });
        assert!(key.validate().is_ok());
        key.locator = "x".repeat(KEYREF_LOCATOR_MAX_BYTES + 1);
        assert!(key.validate().is_err());
    }
}
