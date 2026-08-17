//! Wallet-seed and derivation-profile contracts.
//!
//! A wallet seed root is never a signable key and has no public key. Only
//! registered derived accounts can satisfy a signing request. These types
//! carry public wire metadata only; seed entropy, private keys, passkey PRF
//! output, and WKEK material are deliberately unrepresentable here.

use serde::{Deserialize, Serialize};

use crate::{
    Base64UrlBytes, CryptoSuite, Digest32, KeyRef, KeySpec, ProtocolError, ProtocolErrorCode, Token,
};

/// Root seed profile. `bip39-multicurve-v1` uses 256-bit BIP-39 entropy, the
/// English 24-word encoding, and the empty BIP-39 passphrase for the
/// interoperable default profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WalletSeedProfile {
    Bip39MulticurveV1,
}

/// Versioned derivation profile naming a curve, a derivation scheme, and a
/// canonical path template. Profiles never change silently: a new path, curve,
/// or scheme becomes a new profile version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DerivationProfile {
    Bip44EvmSecp256k1V1,
    Bip44SolanaSlip10Ed25519V1,
}

impl DerivationProfile {
    pub const ALL: [Self; 2] = [Self::Bip44EvmSecp256k1V1, Self::Bip44SolanaSlip10Ed25519V1];

    /// Canonical path template. `<account>` is a hardened index and `<index>`
    /// a non-hardened index; concrete allocated paths substitute these.
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::Bip44EvmSecp256k1V1 => "m/44'/60'/<account>'/0/<index>",
            Self::Bip44SolanaSlip10Ed25519V1 => "m/44'/501'/<account>'/0'",
        }
    }

    pub const fn coin_type(self) -> u32 {
        match self {
            Self::Bip44EvmSecp256k1V1 => 60,
            Self::Bip44SolanaSlip10Ed25519V1 => 501,
        }
    }

    pub const fn key_spec(self) -> KeySpec {
        match self {
            Self::Bip44EvmSecp256k1V1 => KeySpec::Secp256k1,
            Self::Bip44SolanaSlip10Ed25519V1 => KeySpec::Ed25519,
        }
    }
}

/// Explicit encoding of a descriptor's `canonical_public_key` bytes.
///
/// Bloom canonicalizes public keys as X.509 SubjectPublicKeyInfo (SPKI) DER:
/// secp256k1 as the uncompressed `0x04 || x || y` point under the
/// `id-ecPublicKey`/`secp256k1` algorithm identifiers, and Ed25519 as the raw
/// 32-byte key under the RFC 8410 `id-Ed25519` identifier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicKeyEncoding {
    Secp256k1SpkiDer,
    Ed25519SpkiDer,
}

impl PublicKeyEncoding {
    pub const fn key_spec(self) -> KeySpec {
        match self {
            Self::Secp256k1SpkiDer => KeySpec::Secp256k1,
            Self::Ed25519SpkiDer => KeySpec::Ed25519,
        }
    }
}

/// Signer-owned identity of a wallet seed root.
///
/// A `WalletSeedRef` is not a signable `KeyRef` and carries no public key.
/// Neither Broker nor Machine may select it as a signing key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletSeedRef {
    pub wallet_id: Token,
    pub profile: WalletSeedProfile,
}

const PUBLIC_KEY_MAX_BYTES: usize = 128;

/// A registered derived child account.
///
/// Signer verifies that the requested child, path, suite, public key, and
/// wallet-seed relationship all refer to one registered registry entry. The
/// descriptor binds the child `KeyRef`, the non-signable seed root, the
/// derivation profile, the allocated path, and the canonical public key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedAccountDescriptor {
    pub key_ref: KeyRef,
    pub wallet_seed_ref: WalletSeedRef,
    pub derivation_profile: DerivationProfile,
    pub path: String,
    pub canonical_public_key: Base64UrlBytes,
    pub public_key_encoding: PublicKeyEncoding,
    pub public_key_fingerprint: Digest32,
    pub supported_crypto_suites: Vec<CryptoSuite>,
}

impl<'de> Deserialize<'de> for DerivedAccountDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unchecked {
            key_ref: KeyRef,
            wallet_seed_ref: WalletSeedRef,
            derivation_profile: DerivationProfile,
            path: String,
            canonical_public_key: Base64UrlBytes,
            public_key_encoding: PublicKeyEncoding,
            public_key_fingerprint: Digest32,
            supported_crypto_suites: Vec<CryptoSuite>,
        }

        let unchecked = Unchecked::deserialize(deserializer)?;
        let descriptor = Self {
            key_ref: unchecked.key_ref,
            wallet_seed_ref: unchecked.wallet_seed_ref,
            derivation_profile: unchecked.derivation_profile,
            path: unchecked.path,
            canonical_public_key: unchecked.canonical_public_key,
            public_key_encoding: unchecked.public_key_encoding,
            public_key_fingerprint: unchecked.public_key_fingerprint,
            supported_crypto_suites: unchecked.supported_crypto_suites,
        };
        descriptor.validate().map_err(serde::de::Error::custom)?;
        Ok(descriptor)
    }
}

impl DerivedAccountDescriptor {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.key_ref.validate()?;
        if self.key_ref.key_spec != self.derivation_profile.key_spec() {
            return Err(invalid(
                "derivation profile curve does not match the child KeyRef",
            ));
        }
        if self.public_key_encoding.key_spec() != self.key_ref.key_spec {
            return Err(invalid(
                "public-key encoding does not match the child KeyRef",
            ));
        }
        validate_allocated_path(self.derivation_profile, &self.path)?;
        let key_len = self.canonical_public_key.decode().len();
        if key_len == 0 || key_len > PUBLIC_KEY_MAX_BYTES {
            return Err(invalid("canonical public key must be 1-128 bytes"));
        }
        let unique_suites: std::collections::HashSet<_> =
            self.supported_crypto_suites.iter().copied().collect();
        if self.supported_crypto_suites.is_empty()
            || self.supported_crypto_suites.len() > CryptoSuite::ALL.len()
            || unique_suites.len() != self.supported_crypto_suites.len()
            || self
                .supported_crypto_suites
                .iter()
                .any(|suite| suite.key_spec() != self.key_ref.key_spec)
        {
            return Err(invalid(
                "supported crypto suites must be unique and match the child KeyRef",
            ));
        }
        Ok(())
    }
}

/// Validate an allocated concrete path against a derivation profile's
/// canonical template.
pub fn validate_allocated_path(
    profile: DerivationProfile,
    path: &str,
) -> Result<(), ProtocolError> {
    let mut parts = path.split('/');
    if parts.next() != Some("m") {
        return Err(invalid_path());
    }
    let children: Vec<&str> = parts.collect();
    match profile {
        DerivationProfile::Bip44EvmSecp256k1V1 => {
            if children.len() != 5 {
                return Err(invalid_path());
            }
            require_hardened(children[0], Some(44))?;
            require_hardened(children[1], Some(60))?;
            require_hardened(children[2], None)?;
            require_plain(children[3], Some(0))?;
            require_plain(children[4], None)?;
        }
        DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
            if children.len() != 4 {
                return Err(invalid_path());
            }
            require_hardened(children[0], Some(44))?;
            require_hardened(children[1], Some(501))?;
            require_hardened(children[2], None)?;
            require_hardened(children[3], Some(0))?;
        }
    }
    Ok(())
}

fn parse_child(segment: &str, hardened: bool) -> Result<u32, ProtocolError> {
    let (number, marked) = match segment.strip_suffix('\'') {
        Some(number) => (number, true),
        None => (segment, false),
    };
    if marked != hardened || number.is_empty() || (number.len() > 1 && number.starts_with('0')) {
        return Err(invalid_path());
    }
    let value = number.parse::<u32>().map_err(|_| invalid_path())?;
    if value >= (1 << 31) {
        return Err(invalid_path());
    }
    Ok(value)
}

fn require_hardened(segment: &str, expected: Option<u32>) -> Result<(), ProtocolError> {
    let value = parse_child(segment, true)?;
    if expected.is_some_and(|expected| value != expected) {
        return Err(invalid_path());
    }
    Ok(())
}

fn require_plain(segment: &str, expected: Option<u32>) -> Result<(), ProtocolError> {
    let value = parse_child(segment, false)?;
    if expected.is_some_and(|expected| value != expected) {
        return Err(invalid_path());
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::KeyrefMismatch, message)
}

fn invalid_path() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::KeyrefMismatch,
        "path does not match the derivation profile canonical template",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DerivationRef;

    fn token(value: &str) -> Token {
        Token::new(value).unwrap()
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn child_key_ref(key_spec: KeySpec) -> KeyRef {
        KeyRef {
            backend: token("local"),
            backend_instance: token("local-default"),
            locator: "wallet/primary/child-0".into(),
            key_spec,
            public_key_fingerprint: digest(7),
            derivation: match key_spec {
                KeySpec::Secp256k1 => Some(DerivationRef::Bip32Secp256k1 {
                    root_key_id: token("primary-root"),
                    path: "m/44'/60'/0'/0/0".into(),
                }),
                KeySpec::Ed25519 => None,
            },
        }
    }

    fn descriptor(
        profile: DerivationProfile,
        key_spec: KeySpec,
        path: &str,
    ) -> DerivedAccountDescriptor {
        let (encoding, public_key) = match key_spec {
            KeySpec::Secp256k1 => (PublicKeyEncoding::Secp256k1SpkiDer, vec![2u8; 88]),
            KeySpec::Ed25519 => (PublicKeyEncoding::Ed25519SpkiDer, vec![3u8; 44]),
        };
        DerivedAccountDescriptor {
            key_ref: child_key_ref(key_spec),
            wallet_seed_ref: WalletSeedRef {
                wallet_id: token("primary"),
                profile: WalletSeedProfile::Bip39MulticurveV1,
            },
            derivation_profile: profile,
            path: path.into(),
            canonical_public_key: Base64UrlBytes::from_bytes(&public_key),
            public_key_encoding: encoding,
            public_key_fingerprint: digest(9),
            supported_crypto_suites: match key_spec {
                KeySpec::Secp256k1 => vec![
                    CryptoSuite::Secp256k1Keccak256Recoverable,
                    CryptoSuite::Secp256k1Sha256Recoverable,
                ],
                KeySpec::Ed25519 => vec![CryptoSuite::Ed25519Message],
            },
        }
    }

    #[test]
    fn canonical_profiles_validate() {
        assert!(
            descriptor(
                DerivationProfile::Bip44EvmSecp256k1V1,
                KeySpec::Secp256k1,
                "m/44'/60'/0'/0/0",
            )
            .validate()
            .is_ok()
        );
        assert!(
            descriptor(
                DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                KeySpec::Ed25519,
                "m/44'/501'/0'/0'",
            )
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn rejects_profile_curve_mismatch() {
        let descriptor = descriptor(
            DerivationProfile::Bip44SolanaSlip10Ed25519V1,
            KeySpec::Secp256k1,
            "m/44'/501'/0'/0'",
        );
        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn rejects_wrong_encoding() {
        let mut descriptor = descriptor(
            DerivationProfile::Bip44EvmSecp256k1V1,
            KeySpec::Secp256k1,
            "m/44'/60'/0'/0/0",
        );
        descriptor.public_key_encoding = PublicKeyEncoding::Ed25519SpkiDer;
        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn rejects_paths_that_stray_from_the_template() {
        // Solana change step must be hardened.
        assert!(
            validate_allocated_path(
                DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                "m/44'/501'/0'/0",
            )
            .is_err()
        );
        // EVM account step must be hardened.
        assert!(
            validate_allocated_path(DerivationProfile::Bip44EvmSecp256k1V1, "m/44'/60'/0/0/0",)
                .is_err()
        );
        // Wrong coin type.
        assert!(
            validate_allocated_path(
                DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                "m/44'/501'/0'/1'",
            )
            .is_err()
        );
        // Wrong element count.
        assert!(
            validate_allocated_path(
                DerivationProfile::Bip44EvmSecp256k1V1,
                "m/44'/60'/0'/0'/0'/0"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_empty_suites() {
        let mut descriptor = descriptor(
            DerivationProfile::Bip44EvmSecp256k1V1,
            KeySpec::Secp256k1,
            "m/44'/60'/0'/0/0",
        );
        descriptor.supported_crypto_suites.clear();
        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn descriptor_serde_round_trips_and_validates() {
        let descriptor = descriptor(
            DerivationProfile::Bip44SolanaSlip10Ed25519V1,
            KeySpec::Ed25519,
            "m/44'/501'/0'/0'",
        );
        let encoded = serde_json::to_string(&descriptor).unwrap();
        let decoded: DerivedAccountDescriptor = serde_json::from_str(&encoded).unwrap();
        assert_eq!(descriptor, decoded);
    }
}
