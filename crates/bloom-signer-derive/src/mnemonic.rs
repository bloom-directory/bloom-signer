//! BIP-39 entropy and the English mnemonic for every valid word length
//! (12/15/18/21/24).
//!
//! The production mnemonic/checksum path uses the established [`bip39`]
//! crate; Bloom owns policy enforcement, word-count rules, and the
//! zeroizing wrappers around every secret. The crate applies BIP-39 NFKD
//! normalization exactly — `Mnemonic::parse` normalizes the phrase and
//! `to_seed` normalizes the passphrase — and the v1 policy rejects
//! non-empty passphrases before derivation, so the frozen empty-passphrase
//! profile needs no normalization of its own.
//!
//! Generated wallets always use 256-bit entropy (24 words); imports accept
//! every valid length (see [`crate::policy`]). Passphrase policy is
//! enforced by the wallet layer, not here.

use thiserror::Error;
use zeroize::Zeroizing;

use crate::policy;

#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("mnemonic word count {found} is not one of 12/15/18/21/24")]
    WrongWordCount { found: usize },
    #[error("word {index} is not in the BIP-39 English wordlist: {word:?}")]
    UnknownWord { index: usize, word: String },
    #[error("mnemonic checksum is invalid")]
    BadChecksum,
    #[error("mnemonic is not already NFKD-normalized")]
    Unnormalized,
    #[error("entropy length {found} bytes is not a valid BIP-39 length")]
    InvalidEntropyLength { found: usize },
    #[error("the bip39 crate rejected the input: {0}")]
    Reference(String),
}

/// A parsed English mnemonic holding its entropy. Dropping zeroizes the
/// entropy; the phrase itself lives in the caller's Zeroizing string.
pub struct ParsedMnemonic {
    mnemonic: bip39::Mnemonic,
}

impl ParsedMnemonic {
    /// The entropy bytes.
    pub fn entropy(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.mnemonic.to_entropy())
    }

    /// The normalized phrase.
    pub fn phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(self.mnemonic.to_string())
    }

    /// The 64-byte BIP-39 seed. The passphrase must already be
    /// policy-approved (empty for v1); NFKD normalization of both phrase
    /// and passphrase is applied by the reference implementation.
    pub fn seed(&self, passphrase: &str) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(self.mnemonic.to_seed(passphrase))
    }
}

/// Generate 256 bits of cryptographically random BIP-39 entropy — the
/// generated-wallet length frozen by the v1 policy.
pub fn generate_entropy() -> Zeroizing<[u8; 32]> {
    use rand::RngCore;
    let mut entropy = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(entropy.as_mut());
    entropy
}

/// Encode entropy of any valid length (16/20/24/28/32 bytes) as its English
/// mnemonic, using the reference implementation.
pub fn mnemonic_from_entropy(entropy: &[u8]) -> Result<Zeroizing<String>, MnemonicError> {
    match entropy.len() {
        16 | 20 | 24 | 28 | 32 => {}
        found => return Err(MnemonicError::InvalidEntropyLength { found }),
    }
    let mnemonic = bip39::Mnemonic::from_entropy(entropy)
        .map_err(|error| MnemonicError::Reference(error.to_string()))?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

/// Parse an English mnemonic of any valid length: NFKD-normalize, validate
/// every word against the wordlist, and verify the checksum — all through
/// the reference implementation — then re-check the word count against the
/// v1 import policy.
pub fn parse_mnemonic(mnemonic: &str) -> Result<ParsedMnemonic, MnemonicError> {
    // Word count is checked first so callers get the policy error, not the
    // reference error, for a wrong length.
    let words = mnemonic.split_whitespace().count();
    if policy::entropy_bytes_for_words(words).is_none() {
        return Err(MnemonicError::WrongWordCount { found: words });
    }
    // Strict NFKD: the reference parser normalizes before validating, so an
    // unnormalized phrase (for example a compatibility character that folds
    // to an ASCII word) would otherwise be silently accepted. Reject it.
    use unicode_normalization::UnicodeNormalization as _;
    if mnemonic.nfkd().collect::<String>() != mnemonic {
        return Err(MnemonicError::Unnormalized);
    }
    let parsed = match bip39::Mnemonic::parse(mnemonic) {
        Ok(parsed) => parsed,
        Err(bip39::Error::UnknownWord(_)) => {
            // Recover the offending index for the caller.
            for (index, word) in mnemonic.split_whitespace().enumerate() {
                if bip39::Language::English.find_word(word).is_none() {
                    return Err(MnemonicError::UnknownWord {
                        index,
                        word: word.to_owned(),
                    });
                }
            }
            return Err(MnemonicError::UnknownWord {
                index: 0,
                word: String::new(),
            });
        }
        Err(bip39::Error::InvalidChecksum) => return Err(MnemonicError::BadChecksum),
        Err(other) => return Err(MnemonicError::Reference(other.to_string())),
    };
    Ok(ParsedMnemonic { mnemonic: parsed })
}

/// Recover entropy from a mnemonic; see [`parse_mnemonic`].
pub fn entropy_from_mnemonic(mnemonic: &str) -> Result<Zeroizing<Vec<u8>>, MnemonicError> {
    Ok(parse_mnemonic(mnemonic)?.entropy())
}

/// Derive the 64-byte BIP-39 seed. `passphrase` must be policy-approved
/// (empty for v1; see [`policy::import_passphrase_allowed`]); the reference
/// implementation NFKD-normalizes both phrase and passphrase.
pub fn seed_from_mnemonic(
    mnemonic: &str,
    passphrase: &str,
) -> Result<Zeroizing<[u8; 64]>, MnemonicError> {
    Ok(parse_mnemonic(mnemonic)?.seed(passphrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_valid_length() {
        for words in [12usize, 15, 18, 21, 24] {
            let entropy = Zeroizing::new(vec![
                0x5Au8;
                policy::entropy_bytes_for_words(words).unwrap()
            ]);
            let mnemonic = mnemonic_from_entropy(entropy.as_slice()).unwrap();
            assert_eq!(mnemonic.split_whitespace().count(), words);
            let recovered = entropy_from_mnemonic(&mnemonic).unwrap();
            assert_eq!(*recovered, *entropy);
        }
    }

    #[test]
    fn normalizes_whitespace_before_validation() {
        let entropy = Zeroizing::new(vec![0u8; 32]);
        let mnemonic = mnemonic_from_entropy(entropy.as_slice()).unwrap();
        let padded = format!("  {}\n", mnemonic.replace(' ', "  "));
        assert!(entropy_from_mnemonic(&padded).is_ok());
    }

    #[test]
    fn rejects_nfkd_unnormalized_mnemonic() {
        let entropy = Zeroizing::new(vec![0u8; 16]);
        let mnemonic = mnemonic_from_entropy(entropy.as_slice()).unwrap();
        // A fullwidth compatibility 'a' NFKD-normalizes to ASCII 'a'; the
        // phrase is otherwise a valid mnemonic, so only the strict NFKD check
        // can reject it.
        let unnormalized = mnemonic.replace('a', "\u{ff41}");
        assert!(matches!(
            parse_mnemonic(&unnormalized),
            Err(MnemonicError::Unnormalized)
        ));
        assert!(parse_mnemonic(&mnemonic).is_ok());
    }

    #[test]
    fn rejects_wrong_count_unknown_word_bad_checksum_and_length() {
        assert!(matches!(
            entropy_from_mnemonic("abandon abandon"),
            Err(MnemonicError::WrongWordCount { found: 2 })
        ));

        let entropy = Zeroizing::new(vec![0u8; 16]);
        let mnemonic = mnemonic_from_entropy(entropy.as_slice()).unwrap();
        let unknown = format!(
            "zzzzz {}",
            mnemonic.split_whitespace().collect::<Vec<_>>()[..11].join(" ")
        );
        assert!(matches!(
            entropy_from_mnemonic(&unknown),
            Err(MnemonicError::UnknownWord { index: 0, .. })
        ));

        let mut corrupted: Vec<&str> = mnemonic.split_whitespace().collect();
        corrupted[0] = "zoo";
        let joined = corrupted.join(" ");
        assert!(matches!(
            entropy_from_mnemonic(&joined),
            Err(MnemonicError::BadChecksum)
        ));

        assert!(matches!(
            mnemonic_from_entropy(&[0u8; 17]),
            Err(MnemonicError::InvalidEntropyLength { found: 17 })
        ));
    }

    #[test]
    fn generated_entropy_round_trips() {
        for _ in 0..8 {
            let entropy = generate_entropy();
            let mnemonic = mnemonic_from_entropy(entropy.as_slice()).unwrap();
            let recovered = entropy_from_mnemonic(&mnemonic).unwrap();
            assert_eq!(*recovered, entropy.to_vec());
        }
    }
}
