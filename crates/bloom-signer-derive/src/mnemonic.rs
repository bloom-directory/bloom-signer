//! BIP-39 entropy and the English mnemonic for every valid word length
//! (12/15/18/21/24).
//!
//! The production mnemonic/checksum path uses the established [`bip39`]
//! crate; Bloom owns policy enforcement, word-count rules, and the
//! zeroizing wrappers around every secret. The crate applies BIP-39 NFKD
//! normalization exactly. The v1 product surface has no passphrase input;
//! seed derivation always uses the BIP-39 default empty salt suffix.
//!
//! Generated wallets always use 256-bit entropy (24 words); imports accept
//! every valid length (see [`crate::policy`]).

use thiserror::Error;
use zeroize::Zeroizing;

use crate::policy;

#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("mnemonic word count {found} is not one of 12/15/18/21/24")]
    WrongWordCount { found: usize },
    /// The offending token is deliberately not carried. It is a fragment of
    /// what the operator typed while entering recovery material, and this
    /// error is stringified onto the wire by the import ceremony. The
    /// position is enough to correct a typo.
    #[error("word {index} is not in the BIP-39 English wordlist")]
    UnknownWord { index: usize },
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
///
/// The zeroize-on-drop guarantee comes from the [`bip39`] crate's optional
/// `zeroize` feature, which this crate enables. Without it `bip39::Mnemonic`
/// is a plain `[u16; 24]` of word indices — the entropy in another encoding
/// — left in freed memory. The `const` assertion below makes that a
/// compile-time requirement rather than a comment.
pub struct ParsedMnemonic {
    mnemonic: bip39::Mnemonic,
}

/// Compile-time proof of the guarantee documented on [`ParsedMnemonic`]:
/// dropping the reference mnemonic wipes the word indices. Removing
/// `features = ["zeroize"]` from the `bip39` dependency fails the build
/// here instead of silently downgrading every import to a memory leak of
/// recovery material.
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<bip39::Mnemonic>();
};

impl ParsedMnemonic {
    /// The entropy bytes.
    pub fn entropy(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.mnemonic.to_entropy())
    }

    /// The normalized phrase.
    pub fn phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(self.mnemonic.to_string())
    }

    /// The 64-byte BIP-39 seed for the frozen v1 profile.
    ///
    /// There is intentionally no passphrase parameter in the product API.
    pub fn seed(&self) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(self.mnemonic.to_seed(""))
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
        // The reference reports the position within `split_whitespace()` —
        // the same splitting used for the word-count check above — so it is
        // taken directly rather than re-derived by a second scan.
        Err(bip39::Error::UnknownWord(index)) => {
            return Err(MnemonicError::UnknownWord { index });
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

/// Derive the 64-byte BIP-39 seed for the frozen v1 profile.
pub fn seed_from_mnemonic(mnemonic: &str) -> Result<Zeroizing<[u8; 64]>, MnemonicError> {
    Ok(parse_mnemonic(mnemonic)?.seed())
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
            Err(MnemonicError::UnknownWord { index: 0 })
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
    fn unknown_word_reports_its_position_without_echoing_the_token() {
        let entropy = Zeroizing::new(vec![0u8; 32]);
        let mnemonic = mnemonic_from_entropy(entropy.as_slice()).unwrap();
        let mut words: Vec<&str> = mnemonic.split_whitespace().collect();
        // A token outside the wordlist at a position other than the first.
        // The position pins the reference index to the phrase position,
        // which is what `parse_mnemonic` now relies on instead of a second
        // scan of its own.
        const CANARY: &str = "zzzcanaryzzz";
        words[5] = CANARY;
        let corrupted = words.join(" ");

        // `ParsedMnemonic` deliberately implements no `Debug` (it holds the
        // entropy), so the error is taken by match rather than `unwrap_err`.
        let error = match parse_mnemonic(&corrupted) {
            Err(error) => error,
            Ok(_) => panic!("an out-of-wordlist token must not parse"),
        };
        assert!(
            matches!(error, MnemonicError::UnknownWord { index: 5 }),
            "expected the offending position, got {error:?}"
        );
        // The import ceremony stringifies this error onto the wire, so the
        // operator's typed token must not survive into it.
        let rendered = error.to_string();
        assert!(
            !rendered.contains(CANARY),
            "Display rendered the typed token: {rendered}"
        );
        let debugged = format!("{error:?}");
        assert!(
            !debugged.contains(CANARY),
            "Debug rendered the typed token: {debugged}"
        );
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
