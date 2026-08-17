//! BIP-39 entropy and the English mnemonic encoding for every valid
//! word length (12/15/18/21/24), with checksum validation and whitespace
//! normalization.
//!
//! Generated wallets always use 256-bit entropy (24 words); imports accept
//! every valid length (see [`crate::policy`]). Normalization is the
//! standard wallet form: whitespace-splitting and rejoining with single
//! spaces. The English wordlist is pure ASCII, so NFKD normalization is the
//! identity on every valid input; non-empty passphrase profiles (where NFKD
//! of the passphrase matters) are deferred by the plan.
//!
//! Bit layout: the entropy followed by its `word_count / 3` checksum bits
//! (the leading bits of SHA-256 of the entropy) is consumed MSB-first in
//! `word_count` groups of 11 bits.

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::wordlist;

#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("mnemonic word count {found} is not one of 12/15/18/21/24")]
    WrongWordCount { found: usize },
    #[error("word {index} is not in the BIP-39 English wordlist: {word:?}")]
    UnknownWord { index: usize, word: String },
    #[error("mnemonic checksum is invalid")]
    BadChecksum,
    #[error("entropy length {found} bytes is not a valid BIP-39 length")]
    InvalidEntropyLength { found: usize },
}

/// Generate 256 bits of cryptographically random BIP-39 entropy — the
/// generated-wallet length frozen by the v1 policy.
pub fn generate_entropy() -> Zeroizing<[u8; 32]> {
    use rand::RngCore;
    let mut entropy = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(entropy.as_mut());
    entropy
}

/// The checksum-bit count for a word count: `word_count / 3`.
const fn checksum_bits(words: usize) -> usize {
    words / 3
}

/// Encode entropy of any valid length (16/20/24/28/32 bytes) as its
/// English mnemonic.
pub fn mnemonic_from_entropy(entropy: &[u8]) -> Result<Zeroizing<String>, MnemonicError> {
    let words = match entropy.len() {
        16 => 12,
        20 => 15,
        24 => 18,
        28 => 21,
        32 => 24,
        found => {
            return Err(MnemonicError::InvalidEntropyLength { found });
        }
    };
    let entropy_bits = entropy.len() * 8;
    let total_bits = entropy_bits + checksum_bits(words);
    let digest = Sha256::digest(entropy);
    let mut stream = Zeroizing::new(vec![0u8; total_bits.div_ceil(8)]);
    stream[..entropy.len()].copy_from_slice(entropy);
    // Append the leading checksum_bits bits of the digest at the tail of
    // the stream, MSB-first.
    for position in 0..checksum_bits(words) {
        let bit = (digest[position / 8] >> (7 - position % 8)) & 1;
        let target = entropy_bits + position;
        stream[target / 8] |= bit << (7 - target % 8);
    }

    let mut phrase: Vec<&'static str> = Vec::with_capacity(words);
    for group in 0..words {
        let mut index = 0u32;
        for bit_position in 0..11 {
            let target = group * 11 + bit_position;
            index = (index << 1) | u32::from((stream[target / 8] >> (7 - target % 8)) & 1);
        }
        phrase.push(wordlist::word(index as usize));
    }
    Ok(Zeroizing::new(phrase.join(" ")))
}

/// Recover entropy from a mnemonic of any valid length, validating words,
/// length, and checksum. Whitespace is normalized; every word must be an
/// exact wordlist entry.
pub fn entropy_from_mnemonic(
    mnemonic: &str,
) -> Result<Zeroizing<Vec<u8>>, MnemonicError> {
    let tokens: Vec<&str> = mnemonic.split_whitespace().collect();
    let words = tokens.len();
    let entropy_bytes = crate::policy::entropy_bytes_for_words(words)
        .ok_or(MnemonicError::WrongWordCount { found: words })?;
    let entropy_bits = entropy_bytes * 8;
    let total_bits = entropy_bits + checksum_bits(words);

    let mut stream = Zeroizing::new(vec![0u8; total_bits.div_ceil(8)]);
    for (position, token) in tokens.iter().enumerate() {
        let index = wordlist::index(token).ok_or_else(|| MnemonicError::UnknownWord {
            index: position,
            word: (*token).to_owned(),
        })?;
        for bit_position in 0..11 {
            let bit = (index >> (10 - bit_position)) & 1;
            let target = position * 11 + bit_position;
            stream[target / 8] |= (bit as u8) << (7 - target % 8);
        }
    }

    let mut entropy = Zeroizing::new(vec![0u8; entropy_bytes]);
    entropy.copy_from_slice(&stream[..entropy_bytes]);
    let digest = Sha256::digest(entropy.as_slice());
    let checksum_ok = (0..checksum_bits(words)).all(|position| {
        let source = (digest[position / 8] >> (7 - position % 8)) & 1;
        let target = entropy_bits + position;
        source == (stream[target / 8] >> (7 - target % 8)) & 1
    });
    if !checksum_ok {
        return Err(MnemonicError::BadChecksum);
    }
    Ok(entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_valid_length() {
        for words in [12usize, 15, 18, 21, 24] {
            let entropy = Zeroizing::new(vec![0x5Au8; crate::policy::entropy_bytes_for_words(words).unwrap()]);
            let mnemonic = mnemonic_from_entropy(&entropy).unwrap();
            assert_eq!(mnemonic.split_whitespace().count(), words);
            let recovered = entropy_from_mnemonic(&mnemonic).unwrap();
            assert_eq!(*recovered, *entropy);
        }
    }

    #[test]
    fn normalizes_whitespace_before_validation() {
        let entropy = Zeroizing::new(vec![0u8; 32]);
        let mnemonic = mnemonic_from_entropy(&entropy).unwrap();
        let padded = format!("  {}\n", mnemonic.replace(' ', "  "));
        assert!(entropy_from_mnemonic(&padded).is_ok());
    }

    #[test]
    fn rejects_wrong_count_unknown_word_bad_checksum_and_length() {
        assert!(matches!(
            entropy_from_mnemonic("abandon abandon"),
            Err(MnemonicError::WrongWordCount { found: 2 })
        ));

        let entropy = Zeroizing::new(vec![0u8; 16]);
        let mnemonic = mnemonic_from_entropy(&entropy).unwrap();
        let unknown = format!("zzzzz {}", mnemonic.split_whitespace().collect::<Vec<_>>()[..11].join(" "));
        assert!(matches!(
            entropy_from_mnemonic(&unknown),
            Err(MnemonicError::UnknownWord { .. })
        ));

        // Swap a mid word for another valid word: the checksum must fail
        // for at least one of the candidate mutations tested.
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
