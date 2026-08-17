//! BIP-39 entropy and the English 24-word mnemonic encoding.
//!
//! The `bip39-multicurve-v1` profile freezes 256-bit entropy (24 words,
//! 8-bit checksum) and the empty passphrase. Normalization is the standard
//! wallet form: whitespace-splitting and rejoining with single spaces. The
//! English wordlist is pure ASCII, so NFKD normalization is the identity on
//! every valid input; non-empty passphrase profiles (where NFKD of the
//! passphrase matters) are deferred by the plan.

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::wordlist;

/// Entropy byte length frozen by the v1 profile (24 words).
pub const ENTROPY_BYTES: usize = 32;
/// Word count frozen by the v1 profile.
pub const WORDS: usize = 24;

#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("mnemonic must contain exactly 24 words, found {found}")]
    WrongWordCount { found: usize },
    #[error("word {index} is not in the BIP-39 English wordlist: {word:?}")]
    UnknownWord { index: usize, word: String },
    #[error("mnemonic checksum is invalid")]
    BadChecksum,
}

/// Generate 256 bits of cryptographically random BIP-39 entropy.
pub fn generate_entropy() -> Zeroizing<[u8; ENTROPY_BYTES]> {
    use rand::RngCore;
    let mut entropy = Zeroizing::new([0u8; ENTROPY_BYTES]);
    rand::rngs::OsRng.fill_bytes(entropy.as_mut());
    entropy
}

/// The 264-bit stream: 256 entropy bits then the 8-bit SHA-256 checksum.
fn checksum_byte(entropy: &[u8; ENTROPY_BYTES]) -> u8 {
    Sha256::digest(entropy)[0]
}

/// Encode 256-bit entropy as the English 24-word mnemonic.
///
/// Bit layout: the 264-bit stream is consumed MSB-first in 24 groups of 11
/// bits; the final 8 bits are the checksum and always land in the last
/// group's low bits.
pub fn mnemonic_from_entropy(entropy: &[u8; ENTROPY_BYTES]) -> Zeroizing<String> {
    let mut bits = Zeroizing::new([0u8; ENTROPY_BYTES + 1]);
    bits[..ENTROPY_BYTES].copy_from_slice(entropy);
    bits[ENTROPY_BYTES] = checksum_byte(entropy);

    let mut words = Vec::with_capacity(WORDS);
    for group in 0..WORDS {
        let start = group * 11;
        let byte = start / 8;
        let offset = start % 8;
        // Three-byte window; the group's 11 bits sit at window bits
        // [offset, offset+11), so shift right by 24 - 11 - offset.
        let window = (u32::from(bits[byte]) << 16)
            | (u32::from(bits.get(byte + 1).copied().unwrap_or(0)) << 8)
            | u32::from(bits.get(byte + 2).copied().unwrap_or(0));
        let index = ((window >> (13 - offset)) & 0x7FF) as usize;
        words.push(wordlist::word(index));
    }
    Zeroizing::new(words.join(" "))
}

/// Recover 256-bit entropy from a mnemonic, validating words, length, and
/// checksum. Whitespace is normalized; every word must be an exact
/// wordlist entry.
pub fn entropy_from_mnemonic(
    mnemonic: &str,
) -> Result<Zeroizing<[u8; ENTROPY_BYTES]>, MnemonicError> {
    let tokens: Vec<&str> = mnemonic.split_whitespace().collect();
    if tokens.len() != WORDS {
        return Err(MnemonicError::WrongWordCount {
            found: tokens.len(),
        });
    }
    let mut bits = Zeroizing::new([0u8; ENTROPY_BYTES + 1]);
    for (position, token) in tokens.iter().enumerate() {
        let index = wordlist::index(token).ok_or_else(|| MnemonicError::UnknownWord {
            index: position,
            word: (*token).to_owned(),
        })?;
        let start = position * 11;
        let byte = start / 8;
        let offset = start % 8;
        // Place the 11 bits at window bits [offset, offset+11) of the
        // four-byte window starting at `byte`: left-align in 32 bits, then
        // shift down past the 11 bits and the offset.
        let window = (index as u32) << (21 - offset);
        for (delta, source) in window.to_be_bytes().iter().enumerate() {
            let target = byte + delta;
            if target < bits.len() {
                bits[target] |= source;
            }
        }
    }
    let mut entropy = Zeroizing::new([0u8; ENTROPY_BYTES]);
    entropy.copy_from_slice(&bits[..ENTROPY_BYTES]);
    if checksum_byte(&entropy) != bits[ENTROPY_BYTES] {
        return Err(MnemonicError::BadChecksum);
    }
    Ok(entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FROZEN_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon art";

    #[test]
    fn round_trips_frozen_entropy_and_mnemonic() {
        let entropy = Zeroizing::new([0u8; ENTROPY_BYTES]);
        let mnemonic = mnemonic_from_entropy(&entropy);
        assert_eq!(*mnemonic, FROZEN_MNEMONIC);
        let recovered = entropy_from_mnemonic(&mnemonic).unwrap();
        assert_eq!(*recovered, *entropy);
    }

    #[test]
    fn normalizes_whitespace_before_validation() {
        let padded = format!("  {}\n", FROZEN_MNEMONIC.replace(' ', "  "));
        assert!(entropy_from_mnemonic(&padded).is_ok());
    }

    #[test]
    fn rejects_wrong_count_unknown_word_and_bad_checksum() {
        let twenty_three: String = FROZEN_MNEMONIC
            .split_whitespace()
            .take(23)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(matches!(
            entropy_from_mnemonic(&twenty_three),
            Err(MnemonicError::WrongWordCount { found: 23 })
        ));

        let unknown = FROZEN_MNEMONIC.replace("art", "zzzzz");
        assert!(matches!(
            entropy_from_mnemonic(&unknown),
            Err(MnemonicError::UnknownWord { index: 23, .. })
        ));

        // Swap the final word for another valid word: checksum must fail.
        let corrupted = FROZEN_MNEMONIC.replace("art", "zebra");
        assert!(matches!(
            entropy_from_mnemonic(&corrupted),
            Err(MnemonicError::BadChecksum)
        ));
    }

    #[test]
    fn generated_entropy_round_trips() {
        for _ in 0..8 {
            let entropy = generate_entropy();
            let mnemonic = mnemonic_from_entropy(&entropy);
            let recovered = entropy_from_mnemonic(&mnemonic).unwrap();
            assert_eq!(*recovered, *entropy);
        }
    }
}
