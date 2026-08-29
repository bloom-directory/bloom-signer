//! Frozen `bip39-multicurve-v1` wallet policy.
//!
//! These rules are the settled product policy for the v1 profile. Changing
//! any of them is a profile-version change, not an edit here.

/// Generated wallets always use 256-bit entropy: 24 English words.
pub const GENERATE_WORDS: usize = 24;

/// Import accepts every valid English BIP-39 mnemonic length: 12, 15, 18,
/// 21, or 24 words.
pub const IMPORT_WORDS: [usize; 5] = [12, 15, 18, 21, 24];

/// Generated wallets use the empty BIP-39 passphrase.
pub const GENERATE_PASSPHRASE: &str = "";

/// Entropy byte length for a valid BIP-39 word count, or `None`.
///
/// 12 words = 128 bits, 15 = 160, 18 = 192, 21 = 224, 24 = 256; the
/// checksum is `word_count / 3` bits.
pub const fn entropy_bytes_for_words(words: usize) -> Option<usize> {
    match words {
        12 => Some(16),
        15 => Some(20),
        18 => Some(24),
        21 => Some(28),
        24 => Some(32),
        _ => None,
    }
}

/// Whether an import passphrase is permitted for the v1 profile.
///
/// v1 rejects non-empty import passphrases: losing or omitting a passphrase
/// silently yields a different wallet while the words still validate, and
/// the two-part recovery UX for that case is deliberately not designed yet.
/// Adding it requires an explicit new profile version.
pub const fn import_passphrase_allowed(passphrase: &str) -> bool {
    passphrase.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_frozen_as_documented() {
        assert_eq!(GENERATE_WORDS, 24);
        assert_eq!(entropy_bytes_for_words(12), Some(16));
        assert_eq!(entropy_bytes_for_words(15), Some(20));
        assert_eq!(entropy_bytes_for_words(18), Some(24));
        assert_eq!(entropy_bytes_for_words(21), Some(28));
        assert_eq!(entropy_bytes_for_words(24), Some(32));
        assert_eq!(entropy_bytes_for_words(13), None);
        assert!(import_passphrase_allowed(""));
        assert!(!import_passphrase_allowed("TREZOR"));
    }
}
