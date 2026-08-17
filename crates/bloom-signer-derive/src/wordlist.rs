//! The canonical BIP-39 English wordlist (2048 words).

use std::collections::HashMap;
use std::sync::LazyLock;

const ENGLISH: &str = include_str!("../wordlist/english.txt");

pub const WORD_COUNT: usize = 2048;

pub static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let words: Vec<&'static str> = ENGLISH.lines().map(str::trim).collect();
    assert_eq!(words.len(), WORD_COUNT, "BIP-39 wordlist must have 2048 words");
    words
});

static INDEX: LazyLock<HashMap<&'static str, usize>> =
    LazyLock::new(|| WORDS.iter().copied().enumerate().map(|(i, w)| (w, i)).collect());

/// Word at BIP-39 index `index` (0-2047).
pub fn word(index: usize) -> &'static str {
    WORDS[index]
}

/// BIP-39 index of `value`, or `None` when it is not in the wordlist.
pub fn index(value: &str) -> Option<usize> {
    INDEX.get(value).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_canonical() {
        assert_eq!(word(0), "abandon");
        assert_eq!(word(2047), "zoo");
        assert_eq!(index("art").is_some(), true);
        assert_eq!(index("zzz"), None);
        // The frozen mnemonic's words are all present.
        for token in ["abandon", "art"] {
            assert!(index(token).is_some());
        }
    }
}
