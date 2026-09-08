//! Fuzz the BIP-39 import parser (`bloom-signer-derive/src/mnemonic.rs`).
//!
//! `parse_mnemonic` is the Signer's only untrusted-input boundary that
//! handles recovery material: the ceremony feeds it whatever the operator
//! typed. The invariants under fuzz are:
//!
//! 1. **Totality** — no input panics the parser. libfuzzer catches the
//!    panic, so simply reaching the call is the check.
//! 2. **Round-trip** — every phrase the parser accepts must re-encode to a
//!    canonical mnemonic that parses back to the same entropy. A parser
//!    that accepted a phrase but recovered different entropy would silently
//!    import the wrong wallet.
//! 3. **No echo of typed input** — a rejection must never render any part
//!    of what the operator typed. The ceremony stringifies this error onto
//!    the wire (`bloom-signer/src/ceremony.rs`), so anything the error
//!    carries leaves the Signer. A high-entropy canary token is spliced
//!    into the input and must not appear in `Display` or `Debug`.
//!
//! These complement, rather than replace, the spec-derived differential
//! gates in `tests/differential.rs`: those pin what the parser computes,
//! this pins how it behaves on input it was never meant to receive.
//!
//! Run (requires nightly and `cargo install cargo-fuzz`):
//!
//! ```text
//! cargo +nightly fuzz run mnemonic_parse
//! ```
//!
//! This target is deliberately not wired into CI, which builds on stable.

#![no_main]

use libfuzzer_sys::fuzz_target;

use bloom_signer_derive::{MnemonicError, mnemonic_from_entropy, parse_mnemonic, policy};

/// A token that appears in no error template and in no wordlist, so any
/// occurrence in a rendered error came from the caller's input.
const CANARY: &str = "Zq7canaryX9";

/// Invariants 1 and 2: parsing never panics, and anything accepted
/// round-trips through the canonical encoding to the same entropy.
fn parse_is_total_and_round_trips(text: &str) {
    let Ok(parsed) = parse_mnemonic(text) else {
        return;
    };
    let entropy = parsed.entropy();
    let canonical = mnemonic_from_entropy(&entropy)
        .expect("an accepted phrase must have a valid entropy length");
    let reparsed = parse_mnemonic(&canonical)
        .expect("the canonical encoding of accepted entropy must itself parse");
    assert_eq!(
        *reparsed.entropy(),
        *entropy,
        "accepted phrase did not round-trip through its canonical encoding"
    );
    assert_eq!(
        canonical.split_whitespace().count(),
        text.split_whitespace().count(),
        "canonical encoding changed the word count"
    );
    assert!(
        policy::entropy_bytes_for_words(text.split_whitespace().count()).is_some(),
        "accepted a phrase whose word count the v1 policy rejects"
    );
}

/// Invariant 3: no rejection renders any part of the typed input.
fn rejection_never_echoes_input(text: &str) {
    let Err(error) = parse_mnemonic(text) else {
        return;
    };
    let rendered = error.to_string();
    assert!(
        !rendered.contains(CANARY),
        "Display echoed typed input: {rendered}"
    );
    let debugged = format!("{error:?}");
    assert!(
        !debugged.contains(CANARY),
        "Debug echoed typed input: {debugged}"
    );
    // The `Reference` arm forwards a message from the `bip39` crate. Today
    // none of its messages embed a word, but that is a property of a
    // dependency, so it is asserted here rather than assumed.
    if let MnemonicError::Reference(inner) = &error {
        assert!(
            !inner.contains(CANARY),
            "the reference parser echoed typed input: {inner}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    parse_is_total_and_round_trips(text);
    rejection_never_echoes_input(text);

    // Splice the canary in at an input-chosen word position so the echo
    // check reaches deep rejection paths (unknown word, bad checksum)
    // rather than only the word-count guard.
    let mut words: Vec<&str> = text.split_whitespace().collect();
    if !words.is_empty() {
        let position = usize::from(data[0]) % words.len();
        words[position] = CANARY;
        let spliced = words.join(" ");
        parse_is_total_and_round_trips(&spliced);
        rejection_never_echoes_input(&spliced);
    }

    // Reach the accept path from arbitrary bytes: random input is
    // essentially never a valid mnemonic, so build one from the input as
    // entropy, then let the checks above exercise it and a corruption of
    // it. A corrupted phrase may still checksum correctly, so acceptance
    // is not asserted — only that whichever way it lands is sound.
    for word_count in policy::IMPORT_WORDS {
        let bytes = policy::entropy_bytes_for_words(word_count).expect("policy length");
        if data.len() < bytes {
            continue;
        }
        let Ok(phrase) = mnemonic_from_entropy(&data[..bytes]) else {
            continue;
        };
        parse_is_total_and_round_trips(&phrase);

        let mut tokens: Vec<&str> = phrase.split_whitespace().collect();
        let position = usize::from(data[0]) % tokens.len();
        tokens[position] = CANARY;
        let corrupted = tokens.join(" ");
        parse_is_total_and_round_trips(&corrupted);
        rejection_never_echoes_input(&corrupted);
    }
});
