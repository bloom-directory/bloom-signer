//! Differential gates against independent implementations.
//!
//! The production mnemonic/checksum/seed path delegates to the established
//! `bip39` crate. To keep a genuinely independent check, this file
//! re-implements the BIP-39 MSB-first bit codec and the PBKDF2-HMAC-SHA512
//! seed derivation from scratch (from the specification, not the crate) and
//! requires agreement on every randomized case, alongside the `bip32`/`k256`
//! differentials for derivation. The hand-written scalar limb arithmetic
//! previously shipped a real ordering bug that official vectors alone did
//! not catch; these gates are the standing defense.

use bloom_signer_derive::{
    MnemonicError,
    bip32::{hardened_child, master_secp256k1, non_hardened_child},
    mnemonic_from_entropy, parse_mnemonic, seed_from_mnemonic,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use zeroize::Zeroizing;

fn deterministic_rng() -> StdRng {
    StdRng::seed_from_u64(0xB100_39C0_DE00_0002)
}

// ---------------------------------------------------------------------------
// Independent reference implementations (specification-derived).
// ---------------------------------------------------------------------------

mod reference {
    use sha2::Digest as _;

    pub fn checksum_byte_count(words: usize) -> usize {
        words / 3
    }

    /// MSB-first 11-bit codec: entropy || checksum -> word indices.
    pub fn indices_from_entropy(entropy: &[u8], words: usize) -> Vec<usize> {
        let total_bits = entropy.len() * 8 + checksum_byte_count(words);
        let digest = sha2::Sha256::digest(entropy);
        let mut stream = vec![0u8; total_bits.div_ceil(8)];
        stream[..entropy.len()].copy_from_slice(entropy);
        for position in 0..checksum_byte_count(words) {
            let bit = (digest[position / 8] >> (7 - position % 8)) & 1;
            let target = entropy.len() * 8 + position;
            stream[target / 8] |= bit << (7 - target % 8);
        }
        (0..words)
            .map(|group| {
                let mut index = 0usize;
                for bit in 0..11 {
                    let target = group * 11 + bit;
                    index =
                        (index << 1) | usize::from((stream[target / 8] >> (7 - target % 8)) & 1);
                }
                index
            })
            .collect()
    }

    /// MSB-first decode: word indices -> entropy, plus checksum validation.
    pub fn entropy_from_indices(indices: &[usize], words: usize) -> Result<Vec<u8>, &'static str> {
        let entropy_bytes = match words {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => return Err("bad word count"),
        };
        let total_bits = entropy_bytes * 8 + checksum_byte_count(words);
        let mut stream = vec![0u8; total_bits.div_ceil(8)];
        for (position, index) in indices.iter().enumerate() {
            for bit in 0..11 {
                let value = (index >> (10 - bit)) & 1;
                let target = position * 11 + bit;
                stream[target / 8] |= (value as u8) << (7 - target % 8);
            }
        }
        let entropy = stream[..entropy_bytes].to_vec();
        let digest = sha2::Sha256::digest(&entropy);
        let ok = (0..checksum_byte_count(words)).all(|position| {
            let source = (digest[position / 8] >> (7 - position % 8)) & 1;
            let target = entropy_bytes * 8 + position;
            source == (stream[target / 8] >> (7 - target % 8)) & 1
        });
        if !ok {
            return Err("checksum");
        }
        Ok(entropy)
    }

    /// Single-block PBKDF2-HMAC-SHA512 (the seed is one 64-byte block).
    pub fn pbkdf2_seed(phrase: &str, passphrase: &str) -> [u8; 64] {
        let salt = format!("mnemonic{passphrase}");
        let mut previous = {
            let mut mac = HmacSha512::new_from_slice(phrase.as_bytes()).unwrap();
            mac.update(salt.as_bytes());
            mac.update(&1u32.to_be_bytes());
            mac.finalize().into_bytes()
        };
        let mut accumulated = previous;
        for _ in 1..2048 {
            let mut mac = HmacSha512::new_from_slice(phrase.as_bytes()).unwrap();
            mac.update(&previous);
            previous = mac.finalize().into_bytes();
            for (slot, byte) in accumulated.iter_mut().zip(previous.iter()) {
                *slot ^= byte;
            }
        }
        accumulated.into()
    }

    type HmacSha512 = Hmac<Sha512>;
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
}

// ---------------------------------------------------------------------------
// BIP-39 differentials: crate vs hand-rolled codec and PBKDF2.
// ---------------------------------------------------------------------------

#[test]
fn randomized_mnemonics_agree_with_the_independent_codec() {
    let mut rng = deterministic_rng();
    for words in [12usize, 15, 18, 21, 24] {
        let entropy_bytes = bloom_signer_derive::policy::entropy_bytes_for_words(words).unwrap();
        for _ in 0..16 {
            let entropy: Vec<u8> = (0..entropy_bytes).map(|_| rng.r#gen::<u8>()).collect();

            // Crate phrase vs codec indices.
            let phrase = mnemonic_from_entropy(&entropy).unwrap();
            let tokens: Vec<&str> = phrase.split_whitespace().collect();
            assert_eq!(tokens.len(), words);
            let indices: Vec<usize> = tokens
                .iter()
                .map(|token| bloom_signer_derive::wordlist::index(token).unwrap())
                .collect();
            assert_eq!(indices, reference::indices_from_entropy(&entropy, words));

            // Codec decode returns the exact entropy.
            let decoded = reference::entropy_from_indices(&indices, words).unwrap();
            assert_eq!(decoded, entropy);

            // Crate round-trip.
            let recovered = bloom_signer_derive::entropy_from_mnemonic(&phrase).unwrap();
            assert_eq!(*recovered, entropy);

            // Crate seed vs hand-rolled PBKDF2 (passphrase "TREZOR": the
            // reference PBKDF2 is specification-derived; the crate NFKD
            // normalizes, which is identity for ASCII).
            let crate_seed = seed_from_mnemonic(&phrase, "TREZOR").unwrap();
            let reference_seed = reference::pbkdf2_seed(&phrase, "TREZOR");
            assert_eq!(
                *crate_seed, reference_seed,
                "seed disagreement at {words} words"
            );

            // Empty passphrase too — the v1 profile.
            let crate_empty = seed_from_mnemonic(&phrase, "").unwrap();
            let reference_empty = reference::pbkdf2_seed(&phrase, "");
            assert_eq!(*crate_empty, reference_empty);
        }
    }
}

/// Official Trezor vectors (passphrase "TREZOR") pin every available word
/// length against the published seeds, through both implementations.
#[test]
fn official_trezor_vectors_reproduce_for_every_available_length() {
    let cases: [(&str, &str); 3] = [
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        ),
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        ),
    ];
    for (mnemonic, seed) in cases {
        assert_eq!(
            hex::encode(seed_from_mnemonic(mnemonic, "TREZOR").unwrap().as_slice()),
            seed
        );
        assert_eq!(
            hex::encode(reference::pbkdf2_seed(mnemonic, "TREZOR")),
            seed
        );
        assert!(parse_mnemonic(mnemonic).is_ok());
    }
}

/// Unicode normalization: the crate enforces the strict v1 NFKD policy. A
/// phrase whose separators are compatibility whitespace (U+00A0 NBSP) is not
/// in canonical NFKD form, so it is rejected rather than silently folded to
/// a different-looking phrase.
#[test]
fn nfkd_unnormalized_separators_are_rejected() {
    let entropy: Vec<u8> = vec![0x77u8; 20];
    let canonical = mnemonic_from_entropy(&entropy).unwrap();
    let nbsp_joined = canonical.replace(' ', "\u{00a0}");
    assert!(matches!(
        parse_mnemonic(&nbsp_joined),
        Err(MnemonicError::Unnormalized)
    ));
    let parsed = parse_mnemonic(&canonical).unwrap();
    assert_eq!(*parsed.entropy(), entropy);
}

#[test]
fn non_empty_passphrase_policy_is_enforced_at_the_wallet_layer() {
    // The codec itself is passphrase-capable (the differentials above use
    // "TREZOR"); v1 policy lives in `policy::import_passphrase_allowed`.
    assert!(!bloom_signer_derive::policy::import_passphrase_allowed(
        "TREZOR"
    ));
    assert!(bloom_signer_derive::policy::import_passphrase_allowed(""));
}

// ---------------------------------------------------------------------------
// BIP-32 differentials: this crate vs the bip32 crate's own field math.
// ---------------------------------------------------------------------------

fn xprv_of(seed: &[u8]) -> bip32::XPrv {
    bip32::XPrv::new(seed).expect("bip32 crate accepts the seed")
}

fn xprv_key_code(xprv: &bip32::XPrv) -> ([u8; 32], [u8; 32]) {
    let key: [u8; 32] = xprv
        .private_key()
        .to_bytes()
        .into_iter()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let code = xprv.attrs().chain_code;
    (key, code)
}

#[test]
fn randomized_bip32_paths_agree_with_the_bip32_crate() {
    let mut rng = deterministic_rng();
    for _ in 0..64 {
        let seed: [u8; 64] = (0..64)
            .map(|_| rng.r#gen::<u8>())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        let reference_xprv = xprv_of(&seed);
        let (mine_key, mine_code) = master_secp256k1(&seed).unwrap();
        let (ref_key, ref_code) = xprv_key_code(&reference_xprv);
        assert_eq!(*mine_key, ref_key, "master key disagreement");
        assert_eq!(mine_code, ref_code, "master chain code disagreement");

        let mut my_key = mine_key;
        let mut my_code = mine_code;
        let mut walking = reference_xprv;
        for depth in 0..5 {
            let index: u32 = rng.gen_range(0..(1 << 20));
            let hardened = rng.r#gen::<bool>();
            let child_number =
                bip32::ChildNumber::new(index, hardened).expect("valid child number");
            walking = walking
                .derive_child(child_number)
                .expect("reference derivation");
            let (my_child, my_child_code) = if hardened {
                hardened_child(&my_key, &my_code, index).unwrap()
            } else {
                non_hardened_child(&my_key, &my_code, index).unwrap()
            };
            let (ref_child_key, ref_child_code) = xprv_key_code(&walking);
            assert_eq!(
                *my_child, ref_child_key,
                "child key disagreement at depth {depth} index {index} hardened={hardened}"
            );
            assert_eq!(
                my_child_code, ref_child_code,
                "chain code disagreement at depth {depth}"
            );
            my_key = my_child;
            my_code = my_child_code;
        }
    }
}

/// The frozen corpus remains the pinned anchor after the crate rewrite.
#[test]
fn frozen_corpus_still_reproduces_after_the_reference_rewrite() {
    use bloom_signer_vectors as vectors;
    let seed: [u8; 64] = hex::decode(vectors::BIP39_SEED_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    let evm = bloom_signer_derive::derive_evm_account(&seed, 0, 0).unwrap();
    assert_eq!(
        hex::encode(evm.private_key.as_slice()),
        vectors::BIP32_EVM_TERMINAL_PRIVATE_KEY_HEX
    );
    assert_eq!(
        hex::encode(evm.chain_code),
        vectors::BIP32_EVM_TERMINAL_CHAIN_CODE_HEX
    );
    assert_eq!(
        hex::encode(&evm.spki_der),
        vectors::BIP32_EVM_TERMINAL_PUBLIC_KEY_SPKI_DER_HEX
    );
    let solana = bloom_signer_derive::derive_solana_account(&seed, 0).unwrap();
    assert_eq!(
        hex::encode(solana.private_key.as_slice()),
        vectors::SLIP10_SOLANA_TERMINAL_PRIVATE_KEY_HEX
    );
    assert_eq!(
        hex::encode(solana.chain_code),
        vectors::SLIP10_SOLANA_TERMINAL_CHAIN_CODE_HEX
    );
}

#[test]
fn zeroizing_wrappers_cover_every_secret_stage() {
    let entropy = bloom_signer_derive::generate_entropy();
    let phrase = mnemonic_from_entropy(entropy.as_slice()).unwrap();
    let parsed = parse_mnemonic(&phrase).unwrap();
    let seed = parsed.seed("");
    // Compile-time existence of the wrappers is the contract; this test
    // pins the API shape so a refactor cannot silently drop Zeroizing.
    let _: &Zeroizing<[u8; 64]> = &seed;
    let _: &Zeroizing<[u8; 32]> = &entropy;
}
