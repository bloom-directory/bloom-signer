//! Differential gates against independent implementations.
//!
//! The hand-written scalar arithmetic previously shipped a real ordering
//! bug that official vectors alone did not catch (it reproduced the
//! master key but corrupted children). These tests are the standing gate:
//! every randomized derivation must agree with the `bip32` crate (which
//! uses its own field arithmetic), every mnemonic/seed must agree with the
//! `bip39` crate, and the invalid-child rules must hold by construction.

use bloom_signer_derive::{
    bip32::{hardened_child, master_secp256k1, non_hardened_child},
    mnemonic_from_entropy, seed_from_mnemonic,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn deterministic_rng() -> StdRng {
    StdRng::seed_from_u64(0xB100_39C0_DE00_0001)
}

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
        let reference = xprv_of(&seed);
        let (mine_key, mine_code) = master_secp256k1(&seed).unwrap();
        let (ref_key, ref_code) = xprv_key_code(&reference);
        assert_eq!(*mine_key, ref_key, "master key disagreement");
        assert_eq!(mine_code, ref_code, "master chain code disagreement");

        let mut my_key = mine_key;
        let mut my_code = mine_code;
        let mut walking = reference;
        for depth in 0..5 {
            let index: u32 = rng.gen_range(0..(1 << 20));
            let hardened = rng.r#gen::<bool>();
            let child_number =
                bip32::ChildNumber::new(index, hardened).expect("valid child number");
            walking = walking.derive_child(child_number).expect("reference derivation");
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

#[test]
fn randomized_mnemonics_and_seeds_agree_with_the_bip39_crate() {
    let mut rng = deterministic_rng();
    for words in [12usize, 15, 18, 21, 24] {
        let entropy_bytes = bloom_signer_derive::policy::entropy_bytes_for_words(words).unwrap();
        for _ in 0..8 {
            let entropy: Vec<u8> = (0..entropy_bytes).map(|_| rng.r#gen::<u8>()).collect();
            let mine = mnemonic_from_entropy(&entropy).unwrap();
            let reference =
                bip39::Mnemonic::from_entropy(&entropy).expect("bip39 accepts the entropy");
            assert_eq!(
                mine.as_str(),
                reference.to_string(),
                "mnemonic disagreement at {words} words"
            );

            let recovered = bloom_signer_derive::entropy_from_mnemonic(&mine).unwrap();
            assert_eq!(*recovered, entropy);

            let my_seed = seed_from_mnemonic(&mine, "TREZOR");
            let reference_seed = reference.to_seed("TREZOR");
            assert_eq!(*my_seed, reference_seed, "seed disagreement at {words} words");
        }
    }
}

/// Official Trezor vectors (passphrase "TREZOR") pin every available word
/// length against the published seeds.
#[test]
fn official_trezor_vectors_reproduce_for_every_available_length() {
    let cases: [(usize, &str, &str); 3] = [
        (
            12,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        ),
        (
            18,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        ),
        (
            24,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        ),
    ];
    for (_, mnemonic, seed) in cases {
        assert_eq!(
            hex::encode(seed_from_mnemonic(mnemonic, "TREZOR").as_slice()),
            seed
        );
        // The entropy round-trips too.
        assert!(bloom_signer_derive::entropy_from_mnemonic(mnemonic).is_ok());
    }
}

/// The frozen corpus remains the pinned anchor after the k256 rewrite.
#[test]
fn frozen_corpus_still_reproduces_after_the_scalar_rewrite() {
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
