//! The frozen golden corpus, reproduced end to end.
//!
//! Every stage of `bip39-multicurve-v1` derivation is pinned: entropy to
//! mnemonic, mnemonic to seed, seed to BIP-32 / SLIP-10 masters, each
//! profile path step, terminal keys, public keys, SPKI DER, and
//! fingerprints. Any change to any constant or algorithm breaks here.

use bloom_signer_derive::{
    derive_evm_account, derive_solana_account, entropy_from_mnemonic, mnemonic_from_entropy,
    seed_from_mnemonic,
};
use bloom_signer_vectors as vectors;

fn hex32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn hex64(value: &str) -> [u8; 64] {
    hex::decode(value).unwrap().try_into().unwrap()
}

#[test]
fn frozen_bip39_entropy_mnemonic_and_seed_reproduce_exactly() {
    let entropy: [u8; 32] = [0u8; 32];
    let mnemonic = mnemonic_from_entropy(entropy.as_slice()).unwrap();
    assert_eq!(mnemonic.as_str(), vectors::BIP39_MNEMONIC);
    let recovered = entropy_from_mnemonic(vectors::BIP39_MNEMONIC).unwrap();
    assert_eq!(*recovered, entropy.to_vec());

    let seed = seed_from_mnemonic(vectors::BIP39_MNEMONIC, "");
    assert_eq!(*seed, hex64(vectors::BIP39_SEED_HEX));
}

#[test]
fn frozen_evm_account_reproduces_every_step() {
    let seed = hex64(vectors::BIP39_SEED_HEX);

    // Account-level checkpoint (m/44'/60'/0') via the exported derivation.
    let evm = derive_evm_account(&seed, 0, 0).unwrap();
    assert_eq!(evm.path, vectors::BIP32_EVM_PATH);
    assert_eq!(*evm.private_key, hex32(vectors::BIP32_EVM_TERMINAL_PRIVATE_KEY_HEX));
    assert_eq!(evm.chain_code, hex32(vectors::BIP32_EVM_TERMINAL_CHAIN_CODE_HEX));
    assert_eq!(
        hex::encode(evm.compressed_public_key),
        vectors::BIP32_EVM_TERMINAL_PUBLIC_KEY_COMPRESSED_HEX
    );
    assert_eq!(
        hex::encode(&evm.spki_der),
        vectors::BIP32_EVM_TERMINAL_PUBLIC_KEY_SPKI_DER_HEX
    );
    assert_eq!(
        hex::encode(evm.fingerprint),
        vectors::BIP32_EVM_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX
    );
}

#[test]
fn frozen_solana_account_reproduces_every_step() {
    let seed = hex64(vectors::BIP39_SEED_HEX);
    let solana = derive_solana_account(&seed, 0).unwrap();
    assert_eq!(solana.path, vectors::SLIP10_SOLANA_PATH);
    assert_eq!(
        *solana.private_key,
        hex32(vectors::SLIP10_SOLANA_TERMINAL_PRIVATE_KEY_HEX)
    );
    assert_eq!(
        solana.chain_code,
        hex32(vectors::SLIP10_SOLANA_TERMINAL_CHAIN_CODE_HEX)
    );
    assert_eq!(
        hex::encode(solana.public_key),
        vectors::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_HEX
    );
    assert_eq!(
        hex::encode(&solana.spki_der),
        vectors::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_SPKI_DER_HEX
    );
    assert_eq!(
        hex::encode(solana.fingerprint),
        vectors::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX
    );
}

#[test]
fn distinct_accounts_yield_distinct_keys() {
    let seed = hex64(vectors::BIP39_SEED_HEX);
    let first = derive_evm_account(&seed, 0, 0).unwrap();
    let second = derive_evm_account(&seed, 0, 1).unwrap();
    let other_account = derive_evm_account(&seed, 1, 0).unwrap();
    assert_ne!(*first.private_key, *second.private_key);
    assert_ne!(*first.private_key, *other_account.private_key);

    let sol_zero = derive_solana_account(&seed, 0).unwrap();
    let sol_one = derive_solana_account(&seed, 1).unwrap();
    assert_ne!(*sol_zero.private_key, *sol_one.private_key);
}

#[test]
fn evm_and_solana_children_come_from_one_seed_without_shared_material() {
    let seed = hex64(vectors::BIP39_SEED_HEX);
    let evm = derive_evm_account(&seed, 0, 0).unwrap();
    let solana = derive_solana_account(&seed, 0).unwrap();
    assert_ne!(*evm.private_key, *solana.private_key);
}
