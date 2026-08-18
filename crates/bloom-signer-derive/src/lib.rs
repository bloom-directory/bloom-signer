//! Deterministic key derivation for the Bloom local Signer.
//!
//! This crate implements the frozen `bip39-multicurve-v1` derivation stack
//! exactly as specified by the plan and pinned by the golden vectors in
//! `bloom-signer-vectors`:
//!
//! * [`mnemonic`] — 256-bit BIP-39 entropy and the English 24-word
//!   encoding, with checksum validation and strict normalization;
//! * [`seed`] — the BIP-39 passphrase-to-seed PBKDF2 (HMAC-SHA512, 2048
//!   iterations, 64 bytes); the v1 profile freezes the **empty** passphrase;
//! * [`bip32`] — BIP-32 secp256k1 derivation for the
//!   `bip44-evm-secp256k1-v1` profile (`m/44'/60'/<account>'/0/<index>`,
//!   hardened purpose/coin/account, non-hardened change and index);
//! * [`slip10`] — hardened SLIP-10 Ed25519 derivation for the
//!   `bip44-solana-slip10-ed25519-v1` profile (`m/44'/501'/<account>'/0'`).
//!
//! Design rules:
//!
//! - **No arbitrary paths.** Callers select a profile and account/index;
//!   every public function derives a profile-canonical path or rejects.
//! - **No secret leaves unzeroized.** Entropy, mnemonics, seeds, and private
//!   keys are wrapped in [`zeroize::Zeroizing`].
//! - **Everything is vector-pinned.** The integration tests reproduce the
//!   frozen corpus and the official BIP-32 / SLIP-10 test-vector-1 masters
//!   byte-for-byte before any derivation is trusted.
//! - Non-empty BIP-39 passphrases are deliberately absent: the v1 profile
//!   freezes the empty passphrase and the plan defers others explicitly.

#![forbid(unsafe_code)]

pub mod allocation;
pub mod bip32;
pub mod mnemonic;
pub mod policy;
pub mod seed;
pub mod slip10;

pub use allocation::next_valid_index;
pub use bip32::{DerivedSecp256k1, Secp256k1DeriveError, derive_evm_account, master_secp256k1};
pub use mnemonic::{
    MnemonicError, ParsedMnemonic, entropy_from_mnemonic, generate_entropy, mnemonic_from_entropy,
    parse_mnemonic, seed_from_mnemonic,
};
pub use policy::{
    GENERATE_PASSPHRASE, GENERATE_WORDS, IMPORT_WORDS, entropy_bytes_for_words,
    import_passphrase_allowed,
};
pub use seed::SEED_BYTES;
pub use slip10::{DerivedEd25519, Ed25519DeriveError, derive_solana_account};
