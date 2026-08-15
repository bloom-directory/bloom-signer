//! Frozen golden vectors for BIP-39 / BIP-32 / SLIP-10 derivation.
//!
//! This crate is test-only data. It is consumed as a dev-dependency by the
//! crypto and backend crates so every repository reproduces the same canonical
//! corpus. It must never become a production dependency: the private keys
//! below are public test fixtures, not secrets.
//!
//! # Provenance
//!
//! The pipeline was cross-checked against authoritative sources before
//! freezing:
//!
//! * BIP-39 PBKDF2 seed against the Trezor `python-mnemonic` `vectors.json`
//!   (English, 12- and 24-word vectors, passphrase `"TREZOR"`);
//! * BIP-32 master key / chain code / public key against BIP-32 test vector 1
//!   (seed `000102030405060708090a0b0c0d0e0f`);
//! * SLIP-10 Ed25519 master key / chain code / public key against SLIP-0010
//!   test vector 1 (same seed).
//!
//! The canonical corpus uses the official 256-bit BIP-39 entropy of all zero
//! bytes (mnemonic `abandon` x23 + `art`) with the **empty** BIP-39 passphrase,
//! which is the interoperable default profile `bip39-multicurve-v1`.
//!
//! Public keys are frozen in canonical SPKI DER form (see
//! `bloom_signer_api::PublicKeyEncoding`): secp256k1 as the uncompressed
//! `0x04 || x || y` point under `id-ecPublicKey`/`secp256k1`, Ed25519 as the
//! raw 32-byte key under RFC 8410 `id-Ed25519`.

pub const BIP39_ENTROPY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub const BIP39_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon art";
pub const BIP39_SEED_HEX: &str = "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70\
5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840";

pub const BIP32_EVM_PATH: &str = "m/44'/60'/0'/0/0";

pub const BIP32_EVM_MASTER_PRIVATE_KEY_HEX: &str =
    "235b34cd7c9f6d7e4595ffe9ae4b1cb5606df8aca2b527d20a07c8f56b2342f4";
pub const BIP32_EVM_MASTER_CHAIN_CODE_HEX: &str =
    "f40eaad21641ca7cb5ac00f9ce21cac9ba070bb673a237f7bce57acda54386a4";
pub const BIP32_EVM_MASTER_PUBLIC_KEY_COMPRESSED_HEX: &str =
    "025660b70c8770245fb97ce9a811885e8045a1f333a799dcd3035788606cc55754";

pub const BIP32_EVM_M44H_PRIVATE_KEY_HEX: &str =
    "cfacd9b16c3dbbb212919ae27c26d3157016fc0af48b931e59a32d969c7ab869";
pub const BIP32_EVM_M44H_CHAIN_CODE_HEX: &str =
    "cfab712b87837428e6e7e0536ef2ee5b6f832ddeb655122cd1013bdd86f9bc2b";

pub const BIP32_EVM_M44H_60H_PRIVATE_KEY_HEX: &str =
    "d30e2b86ea68a8203dc8a6abda459f55d6ed922b5cccb796dfe5302b815c91e2";
pub const BIP32_EVM_M44H_60H_CHAIN_CODE_HEX: &str =
    "43703171a4f0d5ad8846a6cb5d04db4808b44778396b8baee1dd6170d881a212";

pub const BIP32_EVM_ACCOUNT0_PRIVATE_KEY_HEX: &str =
    "34d51b6c75d62be8130b482405660c8c6a7b5017d14269c926652f3521f2df27";
pub const BIP32_EVM_ACCOUNT0_CHAIN_CODE_HEX: &str =
    "8a7bb4e42a4afe8afd3bc74b8a1980da037d96873f5e17004edb78d4c73daa73";

pub const BIP32_EVM_TERMINAL_PRIVATE_KEY_HEX: &str =
    "b090dfbe5c89c359e7092962a0edff1cb977ba65a4170d855496f4e73b7a18e0";
pub const BIP32_EVM_TERMINAL_CHAIN_CODE_HEX: &str =
    "a92400927960463a4361afbd5db61fb58c6d3f68238f1804839f4ef487f5bebe";
pub const BIP32_EVM_TERMINAL_PUBLIC_KEY_COMPRESSED_HEX: &str =
    "02cfe8374345204b4fada115f67b0e72e4528333e080aa0d81b115173a51cd5dba";
pub const BIP32_EVM_TERMINAL_PUBLIC_KEY_SPKI_DER_HEX: &str = "3056301006072a8648ce3d020106052b\
8104000a03420004cfe8374345204b4fada115f67b0e72e4528333e080aa0d81b115173a51cd5dbabeb4db913c58\
3ba148cad0dd2947d196f63b122e720523d11f5b43a019af234c";
pub const BIP32_EVM_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX: &str =
    "cb06aacbcf5665b27879cf08590d10d3e99b06663476b50c2ed9856bbac2bd54";

pub const SLIP10_SOLANA_PATH: &str = "m/44'/501'/0'/0'";

pub const SLIP10_SOLANA_MASTER_PRIVATE_KEY_HEX: &str =
    "675f1956184972dd0353022d431c6417e8acdce50204de234fd8df9323d152f6";
pub const SLIP10_SOLANA_MASTER_CHAIN_CODE_HEX: &str =
    "531d623d2e03cb2ff52b474821c278fb3acb6173cd6d831193a4ab27ab0a059c";
pub const SLIP10_SOLANA_MASTER_PUBLIC_KEY_HEX: &str =
    "7afa7190d9f5daeaa45d9650ed3ce7c0973bb0e35f7361bf858389a8cf1c3f3c";

pub const SLIP10_SOLANA_M44H_PRIVATE_KEY_HEX: &str =
    "94f213ecf7010bc85c80f5b7fced42d1869f3d70c78657e5b55f5c453f32e680";
pub const SLIP10_SOLANA_M44H_CHAIN_CODE_HEX: &str =
    "cc1458f9a54bcb96effc9cbedd73dfda6dba2bb0c2b65b9aa22128450ea82519";

pub const SLIP10_SOLANA_M44H_501H_PRIVATE_KEY_HEX: &str =
    "1327255e623757de21d8803797918e05340ef3213f755b59c8d4fe996326298f";
pub const SLIP10_SOLANA_M44H_501H_CHAIN_CODE_HEX: &str =
    "957ec67fba8db6b10968ca82cdb3f3aeb3b5615b6c50f8f93267a0552372649a";

pub const SLIP10_SOLANA_ACCOUNT0_PRIVATE_KEY_HEX: &str =
    "2470bb98ef81d7dbe40c2cf95fecce7347d0248b665063aa4e31dec722eb2618";
pub const SLIP10_SOLANA_ACCOUNT0_CHAIN_CODE_HEX: &str =
    "fa886df71802aa0b98e746222aa971fb6a1be73ece4f01db64920581ac57647f";

pub const SLIP10_SOLANA_TERMINAL_PRIVATE_KEY_HEX: &str =
    "7c139e1a603ca04f5f7cff194e1bb6f6d1b9098470ea90695ab628488a9f921b";
pub const SLIP10_SOLANA_TERMINAL_CHAIN_CODE_HEX: &str =
    "3b0406cfbafa63868e626c34adb3a868112413e5fd6d27a2cc9f478612440b53";
pub const SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_HEX: &str =
    "20c821b6510834ae1c47084c6f61fd97864d5f12d731f95f4b06fe477b1efb45";
pub const SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_SPKI_DER_HEX: &str =
    "302a300506032b657003210020c821b6510834ae1c47084c6f61fd97864d5f12d731f95f4b06fe477b1efb45";
pub const SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX: &str =
    "a2abc1225904b713a6630c61da96b6c77d41a64e7f623b6546da1f97f30fe29a";

#[cfg(test)]
mod tests {
    fn is_hex(value: &str) -> bool {
        value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_hexdigit())
    }

    #[test]
    fn every_hex_vector_is_valid_even_length_hex() {
        for value in [
            super::BIP39_ENTROPY_HEX,
            super::BIP39_SEED_HEX,
            super::BIP32_EVM_MASTER_PRIVATE_KEY_HEX,
            super::BIP32_EVM_MASTER_CHAIN_CODE_HEX,
            super::BIP32_EVM_MASTER_PUBLIC_KEY_COMPRESSED_HEX,
            super::BIP32_EVM_M44H_PRIVATE_KEY_HEX,
            super::BIP32_EVM_M44H_CHAIN_CODE_HEX,
            super::BIP32_EVM_M44H_60H_PRIVATE_KEY_HEX,
            super::BIP32_EVM_M44H_60H_CHAIN_CODE_HEX,
            super::BIP32_EVM_ACCOUNT0_PRIVATE_KEY_HEX,
            super::BIP32_EVM_ACCOUNT0_CHAIN_CODE_HEX,
            super::BIP32_EVM_TERMINAL_PRIVATE_KEY_HEX,
            super::BIP32_EVM_TERMINAL_CHAIN_CODE_HEX,
            super::BIP32_EVM_TERMINAL_PUBLIC_KEY_COMPRESSED_HEX,
            super::BIP32_EVM_TERMINAL_PUBLIC_KEY_SPKI_DER_HEX,
            super::BIP32_EVM_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX,
            super::SLIP10_SOLANA_MASTER_PRIVATE_KEY_HEX,
            super::SLIP10_SOLANA_MASTER_CHAIN_CODE_HEX,
            super::SLIP10_SOLANA_MASTER_PUBLIC_KEY_HEX,
            super::SLIP10_SOLANA_M44H_PRIVATE_KEY_HEX,
            super::SLIP10_SOLANA_M44H_CHAIN_CODE_HEX,
            super::SLIP10_SOLANA_M44H_501H_PRIVATE_KEY_HEX,
            super::SLIP10_SOLANA_M44H_501H_CHAIN_CODE_HEX,
            super::SLIP10_SOLANA_ACCOUNT0_PRIVATE_KEY_HEX,
            super::SLIP10_SOLANA_ACCOUNT0_CHAIN_CODE_HEX,
            super::SLIP10_SOLANA_TERMINAL_PRIVATE_KEY_HEX,
            super::SLIP10_SOLANA_TERMINAL_CHAIN_CODE_HEX,
            super::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_HEX,
            super::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_SPKI_DER_HEX,
            super::SLIP10_SOLANA_TERMINAL_PUBLIC_KEY_FINGERPRINT_HEX,
        ] {
            assert!(is_hex(value), "invalid hex vector: {value}");
        }
    }
}
