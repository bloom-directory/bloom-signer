//! Hardened SLIP-10 Ed25519 derivation for `bip44-solana-slip10-ed25519-v1`.
//!
//! Master: `I = HMAC-SHA512("ed25519 seed", seed)`; `k = I_L`, `c = I_R`.
//! Child (always hardened for Ed25519):
//! `I = HMAC-SHA512(c_par, 0x00 || k_par || ser32(i + 2^31))`;
//! `k_i = I_L` (no modular addition — SLIP-10 defines Ed25519 keys this
//! way), `c_i = I_R`. Canonical path: `m/44'/501'/<account>'/0'`.

use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256, Sha512};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::seed::SEED_BYTES;

const MASTER_DOMAIN: &[u8] = b"ed25519 seed";
const HARDENED_OFFSET: u32 = 1 << 31;

pub const PATH_PURPOSE: u32 = 44;
pub const PATH_COIN: u32 = 501;

#[derive(Debug, Error)]
pub enum Ed25519DeriveError {
    #[error("account must be a non-hardened BIP-44 value (< 2^31)")]
    InvalidIndex,
    #[error("derived key is not a valid Ed25519 scalar")]
    InvalidKey,
}

/// A fully described SLIP-10 Ed25519 derived account.
pub struct DerivedEd25519 {
    pub private_key: Zeroizing<[u8; 32]>,
    pub chain_code: [u8; 32],
    /// Raw 32-byte public key.
    pub public_key: [u8; 32],
    /// Canonical SPKI DER (RFC 8410, 44 bytes).
    pub spki_der: Vec<u8>,
    /// SHA-256 of the SPKI DER — the Signer fingerprint convention.
    pub fingerprint: [u8; 32],
    /// The canonical allocated path.
    pub path: String,
}

type HmacSha512 = Hmac<Sha512>;

fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// SLIP-10 Ed25519 master (secret key, chain code). Accepts any seed
/// length from 16 to 64 bytes, as SLIP-10 does.
pub fn master_ed25519(seed: &[u8]) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let digest = hmac_sha512(MASTER_DOMAIN, seed);
    let mut private_key = Zeroizing::new([0u8; 32]);
    private_key.copy_from_slice(&digest[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&digest[32..]);
    (private_key, chain_code)
}

/// One hardened child step (the only form Ed25519 supports).
pub fn hardened_child(
    parent_key: &[u8; 32],
    parent_code: &[u8; 32],
    index: u32,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), Ed25519DeriveError> {
    if index >= HARDENED_OFFSET {
        return Err(Ed25519DeriveError::InvalidIndex);
    }
    let mut message = [0u8; 37];
    message[0] = 0x00;
    message[1..33].copy_from_slice(parent_key);
    message[33..37].copy_from_slice(&(index + HARDENED_OFFSET).to_be_bytes());
    let digest = hmac_sha512(parent_code, &message);
    let mut private_key = Zeroizing::new([0u8; 32]);
    private_key.copy_from_slice(&digest[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&digest[32..]);
    Ok((private_key, chain_code))
}

/// Canonical Ed25519 SPKI DER for a raw 32-byte public key.
pub fn ed25519_spki_der(public_key: &[u8; 32]) -> Vec<u8> {
    const PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&PREFIX);
    spki.extend_from_slice(public_key);
    spki
}

/// Describe a SLIP-10 secret key: public key, SPKI DER, fingerprint.
pub fn describe_ed25519(private_key: &[u8; 32]) -> DerivedEd25519 {
    let signing = SigningKey::from_bytes(private_key);
    let public_key = signing.verifying_key().to_bytes();
    let spki_der = ed25519_spki_der(&public_key);
    let fingerprint: [u8; 32] = Sha256::digest(&spki_der).into();
    DerivedEd25519 {
        private_key: Zeroizing::new(*private_key),
        chain_code: [0u8; 32],
        public_key,
        spki_der,
        fingerprint,
        path: String::new(),
    }
}

/// Derive the canonical Solana account `m/44'/501'/<account>'/0'`.
pub fn derive_solana_account(
    seed: &[u8; SEED_BYTES],
    account: u32,
) -> Result<DerivedEd25519, Ed25519DeriveError> {
    if account >= HARDENED_OFFSET {
        return Err(Ed25519DeriveError::InvalidIndex);
    }
    let (key, code) = master_ed25519(seed);
    let (key, code) = hardened_child(&key, &code, PATH_PURPOSE)?;
    let (key, code) = hardened_child(&key, &code, PATH_COIN)?;
    let (key, code) = hardened_child(&key, &code, account)?;
    let (key, code) = hardened_child(&key, &code, 0)?;
    let mut described = describe_ed25519(&key);
    described.chain_code = code;
    described.path = format!("m/{PATH_PURPOSE}'/{PATH_COIN}'/{account}'/0'");
    Ok(described)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_tv1() -> Vec<u8> {
        (0u8..16).collect()
    }

    /// SLIP-0010 test vector 1 (Ed25519), decoded values: master and m/0'.
    #[test]
    fn master_and_first_child_match_slip10_test_vector_1() {
        let (key, code) = master_ed25519(&seed_tv1());
        assert_eq!(
            hex::encode(key.as_slice()),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            hex::encode(code),
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
        );
        let described = describe_ed25519(&key);
        assert_eq!(
            hex::encode(described.public_key),
            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"
        );

        let (child_key, child_code) = hardened_child(&key, &code, 0).unwrap();
        assert_eq!(
            hex::encode(child_key.as_slice()),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
        assert_eq!(
            hex::encode(child_code),
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"
        );
    }
}
