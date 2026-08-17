//! Hardened and non-hardened BIP-32 secp256k1 derivation for
//! `bip44-evm-secp256k1-v1`.
//!
//! Master key: `I = HMAC-SHA512("Bitcoin seed", seed)`; `k = I_L`,
//! `c = I_R`. Hardened child:
//! `I = HMAC-SHA512(c_par, 0x00 || k_par || ser32(i + 2^31))`,
//! `k_i = (I_L + k_par) mod n`, `c_i = I_R`. Non-hardened child (BIP-44
//! change/index levels only):
//! `I = HMAC-SHA512(c_par, serP(K_par) || ser32(i))`. Callers cannot pass
//! arbitrary paths: derivation is exposed per profile canonical template.

use hmac::{Hmac, Mac};
use k256::ecdsa::SigningKey;
use k256::pkcs8::EncodePublicKey;
use sha2::{Digest as _, Sha256, Sha512};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::seed::SEED_BYTES;

/// secp256k1 group order `n`.
const N: [u64; 4] = [
    0xBFD25E8C_D0364141,
    0xBAAEDCE6_AF48A03B,
    0xFFFFFFFF_FFFFFFFE,
    0xFFFFFFFF_FFFFFFFF,
];

const MASTER_DOMAIN: &[u8] = b"Bitcoin seed";
const HARDENED_OFFSET: u32 = 1 << 31;

pub const PATH_COIN: u32 = 60;
pub const PATH_PURPOSE: u32 = 44;

#[derive(Debug, Error)]
pub enum Secp256k1DeriveError {
    #[error("derived private key is zero or >= n (invalid master seed)")]
    InvalidKey,
    #[error("account or index must be a non-hardened BIP-44 value (< 2^31)")]
    InvalidIndex,
}

/// A fully described secp256k1 derived account.
pub struct DerivedSecp256k1 {
    pub private_key: Zeroizing<[u8; 32]>,
    pub chain_code: [u8; 32],
    /// SEC1 compressed point (0x02/0x03 || x).
    pub compressed_public_key: [u8; 33],
    /// Canonical SPKI DER (uncompressed point).
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

fn valid_private(key: &[u8; 32]) -> bool {
    if key.iter().all(|byte| *byte == 0) {
        return false;
    }
    let limbs = limbs_of(key);
    !exceeds_n(&limbs)
}

/// Magnitude comparison against n for little-endian limb values: array
/// ordering compares the least-significant limb first, so compare from the
/// most significant limb explicitly.
fn exceeds_n(value: &[u64; 4]) -> bool {
    for position in (0..4).rev() {
        if value[position] != N[position] {
            return value[position] > N[position];
        }
    }
    false
}

/// (a + b) mod n over 256-bit little-endian limb values.
fn add_mod_n(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut carry: u128 = 0;
    let mut sum = [0u64; 4];
    for position in 0..4 {
        let total = u128::from(a[position]) + u128::from(b[position]) + carry;
        sum[position] = total as u64;
        carry = total >> 64;
    }
    if carry == 1 || exceeds_n(&sum) {
        // sum - n, borrowing is impossible to underflow given the check.
        let mut borrow: i128 = 0;
        for position in 0..4 {
            let difference = i128::from(sum[position]) - i128::from(N[position]) + borrow;
            sum[position] = difference as u64;
            borrow = difference >> 64;
        }
    }
    sum
}

fn limbs_of(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let start = 24 - index * 8;
        *limb = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
    }
    limbs
}

fn bytes_of(limbs: &[u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, limb) in limbs.iter().enumerate() {
        bytes[24 - index * 8..32 - index * 8].copy_from_slice(&limb.to_be_bytes());
    }
    bytes
}

/// BIP-32 master (private key, chain code). Accepts any seed length
/// from 16 to 64 bytes, as BIP-32 does; profile derivers pass the 64-byte
/// BIP-39 seed.
pub fn master_secp256k1(
    seed: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), Secp256k1DeriveError> {
    if seed.len() < 16 || seed.len() > SEED_BYTES {
        return Err(Secp256k1DeriveError::InvalidKey);
    }
    let digest = hmac_sha512(MASTER_DOMAIN, seed);
    let mut private_key = Zeroizing::new([0u8; 32]);
    private_key.copy_from_slice(&digest[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&digest[32..]);
    if !valid_private(&private_key) {
        return Err(Secp256k1DeriveError::InvalidKey);
    }
    Ok((private_key, chain_code))
}

/// One hardened child step: `i` is the non-hardened index (< 2^31).
pub fn hardened_child(
    parent_key: &[u8; 32],
    parent_code: &[u8; 32],
    index: u32,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), Secp256k1DeriveError> {
    if index >= HARDENED_OFFSET {
        return Err(Secp256k1DeriveError::InvalidIndex);
    }
    let mut message = [0u8; 37];
    message[0] = 0x00;
    message[1..33].copy_from_slice(parent_key);
    message[33..37].copy_from_slice(&(index + HARDENED_OFFSET).to_be_bytes());
    let digest = hmac_sha512(parent_code, &message);
    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&digest[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&digest[32..]);
    let child = add_mod_n(&limbs_of(&tweak), &limbs_of(parent_key));
    let private_key = Zeroizing::new(bytes_of(&child));
    if !valid_private(&private_key) {
        return Err(Secp256k1DeriveError::InvalidKey);
    }
    Ok((private_key, chain_code))
}

/// One non-hardened child step, used only for the BIP-44 change and index
/// levels: `I = HMAC-SHA512(c_par, serP(K_par) || ser32(i))`,
/// `k_i = (I_L + k_par) mod n`, `c_i = I_R`.
pub fn non_hardened_child(
    parent_key: &[u8; 32],
    parent_code: &[u8; 32],
    index: u32,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), Secp256k1DeriveError> {
    if index >= HARDENED_OFFSET {
        return Err(Secp256k1DeriveError::InvalidIndex);
    }
    let parent = describe_secp256k1(parent_key);
    let mut message = [0u8; 37];
    message[..33].copy_from_slice(&parent.compressed_public_key);
    message[33..37].copy_from_slice(&index.to_be_bytes());
    let digest = hmac_sha512(parent_code, &message);
    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&digest[..32]);
    if tweak.iter().all(|byte| *byte == 0) || exceeds_n(&limbs_of(&tweak)) {
        return Err(Secp256k1DeriveError::InvalidKey);
    }
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&digest[32..]);
    let child = add_mod_n(&limbs_of(&tweak), &limbs_of(parent_key));
    let private_key = Zeroizing::new(bytes_of(&child));
    if !valid_private(&private_key) {
        return Err(Secp256k1DeriveError::InvalidKey);
    }
    Ok((private_key, chain_code))
}

/// Describe a private key: compressed point, SPKI DER, fingerprint.
pub fn describe_secp256k1(private_key: &[u8; 32]) -> DerivedSecp256k1 {
    let signing = SigningKey::from_bytes(private_key.into()).expect("validated private key");
    let verifying = signing.verifying_key();
    let mut compressed_public_key = [0u8; 33];
    compressed_public_key.copy_from_slice(verifying.to_encoded_point(true).as_bytes());
    let public_key = k256::PublicKey::from_sec1_bytes(
        verifying.to_encoded_point(false).as_bytes(),
    )
    .expect("valid SEC1 point");
    let spki_der = public_key
        .to_public_key_der()
        .expect("SPKI encoding of a valid key")
        .as_bytes()
        .to_vec();
    let fingerprint: [u8; 32] = Sha256::digest(&spki_der).into();
    DerivedSecp256k1 {
        private_key: Zeroizing::new(*private_key),
        chain_code: [0u8; 32],
        compressed_public_key,
        spki_der,
        fingerprint,
        path: String::new(),
    }
}

/// Derive the canonical EVM account `m/44'/60'/<account>'/0/<index>`.
///
/// Purpose, coin type, and account are hardened; the BIP-44 change level is
/// fixed to non-hardened 0 and the index is non-hardened, exactly as the
/// frozen template and `validate_allocated_path` require.
pub fn derive_evm_account(
    seed: &[u8; SEED_BYTES],
    account: u32,
    index: u32,
) -> Result<DerivedSecp256k1, Secp256k1DeriveError> {
    if account >= HARDENED_OFFSET || index >= HARDENED_OFFSET {
        return Err(Secp256k1DeriveError::InvalidIndex);
    }
    let (key, code) = master_secp256k1(seed)?;
    let (key, code) = hardened_child(&key, &code, PATH_PURPOSE)?;
    let (key, code) = hardened_child(&key, &code, PATH_COIN)?;
    let (key, code) = hardened_child(&key, &code, account)?;
    let (key, code) = non_hardened_child(&key, &code, 0)?;
    let (key, code) = non_hardened_child(&key, &code, index)?;
    let mut described = describe_secp256k1(&key);
    described.chain_code = code;
    described.path = format!("m/{PATH_PURPOSE}'/{PATH_COIN}'/{account}'/0/{index}");
    Ok(described)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(value: &str) -> [u8; 32] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    #[test]
    fn master_matches_bip32_test_vector_1() {
        // Seed 000102...0f, the official test-vector-1 seed.
        let seed = (0u8..16).collect::<Vec<u8>>();
        let (key, code) = master_secp256k1(&seed).unwrap();
        assert_eq!(
            hex::encode(key.as_slice()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex::encode(code),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );
        let described = describe_secp256k1(&key);
        assert_eq!(
            hex::encode(described.compressed_public_key),
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
        );
    }

    #[test]
    fn children_match_bip32_test_vector_1() {
        let key = hex32(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        );
        let code = hex32(
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        );
        // m/0' — hardened child; constants decoded from the official xprv.
        let (child_key, child_code) = hardened_child(&key, &code, 0).unwrap();
        assert_eq!(
            hex::encode(child_key.as_slice()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        assert_eq!(hex::encode(child_code), "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
        // m/0'/1 — non-hardened child; constants decoded from the official xprv.
        let (grandchild_key, grandchild_code) =
            non_hardened_child(&child_key, &child_code, 1).unwrap();
        assert_eq!(
            hex::encode(grandchild_key.as_slice()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
        assert_eq!(hex::encode(grandchild_code), "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19");
    }
}
