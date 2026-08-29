//! BIP-32 secp256k1 derivation for `bip44-evm-secp256k1-v1`.
//!
//! Master key: `I = HMAC-SHA512("Bitcoin seed", seed)`; `k = I_L`,
//! `c = I_R`. Hardened child:
//! `I = HMAC-SHA512(c_par, 0x00 || k_par || ser32(i + 2^31))`. Non-hardened
//! child (BIP-44 change/index levels only):
//! `I = HMAC-SHA512(c_par, serP(K_par) || ser32(i))`. In both forms
//! `k_i = (I_L + k_par) mod n`, `c_i = I_R`.
//!
//! Scalar arithmetic uses the `k256` crate's field implementation — no
//! hand-written limb math (which previously shipped a real ordering bug).
//! The BIP-32 invalid-child rules are enforced explicitly:
//! [`Secp256k1DeriveError::InvalidChild`] when `I_L >= n` or when the sum
//! is zero; callers must deterministically skip (tombstone) such indices
//! (see [`crate::allocation::next_valid_index`]).
//!
//! Callers cannot pass arbitrary paths: derivation is exposed per profile
//! canonical template only.

use hmac::{Hmac, Mac};
use k256::ecdsa::SigningKey;
use k256::pkcs8::EncodePublicKey;
use k256::{Scalar, elliptic_curve::ops::Reduce};
use sha2::{Digest as _, Sha256, Sha512};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::seed::SEED_BYTES;

const MASTER_DOMAIN: &[u8] = b"Bitcoin seed";
const HARDENED_OFFSET: u32 = 1 << 31;

pub const PATH_PURPOSE: u32 = 44;
pub const PATH_COIN: u32 = 60;

#[derive(Debug, Error)]
pub enum Secp256k1DeriveError {
    #[error("master seed produced an invalid private key")]
    InvalidMasterKey,
    #[error("seed length must be 16-64 bytes")]
    InvalidSeedLength,
    #[error("account or index must be a non-hardened BIP-44 value (< 2^31)")]
    InvalidIndex,
    /// BIP-32 invalid child: `I_L >= n` or the derived scalar is zero.
    /// Deterministically skip this index and proceed with the next.
    #[error("BIP-32 invalid child at this index (I_L >= n or zero scalar); skip deterministically")]
    InvalidChild,
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

/// Parse 32 bytes as a canonical scalar (less than n). Returns `None` for
/// values at or above n; canonicality is checked by reduction round-trip,
/// independent of any single constructor's failure mode.
fn scalar_from_canonical(bytes: &[u8; 32]) -> Option<Scalar> {
    let reduced =
        <Scalar as Reduce<k256::elliptic_curve::bigint::U256>>::reduce_bytes(&(*bytes).into());
    if reduced.to_bytes().as_slice() == bytes.as_slice() {
        Some(reduced)
    } else {
        None
    }
}

fn scalar_bytes(value: &Scalar) -> [u8; 32] {
    let bytes = value.to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// `(I_L + parent) mod n`, enforcing the invalid-child rules. Exposed for
/// tests that construct `I_L` directly.
pub fn child_key_from_tweak(
    tweak: &[u8; 32],
    parent_key: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Secp256k1DeriveError> {
    let tweak_scalar = scalar_from_canonical(tweak).ok_or(Secp256k1DeriveError::InvalidChild)?;
    let parent_scalar =
        scalar_from_canonical(parent_key).ok_or(Secp256k1DeriveError::InvalidMasterKey)?;
    let child = tweak_scalar + parent_scalar;
    let bytes = scalar_bytes(&child);
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(Secp256k1DeriveError::InvalidChild);
    }
    Ok(Zeroizing::new(bytes))
}

/// BIP-32 master (private key, chain code). Accepts any seed length
/// from 16 to 64 bytes, as BIP-32 does; profile derivers pass the 64-byte
/// BIP-39 seed.
pub fn master_secp256k1(
    seed: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), Secp256k1DeriveError> {
    if seed.len() < 16 || seed.len() > SEED_BYTES {
        return Err(Secp256k1DeriveError::InvalidSeedLength);
    }
    let digest = hmac_sha512(MASTER_DOMAIN, seed);
    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&digest[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&digest[32..]);
    let private_key = child_key_from_tweak(&tweak, &[0u8; 32])?;
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
    child_from_digest(&digest, parent_key)
}

/// One non-hardened child step, used only for the BIP-44 change and index
/// levels: `I = HMAC-SHA512(c_par, serP(K_par) || ser32(i))`.
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
    child_from_digest(&digest, parent_key)
}

fn child_from_digest(
    digest: &[u8; 64],
    parent_key: &[u8; 32],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), Secp256k1DeriveError> {
    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&digest[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&digest[32..]);
    let private_key = child_key_from_tweak(&tweak, parent_key)?;
    Ok((private_key, chain_code))
}

/// Describe a private key: compressed point, SPKI DER, fingerprint.
pub fn describe_secp256k1(private_key: &[u8; 32]) -> DerivedSecp256k1 {
    let signing = SigningKey::from_bytes(private_key.into()).expect("validated private key");
    let verifying = signing.verifying_key();
    let mut compressed_public_key = [0u8; 33];
    compressed_public_key.copy_from_slice(verifying.to_encoded_point(true).as_bytes());
    let public_key = k256::PublicKey::from_sec1_bytes(verifying.to_encoded_point(false).as_bytes())
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
        let key = hex32("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        let code = hex32("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
        // m/0' — hardened child; constants decoded from the official xprv.
        let (child_key, child_code) = hardened_child(&key, &code, 0).unwrap();
        assert_eq!(
            hex::encode(child_key.as_slice()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        assert_eq!(
            hex::encode(child_code),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );
        // m/0'/1 — non-hardened child; constants decoded from the official xprv.
        let (grandchild_key, grandchild_code) =
            non_hardened_child(&child_key, &child_code, 1).unwrap();
        assert_eq!(
            hex::encode(grandchild_key.as_slice()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
        assert_eq!(
            hex::encode(grandchild_code),
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
        );
    }

    #[test]
    fn invalid_child_rules_are_enforced_by_construction() {
        let parent = hex32("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        // I_L >= n: all-ones is greater than the group order.
        assert!(matches!(
            child_key_from_tweak(&[0xFF; 32], &parent),
            Err(Secp256k1DeriveError::InvalidChild)
        ));
        // I_L = n - parent (canonical, since 0 < parent < n): the sum is
        // exactly n, which reduces to the zero scalar.
        let n_minus_parent = {
            let n = hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
            let mut borrow: i16 = 0;
            let mut out = [0u8; 32];
            for position in (0..32).rev() {
                let difference = i16::from(n[position]) - i16::from(parent[position]) - borrow;
                if difference < 0 {
                    out[position] = (difference + 256) as u8;
                    borrow = 1;
                } else {
                    out[position] = difference as u8;
                    borrow = 0;
                }
            }
            out
        };
        assert!(matches!(
            child_key_from_tweak(&n_minus_parent, &parent),
            Err(Secp256k1DeriveError::InvalidChild)
        ));
    }
}
