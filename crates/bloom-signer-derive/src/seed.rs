//! BIP-39 seed derivation: PBKDF2-HMAC-SHA512.
//!
//! `seed = PBKDF2(mnemonic_utf8, "mnemonic" + passphrase, 2048, 64)`.
//! The `bip39-multicurve-v1` profile freezes the empty passphrase.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

pub const ITERATIONS: u32 = 2048;
pub const SEED_BYTES: usize = 64;
const SALT_PREFIX: &str = "mnemonic";

type HmacSha512 = Hmac<Sha512>;

/// Derive the 64-byte BIP-39 seed. `passphrase` must already be normalized
/// per the profile (empty for v1).
pub fn seed_from_mnemonic(mnemonic: &str, passphrase: &str) -> Zeroizing<[u8; SEED_BYTES]> {
    let salt = format!("{SALT_PREFIX}{passphrase}");
    let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
    pbkdf2_hmac_sha512(
        mnemonic.as_bytes(),
        salt.as_bytes(),
        ITERATIONS,
        seed.as_mut(),
    );
    seed
}

/// Single-block PBKDF2 with HMAC-SHA512 (the seed is exactly one block).
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    debug_assert!(out.len() <= 64);
    let mut mac = HmacSha512::new_from_slice(password).expect("HMAC accepts any key length");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut previous = mac.finalize().into_bytes();
    let mut accumulated = previous;
    for _ in 1..iterations {
        let mut mac = HmacSha512::new_from_slice(password).expect("HMAC accepts any key length");
        mac.update(&previous);
        previous = mac.finalize().into_bytes();
        for (slot, byte) in accumulated.iter_mut().zip(previous.iter()) {
            *slot ^= byte;
        }
    }
    out.copy_from_slice(&accumulated[..out.len()]);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official Trezor vectors (english, 24 words) use passphrase "TREZOR".
    const TREZOR_24W: &str = "abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon art";
    const TREZOR_24W_SEED: &str = "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2\
bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8";

    #[test]
    fn reproduces_the_official_trezor_vector() {
        let seed = seed_from_mnemonic(TREZOR_24W, "TREZOR");
        assert_eq!(hex::encode(seed.as_slice()), TREZOR_24W_SEED);
    }

    #[test]
    fn passphrase_changes_the_seed() {
        let empty = seed_from_mnemonic(TREZOR_24W, "");
        let trezor = seed_from_mnemonic(TREZOR_24W, "TREZOR");
        assert_ne!(*empty, *trezor);
    }
}
