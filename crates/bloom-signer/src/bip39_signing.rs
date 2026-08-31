//! The `bip39-multicurve-v1` signing edge.
//!
//! A BIP-39 wallet root is never a signable key. Signing happens only through
//! a registered, ACTIVATED child account:
//!
//! 1. unlock (passkey/recovery) produces the WKEK;
//! 2. the wrapped entropy is AEAD-authenticated and decrypted into
//!    zeroizing memory;
//! 3. the decrypted length is validated against the stored `entropy_bits`
//!    metadata;
//! 4. the normalized mnemonic and the transient 64-byte seed are derived;
//! 5. the exact registered child is derived from the canonical path;
//! 6. the child's SPKI DER and fingerprint are verified against the
//!    activated registry entry;
//! 7. the payload is signed (EVM digest -> recoverable secp256k1; Solana
//!    raw message -> Ed25519);
//! 8. the signature is locally verified;
//! 9. all transient secret material is zeroized.
//!
//! No derivation path crosses the signing boundary: callers select a
//! profile and the registry supplies the canonical path. Root references,
//! unactivated accounts, and mismatched descriptors fail closed.

use ed25519_dalek::Signer as _;
use k256::ecdsa::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use bloom_signer_api::Digest32;
use bloom_signer_derive::{
    SEED_BYTES, derive_evm_account, derive_solana_account, mnemonic_from_entropy,
    seed_from_mnemonic,
};

#[derive(Debug, Error)]
pub enum SigningEdgeError {
    #[error("root material cannot sign; a registered child account is required")]
    RootNotSignable,
    #[error("entropy length does not match the stored profile metadata")]
    EntropyLengthMismatch,
    #[error("derived public key does not match the activated registry entry")]
    DescriptorMismatch,
    #[error("signature verification failed after signing")]
    SelfVerificationFailed,
    #[error("input size limit exceeded")]
    InputTooLarge,
    #[error("derivation failed: {0}")]
    Derivation(String),
}

/// Exact limits for the MVP signing inputs.
pub const MAX_ED25519_MESSAGE_BYTES: usize = bloom_signer_api::MAX_ED25519_MESSAGE_BYTES;
pub const EVM_DIGEST_BYTES: usize = 32;

/// The expected public descriptor of an activated registry entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedAccount {
    pub profile: String,
    pub path: String,
    /// Canonical SPKI DER (hex), the Signer descriptor convention.
    pub spki_der_hex: String,
    /// SHA-256 of the SPKI DER.
    pub fingerprint: Digest32,
}

/// Decrypt-entropy → validate-length → transient mnemonic → transient seed.
///
/// `wkek` is the already-recovered key-encryption key; `decrypt` is the
/// custody AEAD unwrap. Every secret is zeroized on return and on error.
/// (Deprecated in favor of `UnlockedWallet::bip39_seed`; retained for the
/// raw-AEAD boundary tests.)
pub fn entropy_to_seed(
    wkek: &[u8],
    wallet_id: &bloom_signer_api::Token,
    wrap_format_version: u32,
    wrapped_entropy_nonce: &[u8],
    wrapped_entropy_ciphertext: &[u8],
    entropy_bits: usize,
) -> Result<Zeroizing<[u8; SEED_BYTES]>, SigningEdgeError> {
    let blob = crate::custody::EncryptedBlob {
        nonce: bloom_signer_api::Base64UrlBytes::from_bytes(wrapped_entropy_nonce),
        ciphertext: bloom_signer_api::Base64UrlBytes::from_bytes(wrapped_entropy_ciphertext),
    };
    // This helper only ever unwraps BIP-39 entropy, so the AAD is built for
    // that profile and the caller's declared entropy size. From
    // WRAP_FORMAT_V2 those values are authenticated, so a mismatch fails the
    // AEAD here rather than after derivation.
    let aad = crate::custody::root_aad(
        wallet_id,
        wrap_format_version,
        crate::custody::RootMaterialProfile::Bip39MulticurveV1,
        u32::try_from(entropy_bits).ok(),
    );
    let secret = bloom_signer_backend_api::SecretBytes::new(wkek.to_vec());
    let entropy = Zeroizing::new(
        crate::custody::decrypt(&secret, &blob, &aad)
            .map_err(|_| SigningEdgeError::DescriptorMismatch)?,
    );
    if !crate::bip39_store::entropy_plaintext_matches_metadata(&entropy, entropy_bits) {
        return Err(SigningEdgeError::EntropyLengthMismatch);
    }
    let mnemonic = Zeroizing::new(
        mnemonic_from_entropy(&entropy)
            .map_err(|error| SigningEdgeError::Derivation(error.to_string()))?,
    );
    seed_from_mnemonic(&mnemonic).map_err(|error| SigningEdgeError::Derivation(error.to_string()))
}

/// The BIP-39 root material can never sign: only a registered, activated
/// child account is a signable reference.
#[allow(dead_code)]
fn root_never_signs(_root: &[u8]) -> Result<(), SigningEdgeError> {
    Err(SigningEdgeError::RootNotSignable)
}

fn verify_descriptor(
    derived_spki_der: &[u8],
    account: &ActivatedAccount,
) -> Result<(), SigningEdgeError> {
    let expected_spki =
        hex::decode(&account.spki_der_hex).map_err(|_| SigningEdgeError::DescriptorMismatch)?;
    if derived_spki_der != expected_spki {
        return Err(SigningEdgeError::DescriptorMismatch);
    }
    let fingerprint = Digest32::from_bytes(Sha256::digest(derived_spki_der).into());
    if fingerprint != account.fingerprint {
        return Err(SigningEdgeError::DescriptorMismatch);
    }
    Ok(())
}

fn account_index(account: &ActivatedAccount) -> Result<(u32, u32), SigningEdgeError> {
    // The registry resolves the canonical path; parse account and index back
    // out for derivation. The path is validated below by descriptor
    // equality, so a malformed path cannot reach a valid key.
    match account.profile.as_str() {
        crate::derivation_registry::PROFILE_EVM => {
            let tail = account
                .path
                .strip_prefix("m/44'/60'/")
                .ok_or(SigningEdgeError::DescriptorMismatch)?;
            let (account_part, index_part) = tail
                .split_once("/0/")
                .ok_or(SigningEdgeError::DescriptorMismatch)?;
            let account_value = account_part
                .strip_suffix('\'')
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or(SigningEdgeError::DescriptorMismatch)?;
            let index_value = index_part
                .parse::<u32>()
                .ok()
                .ok_or(SigningEdgeError::DescriptorMismatch)?;
            Ok((account_value, index_value))
        }
        crate::derivation_registry::PROFILE_SOLANA => {
            let tail = account
                .path
                .strip_prefix("m/44'/501'/")
                .ok_or(SigningEdgeError::DescriptorMismatch)?;
            let account_value = tail
                .strip_suffix("/0'")
                .and_then(|value| value.strip_suffix('\''))
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or(SigningEdgeError::DescriptorMismatch)?;
            Ok((account_value, 0))
        }
        _ => Err(SigningEdgeError::DescriptorMismatch),
    }
}

/// Sign a raw Solana message with the registered SLIP-10 Ed25519 child.
pub fn sign_ed25519_message(
    seed: &[u8; SEED_BYTES],
    account: &ActivatedAccount,
    message: &[u8],
) -> Result<[u8; 64], SigningEdgeError> {
    if account.profile != crate::derivation_registry::PROFILE_SOLANA {
        return Err(SigningEdgeError::DescriptorMismatch);
    }
    if message.is_empty() || message.len() > MAX_ED25519_MESSAGE_BYTES {
        return Err(SigningEdgeError::InputTooLarge);
    }
    let (account_value, _) = account_index(account)?;
    let derived = derive_solana_account(seed, account_value)
        .map_err(|error| SigningEdgeError::Derivation(error.to_string()))?;
    verify_descriptor(&derived.spki_der, account)?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&derived.private_key);
    let signature = signing.sign(message).to_bytes();
    // Local verification before returning.
    signing
        .verifying_key()
        .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| SigningEdgeError::SelfVerificationFailed)?;
    Ok(signature)
}

/// Sign a 32-byte EVM digest with the registered BIP-32 secp256k1 child,
/// returning a 65-byte recoverable signature.
pub fn sign_evm_digest(
    seed: &[u8; SEED_BYTES],
    account: &ActivatedAccount,
    digest: &[u8; EVM_DIGEST_BYTES],
) -> Result<[u8; 65], SigningEdgeError> {
    if account.profile != crate::derivation_registry::PROFILE_EVM {
        return Err(SigningEdgeError::DescriptorMismatch);
    }
    let (account_value, index_value) = account_index(account)?;
    let derived = derive_evm_account(seed, account_value, index_value)
        .map_err(|error| SigningEdgeError::Derivation(error.to_string()))?;
    verify_descriptor(&derived.spki_der, account)?;
    let signing = SigningKey::from_bytes((&*derived.private_key).into())
        .map_err(|_| SigningEdgeError::DescriptorMismatch)?;
    let (signature, recovery_id) = signing
        .sign_prehash_recoverable(digest)
        .map_err(|_| SigningEdgeError::SelfVerificationFailed)?;
    let verifying: VerifyingKey = *signing.verifying_key();
    let recovered = VerifyingKey::recover_from_prehash(digest, &signature, recovery_id)
        .map_err(|_| SigningEdgeError::SelfVerificationFailed)?;
    if recovered != verifying {
        return Err(SigningEdgeError::SelfVerificationFailed);
    }
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&signature.to_bytes());
    out[64] = recovery_id.to_byte();
    Ok(out)
}

/// Capability check: a backend advertises a derivation capability only when
/// the active profile and primitive are actually implemented and tested.
pub fn ed25519_capability_supported() -> bool {
    true
}

pub fn secp256k1_capability_supported() -> bool {
    true
}
