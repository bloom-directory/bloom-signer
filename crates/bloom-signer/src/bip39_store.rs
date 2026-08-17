//! Signer database durability and plaintext-policy helpers.
//!
//! After the custody reconciliation, the BIP-39 root lives in the single
//! `custody` record (persisted by the engine into `wallet_state`), not in
//! parallel tables. This module retains only the cross-cutting pieces:
//! WAL/durability configuration and decrypt-time plaintext-length policy.

use rusqlite::Connection;

use bloom_signer_api::ProtocolError;

use crate::engine::storage;

pub const ROOT_PROFILE_BIP39_MULTICURVE_V1: &str = "bip39-multicurve-v1";

/// WAL + explicit durability for the file-backed database. In-memory
/// connections (tests) skip journal configuration, which is a no-op there.
pub fn configure_durability(connection: &Connection) -> Result<(), ProtocolError> {
    let file_backed = connection.path().is_some_and(|path| !path.is_empty());
    if file_backed {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(storage)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(storage)?;
    }
    connection
        .pragma_update(None, "busy_timeout", 5_000)
        .map_err(storage)?;
    Ok(())
}

/// Decrypt-time plaintext validation. Schema constraints can enforce one
/// root row, profile, entropy-length metadata, and allowed formats — they
/// cannot prove what an opaque ciphertext contains. After the ciphertext is
/// authenticated and decrypted at unlock/restore, the plaintext length MUST
/// match the stored `entropy_bits` metadata before any derivation proceeds.
pub fn entropy_plaintext_matches_metadata(plaintext: &[u8], entropy_bits: usize) -> bool {
    match entropy_bits {
        128 => plaintext.len() == 16,
        160 => plaintext.len() == 20,
        192 => plaintext.len() == 24,
        224 => plaintext.len() == 28,
        256 => plaintext.len() == 32,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::entropy_plaintext_matches_metadata;

    #[test]
    fn entropy_lengths_map_to_their_metadata() {
        assert!(entropy_plaintext_matches_metadata(&[0u8; 16], 128));
        assert!(entropy_plaintext_matches_metadata(&[0u8; 20], 160));
        assert!(entropy_plaintext_matches_metadata(&[0u8; 24], 192));
        assert!(entropy_plaintext_matches_metadata(&[0u8; 28], 224));
        assert!(entropy_plaintext_matches_metadata(&[0u8; 32], 256));
        assert!(!entropy_plaintext_matches_metadata(&[0u8; 64], 256));
        assert!(!entropy_plaintext_matches_metadata(&[0u8; 32], 128));
        assert!(!entropy_plaintext_matches_metadata(&[0u8; 32], 999));
    }

    #[test]
    fn profile_constant_is_stable() {
        assert_eq!(super::ROOT_PROFILE_BIP39_MULTICURVE_V1, "bip39-multicurve-v1");
    }
}
