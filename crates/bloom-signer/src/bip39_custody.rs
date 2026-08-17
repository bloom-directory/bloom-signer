//! Recovery orchestration for `bip39-multicurve-v1` over the SQLite store.
//!
//! Ownership rules enforced by construction:
//!
//! - The BIP-39 flow never calls the legacy `custody` registration path, so
//!   no second `encrypted_root` is written to the legacy JSON file. Entropy
//!   ciphertext exists exactly once, in SQLite.
//! - Credential and recovery factors wrap the same WKEK; only the wrapped
//!   entropy is a root secret, and only the WKEK is wrapped per factor.
//! - Legacy JSON custody remains exclusively for legacy profiles.
//!
//! Phase discipline: no external WebAuthn or user interaction occurs inside a
//! SQLite transaction. Ceremonies split into prepare → exact reviewed terms
//! → contribute → commit; each local mutation is its own atomic transaction,
//! and every authority-changing operation appends a canonical audit entry in
//! the same transaction as the mutation.

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use bloom_signer_api::{Base64UrlBytes, Digest32, ProtocolError, ProtocolErrorCode, Token};
use bloom_signer_backend_api::SecretBytes;
use bloom_signer_derive::{generate_entropy, mnemonic_from_entropy, parse_mnemonic};

use crate::bip39_store::{self, NewWalletRoot, WrappedBlob, WrapRecord};
use crate::custody::{credential_aad, decrypt, encrypt, recovery_aad, root_aad};
use crate::derivation_registry::AuditRecorder;
use crate::engine::storage;

fn invalid(code: ProtocolErrorCode, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(code, message)
}

/// A transiently unlocked wallet session: the WKEK recovered from one
/// active factor. Never persisted; dropped on scope exit.
pub struct Unlocked {
    wallet_id: Token,
    wkek: Zeroizing<Vec<u8>>,
}

impl Unlocked {
    pub fn wallet_id(&self) -> &Token {
        &self.wallet_id
    }

    pub(crate) fn wkek(&self) -> &[u8] {
        self.wkek.as_slice()
    }

    /// Decrypt entropy → validate length → transient seed, for signing.
    fn transient_seed(&self, connection: &rusqlite::Connection) -> Result<Zeroizing<[u8; 64]>, ProtocolError> {
        let root = bip39_store::load_root(connection, &self.wallet_id)?
            .ok_or_else(|| invalid(ProtocolErrorCode::ApprovalNotFound, "wallet not found"))?;
        let entropy = decrypt(
            &wrap_kind(self.wkek()),
            &crate::custody::EncryptedBlob {
                nonce: Base64UrlBytes::from_bytes(&root.wrapped_entropy.nonce),
                ciphertext: Base64UrlBytes::from_bytes(&root.wrapped_entropy.ciphertext),
            },
            &root_aad(&self.wallet_id, root.wrap_format_version),
        )
        .map_err(|_| invalid(ProtocolErrorCode::UnauthenticatedPeer, "root authentication failed"))?;
        if !bip39_store::entropy_plaintext_matches_metadata(&entropy, root.entropy_bits) {
            return Err(invalid(
                ProtocolErrorCode::MalformedFrame,
                "decrypted entropy length does not match metadata",
            ));
        }
        let mnemonic = mnemonic_from_entropy(&entropy)
            .map_err(|error| invalid(ProtocolErrorCode::MalformedFrame, error.to_string()))?;
        bloom_signer_derive::seed_from_mnemonic(&mnemonic, "")
            .map_err(|error| invalid(ProtocolErrorCode::MalformedFrame, error.to_string()))
    }

    /// Sign a raw message through the registered SLIP-10 Ed25519 child.
    pub fn sign_ed25519(
        &self,
        connection: &rusqlite::Connection,
        account: &crate::bip39_signing::ActivatedAccount,
        message: &[u8],
    ) -> Result<[u8; 64], ProtocolError> {
        let seed = self.transient_seed(connection)?;
        crate::bip39_signing::sign_ed25519_message(&seed, account, message)
            .map_err(|error| invalid(ProtocolErrorCode::BackendInvalidRequest, error.to_string()))
    }

    /// Sign a 32-byte EVM digest through the registered BIP-32 secp256k1 child.
    pub fn sign_evm(
        &self,
        connection: &rusqlite::Connection,
        account: &crate::bip39_signing::ActivatedAccount,
        digest: &[u8; 32],
    ) -> Result<[u8; 65], ProtocolError> {
        let seed = self.transient_seed(connection)?;
        crate::bip39_signing::sign_evm_digest(&seed, account, digest)
            .map_err(|error| invalid(ProtocolErrorCode::BackendInvalidRequest, error.to_string()))
    }
}

fn wrap_kind(wkek: &[u8]) -> SecretBytes {
    SecretBytes::new(wkek.to_vec())
}

/// Generate fresh 256-bit entropy (the generated-wallet policy length).
pub fn fresh_entropy() -> Zeroizing<[u8; 32]> {
    generate_entropy()
}

fn validate_entropy(entropy: &[u8]) -> Result<usize, ProtocolError> {
    let bits = match entropy.len() {
        16 => 128,
        20 => 160,
        24 => 192,
        28 => 224,
        32 => 256,
        _ => {
            return Err(invalid(
                ProtocolErrorCode::MalformedFrame,
                "entropy length is not a valid BIP-39 length",
            ));
        }
    };
    Ok(bits)
}

fn encrypted_root_blob(
    wallet_id: &Token,
    wrap_format_version: u32,
    wkek: &[u8],
    entropy: &[u8],
) -> Result<WrappedBlob, ProtocolError> {
    let ciphertext = encrypt(
        &wrap_kind(wkek),
        entropy,
        &root_aad(wallet_id, wrap_format_version),
    )?;
    Ok(WrappedBlob {
        nonce: ciphertext.nonce.decode(),
        ciphertext: ciphertext.ciphertext.decode(),
    })
}

/// Register a new BIP-39 wallet: persist the single WKEK-wrapped entropy and
/// the first credential wrap (and optional recovery wrap) in one transaction,
/// with a canonical audit entry.
#[allow(clippy::too_many_arguments)]
pub fn register_wallet(
    connection: &mut rusqlite::Connection,
    wallet_id: &Token,
    entropy: &[u8],
    wkek: &[u8],
    first_credential_id: &[u8],
    first_credential_key: &[u8],
    recovery: Option<(&str, &[u8])>,
    now_ms: u64,
    audit: AuditRecorder<'_>,
) -> Result<(), ProtocolError> {
    let entropy_bits = validate_entropy(entropy)?;
    if bip39_store::load_root(connection, wallet_id)?.is_some() {
        return Err(invalid(
            ProtocolErrorCode::OperationIdConflict,
            "wallet root already exists",
        ));
    }
    let wrap_format_version = 1u32;
    let wrapped_entropy = encrypted_root_blob(wallet_id, wrap_format_version, wkek, entropy)?;
    let root_fingerprint = wrapped_entropy.fingerprint();

    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(storage)?;
    bip39_store::insert_root(
        &transaction,
        &NewWalletRoot {
            wallet_id: wallet_id.clone(),
            profile_version: 1,
            entropy_bits,
            language: "english",
            wrap_format_version,
            wrapped_entropy: wrapped_entropy.clone(),
            created_at_ms: now_ms,
        },
    )?;
    let credential_wrap = encrypt(
        &SecretBytes::new(first_credential_key.to_vec()),
        wkek,
        &credential_aad(wallet_id, &Base64UrlBytes::from_bytes(first_credential_id), &root_fingerprint, wrap_format_version)?,
    )?;
    bip39_store::put_wrap(
        &transaction,
        &WrapRecord {
            wrap_id: hex::encode(first_credential_id),
            wallet_id: wallet_id.clone(),
            wrap_kind: bip39_store::WRAP_KIND_CREDENTIAL,
            active: true,
            wrap_format_version,
            wrapped_wkek: WrappedBlob {
                nonce: credential_wrap.nonce.decode(),
                ciphertext: credential_wrap.ciphertext.decode(),
            },
            snapshot_epoch: 1,
            created_at_ms: now_ms,
        },
    )?;
    if let Some((recovery_id, recovery_key)) = recovery {
        let recovery_wrap = encrypt(
            &SecretBytes::new(recovery_key.to_vec()),
            wkek,
            &recovery_aad(wallet_id, &Token::new(recovery_id).map_err(|_| {
                invalid(ProtocolErrorCode::MalformedFrame, "invalid recovery id")
            })?, &root_fingerprint, wrap_format_version)?,
        )?;
        bip39_store::put_wrap(
            &transaction,
            &WrapRecord {
                wrap_id: recovery_id.to_owned(),
                wallet_id: wallet_id.clone(),
                wrap_kind: bip39_store::WRAP_KIND_RECOVERY,
                active: true,
                wrap_format_version,
                wrapped_wkek: WrappedBlob {
                    nonce: recovery_wrap.nonce.decode(),
                    ciphertext: recovery_wrap.ciphertext.decode(),
                },
                snapshot_epoch: 1,
                created_at_ms: now_ms,
            },
        )?;
    }
    audit(
        &transaction,
        "custody.register",
        serde_json::json!({
            "wallet_id": wallet_id.as_str(),
            "profile": bip39_store::ROOT_PROFILE_BIP39_MULTICURVE_V1,
            "entropy_bits": entropy_bits,
            "credential_count": 1,
            "recovery_installed": recovery.is_some(),
        }),
    )?;
    transaction.commit().map_err(storage)
}

/// Unlock the WKEK from a credential factor, authenticating the wrap.
pub fn unlock_with_credential(
    connection: &rusqlite::Connection,
    wallet_id: &Token,
    credential_id: &[u8],
    credential_key: &[u8],
) -> Result<Unlocked, ProtocolError> {
    let root = bip39_store::load_root(connection, wallet_id)?
        .ok_or_else(|| invalid(ProtocolErrorCode::ApprovalNotFound, "wallet not found"))?;
    let wrap_id = hex::encode(credential_id);
    let wrap = bip39_store::wraps(connection, wallet_id)?
        .into_iter()
        .find(|record| record.wrap_kind == bip39_store::WRAP_KIND_CREDENTIAL && record.wrap_id == wrap_id && record.active)
        .ok_or_else(|| invalid(ProtocolErrorCode::ApprovalNotFound, "credential is absent or revoked"))?;
    let wkek = decrypt(
        &SecretBytes::new(credential_key.to_vec()),
        &crate::custody::EncryptedBlob {
            nonce: Base64UrlBytes::from_bytes(&wrap.wrapped_wkek.nonce),
            ciphertext: Base64UrlBytes::from_bytes(&wrap.wrapped_wkek.ciphertext),
        },
        &credential_aad(
            wallet_id,
            &Base64UrlBytes::from_bytes(credential_id),
            &root.root_ciphertext_fingerprint,
            wrap.wrap_format_version,
        )?,
    )
    .map_err(|_| invalid(ProtocolErrorCode::UnauthenticatedPeer, "credential wrap authentication failed"))?;
    Ok(Unlocked {
        wallet_id: wallet_id.clone(),
        wkek: Zeroizing::new(wkek),
    })
}

/// Unlock via the recovery factor.
pub fn unlock_with_recovery(
    connection: &rusqlite::Connection,
    wallet_id: &Token,
    recovery_id: &str,
    recovery_key: &[u8],
) -> Result<Unlocked, ProtocolError> {
    let root = bip39_store::load_root(connection, wallet_id)?
        .ok_or_else(|| invalid(ProtocolErrorCode::ApprovalNotFound, "wallet not found"))?;
    let wrap = bip39_store::wraps(connection, wallet_id)?
        .into_iter()
        .find(|record| record.wrap_kind == bip39_store::WRAP_KIND_RECOVERY && record.wrap_id == recovery_id && record.active)
        .ok_or_else(|| invalid(ProtocolErrorCode::ApprovalNotFound, "recovery factor is unavailable"))?;
    let wkek = decrypt(
        &SecretBytes::new(recovery_key.to_vec()),
        &crate::custody::EncryptedBlob {
            nonce: Base64UrlBytes::from_bytes(&wrap.wrapped_wkek.nonce),
            ciphertext: Base64UrlBytes::from_bytes(&wrap.wrapped_wkek.ciphertext),
        },
        &recovery_aad(
            wallet_id,
            &Token::new(recovery_id).map_err(|_| invalid(ProtocolErrorCode::MalformedFrame, "invalid recovery id"))?,
            &root.root_ciphertext_fingerprint,
            wrap.wrap_format_version,
        )?,
    )
    .map_err(|_| invalid(ProtocolErrorCode::UnauthenticatedPeer, "recovery wrap authentication failed"))?;
    Ok(Unlocked {
        wallet_id: wallet_id.clone(),
        wkek: Zeroizing::new(wkek),
    })
}

/// Add a passkey: wrap the WKEK for a new credential.
pub fn add_credential(
    connection: &mut rusqlite::Connection,
    unlocked: &Unlocked,
    credential_id: &[u8],
    credential_key: &[u8],
    now_ms: u64,
    audit: AuditRecorder<'_>,
) -> Result<(), ProtocolError> {
    let root = bip39_store::load_root(connection, &unlocked.wallet_id)?
        .ok_or_else(|| invalid(ProtocolErrorCode::ApprovalNotFound, "wallet not found"))?;
    let wrap_id = hex::encode(credential_id);
    if bip39_store::wraps(connection, &unlocked.wallet_id)?
        .iter()
        .any(|record| record.wrap_id == wrap_id)
    {
        return Err(invalid(
            ProtocolErrorCode::OperationIdConflict,
            "credential ID already exists",
        ));
    }
    let wrap = encrypt(
        &SecretBytes::new(credential_key.to_vec()),
        unlocked.wkek(),
        &credential_aad(&unlocked.wallet_id, &Base64UrlBytes::from_bytes(credential_id), &root.root_ciphertext_fingerprint, root.wrap_format_version)?,
    )?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(storage)?;
    bip39_store::put_wrap(
        &transaction,
        &WrapRecord {
            wrap_id,
            wallet_id: unlocked.wallet_id.clone(),
            wrap_kind: bip39_store::WRAP_KIND_CREDENTIAL,
            active: true,
            wrap_format_version: root.wrap_format_version,
            wrapped_wkek: WrappedBlob {
                nonce: wrap.nonce.decode(),
                ciphertext: wrap.ciphertext.decode(),
            },
            snapshot_epoch: root.snapshot_epoch,
            created_at_ms: now_ms,
        },
    )?;
    audit(
        &transaction,
        "custody.credential_added",
        serde_json::json!({ "wallet_id": unlocked.wallet_id.as_str() }),
    )?;
    transaction.commit().map_err(storage)
}

/// Replace a passkey in place (same credential id, new wrap), in one tx.
pub fn replace_credential(
    connection: &mut rusqlite::Connection,
    unlocked: &Unlocked,
    credential_id: &[u8],
    credential_key: &[u8],
    now_ms: u64,
    audit: AuditRecorder<'_>,
) -> Result<(), ProtocolError> {
    let root = bip39_store::load_root(connection, &unlocked.wallet_id)?
        .ok_or_else(|| invalid(ProtocolErrorCode::ApprovalNotFound, "wallet not found"))?;
    let wrap = encrypt(
        &SecretBytes::new(credential_key.to_vec()),
        unlocked.wkek(),
        &credential_aad(&unlocked.wallet_id, &Base64UrlBytes::from_bytes(credential_id), &root.root_ciphertext_fingerprint, root.wrap_format_version)?,
    )?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(storage)?;
    bip39_store::put_wrap(
        &transaction,
        &WrapRecord {
            wrap_id: hex::encode(credential_id),
            wallet_id: unlocked.wallet_id.clone(),
            wrap_kind: bip39_store::WRAP_KIND_CREDENTIAL,
            active: true,
            wrap_format_version: root.wrap_format_version,
            wrapped_wkek: WrappedBlob {
                nonce: wrap.nonce.decode(),
                ciphertext: wrap.ciphertext.decode(),
            },
            snapshot_epoch: root.snapshot_epoch,
            created_at_ms: now_ms,
        },
    )?;
    audit(
        &transaction,
        "custody.credential_replaced",
        serde_json::json!({ "wallet_id": unlocked.wallet_id.as_str() }),
    )?;
    transaction.commit().map_err(storage)
}

/// Deactivate a passkey, refusing to remove the final usable factor unless a
/// recovery wrap remains active.
pub fn deactivate_credential(
    connection: &mut rusqlite::Connection,
    wallet_id: &Token,
    credential_id: &[u8],
    now_ms: u64,
    audit: AuditRecorder<'_>,
) -> Result<(), ProtocolError> {
    let active_credentials = bip39_store::wraps(connection, wallet_id)?
        .into_iter()
        .filter(|record| record.wrap_kind == bip39_store::WRAP_KIND_CREDENTIAL && record.active)
        .count();
    let has_recovery = bip39_store::wraps(connection, wallet_id)?
        .into_iter()
        .any(|record| record.wrap_kind == bip39_store::WRAP_KIND_RECOVERY && record.active);
    let wrap_id = hex::encode(credential_id);
    let target = bip39_store::wraps(connection, wallet_id)?
        .into_iter()
        .find(|record| record.wrap_id == wrap_id && record.wrap_kind == bip39_store::WRAP_KIND_CREDENTIAL)
        .ok_or_else(|| invalid(ProtocolErrorCode::ApprovalNotFound, "credential not found"))?;
    if target.active && active_credentials == 1 && !has_recovery {
        return Err(invalid(
            ProtocolErrorCode::ApprovalRearmRequired,
            "cannot revoke the final credential without recovery",
        ));
    }
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(storage)?;
    bip39_store::deactivate_wrap(&transaction, wallet_id, &wrap_id)?;
    audit(
        &transaction,
        "custody.credential_deactivated",
        serde_json::json!({ "wallet_id": wallet_id.as_str(), "now_ms": now_ms }),
    )?;
    transaction.commit().map_err(storage)
}

/// Install the recovery factor (wrap the same WKEK).
pub fn install_recovery(
    connection: &mut rusqlite::Connection,
    unlocked: &Unlocked,
    recovery_id: &str,
    recovery_key: &[u8],
    now_ms: u64,
    audit: AuditRecorder<'_>,
) -> Result<(), ProtocolError> {
    let root = bip39_store::load_root(connection, &unlocked.wallet_id)?
        .ok_or_else(|| invalid(ProtocolErrorCode::ApprovalNotFound, "wallet not found"))?;
    let wrap = encrypt(
        &SecretBytes::new(recovery_key.to_vec()),
        unlocked.wkek(),
        &recovery_aad(&unlocked.wallet_id, &Token::new(recovery_id).map_err(|_| {
            invalid(ProtocolErrorCode::MalformedFrame, "invalid recovery id")
        })?, &root.root_ciphertext_fingerprint, root.wrap_format_version)?,
    )?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(storage)?;
    bip39_store::put_wrap(
        &transaction,
        &WrapRecord {
            wrap_id: recovery_id.to_owned(),
            wallet_id: unlocked.wallet_id.clone(),
            wrap_kind: bip39_store::WRAP_KIND_RECOVERY,
            active: true,
            wrap_format_version: root.wrap_format_version,
            wrapped_wkek: WrappedBlob {
                nonce: wrap.nonce.decode(),
                ciphertext: wrap.ciphertext.decode(),
            },
            snapshot_epoch: root.snapshot_epoch,
            created_at_ms: now_ms,
        },
    )?;
    audit(
        &transaction,
        "custody.recovery_installed",
        serde_json::json!({ "wallet_id": unlocked.wallet_id.as_str() }),
    )?;
    transaction.commit().map_err(storage)
}

/// Atomic rekey: re-encrypt the entropy and re-wrap every factor under a new
/// WKEK in one transaction. `factor_keys` supplies each active factor's wrap
/// key (credential keys from passkey PRF, recovery key from the factor), as
/// the rekey ceremony collects them out-of-band from any database work.
#[allow(clippy::too_many_arguments)]
pub fn rekey(
    connection: &mut rusqlite::Connection,
    unlocked: &Unlocked,
    new_wkek: &[u8],
    factor_keys: &[(String, &'static str, Vec<u8>)],
    now_ms: u64,
    audit: AuditRecorder<'_>,
) -> Result<(), ProtocolError> {
    let root = bip39_store::load_root(connection, &unlocked.wallet_id)?
        .ok_or_else(|| invalid(ProtocolErrorCode::ApprovalNotFound, "wallet not found"))?;
    let entropy = decrypt(
        &wrap_kind(unlocked.wkek()),
        &crate::custody::EncryptedBlob {
            nonce: Base64UrlBytes::from_bytes(&root.wrapped_entropy.nonce),
            ciphertext: Base64UrlBytes::from_bytes(&root.wrapped_entropy.ciphertext),
        },
        &root_aad(&unlocked.wallet_id, root.wrap_format_version),
    )
    .map_err(|_| invalid(ProtocolErrorCode::UnauthenticatedPeer, "root authentication failed"))?;
    if !bip39_store::entropy_plaintext_matches_metadata(&entropy, root.entropy_bits) {
        return Err(invalid(
            ProtocolErrorCode::MalformedFrame,
            "decrypted entropy length does not match metadata",
        ));
    }
    let new_wrapped = encrypted_root_blob(&unlocked.wallet_id, root.wrap_format_version, new_wkek, &entropy)?;

    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(storage)?;
    bip39_store::replace_wrapped_entropy(
        &transaction,
        &unlocked.wallet_id,
        &new_wrapped,
        root.revision,
    )?;
    for (wrap_id, wrap_kind, factor_key) in factor_keys {
        let (aad, kind) = if *wrap_kind == bip39_store::WRAP_KIND_RECOVERY {
            (
                recovery_aad(
                    &unlocked.wallet_id,
                    &Token::new(wrap_id).map_err(|_| {
                        invalid(ProtocolErrorCode::MalformedFrame, "invalid recovery id")
                    })?,
                    &Digest32::from_bytes(Sha256::digest(&new_wrapped.ciphertext).into()),
                    root.wrap_format_version,
                )?,
                bip39_store::WRAP_KIND_RECOVERY,
            )
        } else {
            (
                credential_aad(
                    &unlocked.wallet_id,
                    &Base64UrlBytes::from_bytes(&hex::decode(wrap_id).map_err(|_| {
                        invalid(ProtocolErrorCode::MalformedFrame, "invalid credential id")
                    })?),
                    &Digest32::from_bytes(Sha256::digest(&new_wrapped.ciphertext).into()),
                    root.wrap_format_version,
                )?,
                bip39_store::WRAP_KIND_CREDENTIAL,
            )
        };
        let wrapped = encrypt(&SecretBytes::new(factor_key.clone()), new_wkek, &aad)?;
        bip39_store::put_wrap(
            &transaction,
            &WrapRecord {
                wrap_id: wrap_id.clone(),
                wallet_id: unlocked.wallet_id.clone(),
                wrap_kind: kind,
                active: true,
                wrap_format_version: root.wrap_format_version,
                wrapped_wkek: WrappedBlob {
                    nonce: wrapped.nonce.decode(),
                    ciphertext: wrapped.ciphertext.decode(),
                },
                snapshot_epoch: root.snapshot_epoch + 1,
                created_at_ms: now_ms,
            },
        )?;
    }
    audit(
        &transaction,
        "custody.rekeyed",
        serde_json::json!({ "wallet_id": unlocked.wallet_id.as_str() }),
    )?;
    transaction.commit().map_err(storage)
}

/// Export the mnemonic transiently. The words never touch storage, the
/// backup, the audit chain, or any projection — they exist only in this
/// zeroizing return value, which the ceremony hands directly to the user.
pub fn export_mnemonic(
    connection: &rusqlite::Connection,
    unlocked: &Unlocked,
) -> Result<Zeroizing<String>, ProtocolError> {
    let root = bip39_store::load_root(connection, &unlocked.wallet_id)?
        .ok_or_else(|| invalid(ProtocolErrorCode::ApprovalNotFound, "wallet not found"))?;
    let entropy = decrypt(
        &wrap_kind(unlocked.wkek()),
        &crate::custody::EncryptedBlob {
            nonce: Base64UrlBytes::from_bytes(&root.wrapped_entropy.nonce),
            ciphertext: Base64UrlBytes::from_bytes(&root.wrapped_entropy.ciphertext),
        },
        &root_aad(&unlocked.wallet_id, root.wrap_format_version),
    )
    .map_err(|_| invalid(ProtocolErrorCode::UnauthenticatedPeer, "root authentication failed"))?;
    if !bip39_store::entropy_plaintext_matches_metadata(&entropy, root.entropy_bits) {
        return Err(invalid(
            ProtocolErrorCode::MalformedFrame,
            "decrypted entropy length does not match metadata",
        ));
    }
    mnemonic_from_entropy(&entropy)
        .map_err(|error| invalid(ProtocolErrorCode::MalformedFrame, error.to_string()))
}

/// Import a mnemonic into a new wallet id. v1 rejects non-empty passphrases
/// (they are rejected before any state is created) and validates checksum.
#[allow(clippy::too_many_arguments)]
pub fn import_mnemonic(
    connection: &mut rusqlite::Connection,
    new_wallet_id: &Token,
    mnemonic: &str,
    passphrase: &str,
    wkek: &[u8],
    first_credential_id: &[u8],
    first_credential_key: &[u8],
    now_ms: u64,
    audit: AuditRecorder<'_>,
) -> Result<(), ProtocolError> {
    if !passphrase.is_empty() {
        return Err(invalid(
            ProtocolErrorCode::MalformedFrame,
            "non-empty BIP-39 passphrases are rejected for v1",
        ));
    }
    let parsed = parse_mnemonic(mnemonic)
        .map_err(|error| invalid(ProtocolErrorCode::MalformedFrame, error.to_string()))?;
    let entropy = parsed.entropy();
    register_wallet(
        connection,
        new_wallet_id,
        &entropy,
        wkek,
        first_credential_id,
        first_credential_key,
        None,
        now_ms,
        audit,
    )
}

/// Consistent backup via the SQLite backup API.
pub fn backup(connection: &rusqlite::Connection, destination: &std::path::Path) -> Result<(), ProtocolError> {
    bip39_store::backup_database(connection, destination)
}
