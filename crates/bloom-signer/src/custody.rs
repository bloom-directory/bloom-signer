use bloom_signer_backend_api::SecretBytes;
use bloom_triad_protocol::{Base64UrlBytes, Digest32, ProtocolError, ProtocolErrorCode, Token};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signer as _, SigningKey};
use hkdf::Hkdf;
use parking_lot::Mutex;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const ROOT_AAD: &[u8] = b"bloom-wallet-root/v1";
const POLICY_KEY_AAD: &[u8] = b"bloom-policy-signing-key/v1";
const LOCAL_BACKEND_WRAP_INFO: &[u8] = b"bloom-local-backend-wrap/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedBlob {
    pub nonce: Base64UrlBytes,
    pub ciphertext: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialWrap {
    pub credential_id: Base64UrlBytes,
    pub active: bool,
    pub wrap_format_version: u32,
    pub wrapped_wkek: EncryptedBlob,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryWrap {
    pub recovery_id: Token,
    pub wrap_format_version: u32,
    pub wrapped_wkek: EncryptedBlob,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletCustodyBackup {
    pub wallet_id: Token,
    pub policy_version: u64,
    pub wrap_format_version: u32,
    pub encrypted_root: EncryptedBlob,
    pub encrypted_policy_signing_key: EncryptedBlob,
    pub credential_wraps: Vec<CredentialWrap>,
    pub recovery_wrap: Option<RecoveryWrap>,
}

struct CustodyState {
    backup: WalletCustodyBackup,
    storage_path: Option<PathBuf>,
}

pub struct WalletCustody {
    state: Mutex<CustodyState>,
}

pub struct UnlockedWallet {
    wallet_id: Token,
    root: Zeroizing<Vec<u8>>,
    policy_signing_seed: Zeroizing<Vec<u8>>,
    wkek: Zeroizing<Vec<u8>>,
}

impl UnlockedWallet {
    pub fn wallet_id(&self) -> &Token {
        &self.wallet_id
    }

    pub fn root_fingerprint(&self) -> Digest32 {
        Digest32::from_bytes(Sha256::digest(self.root.as_slice()).into())
    }

    pub fn policy_verifying_key(&self) -> Result<[u8; 32], ProtocolError> {
        let seed: [u8; 32] = self
            .policy_signing_seed
            .as_slice()
            .try_into()
            .map_err(|_| {
                protocol(
                    ProtocolErrorCode::MalformedFrame,
                    "policy signing seed length is invalid",
                )
            })?;
        Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    }

    pub(crate) fn sign_policy_message(&self, message: &[u8]) -> Result<[u8; 64], ProtocolError> {
        let seed: [u8; 32] = self
            .policy_signing_seed
            .as_slice()
            .try_into()
            .map_err(|_| {
                protocol(
                    ProtocolErrorCode::MalformedFrame,
                    "policy signing seed length is invalid",
                )
            })?;
        Ok(SigningKey::from_bytes(&seed).sign(message).to_bytes())
    }

    /// Derive the stable local-backend wrapping key from the wallet WKEK.
    /// Every credential independently unwraps the same WKEK, so backend
    /// activation remains credential-agnostic across add/replace/recovery.
    pub(crate) fn local_backend_activation_secret(&self) -> Result<SecretBytes, ProtocolError> {
        let salt: [u8; 32] = Sha256::digest(self.wallet_id.as_str().as_bytes()).into();
        let mut key = vec![0_u8; 32];
        Hkdf::<Sha256>::new(Some(&salt), self.wkek.as_slice())
            .expand(LOCAL_BACKEND_WRAP_INFO, &mut key)
            .map_err(|_| {
                protocol(
                    ProtocolErrorCode::BackendInvalidRequest,
                    "local backend wrap-key derivation failed",
                )
            })?;
        Ok(SecretBytes::new(key))
    }
}

impl WalletCustody {
    pub fn register(
        wallet_id: Token,
        root: SecretBytes,
        policy_signing_seed: SecretBytes,
        wkek: SecretBytes,
        first_credential_id: Base64UrlBytes,
        first_credential_key: SecretBytes,
    ) -> Result<Self, ProtocolError> {
        validate_key(&wkek)?;
        validate_key(&first_credential_key)?;
        if root.expose_to_backend().is_empty()
            || policy_signing_seed.expose_to_backend().len() != 32
        {
            return Err(protocol(
                ProtocolErrorCode::BackendInvalidRequest,
                "registration root or policy signing key has invalid length",
            ));
        }
        let wrap_format_version = 1;
        let encrypted_root = encrypt(
            &wkek,
            root.expose_to_backend(),
            &root_aad(&wallet_id, wrap_format_version),
        )?;
        let encrypted_policy_signing_key = encrypt(
            &wkek,
            policy_signing_seed.expose_to_backend(),
            &policy_key_aad(&wallet_id, wrap_format_version),
        )?;
        let root_fingerprint = root_ciphertext_fingerprint(&encrypted_root);
        let wrapped_wkek = encrypt(
            &first_credential_key,
            wkek.expose_to_backend(),
            &credential_aad(
                &wallet_id,
                &first_credential_id,
                &root_fingerprint,
                wrap_format_version,
            )?,
        )?;
        Ok(Self {
            state: Mutex::new(CustodyState {
                backup: WalletCustodyBackup {
                    wallet_id,
                    policy_version: 1,
                    wrap_format_version,
                    encrypted_root,
                    encrypted_policy_signing_key,
                    credential_wraps: vec![CredentialWrap {
                        credential_id: first_credential_id,
                        active: true,
                        wrap_format_version,
                        wrapped_wkek,
                    }],
                    recovery_wrap: None,
                },
                storage_path: None,
            }),
        })
    }

    pub fn register_at(
        storage_path: impl AsRef<Path>,
        wallet_id: Token,
        root: SecretBytes,
        policy_signing_seed: SecretBytes,
        wkek: SecretBytes,
        first_credential_id: Base64UrlBytes,
        first_credential_key: SecretBytes,
    ) -> Result<Self, ProtocolError> {
        let custody = Self::register(
            wallet_id,
            root,
            policy_signing_seed,
            wkek,
            first_credential_id,
            first_credential_key,
        )?;
        {
            let mut state = custody.state.lock();
            state.storage_path = Some(storage_path.as_ref().to_path_buf());
            persist_custody(&state)?;
        }
        Ok(custody)
    }

    pub fn open_at(storage_path: impl AsRef<Path>) -> Result<Self, ProtocolError> {
        let bytes = fs::read(storage_path.as_ref()).map_err(|error| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                format!("custody backup read failed: {error}"),
            )
        })?;
        let backup: WalletCustodyBackup = serde_json::from_slice(&bytes)
            .map_err(|error| protocol(ProtocolErrorCode::MalformedFrame, error.to_string()))?;
        let custody = Self::restore(backup)?;
        custody.state.lock().storage_path = Some(storage_path.as_ref().to_path_buf());
        Ok(custody)
    }

    pub fn restore(backup: WalletCustodyBackup) -> Result<Self, ProtocolError> {
        validate_backup_shape(&backup)?;
        Ok(Self {
            state: Mutex::new(CustodyState {
                backup,
                storage_path: None,
            }),
        })
    }

    pub fn backup(&self) -> WalletCustodyBackup {
        self.state.lock().backup.clone()
    }

    pub fn unlock_with_credential(
        &self,
        credential_id: &Base64UrlBytes,
        credential_key: &SecretBytes,
    ) -> Result<UnlockedWallet, ProtocolError> {
        validate_key(credential_key)?;
        let state = self.state.lock();
        let wrap = state
            .backup
            .credential_wraps
            .iter()
            .find(|wrap| wrap.active && &wrap.credential_id == credential_id)
            .ok_or_else(|| {
                protocol(
                    ProtocolErrorCode::ApprovalRevoked,
                    "credential is absent or revoked",
                )
            })?;
        let wkek = Zeroizing::new(decrypt(
            credential_key,
            &wrap.wrapped_wkek,
            &credential_aad(
                &state.backup.wallet_id,
                credential_id,
                &root_ciphertext_fingerprint(&state.backup.encrypted_root),
                wrap.wrap_format_version,
            )?,
        )?);
        unlock_with_wkek(&state.backup, &wkek)
    }

    pub fn unlock_with_recovery(
        &self,
        recovery_id: &Token,
        recovery_key: &SecretBytes,
    ) -> Result<UnlockedWallet, ProtocolError> {
        validate_key(recovery_key)?;
        let state = self.state.lock();
        let recovery = state
            .backup
            .recovery_wrap
            .as_ref()
            .filter(|wrap| &wrap.recovery_id == recovery_id)
            .ok_or_else(|| {
                protocol(
                    ProtocolErrorCode::ApprovalNotFound,
                    "recovery factor is unavailable",
                )
            })?;
        let wkek = Zeroizing::new(decrypt(
            recovery_key,
            &recovery.wrapped_wkek,
            &recovery_aad(
                &state.backup.wallet_id,
                recovery_id,
                &root_ciphertext_fingerprint(&state.backup.encrypted_root),
                recovery.wrap_format_version,
            )?,
        )?);
        unlock_with_wkek(&state.backup, &wkek)
    }

    pub fn add_credential(
        &self,
        unlocked: &UnlockedWallet,
        credential_id: Base64UrlBytes,
        credential_key: &SecretBytes,
    ) -> Result<(), ProtocolError> {
        validate_key(credential_key)?;
        let mut state = self.state.lock();
        let previous = state.backup.clone();
        if state
            .backup
            .credential_wraps
            .iter()
            .any(|wrap| wrap.credential_id == credential_id)
        {
            return Err(protocol(
                ProtocolErrorCode::OperationIdConflict,
                "credential ID already exists",
            ));
        }
        let wkek = recover_wkek_from_unlocked(&state.backup, unlocked)?;
        let wrapped_wkek = encrypt(
            credential_key,
            &wkek,
            &credential_aad(
                &state.backup.wallet_id,
                &credential_id,
                &root_ciphertext_fingerprint(&state.backup.encrypted_root),
                state.backup.wrap_format_version,
            )?,
        )?;
        let version = state.backup.wrap_format_version;
        state.backup.credential_wraps.push(CredentialWrap {
            credential_id,
            active: true,
            wrap_format_version: version,
            wrapped_wkek,
        });
        if let Err(error) = persist_custody(&state) {
            state.backup = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn revoke_credential(&self, credential_id: &Base64UrlBytes) -> Result<(), ProtocolError> {
        let mut state = self.state.lock();
        let previous = state.backup.clone();
        let active_count = state
            .backup
            .credential_wraps
            .iter()
            .filter(|wrap| wrap.active)
            .count();
        let has_recovery = state.backup.recovery_wrap.is_some();
        let wrap = state
            .backup
            .credential_wraps
            .iter_mut()
            .find(|wrap| &wrap.credential_id == credential_id)
            .ok_or_else(|| protocol(ProtocolErrorCode::ApprovalNotFound, "credential not found"))?;
        if wrap.active && active_count == 1 && !has_recovery {
            return Err(protocol(
                ProtocolErrorCode::ApprovalRearmRequired,
                "cannot revoke the final credential without recovery",
            ));
        }
        wrap.active = false;
        if let Err(error) = persist_custody(&state) {
            state.backup = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn set_recovery(
        &self,
        unlocked: &UnlockedWallet,
        recovery_id: Token,
        recovery_key: &SecretBytes,
    ) -> Result<(), ProtocolError> {
        validate_key(recovery_key)?;
        let mut state = self.state.lock();
        let previous = state.backup.clone();
        let wkek = recover_wkek_from_unlocked(&state.backup, unlocked)?;
        let version = state.backup.wrap_format_version;
        let wrapped_wkek = encrypt(
            recovery_key,
            &wkek,
            &recovery_aad(
                &state.backup.wallet_id,
                &recovery_id,
                &root_ciphertext_fingerprint(&state.backup.encrypted_root),
                version,
            )?,
        )?;
        state.backup.recovery_wrap = Some(RecoveryWrap {
            recovery_id,
            wrap_format_version: version,
            wrapped_wkek,
        });
        if let Err(error) = persist_custody(&state) {
            state.backup = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn set_policy_version(&self, next_version: u64) -> Result<(), ProtocolError> {
        let mut state = self.state.lock();
        let previous = state.backup.clone();
        if next_version <= state.backup.policy_version {
            return Err(protocol(
                ProtocolErrorCode::PolicyBaselineStale,
                "policy version must increase",
            ));
        }
        state.backup.policy_version = next_version;
        if let Err(error) = persist_custody(&state) {
            state.backup = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn rekey_wrap_format(
        &self,
        unlocked: &UnlockedWallet,
        next_version: u32,
        credential_keys: &BTreeMap<String, SecretBytes>,
        recovery_key: Option<&SecretBytes>,
    ) -> Result<(), ProtocolError> {
        let mut state = self.state.lock();
        if next_version <= state.backup.wrap_format_version {
            return Err(protocol(
                ProtocolErrorCode::PolicyBaselineStale,
                "wrap format version must increase",
            ));
        }
        let wkek = recover_wkek_from_unlocked(&state.backup, unlocked)?;
        let mut replacement = state.backup.clone();
        replacement.wrap_format_version = next_version;
        let wkek_key = SecretBytes::new(wkek.to_vec());
        replacement.encrypted_root = encrypt(
            &wkek_key,
            unlocked.root.as_slice(),
            &root_aad(&replacement.wallet_id, next_version),
        )?;
        replacement.encrypted_policy_signing_key = encrypt(
            &wkek_key,
            unlocked.policy_signing_seed.as_slice(),
            &policy_key_aad(&replacement.wallet_id, next_version),
        )?;
        let replacement_root_fingerprint = root_ciphertext_fingerprint(&replacement.encrypted_root);
        for wrap in replacement
            .credential_wraps
            .iter_mut()
            .filter(|wrap| wrap.active)
        {
            let key = credential_keys
                .get(wrap.credential_id.encoded())
                .ok_or_else(|| {
                    protocol(
                        ProtocolErrorCode::ApprovalRearmRequired,
                        "all active credential keys are required for atomic rekey",
                    )
                })?;
            validate_key(key)?;
            wrap.wrap_format_version = next_version;
            wrap.wrapped_wkek = encrypt(
                key,
                &wkek,
                &credential_aad(
                    &replacement.wallet_id,
                    &wrap.credential_id,
                    &replacement_root_fingerprint,
                    next_version,
                )?,
            )?;
        }
        if let Some(recovery) = replacement.recovery_wrap.as_mut() {
            let key = recovery_key.ok_or_else(|| {
                protocol(
                    ProtocolErrorCode::ApprovalRearmRequired,
                    "recovery key is required for atomic rekey",
                )
            })?;
            validate_key(key)?;
            recovery.wrap_format_version = next_version;
            recovery.wrapped_wkek = encrypt(
                key,
                &wkek,
                &recovery_aad(
                    &replacement.wallet_id,
                    &recovery.recovery_id,
                    &replacement_root_fingerprint,
                    next_version,
                )?,
            )?;
        }
        let previous = std::mem::replace(&mut state.backup, replacement);
        if let Err(error) = persist_custody(&state) {
            state.backup = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn active_credential_ids(&self) -> BTreeSet<String> {
        self.state
            .lock()
            .backup
            .credential_wraps
            .iter()
            .filter(|wrap| wrap.active)
            .map(|wrap| wrap.credential_id.encoded().to_owned())
            .collect()
    }
}

fn recover_wkek_from_unlocked(
    backup: &WalletCustodyBackup,
    unlocked: &UnlockedWallet,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let candidate = unlock_with_wkek(backup, unlocked.wkek.as_slice())?;
    if candidate.root_fingerprint() != unlocked.root_fingerprint()
        || candidate.policy_verifying_key()? != unlocked.policy_verifying_key()?
    {
        return Err(protocol(
            ProtocolErrorCode::UnauthenticatedPeer,
            "unlocked session does not match wallet custody state",
        ));
    }
    Ok(Zeroizing::new(unlocked.wkek.to_vec()))
}

fn unlock_with_wkek(
    backup: &WalletCustodyBackup,
    wkek: &[u8],
) -> Result<UnlockedWallet, ProtocolError> {
    let key = SecretBytes::new(wkek.to_vec());
    let root = decrypt(
        &key,
        &backup.encrypted_root,
        &root_aad(&backup.wallet_id, backup.wrap_format_version),
    )?;
    let policy_signing_seed = decrypt(
        &key,
        &backup.encrypted_policy_signing_key,
        &policy_key_aad(&backup.wallet_id, backup.wrap_format_version),
    )?;
    Ok(UnlockedWallet {
        wallet_id: backup.wallet_id.clone(),
        root: Zeroizing::new(root),
        policy_signing_seed: Zeroizing::new(policy_signing_seed),
        wkek: Zeroizing::new(wkek.to_vec()),
    })
}

fn encrypt(
    key: &SecretBytes,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedBlob, ProtocolError> {
    validate_key(key)?;
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key.expose_to_backend()))
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| {
            protocol(
                ProtocolErrorCode::ServiceUnavailable,
                "custody encryption failed",
            )
        })?;
    Ok(EncryptedBlob {
        nonce: Base64UrlBytes::from_bytes(&nonce),
        ciphertext: Base64UrlBytes::from_bytes(&ciphertext),
    })
}

fn decrypt(key: &SecretBytes, blob: &EncryptedBlob, aad: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    validate_key(key)?;
    let nonce: [u8; 24] = blob.nonce.decode().try_into().map_err(|_| {
        protocol(
            ProtocolErrorCode::MalformedFrame,
            "custody nonce must contain 24 bytes",
        )
    })?;
    XChaCha20Poly1305::new(Key::from_slice(key.expose_to_backend()))
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &blob.ciphertext.decode(),
                aad,
            },
        )
        .map_err(|_| {
            protocol(
                ProtocolErrorCode::UnauthenticatedPeer,
                "custody wrap authentication failed",
            )
        })
}

fn validate_key(key: &SecretBytes) -> Result<(), ProtocolError> {
    if key.expose_to_backend().len() != 32 {
        return Err(protocol(
            ProtocolErrorCode::BackendInvalidRequest,
            "custody wrapping key must contain 32 bytes",
        ));
    }
    Ok(())
}

fn validate_backup_shape(backup: &WalletCustodyBackup) -> Result<(), ProtocolError> {
    if backup.wrap_format_version == 0
        || backup.credential_wraps.is_empty()
        || backup.credential_wraps.iter().any(|wrap| {
            wrap.wrap_format_version > backup.wrap_format_version
                || (wrap.active && wrap.wrap_format_version != backup.wrap_format_version)
                || wrap.wrapped_wkek.nonce.decode().len() != 24
        })
    {
        return Err(protocol(
            ProtocolErrorCode::MalformedFrame,
            "custody backup has inconsistent wrap metadata",
        ));
    }
    Ok(())
}

fn root_aad(wallet_id: &Token, wrap_format_version: u32) -> Vec<u8> {
    [
        ROOT_AAD,
        wallet_id.as_str().as_bytes(),
        &wrap_format_version.to_be_bytes(),
    ]
    .concat()
}

fn policy_key_aad(wallet_id: &Token, wrap_format_version: u32) -> Vec<u8> {
    [
        POLICY_KEY_AAD,
        wallet_id.as_str().as_bytes(),
        &wrap_format_version.to_be_bytes(),
    ]
    .concat()
}

fn credential_aad(
    wallet_id: &Token,
    credential_id: &Base64UrlBytes,
    root_ciphertext_fingerprint: &Digest32,
    wrap_format_version: u32,
) -> Result<Vec<u8>, ProtocolError> {
    #[derive(Serialize)]
    struct Aad<'a> {
        wallet_id: &'a Token,
        credential_id: &'a Base64UrlBytes,
        root_ciphertext_fingerprint: &'a Digest32,
        wrap_format_version: u32,
    }
    serde_jcs::to_vec(&Aad {
        wallet_id,
        credential_id,
        root_ciphertext_fingerprint,
        wrap_format_version,
    })
    .map_err(|error| protocol(ProtocolErrorCode::MalformedFrame, error.to_string()))
}

fn recovery_aad(
    wallet_id: &Token,
    recovery_record_id: &Token,
    root_ciphertext_fingerprint: &Digest32,
    wrap_format_version: u32,
) -> Result<Vec<u8>, ProtocolError> {
    #[derive(Serialize)]
    struct Aad<'a> {
        wallet_id: &'a Token,
        recovery_record_id: &'a Token,
        root_ciphertext_fingerprint: &'a Digest32,
        wrap_format_version: u32,
    }
    serde_jcs::to_vec(&Aad {
        wallet_id,
        recovery_record_id,
        root_ciphertext_fingerprint,
        wrap_format_version,
    })
    .map_err(|error| protocol(ProtocolErrorCode::MalformedFrame, error.to_string()))
}

fn root_ciphertext_fingerprint(encrypted_root: &EncryptedBlob) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(encrypted_root.ciphertext.decode()).into())
}

fn persist_custody(state: &CustodyState) -> Result<(), ProtocolError> {
    let Some(path) = &state.storage_path else {
        return Ok(());
    };
    let bytes = serde_jcs::to_vec(&state.backup)
        .map_err(|error| protocol(ProtocolErrorCode::MalformedFrame, error.to_string()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| protocol(ProtocolErrorCode::MalformedFrame, "invalid custody path"))?;
    let temporary = path.with_file_name(format!(".{file_name}.new"));
    fs::write(&temporary, bytes).map_err(|error| {
        protocol(
            ProtocolErrorCode::ServiceUnavailable,
            format!("custody staging write failed: {error}"),
        )
    })?;
    fs::rename(&temporary, path).map_err(|error| {
        protocol(
            ProtocolErrorCode::ServiceUnavailable,
            format!("custody atomic publish failed: {error}"),
        )
    })
}

fn protocol(code: ProtocolErrorCode, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(code, message)
}
