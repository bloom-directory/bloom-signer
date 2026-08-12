//! One-time conversion of the historical single-passkey wallet envelope.
//!
//! This module is deliberately not a signing backend. It can stage one exact
//! legacy format and release its root only to the current WKEK registration
//! path after a verified WebAuthn assertion.

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
};

use bloom_signer_api::{
    Base64UrlBytes, DecimalU64, Digest32, OperationId, ProtocolError, ProtocolErrorCode, Token,
    WebAuthnCredential,
};
use bloom_signer_backend_api::SecretBytes;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint as _};
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;
use zeroize::{Zeroize as _, Zeroizing};

use crate::webauthn::es256_cose_public_key;

pub const LEGACY_PASSKEY_INPUT_CLASS: &str = "legacy_passkey_v1_prf";
pub const LEGACY_RECEIPT_SCHEMA: &str = "bloom.legacy_passkey_migration_receipt.v1";

const STAGED_SCHEMA: &str = "bloom.signer_legacy_passkey_staged.v1";
const POLICY_MODE: &str = "restrictive_current_policy";
const PASSKEY_AAD: &[u8] = b"bloom-keystore-passkey";
const MAX_SMALL_FILE: u64 = 16 * 1024;
const MAX_KEY_FILE: u64 = 4 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyMigrationReceipt {
    pub schema: String,
    pub operation_id: OperationId,
    pub wallet_name: Token,
    pub address: String,
    pub public_key_fingerprint: Digest32,
    pub credential_id_fingerprint: Digest32,
    pub legacy_format_version: u8,
    pub bundle_digest: Digest32,
    pub policy_mode: String,
    pub exact_terms_digest: Digest32,
}

impl LegacyMigrationReceipt {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema != LEGACY_RECEIPT_SCHEMA
            || self.legacy_format_version != 1
            || self.policy_mode != POLICY_MODE
            || self.exact_terms_digest != receipt_terms_digest(self)?
        {
            return Err(malformed("legacy migration receipt is invalid"));
        }
        Ok(())
    }

    pub fn public_terms(
        &self,
    ) -> Result<bloom_signer_api::LegacyPasskeyMigrationPublic, ProtocolError> {
        Ok(bloom_signer_api::LegacyPasskeyMigrationPublic {
            schema: Token::new(self.schema.clone())?,
            wallet_name: self.wallet_name.clone(),
            address: self.address.clone(),
            public_key_fingerprint: self.public_key_fingerprint.clone(),
            credential_id_fingerprint: self.credential_id_fingerprint.clone(),
            legacy_format_version: self.legacy_format_version,
            bundle_digest: self.bundle_digest.clone(),
            policy_mode: Token::new(self.policy_mode.clone())?,
        })
    }
}

#[derive(Clone)]
pub struct PreparedLegacyMigration {
    pub receipt: LegacyMigrationReceipt,
    pub credential: WebAuthnCredential,
}

#[derive(Clone)]
pub struct LegacyMigrationStore {
    root: PathBuf,
    expected_owner: u32,
}

impl LegacyMigrationStore {
    pub fn create_for_current_process(
        root: impl Into<PathBuf>,
        expected_owner: u32,
    ) -> Result<Self, ProtocolError> {
        let root = root.into();
        for path in [root.clone(), root.join("pending"), root.join("consumed")] {
            fs::create_dir_all(&path).map_err(storage)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(storage)?;
            require_private_directory(&path, expected_owner)?;
        }
        Self::open(root, expected_owner)
    }

    pub fn open(root: impl Into<PathBuf>, expected_owner: u32) -> Result<Self, ProtocolError> {
        let root = root.into();
        require_private_directory(&root, expected_owner)?;
        require_private_directory(&root.join("pending"), expected_owner)?;
        require_private_directory(&root.join("consumed"), expected_owner)?;
        Ok(Self {
            root,
            expected_owner,
        })
    }

    pub fn load(
        &self,
        operation_id: &OperationId,
    ) -> Result<PreparedLegacyMigration, ProtocolError> {
        let staged = self.load_staged(operation_id)?;
        staged.receipt.validate()?;
        if staged.receipt.operation_id != *operation_id
            || staged.bundle_digest()? != staged.receipt.bundle_digest
        {
            return Err(malformed("staged legacy migration digest is invalid"));
        }
        Ok(PreparedLegacyMigration {
            receipt: staged.receipt,
            credential: staged.credential,
        })
    }

    pub fn decrypt_root(
        &self,
        operation_id: &OperationId,
        prf: &SecretBytes,
    ) -> Result<SecretBytes, ProtocolError> {
        let staged = self.load_staged(operation_id)?;
        if staged.bundle_digest()? != staged.receipt.bundle_digest {
            return Err(malformed("staged legacy migration digest is invalid"));
        }
        staged.decrypt_and_validate(prf)
    }

    pub fn consume(&self, operation_id: &OperationId) -> Result<(), ProtocolError> {
        let source = self.pending_path(operation_id);
        let staged = self.load_staged(operation_id)?;
        let marker = self
            .root
            .join("consumed")
            .join(format!("{}.json", operation_id.as_str()));
        write_atomic_private(
            &marker,
            &serde_jcs::to_vec(&staged.receipt).map_err(malformed)?,
            self.expected_owner,
        )?;
        fs::remove_file(source.join("staged.json")).map_err(storage)?;
        fs::remove_dir(source).map_err(storage)?;
        Ok(())
    }

    fn load_staged(
        &self,
        operation_id: &OperationId,
    ) -> Result<StagedLegacyPasskey, ProtocolError> {
        let directory = self.pending_path(operation_id);
        require_private_directory(&directory, self.expected_owner)?;
        let path = directory.join("staged.json");
        let bytes = read_owned_regular(&path, self.expected_owner, MAX_SMALL_FILE)?;
        serde_json::from_slice(&bytes).map_err(malformed)
    }

    fn pending_path(&self, operation_id: &OperationId) -> PathBuf {
        self.root.join("pending").join(operation_id.as_str())
    }
}

pub fn stage_legacy_wallet(
    source: &Path,
    migration_root: &Path,
    source_uid: u32,
    signer_uid: u32,
    signer_gid: u32,
) -> Result<LegacyMigrationReceipt, ProtocolError> {
    let source_metadata = fs::symlink_metadata(source).map_err(storage)?;
    if !source_metadata.file_type().is_dir() || source_metadata.uid() != source_uid {
        return Err(malformed(
            "legacy wallet source must be a directory owned by the selected login UID",
        ));
    }
    let wallet_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| malformed("legacy wallet source has no valid wallet name"))?;
    let wallet_name = Token::new(wallet_name.to_owned())?;

    let kind = read_text_file(source, "kind", source_uid, 32)?;
    if kind != "passkey" {
        return Err(malformed("legacy wallet kind must be passkey"));
    }
    let address = read_text_file(source, "address", source_uid, 128)?;
    let public_key_hex = read_text_file(source, "pubkey", source_uid, MAX_KEY_FILE)?;
    validate_public_projection(&address, &public_key_hex)?;
    let prf_salt_hex = read_text_file(source, "prf.salt", source_uid, 128)?;
    let prf_salt = decode_fixed_hex::<32>(&prf_salt_hex, "legacy PRF salt")?;
    let encrypted: LegacyEncryptedKey = serde_json::from_slice(&read_named_file(
        source,
        "encrypted.key",
        source_uid,
        MAX_KEY_FILE,
    )?)
    .map_err(malformed)?;
    encrypted.validate()?;
    let credential_file: LegacyPasskeyFile = serde_json::from_slice(&read_named_file(
        source,
        "passkey.json",
        source_uid,
        MAX_SMALL_FILE,
    )?)
    .map_err(malformed)?;
    let credential = credential_file.into_current(&wallet_name, prf_salt)?;

    let mut operation_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut operation_bytes);
    let operation_id = OperationId::from_bytes(operation_bytes);
    let mut staged = StagedLegacyPasskey {
        schema: STAGED_SCHEMA.to_owned(),
        receipt: LegacyMigrationReceipt {
            schema: LEGACY_RECEIPT_SCHEMA.to_owned(),
            operation_id: operation_id.clone(),
            wallet_name,
            address,
            public_key_fingerprint: digest_bytes(&hex::decode(&public_key_hex).map_err(malformed)?),
            credential_id_fingerprint: digest_bytes(&credential.credential_id.decode()),
            legacy_format_version: 1,
            bundle_digest: Digest32::from_bytes([0_u8; 32]),
            policy_mode: POLICY_MODE.to_owned(),
            exact_terms_digest: Digest32::from_bytes([0_u8; 32]),
        },
        public_key_hex,
        encrypted,
        credential,
    };
    staged.receipt.bundle_digest = staged.bundle_digest()?;
    staged.receipt.exact_terms_digest = receipt_terms_digest(&staged.receipt)?;

    prepare_store_directories(migration_root, signer_uid, signer_gid)?;
    let pending_root = migration_root.join("pending");
    // Staging is replay-safe. A retry of the exact legacy bundle returns the
    // already durable receipt; it never creates a second authority operation.
    // Private temporary directories left by process death are not authority
    // and are removed before a new atomic write begins.
    let mut replay_receipt = None;
    for entry in fs::read_dir(&pending_root).map_err(storage)? {
        let entry = entry.map_err(storage)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| malformed("legacy migration staging name is not UTF-8"))?;
        let path = entry.path();
        require_private_directory(&path, signer_uid)?;
        if name.starts_with(".tmp-") {
            fs::remove_dir_all(&path).map_err(storage)?;
            continue;
        }
        let bytes = read_owned_regular(&path.join("staged.json"), signer_uid, MAX_SMALL_FILE)?;
        let existing: StagedLegacyPasskey = serde_json::from_slice(&bytes).map_err(malformed)?;
        existing.receipt.validate()?;
        if existing.receipt.operation_id.as_str() != name
            || existing.bundle_digest()? != existing.receipt.bundle_digest
        {
            return Err(malformed("existing legacy migration staging is invalid"));
        }
        if existing.receipt.bundle_digest == staged.receipt.bundle_digest {
            replay_receipt = Some(existing.receipt);
        }
    }
    if let Some(receipt) = replay_receipt {
        return Ok(receipt);
    }
    let temporary = pending_root.join(format!(".tmp-{}", operation_id.as_str()));
    let final_path = pending_root.join(operation_id.as_str());
    if final_path.exists() || temporary.exists() {
        return Err(protocol(
            ProtocolErrorCode::OperationIdConflict,
            "legacy migration operation already exists",
        ));
    }
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(&temporary).map_err(storage)?;
    chown_exact(&temporary, signer_uid, signer_gid)?;
    write_new_private(
        &temporary.join("staged.json"),
        &serde_jcs::to_vec(&staged).map_err(malformed)?,
        signer_uid,
        signer_gid,
    )?;
    fs::rename(&temporary, &final_path).map_err(storage)?;
    sync_directory(&pending_root)?;
    Ok(staged.receipt)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StagedLegacyPasskey {
    schema: String,
    receipt: LegacyMigrationReceipt,
    public_key_hex: String,
    encrypted: LegacyEncryptedKey,
    credential: WebAuthnCredential,
}

impl StagedLegacyPasskey {
    fn bundle_digest(&self) -> Result<Digest32, ProtocolError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            wallet_name: &'a Token,
            address: &'a str,
            public_key_hex: &'a str,
            encrypted: &'a LegacyEncryptedKey,
            credential: &'a WebAuthnCredential,
        }
        if self.schema != STAGED_SCHEMA {
            return Err(malformed("staged legacy migration schema is unsupported"));
        }
        Ok(digest_bytes(
            &serde_jcs::to_vec(&Preimage {
                schema: &self.schema,
                wallet_name: &self.receipt.wallet_name,
                address: &self.receipt.address,
                public_key_hex: &self.public_key_hex,
                encrypted: &self.encrypted,
                credential: &self.credential,
            })
            .map_err(malformed)?,
        ))
    }

    fn decrypt_and_validate(&self, prf: &SecretBytes) -> Result<SecretBytes, ProtocolError> {
        let prf = prf.expose_to_backend();
        if prf.len() != 32 {
            return Err(authentication_failed());
        }
        self.encrypted.validate()?;
        let wrap_key = Zeroizing::new(blake3::derive_key("bloom passkey wrap key", prf));
        let nonce = hex::decode(&self.encrypted.nonce_hex).map_err(malformed)?;
        let ciphertext = hex::decode(&self.encrypted.ciphertext_hex).map_err(malformed)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(wrap_key.as_slice()));
        let mut plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: PASSKEY_AAD,
                    },
                )
                .map_err(|_| authentication_failed())?,
        );
        if plaintext.len() != 32
            || validate_private_projection(
                plaintext.as_slice(),
                &self.receipt.address,
                &self.public_key_hex,
            )
            .is_err()
        {
            plaintext.zeroize();
            return Err(authentication_failed());
        }
        Ok(SecretBytes::new(plaintext.to_vec()))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyEncryptedKey {
    v: u8,
    nonce_hex: String,
    ciphertext_hex: String,
}

impl LegacyEncryptedKey {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.v != 1
            || hex::decode(&self.nonce_hex).map_err(malformed)?.len() != 12
            || hex::decode(&self.ciphertext_hex).map_err(malformed)?.len() != 48
        {
            return Err(malformed("legacy encrypted key envelope is invalid"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPasskeyFile {
    cred: LegacyPasskey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPasskey {
    cred_id: Base64UrlBytes,
    cred: LegacyCredential,
    counter: u64,
    transports: serde_json::Value,
    user_verified: bool,
    backup_eligible: bool,
    backup_state: bool,
    registration_policy: serde_json::Value,
    extensions: serde_json::Value,
    attestation: serde_json::Value,
    attestation_format: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCredential {
    type_: String,
    key: LegacyCredentialKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct LegacyCredentialKey {
    EC_EC2: LegacyEc2Key,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyEc2Key {
    curve: String,
    x: Base64UrlBytes,
    y: Base64UrlBytes,
}

impl LegacyPasskeyFile {
    fn into_current(
        self,
        wallet_name: &Token,
        prf_salt: [u8; 32],
    ) -> Result<WebAuthnCredential, ProtocolError> {
        let legacy = self.cred;
        let x = legacy.cred.key.EC_EC2.x.decode();
        let y = legacy.cred.key.EC_EC2.y.decode();
        if legacy.cred.type_ != "ES256"
            || legacy.cred.key.EC_EC2.curve != "SECP256R1"
            || x.len() != 32
            || y.len() != 32
            || legacy.counter > u64::from(u32::MAX)
        {
            return Err(malformed("legacy passkey credential is unsupported"));
        }
        let _ = (
            legacy.transports,
            legacy.user_verified,
            legacy.backup_eligible,
            legacy.backup_state,
            legacy.registration_policy,
            legacy.extensions,
            legacy.attestation,
            legacy.attestation_format,
        );
        Ok(WebAuthnCredential {
            credential_id: legacy.cred_id,
            cose_public_key: es256_cose_public_key(&x, &y)?,
            user_handle: Base64UrlBytes::from_bytes(&legacy_user_handle(wallet_name.as_str())),
            rp_id: Token::new("localhost")?,
            prf_salt: Base64UrlBytes::from_bytes(&prf_salt),
            sign_count: DecimalU64::new(legacy.counter),
        })
    }
}

fn receipt_terms_digest(receipt: &LegacyMigrationReceipt) -> Result<Digest32, ProtocolError> {
    #[derive(Serialize)]
    struct Terms<'a> {
        schema: &'a str,
        operation_id: &'a OperationId,
        wallet_name: &'a Token,
        address: &'a str,
        public_key_fingerprint: &'a Digest32,
        credential_id_fingerprint: &'a Digest32,
        legacy_format_version: u8,
        bundle_digest: &'a Digest32,
        policy_mode: &'a str,
    }
    Ok(digest_bytes(
        &serde_jcs::to_vec(&Terms {
            schema: &receipt.schema,
            operation_id: &receipt.operation_id,
            wallet_name: &receipt.wallet_name,
            address: &receipt.address,
            public_key_fingerprint: &receipt.public_key_fingerprint,
            credential_id_fingerprint: &receipt.credential_id_fingerprint,
            legacy_format_version: receipt.legacy_format_version,
            bundle_digest: &receipt.bundle_digest,
            policy_mode: &receipt.policy_mode,
        })
        .map_err(malformed)?,
    ))
}

fn legacy_user_handle(wallet_name: &str) -> [u8; 16] {
    let hash = blake3::hash(wallet_name.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hash.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

fn validate_public_projection(address: &str, public_key_hex: &str) -> Result<(), ProtocolError> {
    let public = hex::decode(public_key_hex).map_err(malformed)?;
    if !address.starts_with("0x") || address.len() != 42 || public.len() != 65 || public[0] != 4 {
        return Err(malformed("legacy wallet public projection is invalid"));
    }
    Ok(())
}

fn validate_private_projection(
    private_key: &[u8],
    address: &str,
    public_key_hex: &str,
) -> Result<(), ProtocolError> {
    let secret = SecretKey::from_slice(private_key).map_err(|_| authentication_failed())?;
    let public = secret.public_key().to_encoded_point(false);
    if !public
        .as_bytes()
        .eq_ignore_ascii_case(&hex::decode(public_key_hex).map_err(malformed)?)
    {
        return Err(authentication_failed());
    }
    let digest = Keccak256::digest(&public.as_bytes()[1..]);
    let derived = format!("0x{}", hex::encode(&digest[12..]));
    if !derived.eq_ignore_ascii_case(address) {
        return Err(authentication_failed());
    }
    Ok(())
}

fn read_text_file(
    source: &Path,
    name: &str,
    owner: u32,
    maximum: u64,
) -> Result<String, ProtocolError> {
    let bytes = read_named_file(source, name, owner, maximum)?;
    let text = std::str::from_utf8(&bytes).map_err(malformed)?.trim();
    if text.is_empty() {
        return Err(malformed(format!("legacy wallet {name} is empty")));
    }
    Ok(text.to_owned())
}

fn read_named_file(
    source: &Path,
    name: &str,
    owner: u32,
    maximum: u64,
) -> Result<Vec<u8>, ProtocolError> {
    read_owned_regular(&source.join(name), owner, maximum)
}

fn read_owned_regular(path: &Path, owner: u32, maximum: u64) -> Result<Vec<u8>, ProtocolError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(storage)?;
    let before = file.metadata().map_err(storage)?;
    if !before.file_type().is_file() || before.uid() != owner || before.len() > maximum {
        return Err(malformed(format!(
            "legacy migration file {} has invalid type, owner, or size",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(storage)?;
    if bytes.len() as u64 > maximum {
        return Err(malformed(format!(
            "legacy migration file {} exceeds its size limit",
            path.display()
        )));
    }
    let after = file.metadata().map_err(storage)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err(malformed(
            "legacy migration source changed while being read",
        ));
    }
    Ok(bytes)
}

fn prepare_store_directories(
    root: &Path,
    signer_uid: u32,
    signer_gid: u32,
) -> Result<(), ProtocolError> {
    for path in [
        root.to_path_buf(),
        root.join("pending"),
        root.join("consumed"),
    ] {
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir()
                    || metadata.uid() != signer_uid
                    || metadata.gid() != signer_gid
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(malformed(format!(
                        "legacy migration directory {} has unsafe existing ownership or mode",
                        path.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                builder.create(&path).map_err(storage)?;
                chown_exact(&path, signer_uid, signer_gid)?;
            }
            Err(error) => return Err(storage(error)),
        }
    }
    Ok(())
}

fn require_private_directory(path: &Path, owner: u32) -> Result<(), ProtocolError> {
    let metadata = fs::symlink_metadata(path).map_err(storage)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(malformed(format!(
            "legacy migration directory {} is not private to Signer",
            path.display()
        )));
    }
    Ok(())
}

fn write_new_private(path: &Path, bytes: &[u8], uid: u32, gid: u32) -> Result<(), ProtocolError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(storage)?;
    file.write_all(bytes).map_err(storage)?;
    file.sync_all().map_err(storage)?;
    chown_exact(path, uid, gid)
}

fn write_atomic_private(path: &Path, bytes: &[u8], owner: u32) -> Result<(), ProtocolError> {
    let parent = path
        .parent()
        .ok_or_else(|| malformed("legacy migration marker has no parent"))?;
    require_private_directory(parent, owner)?;
    let temporary = parent.join(format!(".tmp-{}", random_hex()));
    let metadata = fs::symlink_metadata(parent).map_err(storage)?;
    write_new_private(&temporary, bytes, metadata.uid(), metadata.gid())?;
    fs::rename(&temporary, path).map_err(storage)?;
    sync_directory(parent)
}

fn chown_exact(path: &Path, uid: u32, gid: u32) -> Result<(), ProtocolError> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).map_err(storage)
}

fn sync_directory(path: &Path) -> Result<(), ProtocolError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(storage)
}

fn decode_fixed_hex<const N: usize>(encoded: &str, name: &str) -> Result<[u8; N], ProtocolError> {
    let decoded = hex::decode(encoded).map_err(malformed)?;
    decoded
        .try_into()
        .map_err(|_| malformed(format!("{name} must contain exactly {N} bytes")))
}

fn digest_bytes(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}

fn random_hex() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn authentication_failed() -> ProtocolError {
    protocol(
        ProtocolErrorCode::UnauthenticatedPeer,
        "legacy passkey wallet authentication failed",
    )
}

fn malformed(cause: impl std::fmt::Display) -> ProtocolError {
    protocol(ProtocolErrorCode::MalformedFrame, cause.to_string())
}

fn storage(cause: impl std::fmt::Display) -> ProtocolError {
    protocol(ProtocolErrorCode::ServiceUnavailable, cause.to_string())
}

fn protocol(code: ProtocolErrorCode, message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_user_handle_matches_historical_uuid_shape() {
        let handle = legacy_user_handle("hl-mainnet-validation");
        assert_eq!(handle[6] >> 4, 5);
        assert_eq!(handle[8] >> 6, 2);
        assert_eq!(handle, legacy_user_handle("hl-mainnet-validation"));
        assert_ne!(handle, legacy_user_handle("other-wallet"));
    }

    #[test]
    fn receipt_digest_detects_changed_public_terms() {
        let mut receipt = LegacyMigrationReceipt {
            schema: LEGACY_RECEIPT_SCHEMA.to_owned(),
            operation_id: OperationId::from_bytes([1; 32]),
            wallet_name: Token::new("wallet-a").unwrap(),
            address: "0x0000000000000000000000000000000000000000".to_owned(),
            public_key_fingerprint: Digest32::from_bytes([2; 32]),
            credential_id_fingerprint: Digest32::from_bytes([3; 32]),
            legacy_format_version: 1,
            bundle_digest: Digest32::from_bytes([4; 32]),
            policy_mode: POLICY_MODE.to_owned(),
            exact_terms_digest: Digest32::from_bytes([0; 32]),
        };
        receipt.exact_terms_digest = receipt_terms_digest(&receipt).unwrap();
        receipt.validate().unwrap();
        receipt.address = "0x1000000000000000000000000000000000000000".to_owned();
        assert!(receipt.validate().is_err());
    }

    #[test]
    fn staged_legacy_wallet_decrypts_once_and_consumes() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("legacy-wallet");
        fs::create_dir(&source).unwrap();
        let metadata = fs::metadata(&source).unwrap();
        let uid = metadata.uid();
        let gid = metadata.gid();

        let private = [1_u8; 32];
        let secret = SecretKey::from_slice(&private).unwrap();
        let public = secret.public_key().to_encoded_point(false);
        let address_hash = Keccak256::digest(&public.as_bytes()[1..]);
        let address = format!("0x{}", hex::encode(&address_hash[12..]));
        let prf = [9_u8; 32];
        let nonce = [2_u8; 12];
        let wrap = blake3::derive_key("bloom passkey wrap key", &prf);
        let encrypted = ChaCha20Poly1305::new(Key::from_slice(&wrap))
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &private,
                    aad: PASSKEY_AAD,
                },
            )
            .unwrap();
        let webauthn_secret = p256::SecretKey::from_slice(&[7_u8; 32]).unwrap();
        let webauthn_public = webauthn_secret.public_key().to_encoded_point(false);
        let x = Base64UrlBytes::from_bytes(webauthn_public.x().unwrap());
        let y = Base64UrlBytes::from_bytes(webauthn_public.y().unwrap());
        let credential_id = Base64UrlBytes::from_bytes(&[3_u8; 20]);

        fs::write(source.join("kind"), "passkey").unwrap();
        fs::write(source.join("address"), &address).unwrap();
        fs::write(source.join("pubkey"), hex::encode(public.as_bytes())).unwrap();
        fs::write(source.join("prf.salt"), hex::encode([4_u8; 32])).unwrap();
        fs::write(
            source.join("encrypted.key"),
            serde_json::to_vec(&serde_json::json!({
                "v": 1,
                "nonce_hex": hex::encode(nonce),
                "ciphertext_hex": hex::encode(encrypted),
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            source.join("passkey.json"),
            serde_json::to_vec(&serde_json::json!({
                "cred": {
                    "cred_id": credential_id,
                    "cred": {"type_": "ES256", "key": {"EC_EC2": {
                        "curve": "SECP256R1", "x": x, "y": y
                    }}},
                    "counter": 0,
                    "transports": null,
                    "user_verified": true,
                    "backup_eligible": true,
                    "backup_state": true,
                    "registration_policy": null,
                    "extensions": null,
                    "attestation": null,
                    "attestation_format": null
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let root = temporary.path().join("migrations");
        let receipt = stage_legacy_wallet(&source, &root, uid, uid, gid).unwrap();
        receipt.validate().unwrap();
        let interrupted = root.join("pending/.tmp-interrupted");
        fs::create_dir(&interrupted).unwrap();
        fs::set_permissions(&interrupted, fs::Permissions::from_mode(0o700)).unwrap();
        let repeated = stage_legacy_wallet(&source, &root, uid, uid, gid).unwrap();
        assert_eq!(repeated.operation_id, receipt.operation_id);
        assert!(
            !interrupted.exists(),
            "retry must clean private incomplete staging without activating it"
        );
        let store = LegacyMigrationStore::open(&root, uid).unwrap();
        let prepared = store.load(&receipt.operation_id).unwrap();
        assert_eq!(prepared.receipt.address, address);
        let wrong_prf = store
            .decrypt_root(&receipt.operation_id, &SecretBytes::new(vec![8_u8; 32]))
            .unwrap_err();
        assert_eq!(wrong_prf.code, ProtocolErrorCode::UnauthenticatedPeer);
        assert!(store.load(&receipt.operation_id).is_ok());
        let decrypted = store
            .decrypt_root(&receipt.operation_id, &SecretBytes::new(prf.to_vec()))
            .unwrap();
        assert_eq!(decrypted.expose_to_backend(), private);
        store.consume(&receipt.operation_id).unwrap();
        assert!(store.load(&receipt.operation_id).is_err());
    }
}
