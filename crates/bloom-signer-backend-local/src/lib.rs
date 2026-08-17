//! Encrypted, boot-activated local secp256k1 backend with a BIP32 registry.

use bip32::{DerivationPath, XPrv};
use bloom_signer_api::DerivationProfile;
use bloom_signer_api::{
    Base64UrlBytes, CryptoInputKind, CryptoSuite, DecimalU64, DerivationRef, Digest32, KeyRef,
    KeySpec, OperationId, SignatureEncoding, Token,
};
use bloom_signer_backend_api::{
    ActivationStatus, BackendCapabilities, BackendError, BackendFuture, BackendInput,
    BackendSignRequest, BackendSignature, DerivationCapability, KeyDescription,
    ProviderIdempotency, SecretBytes, SignerBackend, SignerBackendActivation,
    SignerBackendDerivation,
};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer as _, Verifier as _, VerifyingKey};
use k256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
use parking_lot::RwLock;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use zeroize::Zeroizing;

const ROOT_AAD_DOMAIN: &[u8] = b"bloom-local-root-wrap/v1";
const WRAP_FORMAT_VERSION: u32 = 1;
const DERIVATION_AUTHORITY_DOMAIN: &[u8] = b"bloom-key-derive-authority/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedLocalBackup {
    pub root_key_id: Token,
    #[serde(default)]
    pub root_material_kind: LocalRootMaterialKind,
    #[serde(default)]
    pub pinned_root: Option<KeyRef>,
    pub wrap_format_version: u32,
    pub nonce: Base64UrlBytes,
    pub encrypted_seed: Base64UrlBytes,
    pub authority_verifying_key: Base64UrlBytes,
    /// Public SPKI descriptions pinned while custody is active. These permit
    /// key projection after restart without decrypting root material.
    #[serde(default)]
    pub public_descriptions: Vec<KeyDescription>,
    pub derivation_registry: Vec<KeyRef>,
    pub derivation_namespaces: Vec<DerivationNamespace>,
    pub derivation_tombstones: Vec<String>,
    #[serde(default)]
    pub pending_derivations: BTreeMap<String, KeyRef>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalRootMaterialKind {
    #[default]
    Bip32Seed,
    Secp256k1Scalar,
    /// BIP-39 entropy. The root is never a signable key; only registered
    /// derived children sign, via BIP-32 (secp256k1) or hardened SLIP-10
    /// (Ed25519) dispatched by `DerivationRef::Bip39Multicurve`.
    Bip39Entropy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationNamespace {
    pub namespace_id: Token,
    pub canonical_prefix: String,
    pub next_index: DecimalU64,
    pub maximum_children: DecimalU64,
    pub authority_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationGrant {
    pub authority_kind: Token,
    pub namespace_id: Token,
    pub canonical_prefix: String,
    pub starting_index: DecimalU64,
    pub maximum_children: DecimalU64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivationAuthority {
    grant: DerivationGrant,
    signature: Base64UrlBytes,
}

impl DerivationAuthority {
    pub fn from_signed(grant: DerivationGrant, signature: Base64UrlBytes) -> Self {
        Self { grant, signature }
    }
}

#[derive(Default)]
struct LocalState {
    backup: Option<EncryptedLocalBackup>,
    active_kek: Option<SecretBytes>,
    registry: BTreeMap<String, KeyRef>,
    storage_path: Option<PathBuf>,
}

pub struct LocalSignerBackend {
    backend_instance_id: Token,
    state: RwLock<LocalState>,
}

impl LocalSignerBackend {
    pub fn provision(
        backend_instance_id: Token,
        root_key_id: Token,
        seed: SecretBytes,
        kek: SecretBytes,
        authority_verifying_key: VerifyingKey,
    ) -> Result<Self, BackendError> {
        Self::provision_material(
            backend_instance_id,
            root_key_id,
            seed,
            kek,
            authority_verifying_key,
            LocalRootMaterialKind::Bip32Seed,
        )
    }

    pub fn provision_imported_secp256k1(
        backend_instance_id: Token,
        root_key_id: Token,
        private_key: SecretBytes,
        kek: SecretBytes,
        authority_verifying_key: VerifyingKey,
    ) -> Result<Self, BackendError> {
        Self::provision_material(
            backend_instance_id,
            root_key_id,
            private_key,
            kek,
            authority_verifying_key,
            LocalRootMaterialKind::Secp256k1Scalar,
        )
    }

    /// Provision a BIP-39 wallet backend. The root is entropy and is never a
    /// signable key: no root `KeyRef` is produced, and `root_signing_key`
    /// fails closed. Derived children sign via `Bip39Multicurve`.
    pub fn provision_bip39(
        backend_instance_id: Token,
        wallet_seed_ref: Token,
        entropy: SecretBytes,
        kek: SecretBytes,
        authority_verifying_key: VerifyingKey,
    ) -> Result<Self, BackendError> {
        Self::provision_material(
            backend_instance_id,
            wallet_seed_ref,
            entropy,
            kek,
            authority_verifying_key,
            LocalRootMaterialKind::Bip39Entropy,
        )
    }

    fn provision_material(
        backend_instance_id: Token,
        root_key_id: Token,
        material: SecretBytes,
        kek: SecretBytes,
        authority_verifying_key: VerifyingKey,
        root_material_kind: LocalRootMaterialKind,
    ) -> Result<Self, BackendError> {
        let valid_material = match root_material_kind {
            LocalRootMaterialKind::Bip32Seed => {
                (16..=64).contains(&material.expose_to_backend().len())
            }
            LocalRootMaterialKind::Secp256k1Scalar => {
                SigningKey::from_slice(material.expose_to_backend()).is_ok()
            }
            LocalRootMaterialKind::Bip39Entropy => {
                matches!(material.expose_to_backend().len(), 16 | 20 | 24 | 28 | 32)
            }
        };
        if !valid_material || kek.expose_to_backend().len() != 32 {
            return Err(BackendError::InvalidRequest);
        }
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aad = root_aad(&backend_instance_id, &root_key_id);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.expose_to_backend()));
        let encrypted_seed = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: material.expose_to_backend(),
                    aad: &aad,
                },
            )
            .map_err(|_| BackendError::DefinitiveRejected)?;
        let backend = Self {
            backend_instance_id,
            state: RwLock::new(LocalState {
                backup: Some(EncryptedLocalBackup {
                    root_key_id,
                    root_material_kind,
                    pinned_root: None,
                    wrap_format_version: WRAP_FORMAT_VERSION,
                    nonce: Base64UrlBytes::from_bytes(&nonce),
                    encrypted_seed: Base64UrlBytes::from_bytes(&encrypted_seed),
                    authority_verifying_key: Base64UrlBytes::from_bytes(
                        &authority_verifying_key.to_bytes(),
                    ),
                    public_descriptions: vec![],
                    derivation_registry: vec![],
                    derivation_namespaces: vec![],
                    derivation_tombstones: vec![],
                    pending_derivations: BTreeMap::new(),
                }),
                active_kek: Some(kek),
                registry: BTreeMap::new(),
                storage_path: None,
            }),
        };
        // A BIP-39 root is not a signable key: no root KeyRef, no pinned
        // root, and no "m" descriptor are ever produced for it.
        if root_material_kind == LocalRootMaterialKind::Bip39Entropy {
            return Ok(backend);
        }
        let root = backend.root_key_ref()?;
        backend
            .state
            .write()
            .backup
            .as_mut()
            .ok_or(BackendError::DefinitiveRejected)?
            .pinned_root = Some(root);
        let mut description = backend.describe_path("m")?;
        description.key_ref = backend.root_key_ref()?;
        backend
            .state
            .write()
            .backup
            .as_mut()
            .ok_or(BackendError::DefinitiveRejected)?
            .public_descriptions = vec![description];
        Ok(backend)
    }

    pub fn provision_at(
        storage_path: impl AsRef<Path>,
        backend_instance_id: Token,
        root_key_id: Token,
        seed: SecretBytes,
        kek: SecretBytes,
        authority_verifying_key: VerifyingKey,
    ) -> Result<Self, BackendError> {
        let backend = Self::provision(
            backend_instance_id,
            root_key_id,
            seed,
            kek,
            authority_verifying_key,
        )?;
        {
            let mut state = backend.state.write();
            state.storage_path = Some(storage_path.as_ref().to_path_buf());
            persist_backup(&state)?;
        }
        Ok(backend)
    }

    pub fn open_at(
        storage_path: impl AsRef<Path>,
        backend_instance_id: Token,
    ) -> Result<Self, BackendError> {
        let bytes =
            fs::read(storage_path.as_ref()).map_err(|_| BackendError::DefinitiveRejected)?;
        let backup: EncryptedLocalBackup =
            serde_json::from_slice(&bytes).map_err(|_| BackendError::InvalidRequest)?;
        let backend = Self::restore(backend_instance_id, backup)?;
        backend.state.write().storage_path = Some(storage_path.as_ref().to_path_buf());
        Ok(backend)
    }

    pub fn restore(
        backend_instance_id: Token,
        backup: EncryptedLocalBackup,
    ) -> Result<Self, BackendError> {
        let mut locators = std::collections::BTreeSet::new();
        let mut paths = std::collections::BTreeSet::new();
        let mut namespace_ids = std::collections::BTreeSet::new();
        let tombstones: std::collections::BTreeSet<_> =
            backup.derivation_tombstones.iter().cloned().collect();
        if backup.wrap_format_version != WRAP_FORMAT_VERSION
            || backup.nonce.decode().len() != 24
            || backup.authority_verifying_key.decode().len() != 32
            || backup.pinned_root.as_ref().is_some_and(|root| {
                root.backend.as_str() != "local"
                    || root.backend_instance != backend_instance_id
                    || root.key_spec != KeySpec::Secp256k1
                    || root.locator != format!("root:{}", backup.root_key_id.as_str())
                    || root.derivation.is_some()
            })
            || backup.derivation_registry.iter().any(|key| {
                !matches!(
                    &key.derivation,
                    Some(DerivationRef::Bip32Secp256k1 { root_key_id, .. })
                        if root_key_id == &backup.root_key_id
                ) || key.backend.as_str() != "local"
                    || key.backend_instance != backend_instance_id
                    || !locators.insert(key.locator.clone())
                    || match &key.derivation {
                        Some(DerivationRef::Bip32Secp256k1 { path, .. }) => {
                            !paths.insert(path.clone()) || tombstones.contains(path)
                        }
                        _ => true,
                    }
            })
            || tombstones.len() != backup.derivation_tombstones.len()
            || backup.derivation_namespaces.iter().any(|namespace| {
                !namespace_ids.insert(namespace.namespace_id.clone())
                    || validate_namespace_prefix(&namespace.canonical_prefix).is_err()
                    || namespace.next_index.get() > namespace.maximum_children.get()
                    || namespace.maximum_children.get() > 0x8000_0000
            })
        {
            return Err(BackendError::InvalidRequest);
        }
        let registry = backup
            .derivation_registry
            .iter()
            .map(|key| (key.locator.clone(), key.clone()))
            .collect();
        Ok(Self {
            backend_instance_id,
            state: RwLock::new(LocalState {
                backup: Some(backup),
                active_kek: None,
                registry,
                storage_path: None,
            }),
        })
    }

    pub fn encrypted_backup(&self) -> Result<EncryptedLocalBackup, BackendError> {
        self.state
            .read()
            .backup
            .clone()
            .ok_or(BackendError::DefinitiveRejected)
    }

    pub fn key_is_registered(&self, key_ref: &KeyRef) -> bool {
        self.root_key_ref().is_ok_and(|root| &root == key_ref)
            || self.state.read().registry.get(&key_ref.locator) == Some(key_ref)
    }

    /// Activation body shared by the async `SignerBackendActivation::activate`
    /// and by callers on Signer's synchronous custody-apply path, which holds
    /// `parking_lot` guards and so cannot await. Keeping one body ensures the
    /// two entry points cannot drift apart.
    pub fn activate_blocking(&self, secret: SecretBytes) -> Result<(), BackendError> {
        if secret.expose_to_backend().len() != 32 {
            return Err(BackendError::InvalidRequest);
        }
        self.state.write().active_kek = Some(secret);
        if self
            .active_seed()
            .and_then(|_| self.validate_registered_derivations())
            .is_err()
        {
            self.state.write().active_kek = None;
            return Err(BackendError::DefinitiveRejected);
        }
        Ok(())
    }

    pub fn key_is_available(&self, key_ref: &KeyRef) -> Result<bool, BackendError> {
        if !self.key_is_registered(key_ref) {
            return Ok(false);
        }
        Ok(self.state.read().active_kek.is_some())
    }

    /// Register a BIP-39 derived child in the backend's durable registry and
    /// in-memory index. Unlike `allocate_derived_key`, the child is derived
    /// from entropy by the caller (bloom-signer-derive) and handed in as a
    /// fully described `KeyRef`; the backend only pins and indexes it.
    pub fn register_bip39_child(
        &self,
        key_ref: KeyRef,
        operation_id: Option<OperationId>,
    ) -> Result<(), BackendError> {
        if key_ref.derivation.is_none() {
            return Err(BackendError::InvalidRequest);
        }
        let mut state = self.state.write();
        let mut next = state
            .backup
            .clone()
            .ok_or(BackendError::DefinitiveRejected)?;
        if next.derivation_registry.iter().any(|key| key == &key_ref) {
            return Ok(());
        }
        next.derivation_registry.push(key_ref.clone());
        if let Some(operation_id) = operation_id {
            next.pending_derivations
                .insert(operation_id.as_str().to_owned(), key_ref.clone());
        }
        commit_backup(&mut state, next)?;
        state.registry.insert(key_ref.locator.clone(), key_ref);
        Ok(())
    }

    /// Mark a BIP-39 derived child unavailable (retirement).
    pub fn retire_bip39_child(&self, key_ref: &KeyRef) -> Result<(), BackendError> {
        let mut state = self.state.write();
        if state.registry.remove(&key_ref.locator).is_none() {
            return Err(BackendError::InvalidRequest);
        }
        if let Some(next) = state.backup.as_mut() {
            next.derivation_registry.retain(|key| key != key_ref);
        }
        Ok(())
    }

    pub fn root_key_ref(&self) -> Result<KeyRef, BackendError> {
        let backup = self
            .state
            .read()
            .backup
            .clone()
            .ok_or(BackendError::DefinitiveRejected)?;
        if backup.root_material_kind == LocalRootMaterialKind::Bip39Entropy {
            return Err(BackendError::InvalidRequest);
        }
        if let Some(root) = backup.pinned_root {
            return Ok(root);
        }
        let description = self.describe_path("m")?;
        Ok(KeyRef {
            backend: self.backend_id(),
            backend_instance: self.backend_instance_id.clone(),
            locator: format!("root:{}", backup.root_key_id.as_str()),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: description.public_key_fingerprint,
            derivation: None,
        })
    }

    pub fn configure_namespace(&self, authority: &DerivationAuthority) -> Result<(), BackendError> {
        if self.state.read().backup.as_ref().is_some_and(|backup| {
            backup.root_material_kind == LocalRootMaterialKind::Secp256k1Scalar
        }) {
            return Err(BackendError::Unsupported);
        }
        let authority_digest = self.verify_derivation_authority(authority)?;
        let grant = &authority.grant;
        validate_namespace_prefix(&grant.canonical_prefix)?;
        let starting_index = grant.starting_index.get();
        let maximum_children = grant.maximum_children.get();
        if maximum_children == 0
            || starting_index > 0x7fff_ffff
            || maximum_children > 0x8000_0000
            || starting_index.saturating_add(maximum_children) > 0x8000_0000
        {
            return Err(BackendError::InvalidRequest);
        }
        let mut state = self.state.write();
        let mut next = state
            .backup
            .clone()
            .ok_or(BackendError::DefinitiveRejected)?;
        if let Some(existing) = next
            .derivation_namespaces
            .iter()
            .find(|namespace| namespace.namespace_id == grant.namespace_id)
        {
            // Configuration is restart/retry safe only for the exact same
            // Signer-authenticated authority. A namespace can never be
            // retargeted to a different prefix or allocation ceiling.
            return if existing.authority_digest == authority_digest
                && existing.canonical_prefix == grant.canonical_prefix
                && existing.maximum_children.get()
                    == grant.starting_index.get() + grant.maximum_children.get()
            {
                Ok(())
            } else {
                Err(BackendError::InvalidRequest)
            };
        }
        next.derivation_namespaces.push(DerivationNamespace {
            namespace_id: grant.namespace_id.clone(),
            canonical_prefix: grant.canonical_prefix.clone(),
            next_index: DecimalU64::new(starting_index),
            maximum_children: DecimalU64::new(starting_index + maximum_children),
            authority_digest,
        });
        commit_backup(&mut state, next)
    }

    pub fn allocate_derived_key(
        &self,
        root: &KeyRef,
        namespace_id: &Token,
        authority: &DerivationAuthority,
    ) -> Result<KeyDescription, BackendError> {
        self.allocate_derived_key_inner(root, namespace_id, authority, None)
    }

    pub fn allocate_derived_key_for_operation(
        &self,
        root: &KeyRef,
        namespace_id: &Token,
        authority: &DerivationAuthority,
        operation_id: &OperationId,
    ) -> Result<KeyDescription, BackendError> {
        self.allocate_derived_key_inner(root, namespace_id, authority, Some(operation_id))
    }

    fn allocate_derived_key_inner(
        &self,
        root: &KeyRef,
        namespace_id: &Token,
        authority: &DerivationAuthority,
        operation_id: Option<&OperationId>,
    ) -> Result<KeyDescription, BackendError> {
        let authority_digest = self.verify_derivation_authority(authority)?;
        if self.root_key_ref()? != *root {
            return Err(BackendError::InvalidRequest);
        }
        let snapshot = self
            .state
            .read()
            .backup
            .clone()
            .ok_or(BackendError::DefinitiveRejected)?;
        if let Some(existing) = operation_id
            .and_then(|operation_id| snapshot.pending_derivations.get(operation_id.as_str()))
        {
            let Some(DerivationRef::Bip32Secp256k1 { path, .. }) = &existing.derivation else {
                return Err(BackendError::DefinitiveRejected);
            };
            return self.describe_path(path);
        }
        let namespace = snapshot
            .derivation_namespaces
            .iter()
            .find(|item| &item.namespace_id == namespace_id)
            .ok_or(BackendError::InvalidRequest)?;
        if authority.grant.namespace_id != *namespace_id
            || authority_digest != namespace.authority_digest
        {
            return Err(BackendError::InvalidRequest);
        }
        if namespace.next_index.get() >= namespace.maximum_children.get()
            || namespace.next_index.get() > 0x7fff_ffff
        {
            return Err(BackendError::InvalidRequest);
        }
        let path = format!(
            "{}/{}",
            namespace.canonical_prefix,
            namespace.next_index.get()
        );
        if snapshot.derivation_tombstones.contains(&path)
            || snapshot.derivation_registry.iter().any(|key| {
                matches!(
                    &key.derivation,
                    Some(DerivationRef::Bip32Secp256k1 { path: existing, .. })
                        if existing == &path
                )
            })
        {
            return Err(BackendError::DefinitiveRejected);
        }
        let description = self.describe_path(&path)?;
        let mut state = self.state.write();
        let mut next = state
            .backup
            .clone()
            .ok_or(BackendError::DefinitiveRejected)?;
        let current = next
            .derivation_namespaces
            .iter_mut()
            .find(|item| &item.namespace_id == namespace_id)
            .ok_or(BackendError::DefinitiveRejected)?;
        if current.next_index != namespace.next_index {
            return Err(BackendError::DefinitiveRejected);
        }
        current.next_index = DecimalU64::new(
            current
                .next_index
                .get()
                .checked_add(1)
                .ok_or(BackendError::DefinitiveRejected)?,
        );
        next.derivation_registry.push(description.key_ref.clone());
        next.public_descriptions.push(description.clone());
        if let Some(operation_id) = operation_id {
            next.pending_derivations.insert(
                operation_id.as_str().to_owned(),
                description.key_ref.clone(),
            );
        }
        commit_backup(&mut state, next)?;
        state.registry.insert(
            description.key_ref.locator.clone(),
            description.key_ref.clone(),
        );
        Ok(description)
    }

    pub fn pending_derivations(&self) -> Vec<(OperationId, KeyRef)> {
        self.state
            .read()
            .backup
            .as_ref()
            .map(|backup| {
                backup
                    .pending_derivations
                    .iter()
                    .filter_map(|(operation_id, key_ref)| {
                        OperationId::new(operation_id.clone())
                            .ok()
                            .map(|operation_id| (operation_id, key_ref.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn finalize_derived_key(&self, operation_id: &OperationId) -> Result<(), BackendError> {
        let mut state = self.state.write();
        let mut next = state
            .backup
            .clone()
            .ok_or(BackendError::DefinitiveRejected)?;
        if next
            .pending_derivations
            .remove(operation_id.as_str())
            .is_none()
        {
            return Err(BackendError::InvalidRequest);
        }
        commit_backup(&mut state, next)
    }

    pub fn tombstone_derived_key(&self, key_ref: &KeyRef) -> Result<(), BackendError> {
        let path = match &key_ref.derivation {
            Some(DerivationRef::Bip32Secp256k1 { path, .. }) => path.clone(),
            _ => return Err(BackendError::InvalidRequest),
        };
        let mut state = self.state.write();
        if state.registry.get(&key_ref.locator) != Some(key_ref) {
            return Err(BackendError::InvalidRequest);
        }
        let mut next = state
            .backup
            .clone()
            .ok_or(BackendError::DefinitiveRejected)?;
        next.derivation_registry.retain(|key| key != key_ref);
        next.public_descriptions
            .retain(|description| &description.key_ref != key_ref);
        next.pending_derivations
            .retain(|_, pending| pending != key_ref);
        if !next.derivation_tombstones.contains(&path) {
            next.derivation_tombstones.push(path);
        }
        commit_backup(&mut state, next)?;
        state.registry.remove(&key_ref.locator);
        Ok(())
    }

    fn verify_derivation_authority(
        &self,
        authority: &DerivationAuthority,
    ) -> Result<Digest32, BackendError> {
        if !matches!(
            authority.grant.authority_kind.as_str(),
            "policy" | "ceremony"
        ) {
            return Err(BackendError::InvalidRequest);
        }
        let backup = self
            .state
            .read()
            .backup
            .clone()
            .ok_or(BackendError::DefinitiveRejected)?;
        let verifying_key: [u8; 32] = backup
            .authority_verifying_key
            .decode()
            .try_into()
            .map_err(|_| BackendError::InvalidRequest)?;
        let signature: [u8; 64] = authority
            .signature
            .decode()
            .try_into()
            .map_err(|_| BackendError::InvalidRequest)?;
        let grant_jcs =
            serde_jcs::to_vec(&authority.grant).map_err(|_| BackendError::InvalidRequest)?;
        let mut message = DERIVATION_AUTHORITY_DOMAIN.to_vec();
        message.extend_from_slice(&grant_jcs);
        VerifyingKey::from_bytes(&verifying_key)
            .map_err(|_| BackendError::InvalidRequest)?
            .verify(&message, &Signature::from_bytes(&signature))
            .map_err(|_| BackendError::DefinitiveRejected)?;
        Ok(Digest32::from_bytes(Sha256::digest(&message).into()))
    }

    fn active_seed(&self) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        let state = self.state.read();
        let backup = state
            .backup
            .as_ref()
            .ok_or(BackendError::DefinitiveRejected)?;
        let kek = state
            .active_kek
            .as_ref()
            .ok_or(BackendError::DefinitiveRejected)?;
        let nonce: [u8; 24] = backup
            .nonce
            .decode()
            .try_into()
            .map_err(|_| BackendError::InvalidRequest)?;
        let aad = root_aad(&self.backend_instance_id, &backup.root_key_id);
        XChaCha20Poly1305::new(Key::from_slice(kek.expose_to_backend()))
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &backup.encrypted_seed.decode(),
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| BackendError::DefinitiveRejected)
    }

    fn root_signing_key(&self) -> Result<SigningKey, BackendError> {
        let material_kind = self
            .state
            .read()
            .backup
            .as_ref()
            .map(|backup| backup.root_material_kind)
            .ok_or(BackendError::DefinitiveRejected)?;
        let material = self.active_seed()?;
        match material_kind {
            LocalRootMaterialKind::Bip32Seed => {
                let path =
                    DerivationPath::from_str("m").map_err(|_| BackendError::InvalidRequest)?;
                XPrv::derive_from_path(material.as_slice(), &path)
                    .map(SigningKey::from)
                    .map_err(|_| BackendError::DefinitiveRejected)
            }
            LocalRootMaterialKind::Secp256k1Scalar => SigningKey::from_slice(material.as_slice())
                .map_err(|_| BackendError::InvalidRequest),
            LocalRootMaterialKind::Bip39Entropy => Err(BackendError::InvalidRequest),
        }
    }

    /// Decrypt entropy and derive the transient 64-byte BIP-39 seed.
    fn bip39_seed(&self) -> Result<Zeroizing<[u8; 64]>, BackendError> {
        let entropy = self.active_seed()?;
        let mnemonic = bloom_signer_derive::mnemonic_from_entropy(&entropy)
            .map_err(|_| BackendError::InvalidRequest)?;
        bloom_signer_derive::seed_from_mnemonic(&mnemonic, "")
            .map_err(|_| BackendError::DefinitiveRejected)
    }

    fn derive_secp_signing_key(&self, key_ref: &KeyRef) -> Result<SigningKey, BackendError> {
        if self.root_key_ref().is_ok_and(|root| &root == key_ref) {
            return self.root_signing_key();
        }
        let registered = self
            .state
            .read()
            .registry
            .get(&key_ref.locator)
            .cloned()
            .ok_or(BackendError::InvalidRequest)?;
        if &registered != key_ref {
            return Err(BackendError::InvalidRequest);
        }
        match registered.derivation.ok_or(BackendError::InvalidRequest)? {
            DerivationRef::Bip32Secp256k1 { path, .. } => {
                let path =
                    DerivationPath::from_str(&path).map_err(|_| BackendError::InvalidRequest)?;
                let seed = self.active_seed()?;
                XPrv::derive_from_path(seed.as_slice(), &path)
                    .map(SigningKey::from)
                    .map_err(|_| BackendError::DefinitiveRejected)
            }
            DerivationRef::Bip39Multicurve { profile, path, .. } => {
                let (account, index) = parse_bip39_path(profile, &path)?;
                if profile != DerivationProfile::Bip44EvmSecp256k1V1 {
                    return Err(BackendError::InvalidRequest);
                }
                let seed = self.bip39_seed()?;
                let derived = bloom_signer_derive::derive_evm_account(&seed, account, index)
                    .map_err(|_| BackendError::DefinitiveRejected)?;
                if derived.fingerprint != key_ref.public_key_fingerprint.to_bytes() {
                    return Err(BackendError::DefinitiveRejected);
                }
                SigningKey::from_bytes((&*derived.private_key).into())
                    .map_err(|_| BackendError::DefinitiveRejected)
            }
        }
    }

    fn derive_ed25519_signing_key(
        &self,
        key_ref: &KeyRef,
    ) -> Result<ed25519_dalek::SigningKey, BackendError> {
        let registered = self
            .state
            .read()
            .registry
            .get(&key_ref.locator)
            .cloned()
            .ok_or(BackendError::InvalidRequest)?;
        if &registered != key_ref {
            return Err(BackendError::InvalidRequest);
        }
        let Some(DerivationRef::Bip39Multicurve { profile, path, .. }) = registered.derivation
        else {
            return Err(BackendError::InvalidRequest);
        };
        if profile != DerivationProfile::Bip44SolanaSlip10Ed25519V1 {
            return Err(BackendError::InvalidRequest);
        }
        let (account, _) = parse_bip39_path(profile, &path)?;
        let seed = self.bip39_seed()?;
        let derived = bloom_signer_derive::derive_solana_account(&seed, account)
            .map_err(|_| BackendError::DefinitiveRejected)?;
        if derived.fingerprint != key_ref.public_key_fingerprint.to_bytes() {
            return Err(BackendError::DefinitiveRejected);
        }
        let bytes: [u8; 32] = derived
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| BackendError::DefinitiveRejected)?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
    }

    fn validate_registered_derivations(&self) -> Result<(), BackendError> {
        let is_bip39 =
            self.state.read().backup.as_ref().is_some_and(|backup| {
                backup.root_material_kind == LocalRootMaterialKind::Bip39Entropy
            });
        if !is_bip39 {
            let root = self.root_key_ref()?;
            let root_description = self.describe_path("m")?;
            if root.public_key_fingerprint != root_description.public_key_fingerprint {
                return Err(BackendError::DefinitiveRejected);
            }
        }
        let registered: Vec<KeyRef> = self.state.read().registry.values().cloned().collect();
        for key_ref in registered {
            match key_ref.derivation.as_ref() {
                Some(DerivationRef::Bip32Secp256k1 { path, .. }) => {
                    if self.describe_path(path)?.key_ref != key_ref {
                        return Err(BackendError::DefinitiveRejected);
                    }
                }
                Some(DerivationRef::Bip39Multicurve { .. })
                    if self.describe_bip39_child(&key_ref)?.key_ref == key_ref => {}
                Some(DerivationRef::Bip39Multicurve { .. }) => {
                    return Err(BackendError::DefinitiveRejected);
                }
                None => {}
            }
        }
        Ok(())
    }

    fn describe_path(&self, canonical_path: &str) -> Result<KeyDescription, BackendError> {
        let backup = self
            .state
            .read()
            .backup
            .clone()
            .ok_or(BackendError::DefinitiveRejected)?;
        let path =
            DerivationPath::from_str(canonical_path).map_err(|_| BackendError::InvalidRequest)?;
        if path.to_string() != canonical_path {
            return Err(BackendError::InvalidRequest);
        }
        let signing_key = if canonical_path == "m" {
            self.root_signing_key()?
        } else {
            if backup.root_material_kind == LocalRootMaterialKind::Secp256k1Scalar {
                return Err(BackendError::Unsupported);
            }
            let seed = self.active_seed()?;
            XPrv::derive_from_path(seed.as_slice(), &path)
                .map(SigningKey::from)
                .map_err(|_| BackendError::DefinitiveRejected)?
        };
        let public_key = k256::PublicKey::from_sec1_bytes(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .map_err(|_| BackendError::DefinitiveRejected)?;
        let spki = public_key
            .to_public_key_der()
            .map_err(|_| BackendError::DefinitiveRejected)?
            .as_bytes()
            .to_vec();
        let fingerprint = Digest32::from_bytes(Sha256::digest(&spki).into());
        let locator = hex::encode(Sha256::digest(
            [
                backup.root_key_id.as_str().as_bytes(),
                canonical_path.as_bytes(),
            ]
            .concat(),
        ));
        let key_ref = KeyRef {
            backend: Token::new("local").map_err(|_| BackendError::InvalidRequest)?,
            backend_instance: self.backend_instance_id.clone(),
            locator,
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: fingerprint.clone(),
            derivation: Some(DerivationRef::Bip32Secp256k1 {
                root_key_id: backup.root_key_id,
                path: canonical_path.into(),
            }),
        };
        Ok(KeyDescription {
            key_ref,
            canonical_spki_der: Base64UrlBytes::from_bytes(&spki),
            public_key_fingerprint: fingerprint,
            supported_crypto_suites: vec![
                CryptoSuite::Secp256k1Keccak256Recoverable,
                CryptoSuite::Secp256k1Sha256Recoverable,
            ],
        })
    }
    /// Describe a registered BIP-39 derived child by re-deriving from the
    /// stored entropy and verifying the pinned fingerprint.
    fn describe_bip39_child(&self, key_ref: &KeyRef) -> Result<KeyDescription, BackendError> {
        let Some(DerivationRef::Bip39Multicurve { profile, path, .. }) = &key_ref.derivation else {
            return Err(BackendError::InvalidRequest);
        };
        let (account, index) = parse_bip39_path(*profile, path)?;
        let seed = self.bip39_seed()?;
        let (spki, suites) = match profile {
            DerivationProfile::Bip44EvmSecp256k1V1 => {
                let derived = bloom_signer_derive::derive_evm_account(&seed, account, index)
                    .map_err(|_| BackendError::DefinitiveRejected)?;
                (
                    derived.spki_der,
                    vec![
                        CryptoSuite::Secp256k1Keccak256Recoverable,
                        CryptoSuite::Secp256k1Sha256Recoverable,
                    ],
                )
            }
            DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
                let derived = bloom_signer_derive::derive_solana_account(&seed, account)
                    .map_err(|_| BackendError::DefinitiveRejected)?;
                (derived.spki_der, vec![CryptoSuite::Ed25519Message])
            }
        };
        let fingerprint = Digest32::from_bytes(Sha256::digest(&spki).into());
        if fingerprint != key_ref.public_key_fingerprint {
            return Err(BackendError::DefinitiveRejected);
        }
        Ok(KeyDescription {
            key_ref: key_ref.clone(),
            canonical_spki_der: Base64UrlBytes::from_bytes(&spki),
            public_key_fingerprint: fingerprint,
            supported_crypto_suites: suites,
        })
    }
}

impl SignerBackend for LocalSignerBackend {
    fn backend_id(&self) -> Token {
        Token::new("local").expect("static token")
    }

    fn capabilities(&self) -> BackendCapabilities {
        let material_kind = self
            .state
            .read()
            .backup
            .as_ref()
            .map(|backup| backup.root_material_kind)
            .unwrap_or_default();
        let supports_derivation = material_kind == LocalRootMaterialKind::Bip32Seed;
        let is_bip39 = material_kind == LocalRootMaterialKind::Bip39Entropy;
        BackendCapabilities {
            backend_id: self.backend_id(),
            backend_instance_id: self.backend_instance_id.clone(),
            supported_key_specs: if is_bip39 {
                vec![KeySpec::Secp256k1, KeySpec::Ed25519]
            } else {
                vec![KeySpec::Secp256k1]
            },
            supported_crypto_suites: if is_bip39 {
                vec![
                    CryptoSuite::Secp256k1Keccak256Recoverable,
                    CryptoSuite::Secp256k1Sha256Recoverable,
                    CryptoSuite::Ed25519Message,
                ]
            } else {
                vec![
                    CryptoSuite::Secp256k1Keccak256Recoverable,
                    CryptoSuite::Secp256k1Sha256Recoverable,
                ]
            },
            supported_derivation: supports_derivation
                .then(|| DerivationCapability {
                    scheme: Token::new("bip32-secp256k1").expect("static token"),
                    maximum_depth: 10,
                    maximum_index: 0x7fff_ffff,
                })
                .into_iter()
                .collect(),
            input_kinds: if is_bip39 {
                vec![CryptoInputKind::Digest32, CryptoInputKind::Message]
            } else {
                vec![CryptoInputKind::Digest32]
            },
            output_encodings: if is_bip39 {
                vec![
                    SignatureEncoding::Secp256k1Recoverable65,
                    SignatureEncoding::Ed25519Raw64,
                ]
            } else {
                vec![SignatureEncoding::Secp256k1Recoverable65]
            },
            maximum_input_bytes: DecimalU64::new(1232),
            maximum_batch_size: DecimalU64::new(32),
            can_generate: true,
            can_import: true,
            can_export_encrypted: true,
            can_delete: true,
            requires_activation: true,
            requires_user_presence: true,
            networked: false,
            provider_idempotency: ProviderIdempotency::NoDeduplication,
        }
    }

    fn describe_key<'a>(
        &'a self,
        key: &'a KeyRef,
    ) -> BackendFuture<'a, Result<KeyDescription, BackendError>> {
        Box::pin(async move {
            if matches!(key.derivation, Some(DerivationRef::Bip39Multicurve { .. })) {
                return self.describe_bip39_child(key);
            }
            if let Some(description) = self.state.read().backup.as_ref().and_then(|backup| {
                backup
                    .public_descriptions
                    .iter()
                    .find(|description| &description.key_ref == key)
                    .cloned()
            }) {
                if description.public_key_fingerprint != key.public_key_fingerprint
                    || Digest32::from_bytes(
                        Sha256::digest(description.canonical_spki_der.decode()).into(),
                    ) != key.public_key_fingerprint
                {
                    return Err(BackendError::DefinitiveRejected);
                }
                return Ok(description);
            }
            if self.root_key_ref()? == *key {
                let mut description = self.describe_path("m")?;
                description.key_ref = key.clone();
                return Ok(description);
            }
            let registered = self
                .state
                .read()
                .registry
                .get(&key.locator)
                .cloned()
                .ok_or(BackendError::InvalidRequest)?;
            if registered != *key {
                return Err(BackendError::InvalidRequest);
            }
            let DerivationRef::Bip32Secp256k1 { path, .. } = &key
                .derivation
                .as_ref()
                .ok_or(BackendError::InvalidRequest)?
            else {
                return Err(BackendError::InvalidRequest);
            };
            self.describe_path(path)
        })
    }

    fn sign<'a>(
        &'a self,
        request: BackendSignRequest,
    ) -> BackendFuture<'a, Result<BackendSignature, BackendError>> {
        Box::pin(async move {
            if !request.input_matches_suite()
                || !self
                    .capabilities()
                    .supported_crypto_suites
                    .contains(&request.crypto_suite)
            {
                return Err(BackendError::Unsupported);
            }
            match request.crypto_suite {
                CryptoSuite::Secp256k1Keccak256Recoverable
                | CryptoSuite::Secp256k1Sha256Recoverable => {
                    let BackendInput::Digest32 { digest } = request.input else {
                        return Err(BackendError::InvalidRequest);
                    };
                    let digest: [u8; 32] = hex::decode(digest.as_str())
                        .map_err(|_| BackendError::InvalidRequest)?
                        .try_into()
                        .map_err(|_| BackendError::InvalidRequest)?;
                    let key = self.derive_secp_signing_key(&request.key_ref)?;
                    let (signature, recovery_id) = key
                        .sign_prehash_recoverable(&digest)
                        .map_err(|_| BackendError::DefinitiveRejected)?;
                    let mut normalized = signature.to_bytes().to_vec();
                    normalized.push(recovery_id.to_byte());
                    Ok(BackendSignature {
                        crypto_suite: request.crypto_suite,
                        encoding: SignatureEncoding::Secp256k1Recoverable65,
                        bytes: Base64UrlBytes::from_bytes(&normalized),
                        provider_correlation_id: None,
                    })
                }
                CryptoSuite::Ed25519Message => {
                    let BackendInput::Message { message } = request.input else {
                        return Err(BackendError::InvalidRequest);
                    };
                    let key = self.derive_ed25519_signing_key(&request.key_ref)?;
                    let signature = key.sign(&message.decode()).to_bytes();
                    key.verifying_key()
                        .verify_strict(
                            &message.decode(),
                            &ed25519_dalek::Signature::from_bytes(&signature),
                        )
                        .map_err(|_| BackendError::DefinitiveRejected)?;
                    Ok(BackendSignature {
                        crypto_suite: request.crypto_suite,
                        encoding: SignatureEncoding::Ed25519Raw64,
                        bytes: Base64UrlBytes::from_bytes(&signature),
                        provider_correlation_id: None,
                    })
                }
            }
        })
    }
}

impl SignerBackendActivation for LocalSignerBackend {
    fn prepare<'a>(&'a self, _key: &'a KeyRef) -> BackendFuture<'a, Result<Token, BackendError>> {
        Box::pin(async { Token::new("local-kek-v1").map_err(|_| BackendError::InvalidRequest) })
    }

    fn activate<'a>(
        &'a self,
        _key: &'a KeyRef,
        secret: SecretBytes,
    ) -> BackendFuture<'a, Result<(), BackendError>> {
        Box::pin(async move { self.activate_blocking(secret) })
    }

    fn deactivate<'a>(&'a self, _key: &'a KeyRef) -> BackendFuture<'a, Result<(), BackendError>> {
        Box::pin(async move {
            self.state.write().active_kek = None;
            Ok(())
        })
    }

    fn activation_status<'a>(
        &'a self,
        _key: &'a KeyRef,
    ) -> BackendFuture<'a, Result<ActivationStatus, BackendError>> {
        Box::pin(async move {
            Ok(if self.state.read().active_kek.is_some() {
                ActivationStatus::Active
            } else {
                ActivationStatus::Inactive
            })
        })
    }
}

impl SignerBackendDerivation for LocalSignerBackend {
    fn supported_derivation_schemes(&self) -> Vec<DerivationCapability> {
        self.capabilities().supported_derivation
    }

    fn derive_public<'a>(
        &'a self,
        root: &'a KeyRef,
        canonical_path: &'a str,
    ) -> BackendFuture<'a, Result<KeyDescription, BackendError>> {
        Box::pin(async move {
            if self.root_key_ref()? != *root {
                return Err(BackendError::InvalidRequest);
            }
            let key = self
                .state
                .read()
                .registry
                .values()
                .find(|key| {
                    matches!(
                        &key.derivation,
                        Some(DerivationRef::Bip32Secp256k1 { path, .. })
                            if path == canonical_path
                    )
                })
                .cloned()
                .ok_or(BackendError::InvalidRequest)?;
            self.describe_key(&key).await
        })
    }

    fn register_derived_key<'a>(
        &'a self,
        _root: &'a KeyRef,
        _canonical_path: &'a str,
    ) -> BackendFuture<'a, Result<KeyDescription, BackendError>> {
        Box::pin(async { Err(BackendError::InvalidRequest) })
    }
}

fn validate_namespace_prefix(prefix: &str) -> Result<(), BackendError> {
    let path = DerivationPath::from_str(prefix).map_err(|_| BackendError::InvalidRequest)?;
    if path.to_string() != prefix || prefix == "m" || prefix.split('/').count() > 10 {
        return Err(BackendError::InvalidRequest);
    }
    Ok(())
}

fn commit_backup(state: &mut LocalState, next: EncryptedLocalBackup) -> Result<(), BackendError> {
    let previous = state.backup.replace(next);
    if let Err(error) = persist_backup(state) {
        state.backup = previous;
        return Err(error);
    }
    Ok(())
}

fn persist_backup(state: &LocalState) -> Result<(), BackendError> {
    let Some(path) = &state.storage_path else {
        return Ok(());
    };
    let backup = state
        .backup
        .as_ref()
        .ok_or(BackendError::DefinitiveRejected)?;
    let bytes = serde_jcs::to_vec(backup).map_err(|_| BackendError::DefinitiveRejected)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(BackendError::InvalidRequest)?;
    let temporary = path.with_file_name(format!(".{file_name}.new"));
    fs::write(&temporary, bytes).map_err(|_| BackendError::DefinitiveRejected)?;
    fs::rename(&temporary, path).map_err(|_| BackendError::DefinitiveRejected)
}

fn root_aad(backend_instance_id: &Token, root_key_id: &Token) -> Vec<u8> {
    [
        ROOT_AAD_DOMAIN,
        backend_instance_id.as_str().as_bytes(),
        root_key_id.as_str().as_bytes(),
        &WRAP_FORMAT_VERSION.to_be_bytes(),
    ]
    .concat()
}

/// Parse a canonical BIP-39 profile path back into (account, index). Used by
/// the backend to derive the exact registered child from a `Bip39Multicurve`
/// derivation reference. Malformed paths fail closed.
fn parse_bip39_path(profile: DerivationProfile, path: &str) -> Result<(u32, u32), BackendError> {
    match profile {
        DerivationProfile::Bip44EvmSecp256k1V1 => {
            let tail = path
                .strip_prefix("m/44'/60'/")
                .ok_or(BackendError::InvalidRequest)?;
            let (account_part, index_part) =
                tail.split_once("/0/").ok_or(BackendError::InvalidRequest)?;
            let account = account_part
                .strip_suffix('\'')
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or(BackendError::InvalidRequest)?;
            let index = index_part
                .parse::<u32>()
                .ok()
                .ok_or(BackendError::InvalidRequest)?;
            Ok((account, index))
        }
        DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
            let tail = path
                .strip_prefix("m/44'/501'/")
                .ok_or(BackendError::InvalidRequest)?;
            let account = tail
                .strip_suffix("/0'")
                .and_then(|value| value.strip_suffix('\''))
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or(BackendError::InvalidRequest)?;
            Ok((account, 0))
        }
    }
}
