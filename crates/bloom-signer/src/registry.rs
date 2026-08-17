use bloom_signer_api::{Base64UrlBytes, KeyRef, ProtocolError, ProtocolErrorCode, Token};
use bloom_signer_backend_api::{SecretBytes, SignerBackend, SignerBackendActivation};
use parking_lot::RwLock;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone)]
pub enum CompiledBackend {
    #[cfg(feature = "local")]
    Local(Arc<bloom_signer_backend_local::LocalSignerBackend>),
    #[cfg(feature = "aws-kms")]
    AwsKms(Arc<bloom_signer_backend_aws_kms::AwsKmsSignerBackend>),
}

impl CompiledBackend {
    fn as_backend(&self) -> Arc<dyn SignerBackend> {
        match self {
            #[cfg(feature = "local")]
            Self::Local(backend) => backend.clone(),
            #[cfg(feature = "aws-kms")]
            Self::AwsKms(backend) => backend.clone(),
        }
    }
}

pub struct BackendRegistry {
    backends: RwLock<BTreeMap<(Token, Token), CompiledBackend>>,
}

impl BackendRegistry {
    /// Only compile-time backend enum variants can enter the production
    /// registry; there is no runtime library/plugin loading path.
    pub fn from_compiled(backends: Vec<CompiledBackend>) -> Result<Self, ProtocolError> {
        let mut registry = BTreeMap::new();
        for backend in backends {
            let public = backend.as_backend();
            let backend_id = public.backend_id();
            let backend_instance_id = public.capabilities().backend_instance_id;
            if registry
                .insert((backend_id.clone(), backend_instance_id.clone()), backend)
                .is_some()
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::BackendInvalidRequest,
                    format!(
                        "duplicate compiled backend instance {backend_id}/{backend_instance_id}"
                    ),
                ));
            }
        }
        Ok(Self {
            backends: RwLock::new(registry),
        })
    }

    pub fn get(
        &self,
        backend_id: &Token,
        backend_instance_id: &Token,
    ) -> Result<Arc<dyn SignerBackend>, ProtocolError> {
        self.backends
            .read()
            .get(&(backend_id.clone(), backend_instance_id.clone()))
            .map(CompiledBackend::as_backend)
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    format!(
                        "backend instance {backend_id}/{backend_instance_id} is not compiled into this Signer"
                    ),
                )
            })
    }

    pub fn capabilities(&self) -> Vec<bloom_signer_backend_api::BackendCapabilities> {
        self.backends
            .read()
            .values()
            .map(|backend| backend.as_backend().capabilities())
            .collect()
    }

    #[cfg(feature = "aws-kms")]
    pub fn aws_kms_audit_events(&self) -> Vec<bloom_signer_backend_aws_kms::AwsKmsAuditEvent> {
        self.backends
            .read()
            .values()
            .flat_map(|backend| match backend {
                CompiledBackend::AwsKms(aws) => aws.audit_events(),
                #[cfg(feature = "local")]
                CompiledBackend::Local(_) => Vec::new(),
            })
            .collect()
    }

    pub fn key_is_available(
        &self,
        key_ref: &bloom_signer_api::KeyRef,
    ) -> Result<bool, ProtocolError> {
        let backend = self
            .backends
            .read()
            .get(&(key_ref.backend.clone(), key_ref.backend_instance.clone()))
            .cloned()
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    format!(
                        "backend instance {}/{} is not compiled into this Signer",
                        key_ref.backend, key_ref.backend_instance
                    ),
                )
            })?;
        match backend {
            #[cfg(feature = "local")]
            CompiledBackend::Local(local) => local.key_is_available(key_ref).map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!("local backend key availability failed: {error:?}"),
                )
            }),
            #[cfg(feature = "aws-kms")]
            CompiledBackend::AwsKms(aws) => Ok(aws.key_is_available(key_ref)),
        }
    }

    pub fn key_is_registered(
        &self,
        key_ref: &bloom_signer_api::KeyRef,
    ) -> Result<bool, ProtocolError> {
        let backend = self
            .backends
            .read()
            .get(&(key_ref.backend.clone(), key_ref.backend_instance.clone()))
            .cloned()
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    format!(
                        "backend instance {}/{} is not compiled into this Signer",
                        key_ref.backend, key_ref.backend_instance
                    ),
                )
            })?;
        match backend {
            #[cfg(feature = "local")]
            CompiledBackend::Local(local) => Ok(local.key_is_registered(key_ref)),
            #[cfg(feature = "aws-kms")]
            CompiledBackend::AwsKms(aws) => Ok(aws.key_is_registered(key_ref)),
        }
    }

    /// Activate without awaiting, for the synchronous custody-apply path.
    ///
    /// That path holds `parking_lot` guards, whose guards are not `Send`, so it
    /// cannot use `activate_key`. Both entry points funnel into the same backend
    /// body, and this one keeps the AWS-KMS rejection so nothing widens what is
    /// activatable.
    pub fn activate_key_blocking(
        &self,
        key_ref: &bloom_signer_api::KeyRef,
        secret: SecretBytes,
    ) -> Result<(), ProtocolError> {
        let backend = self
            .backends
            .read()
            .get(&(key_ref.backend.clone(), key_ref.backend_instance.clone()))
            .cloned()
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    "activation backend is not compiled into this Signer",
                )
            })?;
        match backend {
            #[cfg(feature = "local")]
            CompiledBackend::Local(local) => local.activate_blocking(secret).map_err(|cause| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendInvalidRequest,
                    format!("local backend activation failed: {cause:?}"),
                )
            }),
            #[cfg(feature = "aws-kms")]
            CompiledBackend::AwsKms(_) => Err(ProtocolError::new(
                ProtocolErrorCode::BackendUnsupported,
                "AWS KMS keys do not use Signer activation",
            )),
        }
    }

    pub async fn activate_key(
        &self,
        key_ref: &bloom_signer_api::KeyRef,
        secret: SecretBytes,
    ) -> Result<(), ProtocolError> {
        let backend = self
            .backends
            .read()
            .get(&(key_ref.backend.clone(), key_ref.backend_instance.clone()))
            .cloned()
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    "activation backend is not compiled into this Signer",
                )
            })?;
        match backend {
            #[cfg(feature = "local")]
            CompiledBackend::Local(local) => {
                local.activate(key_ref, secret).await.map_err(|cause| {
                    ProtocolError::new(
                        ProtocolErrorCode::BackendInvalidRequest,
                        format!("local backend activation failed: {cause:?}"),
                    )
                })
            }
            #[cfg(feature = "aws-kms")]
            CompiledBackend::AwsKms(_) => Err(ProtocolError::new(
                ProtocolErrorCode::BackendUnsupported,
                "AWS KMS keys do not use Signer activation",
            )),
        }
    }

    #[cfg(feature = "local")]
    pub fn provision_local_wallet_backend(
        &self,
        wallet_id: &Token,
        root_material: SecretBytes,
        imported_private_key: bool,
        activation_secret: SecretBytes,
        authority_verifying_key: ed25519_dalek::VerifyingKey,
    ) -> Result<(KeyRef, Base64UrlBytes), ProtocolError> {
        let backend_instance = wallet_id.clone();
        let backend = Arc::new(
            if imported_private_key {
                bloom_signer_backend_local::LocalSignerBackend::provision_imported_secp256k1(
                    backend_instance.clone(),
                    Token::new("wallet-root").expect("static token"),
                    root_material,
                    activation_secret,
                    authority_verifying_key,
                )
            } else {
                bloom_signer_backend_local::LocalSignerBackend::provision(
                    backend_instance.clone(),
                    Token::new("wallet-root").expect("static token"),
                    root_material,
                    activation_secret,
                    authority_verifying_key,
                )
            }
            .map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendInvalidRequest,
                    format!("local wallet provisioning failed: {error:?}"),
                )
            })?,
        );
        let key_ref = backend.root_key_ref().map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::BackendInvalidRequest,
                format!("local root description failed: {error:?}"),
            )
        })?;
        let encrypted_record = Base64UrlBytes::from_bytes(
            &serde_jcs::to_vec(&backend.encrypted_backup().map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!("local wallet backup failed: {error:?}"),
                )
            })?)
            .map_err(|error| {
                ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
            })?,
        );
        let backend_id = Token::new("local").expect("static token");
        let mut backends = self.backends.write();
        if backends.contains_key(&(backend_id.clone(), backend_instance.clone())) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "wallet backend instance already exists",
            ));
        }
        backends.insert(
            (backend_id, backend_instance),
            CompiledBackend::Local(backend),
        );
        Ok((key_ref, encrypted_record))
    }

    /// Provision a BIP-39 wallet backend: the root is entropy and is never a
    /// signable key, so this returns no root `KeyRef` — only the encrypted
    /// backend record for the backup set. Derived children are registered
    /// later via [`BackendRegistry::register_bip39_child`].
    pub fn provision_bip39_wallet_backend(
        &self,
        wallet_id: &Token,
        entropy: SecretBytes,
        activation_secret: SecretBytes,
        authority_verifying_key: ed25519_dalek::VerifyingKey,
    ) -> Result<Base64UrlBytes, ProtocolError> {
        let backend_instance = wallet_id.clone();
        let backend = Arc::new(
            bloom_signer_backend_local::LocalSignerBackend::provision_bip39(
                backend_instance.clone(),
                wallet_id.clone(),
                entropy,
                activation_secret,
                authority_verifying_key,
            )
            .map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendInvalidRequest,
                    format!("local bip39 wallet provisioning failed: {error:?}"),
                )
            })?,
        );
        let encrypted_record = Base64UrlBytes::from_bytes(
            &serde_jcs::to_vec(&backend.encrypted_backup().map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!("local bip39 wallet backup failed: {error:?}"),
                )
            })?)
            .map_err(|error| {
                ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
            })?,
        );
        let backend_id = Token::new("local").expect("static token");
        let mut backends = self.backends.write();
        if backends.contains_key(&(backend_id.clone(), backend_instance.clone())) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "wallet backend instance already exists",
            ));
        }
        backends.insert(
            (backend_id, backend_instance),
            CompiledBackend::Local(backend),
        );
        Ok(encrypted_record)
    }

    /// Restore a BIP-39 wallet backend (entropy root, no signable root KeyRef)
    /// from its persisted enrollment at startup.
    pub fn restore_bip39_wallet_backend(
        &self,
        backend_instance: &Token,
        encrypted_record: &Base64UrlBytes,
    ) -> Result<(), ProtocolError> {
        let backend_id = Token::new("local").expect("static token");
        if self
            .backends
            .read()
            .contains_key(&(backend_id.clone(), backend_instance.clone()))
        {
            return Ok(());
        }
        let backup: bloom_signer_backend_local::EncryptedLocalBackup =
            serde_json::from_slice(&encrypted_record.decode()).map_err(|error| {
                ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
            })?;
        if backup.root_material_kind
            != bloom_signer_backend_local::LocalRootMaterialKind::Bip39Entropy
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "backend enrollment is not a bip39 entropy root",
            ));
        }
        let backend = Arc::new(
            bloom_signer_backend_local::LocalSignerBackend::restore(
                backend_instance.clone(),
                backup,
            )
            .map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!("local bip39 wallet restore failed: {error:?}"),
                )
            })?,
        );
        self.backends.write().insert(
            (backend_id, backend_instance.clone()),
            CompiledBackend::Local(backend),
        );
        Ok(())
    }

    /// Register a BIP-39 derived child in the local backend registry.
    pub fn register_bip39_child(
        &self,
        wallet_id: &Token,
        key_ref: &bloom_signer_api::KeyRef,
        operation_id: Option<bloom_signer_api::OperationId>,
    ) -> Result<(), ProtocolError> {
        let backends = self.backends.read();
        let backend = backends
            .get(&(key_ref.backend.clone(), key_ref.backend_instance.clone()))
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    "backend instance is not compiled into this Signer",
                )
            })?;
        let _ = wallet_id;
        match backend {
            #[cfg(feature = "local")]
            CompiledBackend::Local(local) => local
                .register_bip39_child(key_ref.clone(), operation_id)
                .map_err(|error| {
                    ProtocolError::new(
                        ProtocolErrorCode::BackendInvalidRequest,
                        format!("local bip39 child registration failed: {error:?}"),
                    )
                }),
            #[cfg(feature = "aws-kms")]
            CompiledBackend::AwsKms(_) => Err(ProtocolError::new(
                ProtocolErrorCode::BackendUnsupported,
                "AWS KMS does not support bip39 child registration",
            )),
        }
    }

    /// Retire a BIP-39 derived child in the local backend registry.
    pub fn retire_bip39_child(
        &self,
        key_ref: &bloom_signer_api::KeyRef,
    ) -> Result<(), ProtocolError> {
        let backends = self.backends.read();
        let backend = backends
            .get(&(key_ref.backend.clone(), key_ref.backend_instance.clone()))
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    "backend instance is not compiled into this Signer",
                )
            })?;
        match backend {
            #[cfg(feature = "local")]
            CompiledBackend::Local(local) => local.retire_bip39_child(key_ref).map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendInvalidRequest,
                    format!("local bip39 child retirement failed: {error:?}"),
                )
            }),
            #[cfg(feature = "aws-kms")]
            CompiledBackend::AwsKms(_) => Err(ProtocolError::new(
                ProtocolErrorCode::BackendUnsupported,
                "AWS KMS does not support bip39 child retirement",
            )),
        }
    }

    #[cfg(feature = "local")]
    pub fn restore_local_wallet_backend(
        &self,
        backend_instance: &Token,
        encrypted_record: &Base64UrlBytes,
        expected_root: &KeyRef,
    ) -> Result<(), ProtocolError> {
        let backend_id = Token::new("local").expect("static token");
        if let Some(CompiledBackend::Local(existing)) = self
            .backends
            .read()
            .get(&(backend_id.clone(), backend_instance.clone()))
        {
            if existing.root_key_ref().map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorCode::KeyrefMismatch,
                    format!("existing local root description failed: {error:?}"),
                )
            })? == *expected_root
            {
                return Ok(());
            }
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "existing local wallet root differs from its durable enrollment",
            ));
        }
        let backup = serde_json::from_slice(&encrypted_record.decode()).map_err(|error| {
            ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
        })?;
        let backend = Arc::new(
            bloom_signer_backend_local::LocalSignerBackend::restore(
                backend_instance.clone(),
                backup,
            )
            .map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!("local wallet restore failed: {error:?}"),
                )
            })?,
        );
        if backend.root_key_ref().map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                format!("restored local root description failed: {error:?}"),
            )
        })? != *expected_root
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "restored local wallet root differs from its pinned KeyRef",
            ));
        }
        self.backends.write().insert(
            (backend_id, backend_instance.clone()),
            CompiledBackend::Local(backend),
        );
        Ok(())
    }

    #[cfg(feature = "local")]
    pub fn remove_local_wallet_backend(&self, key_ref: &KeyRef) {
        self.backends
            .write()
            .remove(&(key_ref.backend.clone(), key_ref.backend_instance.clone()));
    }

    #[cfg(feature = "local")]
    pub fn local_encrypted_backup(&self, root: &KeyRef) -> Result<Base64UrlBytes, ProtocolError> {
        let backend = self
            .backends
            .read()
            .get(&(root.backend.clone(), root.backend_instance.clone()))
            .cloned()
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    "local derivation backend is not compiled into this Signer",
                )
            })?;
        match backend {
            CompiledBackend::Local(local) => Ok(Base64UrlBytes::from_bytes(
                &serde_jcs::to_vec(&local.encrypted_backup().map_err(|error| {
                    ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        format!("local wallet backup failed: {error:?}"),
                    )
                })?)
                .map_err(|error| {
                    ProtocolError::new(ProtocolErrorCode::MalformedFrame, error.to_string())
                })?,
            )),
            #[cfg(feature = "aws-kms")]
            CompiledBackend::AwsKms(_) => Err(ProtocolError::new(
                ProtocolErrorCode::BackendUnsupported,
                "AWS KMS does not expose local custody backups",
            )),
        }
    }

    #[cfg(feature = "local")]
    pub fn configure_local_derivation_namespace(
        &self,
        root: &bloom_signer_api::KeyRef,
        grant: bloom_signer_backend_local::DerivationGrant,
        signature: bloom_signer_api::Base64UrlBytes,
    ) -> Result<(), ProtocolError> {
        let backend = self
            .backends
            .read()
            .get(&(root.backend.clone(), root.backend_instance.clone()))
            .cloned()
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    "derivation backend is not compiled into this Signer",
                )
            })?;
        match backend {
            CompiledBackend::Local(local) => local
                .configure_namespace(
                    &bloom_signer_backend_local::DerivationAuthority::from_signed(grant, signature),
                )
                .map_err(|error| {
                    ProtocolError::new(
                        ProtocolErrorCode::BackendInvalidRequest,
                        format!("local derivation namespace configuration failed: {error:?}"),
                    )
                }),
            #[cfg(feature = "aws-kms")]
            CompiledBackend::AwsKms(_) => Err(ProtocolError::new(
                ProtocolErrorCode::BackendUnsupported,
                "AWS KMS does not support derived keys",
            )),
        }
    }

    #[cfg(feature = "local")]
    pub fn allocate_local_derived_key(
        &self,
        root: &bloom_signer_api::KeyRef,
        namespace_id: &Token,
        grant: bloom_signer_backend_local::DerivationGrant,
        signature: bloom_signer_api::Base64UrlBytes,
        operation_id: &bloom_signer_api::OperationId,
    ) -> Result<bloom_signer_backend_api::KeyDescription, ProtocolError> {
        let backend = self
            .backends
            .read()
            .get(&(root.backend.clone(), root.backend_instance.clone()))
            .cloned()
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    "derivation backend is not compiled into this Signer",
                )
            })?;
        match backend {
            CompiledBackend::Local(local) => local
                .allocate_derived_key_for_operation(
                    root,
                    namespace_id,
                    &bloom_signer_backend_local::DerivationAuthority::from_signed(grant, signature),
                    operation_id,
                )
                .map_err(|error| {
                    ProtocolError::new(
                        ProtocolErrorCode::BackendInvalidRequest,
                        format!("local key derivation failed: {error:?}"),
                    )
                }),
            #[cfg(feature = "aws-kms")]
            CompiledBackend::AwsKms(_) => Err(ProtocolError::new(
                ProtocolErrorCode::BackendUnsupported,
                "AWS KMS does not support derived keys",
            )),
        }
    }

    #[cfg(feature = "local")]
    pub fn rollback_local_derived_key(
        &self,
        key_ref: &bloom_signer_api::KeyRef,
    ) -> Result<(), ProtocolError> {
        let backend = self
            .backends
            .read()
            .get(&(key_ref.backend.clone(), key_ref.backend_instance.clone()))
            .cloned()
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    "derivation backend is not compiled into this Signer",
                )
            })?;
        match backend {
            CompiledBackend::Local(local) => {
                local.tombstone_derived_key(key_ref).map_err(|error| {
                    ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        format!("derived-key rollback failed closed: {error:?}"),
                    )
                })
            }
            #[cfg(feature = "aws-kms")]
            CompiledBackend::AwsKms(_) => Err(ProtocolError::new(
                ProtocolErrorCode::BackendUnsupported,
                "AWS KMS does not support derived keys",
            )),
        }
    }

    #[cfg(feature = "local")]
    pub fn finalize_local_derived_key(
        &self,
        key_ref: &bloom_signer_api::KeyRef,
        operation_id: &bloom_signer_api::OperationId,
    ) -> Result<(), ProtocolError> {
        let backend = self
            .backends
            .read()
            .get(&(key_ref.backend.clone(), key_ref.backend_instance.clone()))
            .cloned()
            .ok_or_else(|| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendUnsupported,
                    "derivation backend is not compiled into this Signer",
                )
            })?;
        match backend {
            CompiledBackend::Local(local) => {
                local.finalize_derived_key(operation_id).map_err(|error| {
                    ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        format!("derived-key finalization failed: {error:?}"),
                    )
                })
            }
            #[cfg(feature = "aws-kms")]
            CompiledBackend::AwsKms(_) => Err(ProtocolError::new(
                ProtocolErrorCode::BackendUnsupported,
                "AWS KMS does not support derived keys",
            )),
        }
    }

    #[cfg(feature = "local")]
    pub fn pending_local_derivations(
        &self,
    ) -> Vec<(bloom_signer_api::OperationId, bloom_signer_api::KeyRef)> {
        self.backends
            .read()
            .values()
            .flat_map(|backend| match backend {
                CompiledBackend::Local(local) => local.pending_derivations(),
                #[cfg(feature = "aws-kms")]
                CompiledBackend::AwsKms(_) => Vec::new(),
            })
            .collect()
    }
}
