use bloom_signer_backend_api::SignerBackend;
use bloom_triad_protocol::{ProtocolError, ProtocolErrorCode, Token};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone)]
pub enum CompiledBackend {
    #[cfg(feature = "local")]
    Local(Arc<bloom_signer_backend_local::LocalSignerBackend>),
}

impl CompiledBackend {
    fn as_backend(&self) -> Arc<dyn SignerBackend> {
        match self {
            #[cfg(feature = "local")]
            Self::Local(backend) => backend.clone(),
        }
    }
}

pub struct BackendRegistry {
    backends: BTreeMap<(Token, Token), CompiledBackend>,
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
        Ok(Self { backends: registry })
    }

    pub fn get(
        &self,
        backend_id: &Token,
        backend_instance_id: &Token,
    ) -> Result<Arc<dyn SignerBackend>, ProtocolError> {
        self.backends
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
            .values()
            .map(|backend| backend.as_backend().capabilities())
            .collect()
    }

    pub fn key_is_available(
        &self,
        key_ref: &bloom_triad_protocol::KeyRef,
    ) -> Result<bool, ProtocolError> {
        let backend = self
            .backends
            .get(&(key_ref.backend.clone(), key_ref.backend_instance.clone()))
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
        }
    }

    pub fn key_is_registered(
        &self,
        key_ref: &bloom_triad_protocol::KeyRef,
    ) -> Result<bool, ProtocolError> {
        let backend = self
            .backends
            .get(&(key_ref.backend.clone(), key_ref.backend_instance.clone()))
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
        }
    }
}
