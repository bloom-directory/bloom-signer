//! Signer-owned WebAuthn surfaces. Deployment readiness is deliberately
//! separate from the immutable identity hashed into ceremony authority.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{DecimalU64, Digest32, ProtocolError, ProtocolErrorCode, Token};

pub const LOCAL_CEREMONY_ORIGIN: &str = "http://localhost:18734";
pub const LOCAL_CEREMONY_RP_ID: &str = "localhost";
pub const SURFACE_IDENTITY_SCHEMA: &str = "bloom.surface.identity.v1";
const SURFACE_IDENTITY_DOMAIN: &[u8] = b"bloom.surface.identity.v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceIdentity {
    pub schema: Token,
    pub surface_id: Token,
    pub origin: String,
    pub rp_id: Token,
    pub created_at_ms: DecimalU64,
}

impl SurfaceIdentity {
    pub fn local(created_at_ms: u64) -> Self {
        Self {
            schema: Token::new(SURFACE_IDENTITY_SCHEMA).expect("static surface schema"),
            surface_id: Token::new("local").expect("static surface ID"),
            origin: LOCAL_CEREMONY_ORIGIN.to_owned(),
            rp_id: Token::new(LOCAL_CEREMONY_RP_ID).expect("static RP ID"),
            created_at_ms: DecimalU64::new(created_at_ms),
        }
    }

    pub fn remote(hostname: &str, created_at_ms: u64) -> Result<Self, ProtocolError> {
        validate_remote_hostname(hostname)?;
        Ok(Self {
            schema: Token::new(SURFACE_IDENTITY_SCHEMA)?,
            surface_id: Token::new("remote")?,
            origin: format!("https://{hostname}"),
            rp_id: Token::new(hostname)?,
            created_at_ms: DecimalU64::new(created_at_ms),
        })
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema.as_str() != SURFACE_IDENTITY_SCHEMA {
            return Err(invalid_surface());
        }
        match self.surface_id.as_str() {
            "local"
                if self.origin == LOCAL_CEREMONY_ORIGIN
                    && self.rp_id.as_str() == LOCAL_CEREMONY_RP_ID =>
            {
                Ok(())
            }
            "remote" => {
                let hostname = self
                    .origin
                    .strip_prefix("https://")
                    .ok_or_else(invalid_surface)?;
                validate_remote_hostname(hostname)?;
                if self.rp_id.as_str() != hostname {
                    return Err(invalid_surface());
                }
                Ok(())
            }
            _ => Err(invalid_surface()),
        }
    }

    pub fn reference(&self) -> Result<SurfaceRef, ProtocolError> {
        self.validate()?;
        let canonical = serde_jcs::to_vec(self).map_err(|_| {
            ProtocolError::new(ProtocolErrorCode::MalformedFrame, "surface encoding failed")
        })?;
        let mut hash = Sha256::new();
        hash.update(SURFACE_IDENTITY_DOMAIN);
        hash.update(canonical);
        Ok(SurfaceRef {
            surface_id: self.surface_id.clone(),
            identity_digest: Digest32::from_bytes(hash.finalize().into()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceRef {
    pub surface_id: Token,
    pub identity_digest: Digest32,
}

/// Legacy localhost wallets migrate to this fixed identity. Keeping its
/// creation timestamp at zero avoids changing their RP, user handle, or wraps.
pub fn legacy_local_surface() -> SurfaceRef {
    SurfaceIdentity::local(0)
        .reference()
        .expect("static local surface identity")
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SurfaceLifecycle {
    Active,
    AuthenticationOnly,
    Disabled,
    Tombstoned,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceDescriptor {
    pub identity: SurfaceIdentity,
    pub identity_digest: Digest32,
    pub lifecycle: SurfaceLifecycle,
    pub lifecycle_revision: DecimalU64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureMode {
    RemoteEnabled,
    LocalhostOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceStatus {
    pub surfaces: Vec<SurfaceDescriptor>,
    #[serde(default)]
    pub installation_id: Option<String>,
    #[serde(default)]
    pub installation_admin_key_sha256: Option<Digest32>,
    pub desired_mode: ExposureMode,
    pub desired_revision: DecimalU64,
    pub effective_mode: ExposureMode,
    pub effective_revision: DecimalU64,
    pub remote_tls_ready: bool,
    pub remote_routing_ready: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceEffectiveReport {
    pub desired_revision: DecimalU64,
    pub remote_tls_ready: bool,
    pub remote_routing_ready: bool,
    pub remote_closed: bool,
}

impl SurfaceDescriptor {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.identity.reference()?.identity_digest != self.identity_digest {
            return Err(invalid_surface());
        }
        Ok(())
    }

    pub fn reference(&self) -> SurfaceRef {
        SurfaceRef {
            surface_id: self.identity.surface_id.clone(),
            identity_digest: self.identity_digest.clone(),
        }
    }
}

fn validate_remote_hostname(hostname: &str) -> Result<(), ProtocolError> {
    let Some(label) = hostname.strip_suffix(".relay.bloom.directory") else {
        return Err(invalid_surface());
    };
    if label.len() != 26
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        || hostname.len() > 64
    {
        return Err(invalid_surface());
    }
    Ok(())
}

fn invalid_surface() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::MalformedFrame,
        "unsupported ceremony surface identity",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_digest_is_stable_and_excludes_lifecycle() {
        let identity = SurfaceIdentity::local(42);
        let reference = identity.reference().unwrap();
        let mut descriptor = SurfaceDescriptor {
            identity,
            identity_digest: reference.identity_digest.clone(),
            lifecycle: SurfaceLifecycle::Active,
            lifecycle_revision: DecimalU64::new(1),
        };
        descriptor.validate().unwrap();
        descriptor.lifecycle = SurfaceLifecycle::Disabled;
        descriptor.lifecycle_revision = DecimalU64::new(2);
        assert_eq!(descriptor.reference(), reference);
    }

    #[test]
    fn remote_origin_is_exact_and_random_label_only() {
        let hostname = "abcdefghijklmnopqrstuv2345.relay.bloom.directory";
        let identity = SurfaceIdentity::remote(hostname, 9).unwrap();
        assert_eq!(identity.origin, format!("https://{hostname}"));
        for invalid in [
            "relay.bloom.directory",
            "ABCDEFGHIJKLMNOPQRSTUV2345.relay.bloom.directory",
            "abc123def456abc123def456.relay.bloom.directory.",
            "a.b.relay.bloom.directory",
            "abc123def456abc123def456.bloom.directory",
            "*.relay.bloom.directory",
        ] {
            assert!(SurfaceIdentity::remote(invalid, 9).is_err(), "{invalid}");
        }
    }
}
