//! OS-activated Bloom Signer service process.

#![forbid(unsafe_code)]

use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use bloom_signer::{
    ceremony::SignerCeremonyService, clock::SignerClock, engine::SignerEngine,
    registry::BackendRegistry, registry::CompiledBackend, service::SignerRpcService,
};
#[cfg(feature = "aws-kms")]
use bloom_signer_backend_api::SecretBytes;
use bloom_triad_local_transport::{
    EndpointQuota, LocalIdentity, PeerAcl, load_identity_and_manifest,
};
use bloom_triad_protocol::{Digest32, ProtocolError, ProtocolErrorCode, Token};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::{net::UnixListener, sync::Semaphore};
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerConfig {
    database_path: PathBuf,
    broker_signing_key_id: String,
    broker_signing_public_key_hex: String,
    ceremony_verifying_public_key_hex: String,
    revocation_key_id: String,
    revocation_signing_seed_hex: String,
    ceremony_key_id: String,
    ceremony_signing_seed_hex: String,
    build_digest: String,
    maximum_connections: usize,
    maximum_in_flight_mutations: usize,
    maximum_requests_per_window: usize,
    request_window_ms: u64,
    maximum_journal_admissions_per_window: usize,
    journal_window_ms: u64,
    control_maximum_connections: usize,
    control_maximum_in_flight_mutations: usize,
    control_maximum_requests_per_window: usize,
    control_request_window_ms: u64,
    control_maximum_journal_admissions_per_window: usize,
    control_journal_window_ms: u64,
    aws_kms_backends: Vec<AwsKmsBackendConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsKmsBackendConfig {
    config: serde_json::Value,
    state_authentication_key_hex: String,
}

impl Drop for SignerConfig {
    fn drop(&mut self) {
        self.revocation_signing_seed_hex.zeroize();
        self.ceremony_signing_seed_hex.zeroize();
        for backend in &mut self.aws_kms_backends {
            backend.state_authentication_key_hex.zeroize();
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().len() == 2
        && std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--version"))
    {
        println!("bloom-signer {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let identity_path = env_path(
        "BLOOM_SIGNER_IDENTITY",
        "/var/run/bloom/signer-identity.json",
    );
    let manifest_path = env_path("BLOOM_EDGE_MANIFEST", "/etc/bloom/edge-manifest.json");
    let config_path = env_path("BLOOM_SIGNER_CONFIG", "/etc/bloom/signer.json");
    let activation_name =
        std::env::var("BLOOM_SIGNER_ACTIVATION_NAME").unwrap_or_else(|_| "signer".into());
    let control_activation_name = std::env::var("BLOOM_SIGNER_CONTROL_ACTIVATION_NAME")
        .unwrap_or_else(|_| "signer-control".into());

    let (identity, manifest) =
        load_identity_and_manifest(&identity_path, &manifest_path, "bloom-signer")?;
    let trusted_time_source = manifest.trusted_time_source.clone();
    let broker_acl = manifest.broker.into_acl()?;
    let revoke_client_acl = manifest.revoke_client.into_acl()?;
    if broker_acl.service_id.as_str() != "bloom-broker" {
        return Err("edge manifest does not pin bloom-broker for the Signer edge".into());
    }
    if revoke_client_acl.service_id.as_str() != "bloom-revoke-client" {
        return Err("edge manifest does not pin the dedicated revoke client".into());
    }
    let mut config = load_config(&config_path)?;
    let broker_public_key = verifying_key(&config.broker_signing_public_key_hex)?;
    let ceremony_public_key = verifying_key(&config.ceremony_verifying_public_key_hex)?;
    let revocation_signing_key = take_signing_key(&mut config.revocation_signing_seed_hex)?;
    let ceremony_signing_key = take_signing_key(&mut config.ceremony_signing_seed_hex)?;
    let build_digest = Digest32::new(config.build_digest.clone())?;

    let compiled_backends = build_aws_backends(&mut config.aws_kms_backends)?;
    let registry = Arc::new(BackendRegistry::from_compiled(compiled_backends)?);
    let engine = Arc::new(SignerEngine::open(
        &config.database_path,
        Token::new(config.broker_signing_key_id.clone())?,
        broker_public_key,
        ceremony_public_key,
        Token::new(config.revocation_key_id.clone())?,
        revocation_signing_key,
        registry,
    )?);
    let ceremony = Arc::new(SignerCeremonyService::new(
        engine.clone(),
        Token::new(config.ceremony_key_id.clone())?,
        ceremony_signing_key,
    )?);
    let clock = Arc::new(SignerClock::new(
        engine.clone(),
        &trusted_time_source,
        identity.boot_epoch.clone(),
    )?);
    if let Some(accepted_utc_ms) = clock_repair_request()? {
        let expiring = engine.active_approvals_expiring_by(accepted_utc_ms)?;
        require_clock_repair_confirmation(accepted_utc_ms, &expiring)?;
        let decision = engine.repair_clock(accepted_utc_ms)?;
        eprintln!(
            "Bloom Signer clock repair accepted: effective_utc_ms={}, condition={:?}, expiring_live_approvals={}",
            decision.effective_now_ms,
            decision.condition,
            serde_json::to_string(&expiring)?
        );
        return Ok(());
    }
    let service = Arc::new(SignerRpcService::new(
        engine,
        ceremony,
        clock,
        identity.boot_epoch.clone(),
        build_digest,
        env!("CARGO_PKG_VERSION"),
    ));

    let rpc_listener = UnixListener::from_std(bloom_service_activation::take_unix_listener(
        &activation_name,
    )?)?;
    let control_listener = UnixListener::from_std(bloom_service_activation::take_unix_listener(
        &control_activation_name,
    )?)?;
    let rpc_quota = Arc::new(EndpointQuota::new(
        config.maximum_in_flight_mutations,
        config.maximum_requests_per_window,
        config.request_window_ms,
        config.maximum_journal_admissions_per_window,
        config.journal_window_ms,
    )?);
    let control_quota = Arc::new(EndpointQuota::new(
        config.control_maximum_in_flight_mutations,
        config.control_maximum_requests_per_window,
        config.control_request_window_ms,
        config.control_maximum_journal_admissions_per_window,
        config.control_journal_window_ms,
    )?);
    if config.maximum_connections == 0 || config.control_maximum_connections == 0 {
        return Err("Signer connection quotas must be nonzero".into());
    }
    tokio::try_join!(
        serve_rpc(
            rpc_listener,
            identity.clone(),
            broker_acl,
            rpc_quota,
            service.clone(),
            config.maximum_connections,
        ),
        serve_control(
            control_listener,
            identity,
            revoke_client_acl,
            control_quota,
            service,
            config.control_maximum_connections,
        )
    )?;
    Ok(())
}

fn require_clock_repair_confirmation(
    accepted_utc_ms: u64,
    expiring: &[Digest32],
) -> Result<(), Box<dyn std::error::Error>> {
    if expiring.is_empty() {
        return Ok(());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"bloom-clock-repair-confirmation/v1");
    hasher.update(accepted_utc_ms.to_be_bytes());
    hasher.update(serde_jcs::to_vec(expiring)?);
    let expected = Digest32::from_bytes(hasher.finalize().into());
    let supplied = std::env::var("BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST").ok();
    if supplied.as_deref() != Some(expected.as_str()) {
        eprintln!(
            "Bloom Signer clock repair requires confirmation before mutation: accepted_utc_ms={}, expiring_live_approvals={}, confirmation_digest={}",
            accepted_utc_ms,
            serde_json::to_string(expiring)?,
            expected
        );
        return Err(
            "clock repair not committed; set BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST to the reported digest"
                .into(),
        );
    }
    Ok(())
}

fn clock_repair_request() -> Result<Option<u64>, Box<dyn std::error::Error>> {
    std::env::var("BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS")
        .ok()
        .map(|value| {
            value.parse::<u64>().map_err(|error| {
                format!("invalid BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS: {error}").into()
            })
        })
        .transpose()
}

async fn serve_rpc(
    listener: UnixListener,
    identity: LocalIdentity,
    broker_acl: PeerAcl,
    quota: Arc<EndpointQuota>,
    service: Arc<SignerRpcService>,
    maximum_connections: usize,
) -> std::io::Result<()> {
    let connections = Arc::new(Semaphore::new(maximum_connections));
    loop {
        let permit = connections
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| std::io::Error::other("Signer RPC connection gate closed"))?;
        let (mut stream, _) = listener.accept().await?;
        let identity = identity.clone();
        let broker_acl = broker_acl.clone();
        let quota = quota.clone();
        let service = service.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = bloom_triad_local_transport::dispatch_broker_signer_connection(
                &mut stream,
                &identity,
                &broker_acl,
                &quota,
                service.as_ref(),
            )
            .await;
        });
    }
}

async fn serve_control(
    listener: UnixListener,
    identity: LocalIdentity,
    revoke_client_acl: PeerAcl,
    quota: Arc<EndpointQuota>,
    service: Arc<SignerRpcService>,
    maximum_connections: usize,
) -> std::io::Result<()> {
    let connections = Arc::new(Semaphore::new(maximum_connections));
    loop {
        let permit = connections
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| std::io::Error::other("Signer control connection gate closed"))?;
        let (mut stream, _) = listener.accept().await?;
        let identity = identity.clone();
        let revoke_client_acl = revoke_client_acl.clone();
        let quota = quota.clone();
        let service = service.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = bloom_triad_local_transport::dispatch_control_connection(
                &mut stream,
                &identity,
                &revoke_client_acl,
                &quota,
                service.as_ref(),
            )
            .await;
        });
    }
}

fn env_path(name: &str, default: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

fn load_config(path: &Path) -> Result<SignerConfig, ProtocolError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            format!("inspect {}: {error}", path.display()),
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o077 != 0
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            "Signer config must be a non-symlink regular file with mode 0600 or stricter",
        ));
    }
    let mut bytes = fs::read(path).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            format!("read {}: {error}", path.display()),
        )
    })?;
    let result = serde_json::from_slice(&bytes).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorCode::MalformedFrame,
            format!("parse {}: {error}", path.display()),
        )
    });
    bytes.zeroize();
    result
}

fn verifying_key(encoded: &str) -> Result<VerifyingKey, ProtocolError> {
    let bytes: [u8; 32] = hex::decode(encoded)
        .map_err(|_| invalid_key("public key must be hexadecimal"))?
        .try_into()
        .map_err(|_| invalid_key("public key must contain 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| invalid_key("public key encoding is invalid"))
}

fn take_signing_key(encoded: &mut String) -> Result<SigningKey, ProtocolError> {
    let mut bytes: [u8; 32] = hex::decode(encoded.as_bytes())
        .map_err(|_| invalid_key("signing seed must be hexadecimal"))?
        .try_into()
        .map_err(|_| invalid_key("signing seed must contain 32 bytes"))?;
    encoded.zeroize();
    let key = SigningKey::from_bytes(&bytes);
    bytes.zeroize();
    Ok(key)
}

#[cfg(feature = "aws-kms")]
fn take_secret(encoded: &mut String, expected_bytes: usize) -> Result<SecretBytes, ProtocolError> {
    let mut bytes =
        hex::decode(encoded.as_bytes()).map_err(|_| invalid_key("secret must be hexadecimal"))?;
    encoded.zeroize();
    if bytes.len() != expected_bytes {
        bytes.zeroize();
        return Err(invalid_key("secret has the wrong length"));
    }
    let secret = SecretBytes::new(bytes.clone());
    bytes.zeroize();
    Ok(secret)
}

#[cfg(feature = "aws-kms")]
fn build_aws_backends(
    backends: &mut [AwsKmsBackendConfig],
) -> Result<Vec<CompiledBackend>, ProtocolError> {
    let mut compiled = Vec::with_capacity(backends.len());
    for backend in backends {
        let backend_config: bloom_signer_backend_aws_kms::AwsKmsInstanceConfig =
            serde_json::from_value(backend.config.clone()).map_err(|error| {
                ProtocolError::new(
                    ProtocolErrorCode::BackendInvalidRequest,
                    format!("invalid AWS KMS backend config: {error}"),
                )
            })?;
        let authentication_key = take_secret(&mut backend.state_authentication_key_hex, 32)?;
        let signer = bloom_signer_backend_aws_kms::AwsKmsSignerBackend::from_aws_sdk(
            backend_config,
            authentication_key,
        )
        .map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::BackendInvalidRequest,
                format!("construct AWS KMS backend: {error}"),
            )
        })?;
        compiled.push(CompiledBackend::AwsKms(Arc::new(signer)));
    }
    Ok(compiled)
}

#[cfg(not(feature = "aws-kms"))]
fn build_aws_backends(
    backends: &mut [AwsKmsBackendConfig],
) -> Result<Vec<CompiledBackend>, ProtocolError> {
    for backend in backends.iter() {
        let _ = &backend.config;
    }
    if backends.is_empty() {
        Ok(Vec::new())
    } else {
        Err(ProtocolError::new(
            ProtocolErrorCode::BackendUnsupported,
            "Signer config requires AWS KMS but this artifact excludes the aws-kms feature",
        ))
    }
}

fn invalid_key(message: &str) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::UnauthenticatedPeer, message)
}
