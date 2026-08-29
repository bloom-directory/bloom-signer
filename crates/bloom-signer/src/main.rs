//! OS-activated Bloom Signer service process.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs,
    io::ErrorKind,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bloom_audit_checkpoint::{
    AppendOutcome, AuthorityEdgeHistory, CheckpointDecision, CheckpointDecisionOutcome,
    CheckpointError, CheckpointSink, CheckpointStore, PinnedAuditKey,
};
use bloom_platform_containment::NetworkContainmentGuard;
use bloom_service_observability::{LogOutput, SecureLogFile};
use bloom_signer::{
    ceremony::SignerCeremonyService,
    clock::SignerClock,
    engine::{AuditDegradation, SignerAuditKeys, SignerEngine},
    legacy_passkey::LegacyMigrationStore,
    registry::BackendRegistry,
    registry::CompiledBackend,
    service::SignerRpcService,
};
use bloom_signer_api::{
    BrokerSignerRequest, BrokerSignerResponse, BrokerSignerService, ControlRequest,
    ControlResponse, Digest32, ProtocolError, ProtocolErrorCode, RevocationControlService,
    ServiceFuture, SignedJournalHead, Token, TypedRequestMethod, is_read_only_method,
};
#[cfg(feature = "aws-kms")]
use bloom_signer_backend_api::SecretBytes;
#[cfg(feature = "triad-dev-harness")]
use bloom_triad_local_transport::load_developer_identity_and_manifest;
use bloom_triad_local_transport::{
    AuthenticatedRequestContext, EndpointQuota, JournalExchange, LocalIdentity, PeerAcl,
    load_identity_and_manifest,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::AsyncReadExt as _,
    net::{UnixListener, UnixStream},
    sync::{Semaphore, watch},
};
use tracing::Instrument as _;
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
    audit_key_id: String,
    audit_signing_seed_hex: String,
    #[serde(default)]
    audit_historical_public_keys: Vec<AuditPublicKeyConfig>,
    #[serde(default)]
    audit_rotation_previous_key: Option<AuditPreviousSigningKeyConfig>,
    ceremony_key_id: String,
    ceremony_signing_seed_hex: String,
    build_digest: String,
    network_containment: Option<NetworkContainmentConfig>,
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
struct AuditPublicKeyConfig {
    key_id: String,
    public_key_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditPreviousSigningKeyConfig {
    key_id: String,
    signing_seed_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkContainmentConfig {
    status_path: PathBuf,
    login_uid: u32,
    maximum_age_ms: u64,
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
        self.audit_signing_seed_hex.zeroize();
        if let Some(previous) = &mut self.audit_rotation_previous_key {
            previous.signing_seed_hex.zeroize();
        }
        self.ceremony_signing_seed_hex.zeroize();
        for backend in &mut self.aws_kms_backends {
            backend.state_authentication_key_hex.zeroize();
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if std::env::args_os().len() == 2
        && std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--version"))
    {
        println!("bloom-signer {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if let Err(error) = bloom_signer_process_hardening::harden_process() {
        eprintln!("Signer process hardening failed: {error}");
        std::process::exit(1);
    }
    let output = match signer_log_output() {
        Ok(output) => output,
        Err(()) => {
            eprintln!("Bloom Signer logging configuration is invalid");
            std::process::exit(1);
        }
    };
    if bloom_service_observability::init("signer", env!("CARGO_PKG_VERSION"), output).is_err() {
        eprintln!("Bloom Signer logging initialization failed");
        std::process::exit(1);
    }
    let trusted_metadata_loaded = Arc::new(AtomicBool::new(false));
    let result = run(trusted_metadata_loaded.clone()).await;
    if result.is_err() {
        if !trusted_metadata_loaded.load(Ordering::SeqCst) {
            tracing::error!(
                event = "service.fatal_exit",
                service_role = "signer",
                error_kind = "bootstrap_failure",
                "Bloom Signer exiting after a bootstrap error"
            );
        }
        std::process::exit(1);
    }
}

struct TrustedFatalGuard {
    span: tracing::Span,
    armed: bool,
}

impl TrustedFatalGuard {
    fn new(span: tracing::Span) -> Self {
        Self { span, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TrustedFatalGuard {
    fn drop(&mut self) {
        if self.armed {
            self.span.in_scope(|| {
                tracing::error!(
                    event = "service.fatal_exit",
                    service_role = "signer",
                    error_kind = "service_failure",
                    "Bloom Signer exiting after a fatal error"
                );
            });
        }
    }
}

fn signer_log_output() -> Result<LogOutput, ()> {
    let Some(path) = std::env::var_os("BLOOM_SIGNER_LOG_PATH") else {
        return Ok(LogOutput::JsonStderr);
    };
    let owner_uid = required_u32_env("BLOOM_SIGNER_LOG_OWNER_UID")?;
    let reader_gid = required_u32_env("BLOOM_SIGNER_LOG_READER_GID")?;
    Ok(LogOutput::JsonFile(SecureLogFile::new(
        PathBuf::from(path),
        owner_uid,
        reader_gid,
    )))
}

fn required_u32_env(name: &str) -> Result<u32, ()> {
    std::env::var(name)
        .map_err(|_| ())?
        .parse::<u32>()
        .map_err(|_| ())
}

async fn run(trusted_metadata_loaded: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    let identity_path = env_path(
        "BLOOM_SIGNER_IDENTITY",
        "/var/run/bloom/signer-identity.json",
    );
    let manifest_path = env_path("BLOOM_EDGE_MANIFEST", "/etc/bloom/edge-manifest.json");
    let config_path = env_path("BLOOM_SIGNER_CONFIG", "/etc/bloom/signer.json");
    #[cfg(feature = "triad-dev-harness")]
    let loaded_identity = match std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT") {
        Some(root) => load_developer_identity_and_manifest(
            Path::new(&root),
            &identity_path,
            &manifest_path,
            "bloom-signer",
        )?,
        None => load_identity_and_manifest(&identity_path, &manifest_path, "bloom-signer")?,
    };
    #[cfg(not(feature = "triad-dev-harness"))]
    let loaded_identity =
        load_identity_and_manifest(&identity_path, &manifest_path, "bloom-signer")?;
    let (identity, manifest) = loaded_identity;
    let trusted_time_source = manifest.trusted_time_source.clone();
    let signer_effective_uid = manifest.signer.effective_uid;
    tracing::info!(
        event = "service.identity_loaded",
        service_role = "signer",
        service_id = identity.service_id.as_str(),
        application_key_id = identity.application_key_id.as_str(),
        effective_uid = signer_effective_uid,
        "Bloom Signer trusted identity loaded"
    );
    let session_acl = manifest
        .session
        .clone()
        .ok_or("edge manifest has no login-session identity")?
        .into_acl()?;
    let broker_acl = manifest.broker.into_acl()?;
    let revoke_client_acl = manifest.revoke_client.into_acl()?;
    if broker_acl.service_id.as_str() != "bloom-broker"
        || session_acl.service_id.as_str() != "bloom-session"
    {
        return Err("edge manifest does not pin bloom-broker for the Signer edge".into());
    }
    if revoke_client_acl.service_id.as_str() != "bloom-revoke-client" {
        return Err("edge manifest does not pin the dedicated revoke client".into());
    }
    #[cfg(feature = "triad-dev-harness")]
    let history_owner = if std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT").is_some() {
        signer_effective_uid
    } else {
        0
    };
    #[cfg(not(feature = "triad-dev-harness"))]
    let history_owner = 0;
    let checkpoint_store = (|| -> Result<CheckpointStore, CheckpointError> {
        let history = AuthorityEdgeHistory::load_trusted(
            env_path(
                "BLOOM_AUTHORITY_EDGE_HISTORY",
                "/etc/bloom/authority-edge-history.json",
            ),
            history_owner,
        )?;
        let services = [&broker_acl.service_id, &identity.service_id];
        CheckpointStore::open_with_history(
            env_path(
                "BLOOM_SIGNER_AUDIT_CHECKPOINT_DIR",
                "/var/db/bloom/signer/audit-checkpoints",
            ),
            signer_effective_uid,
            identity.service_id.clone(),
            [
                PinnedAuditKey {
                    service_id: broker_acl.service_id.clone(),
                    key_id: broker_acl.application_key_id.clone(),
                    verifying_key: VerifyingKey::from_bytes(&broker_acl.application_public_key)
                        .map_err(|_| CheckpointError::InvalidSignature)?,
                },
                PinnedAuditKey {
                    service_id: identity.service_id.clone(),
                    key_id: identity.application_key_id.clone(),
                    verifying_key: identity.signing_key.verifying_key(),
                },
            ],
            history.historical_pins_for(&services)?,
            history.handovers_for(&services),
        )
    })();
    let checkpoint_store: Arc<dyn CheckpointSink> = match checkpoint_store {
        Ok(store) => Arc::new(store),
        Err(error) => {
            tracing::error!(
                event = "signer.checkpoint_store_unavailable",
                error_kind = checkpoint_error_kind(&error),
                mutations_disabled = true,
                "Signer checkpoint store is unavailable"
            );
            Arc::new(UnavailableCheckpointSink {
                reason: error.to_string(),
            })
        }
    };
    let mut config = load_config(&config_path)?;
    let broker_public_key = verifying_key(&config.broker_signing_public_key_hex)?;
    let ceremony_public_key = verifying_key(&config.ceremony_verifying_public_key_hex)?;
    let revocation_signing_key = take_signing_key(&mut config.revocation_signing_seed_hex)?;
    let audit_signing_key = take_signing_key(&mut config.audit_signing_seed_hex)?;
    if config.audit_key_id == config.revocation_key_id
        || audit_signing_key.verifying_key() == revocation_signing_key.verifying_key()
        || audit_signing_key.verifying_key() == identity.signing_key.verifying_key()
    {
        return Err(
            "Signer audit key must be distinct from revocation and application keys".into(),
        );
    }
    let previous_audit_signing_key = config
        .audit_rotation_previous_key
        .as_mut()
        .map(|previous| -> Result<(Token, SigningKey), ProtocolError> {
            Ok((
                Token::new(previous.key_id.clone())?,
                take_signing_key(&mut previous.signing_seed_hex)?,
            ))
        })
        .transpose()?;
    let ceremony_signing_key = take_signing_key(&mut config.ceremony_signing_seed_hex)?;
    if config.audit_key_id == config.ceremony_key_id
        || audit_signing_key.verifying_key() == ceremony_signing_key.verifying_key()
    {
        return Err("Signer audit key must be distinct from the ceremony key".into());
    }
    let build_digest = Digest32::new(config.build_digest.clone())?;
    let service_span = bloom_service_observability::service_span(
        "signer",
        env!("CARGO_PKG_VERSION"),
        identity.service_id.as_str(),
        Some(session_acl.effective_uid),
        Some(build_digest.as_str()),
    );
    trusted_metadata_loaded.store(true, Ordering::SeqCst);
    let mut trusted_fatal = TrustedFatalGuard::new(service_span.clone());

    let service_span_guard = service_span.enter();
    let compiled_backends = build_aws_backends(&mut config.aws_kms_backends)?;
    let registry = Arc::new(BackendRegistry::from_compiled(compiled_backends)?);
    let engine = Arc::new(open_operational_signer_engine(
        &config.database_path,
        Token::new(config.broker_signing_key_id.clone())?,
        broker_public_key,
        ceremony_public_key,
        Token::new(config.revocation_key_id.clone())?,
        revocation_signing_key,
        Token::new(config.audit_key_id.clone())?,
        audit_signing_key,
        &config.audit_historical_public_keys,
        previous_audit_signing_key,
        registry,
    )?);
    let migration_root = config
        .database_path
        .parent()
        .ok_or("Signer database path has no parent directory")?
        .join("legacy-passkey-migrations");
    let migration_store = Arc::new(LegacyMigrationStore::create_for_current_process(
        migration_root,
        signer_effective_uid,
    )?);
    let ceremony = Arc::new(
        SignerCeremonyService::new(
            engine.clone(),
            Token::new(config.ceremony_key_id.clone())?,
            ceremony_signing_key,
        )?
        .with_legacy_migrations(migration_store),
    );
    let clock = Arc::new(SignerClock::new(
        engine.clone(),
        &trusted_time_source,
        identity.boot_epoch.clone(),
    )?);
    if let Some(accepted_utc_ms) = clock_repair_request()? {
        if !clock.uses_durable_clock_guard() {
            return Err(
                "clock repair is unavailable when the host wall clock is authoritative".into(),
            );
        }
        let expiring = engine.active_approvals_expiring_by(accepted_utc_ms)?;
        require_clock_repair_confirmation(accepted_utc_ms, &expiring)?;
        let decision = engine.repair_clock(accepted_utc_ms)?;
        tracing::info!(
            event = "signer.clock_repair_committed",
            effective_utc_ms = decision.effective_now_ms,
            condition = decision.condition.as_str(),
            expiring_live_approval_count = expiring.len(),
            "Signer clock repair committed"
        );
        trusted_fatal.disarm();
        return Ok(());
    }
    let containment = config
        .network_containment
        .as_ref()
        .map(|containment| {
            NetworkContainmentGuard::new(
                containment.status_path.clone(),
                containment.login_uid,
                build_digest.clone(),
                containment.maximum_age_ms,
            )
        })
        .transpose()?;
    let initial_audit_head =
        select_initial_self_head(engine.as_ref(), checkpoint_store.as_ref(), &identity)?;
    let journal_exchange = Arc::new(SignerJournalExchange {
        engine: engine.clone(),
        checkpoints: checkpoint_store,
        identity: identity.clone(),
        last_verified_head: Mutex::new(initial_audit_head),
    });
    let mut service = SignerRpcService::new(
        engine,
        ceremony,
        clock,
        identity.boot_epoch.clone(),
        build_digest,
        env!("CARGO_PKG_VERSION"),
    );
    if let Some(containment) = containment {
        service = service.with_network_containment(containment);
    }
    let service = Arc::new(service);
    let control_service = Arc::new(CheckpointingControlService {
        inner: service.clone(),
        journals: journal_exchange.clone(),
    });

    let rpc_listener = UnixListener::from_std(acquire_unix_listener(
        "BLOOM_SIGNER_SOCKET",
        "BLOOM_SIGNER_ACTIVATION_NAME",
        "signer",
    )?)?;
    let control_listener = UnixListener::from_std(acquire_unix_listener(
        "BLOOM_SIGNER_CONTROL_SOCKET",
        "BLOOM_SIGNER_CONTROL_ACTIVATION_NAME",
        "signer-control",
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
    let session_socket_path = env_path(
        "BLOOM_SESSION_SOCKET",
        "/var/run/bloom/session/session.sock",
    );
    drop(service_span_guard);
    let mut session_stream =
        connect_authenticated_session(&session_socket_path, &identity, &session_acl)
            .instrument(service_span.clone())
            .await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut rpc_shutdown = shutdown_rx.clone();
    let mut control_shutdown = shutdown_rx;
    async move {
        tracing::info!(
            event = "service.ready",
            service_role = "signer",
            rpc_endpoint = "broker",
            control_endpoint = "revocation",
            "Bloom Signer ready"
        );
        tokio::try_join!(
            serve_rpc(
                rpc_listener,
                identity.clone(),
                broker_acl,
                rpc_quota,
                service.clone(),
                journal_exchange,
                config.maximum_connections,
                &mut rpc_shutdown,
            ),
            serve_control(
                control_listener,
                identity,
                revoke_client_acl,
                control_quota,
                control_service,
                config.control_maximum_connections,
                &mut control_shutdown,
            ),
            async move {
                let mut unexpected = [0_u8; 1];
                match session_stream.read(&mut unexpected).await {
                    Ok(0) => shutdown_tx.send(true).map_err(|_| {
                        std::io::Error::other("Signer shutdown receivers disappeared")
                    }),
                    Err(error) if is_session_disconnect(&error) => {
                        shutdown_tx.send(true).map_err(|_| {
                            std::io::Error::other("Signer shutdown receivers disappeared")
                        })
                    }
                    Ok(_) => Err(std::io::Error::other(
                        "session sentinel sent unexpected channel data",
                    )),
                    Err(error) => Err(std::io::Error::new(
                        error.kind(),
                        format!("monitor login-session sentinel: {error}"),
                    )),
                }
            },
        )?;
        tracing::info!(
            event = "service.shutdown",
            service_role = "signer",
            reason = "session_ended",
            "Bloom Signer stopped"
        );
        Ok::<(), std::io::Error>(())
    }
    .instrument(service_span)
    .await?;
    trusted_fatal.disarm();
    Ok(())
}

fn is_session_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
    )
}

#[cfg(target_os = "macos")]
fn acquire_unix_listener(
    path_variable: &str,
    _activation_variable: &str,
    _default_activation_name: &str,
) -> Result<std::os::unix::net::UnixListener, Box<dyn std::error::Error>> {
    let path = std::env::var_os(path_variable)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{path_variable} is required by the macOS service profile"))?;
    Ok(bloom_service_activation::bind_owned_unix_listener(&path)?)
}

#[cfg(not(target_os = "macos"))]
fn acquire_unix_listener(
    path_variable: &str,
    _activation_variable: &str,
    _default_activation_name: &str,
) -> Result<std::os::unix::net::UnixListener, Box<dyn std::error::Error>> {
    let path = std::env::var_os(path_variable)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{path_variable} is required by the Linux service profile"))?;
    Ok(bloom_service_activation::bind_owned_unix_listener(&path)?)
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
    // Approval IDs are public operational digests: showing each exact ID is
    // what makes this destructive confirmation informed without exposing the
    // approval terms or any credential material.
    log_clock_repair_expiring_approvals(accepted_utc_ms, expiring, &expected);
    let supplied = std::env::var("BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST").ok();
    if supplied.as_deref() != Some(expected.as_str()) {
        tracing::warn!(
            event = "signer.clock_repair_confirmation_required",
            accepted_utc_ms,
            expiring_live_approval_count = expiring.len(),
            confirmation_digest = expected.as_str(),
            "Signer clock repair requires operator confirmation"
        );
        return Err(
            "clock repair not committed; set BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST to the reported digest"
                .into(),
        );
    }
    Ok(())
}

fn log_clock_repair_expiring_approvals(
    accepted_utc_ms: u64,
    expiring: &[Digest32],
    confirmation_digest: &Digest32,
) {
    for approval_id in expiring {
        tracing::warn!(
            event = "signer.clock_repair_expiring_approval",
            accepted_utc_ms,
            approval_id = approval_id.as_str(),
            confirmation_digest = confirmation_digest.as_str(),
            "Signer clock repair would expire a live approval"
        );
    }
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

/// Whether a Broker request body relies on a protocol-minor-5-only field:
/// the BIP-39 seed profile, the derived-account allocation request, or the
/// account allocate/retire ceremony kinds.
fn request_uses_minor_5_features(request: &BrokerSignerRequest) -> bool {
    let custody = match request {
        BrokerSignerRequest::KeyDerivePrepare(r)
        | BrokerSignerRequest::KeyEnrollPrepare(r)
        | BrokerSignerRequest::WalletRegistrationPrepare(r)
        | BrokerSignerRequest::WalletUnlockPrepare(r)
        | BrokerSignerRequest::WalletImportPrepare(r)
        | BrokerSignerRequest::WalletExportPrepare(r)
        | BrokerSignerRequest::WalletDeletePrepare(r)
        | BrokerSignerRequest::CredentialAddPrepare(r)
        | BrokerSignerRequest::CredentialRemovePrepare(r)
        | BrokerSignerRequest::CredentialReplacePrepare(r)
        | BrokerSignerRequest::RecoveryPrepare(r) => Some(r),
        _ => None,
    };
    custody.is_some_and(|request| {
        request.wallet_seed_profile.is_some()
            || request.derivation_request.is_some()
            || matches!(
                request.ceremony_kind,
                bloom_signer_api::CeremonyKind::AccountAllocate
                    | bloom_signer_api::CeremonyKind::AccountRetire
            )
    })
}

/// Authority-edge dispatch with per-request protocol enforcement. The
/// transport negotiates and verifies the request's signed protocol against
/// the supported range; this seam additionally refuses a pre-1.5 peer that
/// carries a minor-5-only field.
///
/// The floor tracks the bip39 surface, not the supported minimum. Those were
/// both 4 while the bip39 fields were minor-4, but the terminal
/// ceremony-status contract took 1.4 and moved the bip39 surface to 1.5. A
/// gate left at `< 4` would be unreachable, because the transport already
/// refuses anything below the 1.4 floor, and a 1.4 peer would reach dispatch
/// carrying fields it cannot have understood.
async fn dispatch_authority_connection<Dispatch, DispatchFuture>(
    stream: &mut UnixStream,
    identity: &LocalIdentity,
    broker_acl: &PeerAcl,
    quota: &EndpointQuota,
    journals: &dyn JournalExchange<ProtocolError>,
    dispatch: Dispatch,
) -> Result<(), ProtocolError>
where
    Dispatch: Fn(BrokerSignerRequest, AuthenticatedRequestContext) -> DispatchFuture,
    DispatchFuture: Future<Output = Result<BrokerSignerResponse, ProtocolError>>,
{
    use bloom_signer_api::JournalHeadPolicy;

    let request = bloom_triad_local_transport::receive_request::<BrokerSignerRequest>(
        stream,
        identity,
        broker_acl,
        bloom_signer_api::SIGNER_API_CURRENT,
        bloom_signer_api::SIGNER_API_RANGE,
        JournalHeadPolicy::Required,
    )
    .await?;
    let context = AuthenticatedRequestContext {
        method: request.unsigned.method.clone(),
        operation_id: request.unsigned.operation_id.clone(),
        caller_service_id: request.unsigned.caller_service_id.clone(),
        caller_boot_epoch: request.unsigned.caller_boot_epoch.clone(),
        caller_application_key_id: request.unsigned.application_key_id.clone(),
        sent_at_ms: request.unsigned.sent_at_ms.get(),
        deadline_ms: request.unsigned.deadline_ms.get(),
    };
    if request.unsigned.protocol.major == 1
        && request.unsigned.protocol.minor < 5
        && request_uses_minor_5_features(&request.unsigned.body)
    {
        let (sequence, head_hash) = journals.local_journal_head_with_context(&context)?;
        let head = bloom_triad_local_transport::sign_journal_head(identity, sequence, head_hash);
        return bloom_triad_local_transport::send_response_with_journal_head::<
            BrokerSignerRequest,
            BrokerSignerResponse,
            ProtocolError,
        >(
            stream,
            identity,
            &request,
            Err(ProtocolError::new(
                ProtocolErrorCode::UnsupportedVersion,
                "request body uses protocol-minor-5 fields for a pre-1.5 peer",
            )),
            head,
        )
        .await
        .map_err(bloom_signer_api::ProtocolError::from);
    }
    let peer_head = request
        .unsigned
        .sender_journal_head
        .as_ref()
        .ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorCode::UnauthenticatedPeer,
                "authority-edge request omitted its authenticated journal head",
            )
        })?;
    if let Err(error) = journals.checkpoint_request_head_with_context(&context, peer_head) {
        let (sequence, head_hash) = journals.local_journal_head_with_context(&context)?;
        let head = bloom_triad_local_transport::sign_journal_head(identity, sequence, head_hash);
        return bloom_triad_local_transport::send_response_with_journal_head::<
            BrokerSignerRequest,
            BrokerSignerResponse,
            ProtocolError,
        >(stream, identity, &request, Err(error), head)
        .await
        .map_err(bloom_signer_api::ProtocolError::from);
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "system clock before epoch",
            )
        })?
        .as_millis();
    let now_ms = u64::try_from(now_ms).map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCode::ServiceUnavailable,
            "system clock overflow",
        )
    })?;
    let result = match quota.admit(request.unsigned.body.is_read_only(), now_ms) {
        Ok(admission) => {
            let result = dispatch(request.unsigned.body.clone(), context.clone()).await;
            drop(admission);
            result
        }
        Err(error) => Err(error.into()),
    };
    let (sequence, head_hash) = journals.local_journal_head_with_context(&context)?;
    let head = bloom_triad_local_transport::sign_journal_head(identity, sequence, head_hash);
    bloom_triad_local_transport::send_response_with_journal_head::<
        BrokerSignerRequest,
        BrokerSignerResponse,
        ProtocolError,
    >(stream, identity, &request, result, head)
    .await
    .map_err(bloom_signer_api::ProtocolError::from)
}

#[allow(clippy::too_many_arguments)]
async fn serve_rpc(
    listener: UnixListener,
    identity: LocalIdentity,
    broker_acl: PeerAcl,
    quota: Arc<EndpointQuota>,
    service: Arc<SignerRpcService>,
    journals: Arc<SignerJournalExchange>,
    maximum_connections: usize,
    shutdown: &mut watch::Receiver<bool>,
) -> std::io::Result<()> {
    let connections = Arc::new(Semaphore::new(maximum_connections));
    loop {
        let permit = tokio::select! {
            _ = wait_for_shutdown(shutdown) => break,
            permit = connections.clone().acquire_owned() => {
                permit.map_err(|_| std::io::Error::other("Signer RPC connection gate closed"))?
            }
        };
        let (mut stream, _) = tokio::select! {
            _ = wait_for_shutdown(shutdown) => break,
            accepted = listener.accept() => accepted?,
        };
        let identity = identity.clone();
        let broker_acl = broker_acl.clone();
        let quota = quota.clone();
        let service = service.clone();
        let journals = journals.clone();
        let service_span = tracing::Span::current();
        tokio::spawn(
            async move {
                let _permit = permit;
                let _ = dispatch_authority_connection(
                    &mut stream,
                    &identity,
                    &broker_acl,
                    &quota,
                    journals.as_ref(),
                    |request, context| {
                        dispatch_authenticated_rpc(service.as_ref(), request, context)
                    },
                )
                .await;
            }
            .instrument(service_span),
        );
    }
    drain_connections(connections, maximum_connections, "RPC").await
}

async fn dispatch_authenticated_rpc(
    service: &SignerRpcService,
    request: BrokerSignerRequest,
    context: AuthenticatedRequestContext,
) -> Result<BrokerSignerResponse, ProtocolError> {
    let read_only = is_read_only_method(&context.method);
    let started = std::time::Instant::now();
    tracing::debug!(
        event = "signer.rpc_admitted",
        method = context.method.as_str(),
        operation_id = context.operation_id.as_str(),
        peer_service_id = context.caller_service_id.as_str(),
        peer_key_id = context.caller_application_key_id.as_str(),
        "Signer authenticated RPC admitted"
    );
    let result = BrokerSignerService::dispatch(service, request).await;
    log_rpc_completion(&context, read_only, started, &result);
    result
}

async fn dispatch_authenticated_control(
    service: &CheckpointingControlService,
    request: ControlRequest,
    context: AuthenticatedRequestContext,
) -> Result<ControlResponse, ProtocolError> {
    let read_only = is_read_only_method(&context.method);
    let started = std::time::Instant::now();
    tracing::debug!(
        event = "signer.rpc_admitted",
        method = context.method.as_str(),
        operation_id = context.operation_id.as_str(),
        peer_service_id = context.caller_service_id.as_str(),
        peer_key_id = context.caller_application_key_id.as_str(),
        "Signer authenticated control RPC admitted"
    );
    let result = RevocationControlService::dispatch(service.inner.as_ref(), request).await;
    let result = if read_only {
        result
    } else {
        match service
            .journals
            .response_journal_head(false, Some(&context))
        {
            Ok(_) => result,
            Err(checkpoint_error) => Err(checkpoint_error),
        }
    };
    log_rpc_completion(&context, read_only, started, &result);
    result
}

fn log_rpc_completion<T>(
    context: &AuthenticatedRequestContext,
    read_only: bool,
    started: std::time::Instant,
    result: &Result<T, ProtocolError>,
) {
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match result {
        Ok(_) if read_only => tracing::debug!(
            event = "signer.dispatch_completed",
            method = context.method.as_str(),
            operation_id = context.operation_id.as_str(),
            peer_service_id = context.caller_service_id.as_str(),
            peer_key_id = context.caller_application_key_id.as_str(),
            duration_ms,
            outcome = "ok",
            "Signer domain dispatch completed"
        ),
        Ok(_) => tracing::info!(
            event = "signer.dispatch_completed",
            method = context.method.as_str(),
            operation_id = context.operation_id.as_str(),
            peer_service_id = context.caller_service_id.as_str(),
            peer_key_id = context.caller_application_key_id.as_str(),
            duration_ms,
            outcome = "ok",
            "Signer domain dispatch completed"
        ),
        Err(error) => tracing::warn!(
            event = "signer.dispatch_completed",
            method = context.method.as_str(),
            operation_id = context.operation_id.as_str(),
            peer_service_id = context.caller_service_id.as_str(),
            peer_key_id = context.caller_application_key_id.as_str(),
            duration_ms,
            outcome = "error",
            error_code = error.code.as_str(),
            "Signer domain dispatch rejected"
        ),
    }
}

struct SignerJournalExchange {
    engine: Arc<SignerEngine>,
    checkpoints: Arc<dyn CheckpointSink>,
    identity: LocalIdentity,
    last_verified_head: Mutex<Option<SignedJournalHead>>,
}

fn select_initial_self_head(
    engine: &SignerEngine,
    checkpoints: &dyn CheckpointSink,
    identity: &LocalIdentity,
) -> Result<Option<SignedJournalHead>, ProtocolError> {
    let retained = checkpoints
        .latest_peer_head(&identity.service_id)
        .map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                format!("load retained Signer local audit checkpoint: {error}"),
            )
        })?;
    let Ok((sequence, head_hash)) = engine.verified_audit_head() else {
        return Ok(retained);
    };
    let head = bloom_triad_local_transport::sign_journal_head(identity, sequence, head_hash);
    match checkpoints.append_peer_head_diagnosed(&head) {
        Ok(decision) => {
            log_checkpoint_decision("self", None, &decision, engine.audit_is_degraded());
            Ok(Some(head))
        }
        Err(error) => {
            // A rollback/conflict against the independently retained head is
            // audit degradation, not permission to fabricate a zero head or
            // to discard read/status availability.
            log_checkpoint_decision("self", None, &error.decision, true);
            engine.latch_audit_degraded_with(checkpoint_degradation(&error.decision));
            Ok(retained.or(Some(head)))
        }
    }
}

struct UnavailableCheckpointSink {
    reason: String,
}

fn checkpoint_error_kind(error: &CheckpointError) -> &'static str {
    match error {
        CheckpointError::InvalidRoot => "invalid_root",
        CheckpointError::WrongOwner { .. } => "wrong_owner",
        CheckpointError::InsecurePermissions => "insecure_permissions",
        CheckpointError::Malformed(_) => "storage_or_configuration_failure",
        CheckpointError::SequenceRollback => "sequence_rollback",
        CheckpointError::SequenceConflict => "sequence_conflict",
        CheckpointError::InvalidSignature => "invalid_signature",
        CheckpointError::UnpinnedPeer => "unpinned_peer",
        CheckpointError::Io(_) => "storage_io_failure",
    }
}

fn checkpoint_degradation(decision: &CheckpointDecision) -> AuditDegradation {
    AuditDegradation {
        cause_code: checkpoint_outcome_name(decision.outcome),
        peer_service_id: Some(decision.attempted.service_id.as_str().to_owned()),
        peer_key_id: Some(decision.attempted.key_id.as_str().to_owned()),
        attempted_sequence: Some(decision.attempted.sequence),
        attempted_head_digest: Some(decision.attempted.head_digest.clone()),
        retained_sequence: decision.retained.as_ref().map(|head| head.sequence),
        retained_head_digest: decision
            .retained
            .as_ref()
            .map(|head| head.head_digest.clone()),
    }
}

fn log_checkpoint_decision(
    direction: &'static str,
    context: Option<&AuthenticatedRequestContext>,
    decision: &CheckpointDecision,
    mutations_disabled: bool,
) {
    let retained_sequence = decision.retained.as_ref().map(|head| head.sequence);
    let retained_head_digest = decision
        .retained
        .as_ref()
        .map(|head| head.head_digest.as_str());
    if matches!(
        decision.outcome,
        CheckpointDecisionOutcome::Appended | CheckpointDecisionOutcome::AlreadyPresent
    ) {
        tracing::info!(
            event = "signer.checkpoint_decision",
            checkpoint_direction = direction,
            recipient_service_id = decision.recipient_service_id.as_ref().map(Token::as_str),
            peer_service_id = decision.attempted.service_id.as_str(),
            peer_key_id = decision.attempted.key_id.as_str(),
            method = context.map(|context| context.method.as_str()),
            operation_id = context.map(|context| context.operation_id.as_str()),
            attempted_sequence = decision.attempted.sequence,
            attempted_head_digest = decision.attempted.head_digest.as_str(),
            retained_sequence,
            retained_head_digest,
            outcome = checkpoint_outcome_name(decision.outcome),
            mutations_disabled,
            "Signer checkpoint accepted"
        );
    } else {
        tracing::error!(
            event = "signer.checkpoint_decision",
            checkpoint_direction = direction,
            recipient_service_id = decision.recipient_service_id.as_ref().map(Token::as_str),
            peer_service_id = decision.attempted.service_id.as_str(),
            peer_key_id = decision.attempted.key_id.as_str(),
            method = context.map(|context| context.method.as_str()),
            operation_id = context.map(|context| context.operation_id.as_str()),
            attempted_sequence = decision.attempted.sequence,
            attempted_head_digest = decision.attempted.head_digest.as_str(),
            retained_sequence,
            retained_head_digest,
            outcome = checkpoint_outcome_name(decision.outcome),
            mutations_disabled,
            "Signer checkpoint rejected"
        );
    }
}

fn checkpoint_outcome_name(outcome: CheckpointDecisionOutcome) -> &'static str {
    match outcome {
        CheckpointDecisionOutcome::Appended => "appended",
        CheckpointDecisionOutcome::AlreadyPresent => "already_present",
        CheckpointDecisionOutcome::SequenceRollback => "sequence_rollback",
        CheckpointDecisionOutcome::SequenceConflict => "sequence_conflict",
        CheckpointDecisionOutcome::InvalidSignature => "invalid_signature",
        CheckpointDecisionOutcome::UnpinnedPeer => "unpinned_peer",
        CheckpointDecisionOutcome::StorageOrConfigurationFailure => {
            "storage_or_configuration_failure"
        }
    }
}

impl SignerJournalExchange {
    fn response_journal_head(
        &self,
        allow_uncheckpointed_read: bool,
        context: Option<&AuthenticatedRequestContext>,
    ) -> Result<(u64, Digest32), ProtocolError> {
        match self.engine.verified_audit_head() {
            Ok((sequence, head_hash)) => {
                let signed = bloom_triad_local_transport::sign_journal_head(
                    &self.identity,
                    sequence,
                    head_hash.clone(),
                );
                let checkpoint = self.checkpoints.append_peer_head_diagnosed(&signed);
                *self.last_verified_head.lock().map_err(|_| {
                    ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        "Signer last verified audit head lock is poisoned",
                    )
                })? = Some(signed.clone());
                match checkpoint {
                    Err(error) => {
                        log_checkpoint_decision("self", context, &error.decision, true);
                        self.engine
                            .latch_audit_degraded_with(checkpoint_degradation(&error.decision));
                        if !allow_uncheckpointed_read {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::ServiceUnavailable,
                                format!(
                                    "persist Signer local audit checkpoint before response: {}",
                                    error.source
                                ),
                            ));
                        }
                    }
                    Ok(decision) => {
                        log_checkpoint_decision(
                            "self",
                            context,
                            &decision,
                            self.engine.audit_is_degraded(),
                        );
                    }
                }
                Ok((sequence, head_hash))
            }
            Err(_) => self
                .last_verified_head
                .lock()
                .map_err(|_| {
                    ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        "Signer last verified audit head lock is poisoned",
                    )
                })?
                .as_ref()
                .map(|head| (head.sequence.get(), head.head_hash.clone()))
                .ok_or_else(|| {
                    ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        "Signer audit is degraded and has no independently retained local head",
                    )
                }),
        }
    }
}

impl CheckpointSink for UnavailableCheckpointSink {
    fn append_peer_head(
        &self,
        _peer_head: &SignedJournalHead,
    ) -> Result<AppendOutcome, CheckpointError> {
        Err(CheckpointError::Malformed(self.reason.clone()))
    }
}

impl JournalExchange<ProtocolError> for SignerJournalExchange {
    fn checkpoint_request_head(
        &self,
        method: &Token,
        peer_head: &bloom_signer_api::SignedJournalHead,
    ) -> Result<(), ProtocolError> {
        match self.checkpoints.append_peer_head_diagnosed(peer_head) {
            Err(error) => {
                log_checkpoint_decision("peer", None, &error.decision, true);
                self.engine
                    .latch_audit_degraded_with(checkpoint_degradation(&error.decision));
                if !is_read_only_method(method) {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        format!(
                            "persist Broker audit checkpoint before dispatching mutation: {}",
                            error.source
                        ),
                    ));
                }
            }
            Ok(decision) => {
                log_checkpoint_decision("peer", None, &decision, self.engine.audit_is_degraded())
            }
        }
        Ok(())
    }

    fn local_journal_head(&self, method: &Token) -> Result<(u64, Digest32), ProtocolError> {
        self.response_journal_head(is_read_only_method(method), None)
    }

    fn checkpoint_request_head_with_context(
        &self,
        context: &AuthenticatedRequestContext,
        peer_head: &SignedJournalHead,
    ) -> Result<(), ProtocolError> {
        match self.checkpoints.append_peer_head_diagnosed(peer_head) {
            Err(error) => {
                log_checkpoint_decision("peer", Some(context), &error.decision, true);
                self.engine
                    .latch_audit_degraded_with(checkpoint_degradation(&error.decision));
                if !is_read_only_method(&context.method) {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        format!(
                            "persist Broker audit checkpoint before dispatching mutation: {}",
                            error.source
                        ),
                    ));
                }
            }
            Ok(decision) => log_checkpoint_decision(
                "peer",
                Some(context),
                &decision,
                self.engine.audit_is_degraded(),
            ),
        }
        Ok(())
    }

    fn local_journal_head_with_context(
        &self,
        context: &AuthenticatedRequestContext,
    ) -> Result<(u64, Digest32), ProtocolError> {
        // The self-checkpoint path uses the same authenticated operation ID as
        // the request it is publishing.
        let result =
            self.response_journal_head(is_read_only_method(&context.method), Some(context));
        if result.is_err() {
            tracing::warn!(
                event = "signer.response_checkpoint_failed",
                method = context.method.as_str(),
                operation_id = context.operation_id.as_str(),
                error_code = ProtocolErrorCode::ServiceUnavailable.as_str(),
                "Signer could not publish a response checkpoint"
            );
        }
        result
    }
}

async fn serve_control(
    listener: UnixListener,
    identity: LocalIdentity,
    revoke_client_acl: PeerAcl,
    quota: Arc<EndpointQuota>,
    service: Arc<CheckpointingControlService>,
    maximum_connections: usize,
    shutdown: &mut watch::Receiver<bool>,
) -> std::io::Result<()> {
    let connections = Arc::new(Semaphore::new(maximum_connections));
    loop {
        let permit = tokio::select! {
            _ = wait_for_shutdown(shutdown) => break,
            permit = connections.clone().acquire_owned() => {
                permit.map_err(|_| std::io::Error::other("Signer control connection gate closed"))?
            }
        };
        let (mut stream, _) = tokio::select! {
            _ = wait_for_shutdown(shutdown) => break,
            accepted = listener.accept() => accepted?,
        };
        let identity = identity.clone();
        let revoke_client_acl = revoke_client_acl.clone();
        let quota = quota.clone();
        let service = service.clone();
        let service_span = tracing::Span::current();
        tokio::spawn(
            async move {
                let _permit = permit;
                let _ = bloom_triad_local_transport::dispatch_connection_with_context::<
                    ControlRequest,
                    ControlResponse,
                    ProtocolError,
                    _,
                    _,
                >(
                    &mut stream,
                    &identity,
                    &revoke_client_acl,
                    bloom_signer_api::SIGNER_CONTROL_CURRENT,
                    bloom_signer_api::SIGNER_CONTROL_RANGE,
                    &quota,
                    |request, context| {
                        dispatch_authenticated_control(service.as_ref(), request, context)
                    },
                )
                .await;
            }
            .instrument(service_span),
        );
    }
    drain_connections(connections, maximum_connections, "control").await
}

struct CheckpointingControlService {
    inner: Arc<SignerRpcService>,
    journals: Arc<SignerJournalExchange>,
}

impl RevocationControlService for CheckpointingControlService {
    fn dispatch<'a>(&'a self, request: ControlRequest) -> ServiceFuture<'a, ControlResponse> {
        Box::pin(async move {
            let is_read_only = matches!(&request, ControlRequest::Status(_));
            let result = RevocationControlService::dispatch(self.inner.as_ref(), request).await;
            if !is_read_only {
                // The local OS checkpoint is part of publishing a security
                // mutation outcome, including durable-effect error outcomes.
                self.journals.response_journal_head(false, None)?;
            }
            result
        })
    }
}

async fn connect_authenticated_session(
    path: &Path,
    identity: &LocalIdentity,
    session_acl: &PeerAcl,
) -> Result<UnixStream, ProtocolError> {
    loop {
        match UnixStream::connect(path).await {
            Ok(mut stream) => {
                bloom_triad_local_transport::authenticate_client(
                    &mut stream,
                    identity,
                    session_acl,
                    bloom_service_activation::SESSION_PROTOCOL_CURRENT,
                    bloom_service_activation::SESSION_PROTOCOL_RANGE,
                )
                .await?;
                return Ok(stream);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::ConnectionRefused
                ) =>
            {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::ServiceUnavailable,
                    format!("connect login-session sentinel {}: {error}", path.display()),
                ));
            }
        }
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn drain_connections(
    connections: Arc<Semaphore>,
    maximum_connections: usize,
    endpoint: &str,
) -> std::io::Result<()> {
    let permits = u32::try_from(maximum_connections)
        .map_err(|_| std::io::Error::other("Signer connection quota exceeds u32"))?;
    let _drained = tokio::time::timeout(
        Duration::from_secs(35),
        connections.acquire_many_owned(permits),
    )
    .await
    .map_err(|_| {
        std::io::Error::other(format!(
            "Signer {endpoint} connections did not drain within 35 seconds"
        ))
    })?
    .map_err(|_| std::io::Error::other("Signer connection gate closed"))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn open_operational_signer_engine(
    path: &Path,
    broker_key_id: Token,
    broker_public_key: VerifyingKey,
    ceremony_public_key: VerifyingKey,
    revocation_key_id: Token,
    revocation_signing_key: SigningKey,
    current_audit_key_id: Token,
    current_audit_signing_key: SigningKey,
    historical: &[AuditPublicKeyConfig],
    previous: Option<(Token, SigningKey)>,
    registry: Arc<BackendRegistry>,
) -> Result<SignerEngine, ProtocolError> {
    let mut trusted = BTreeMap::new();
    for entry in historical {
        let key_id = Token::new(entry.key_id.clone())?;
        let key = verifying_key(&entry.public_key_hex)?;
        if trusted
            .insert(key_id.clone(), key)
            .is_some_and(|old| old != key)
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("Signer audit key ID {key_id} has conflicting public keys"),
            ));
        }
    }
    if let Some((previous_key_id, previous_key)) = &previous {
        if previous_key_id == &current_audit_key_id
            || previous_key.verifying_key() == current_audit_signing_key.verifying_key()
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "Signer audit rotation previous key ID and material must differ from current key",
            ));
        }
        if trusted
            .insert(previous_key_id.clone(), previous_key.verifying_key())
            .is_some_and(|old| old != previous_key.verifying_key())
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "Signer audit previous key conflicts with retained public key",
            ));
        }
    }
    let open_current = || {
        SignerEngine::open(
            path,
            broker_key_id.clone(),
            broker_public_key,
            ceremony_public_key,
            revocation_key_id.clone(),
            revocation_signing_key.clone(),
            SignerAuditKeys {
                current_key_id: current_audit_key_id.clone(),
                current_signing_key: current_audit_signing_key.clone(),
                historical_verifying_keys: trusted.clone(),
            },
            registry.clone(),
        )
    };
    // With a planned rotation, opening under the new key is only a probe: an
    // existing journal ending under the previous key is the expected signal
    // to reopen and rotate, not an operational degradation worth emitting.
    let current = if previous.is_some() {
        tracing::subscriber::with_default(
            tracing::subscriber::NoSubscriber::default(),
            open_current,
        )?
    } else {
        open_current()?
    };
    if !current.audit_is_degraded() || previous.is_none() {
        return Ok(current);
    }
    let (previous_key_id, previous_signing_key) = previous.expect("checked above");
    trusted.insert(
        current_audit_key_id.clone(),
        current_audit_signing_key.verifying_key(),
    );
    let prior = SignerEngine::open(
        path,
        broker_key_id,
        broker_public_key,
        ceremony_public_key,
        revocation_key_id,
        revocation_signing_key,
        SignerAuditKeys {
            current_key_id: previous_key_id,
            current_signing_key: previous_signing_key,
            historical_verifying_keys: trusted,
        },
        registry,
    )?;
    if prior.audit_is_degraded() {
        // Corrupted history remains readable but cannot be "repaired" by a
        // key rotation. Return the original current-key degraded view.
        return Ok(current);
    }
    prior.rotate_audit_key(current_audit_key_id, current_audit_signing_key)?;
    Ok(prior)
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

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_audit_checkpoint::{AppendOutcome, CheckpointError};
    use bloom_signer_api::{
        Base64UrlBytes, BootEpoch, BrokerSignerRequest, BrokerSignerResponse, ControlRequest,
        ControlResponse, DecimalU64, Empty, OperationId, ProtocolVersion, ProtocolVersionRange,
        SignedJournalHead, WalletRequest,
    };
    use ed25519_dalek::Signer as _;
    use std::os::unix::fs::PermissionsExt as _;

    struct FailingCheckpointSink;

    struct FailingSelfCheckpointSink;

    struct RetainedRollbackSink(SignedJournalHead);

    struct TrackingJournalExchange {
        touched: std::sync::atomic::AtomicBool,
    }

    impl bloom_triad_local_transport::JournalExchange<ProtocolError> for TrackingJournalExchange {
        fn checkpoint_request_head(
            &self,
            _method: &Token,
            _peer_head: &SignedJournalHead,
        ) -> Result<(), ProtocolError> {
            self.touched
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn local_journal_head(&self, _method: &Token) -> Result<(u64, Digest32), ProtocolError> {
            self.touched
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok((0, Digest32::from_bytes([0; 32])))
        }
    }

    impl CheckpointSink for FailingCheckpointSink {
        fn append_peer_head(
            &self,
            peer_head: &SignedJournalHead,
        ) -> Result<AppendOutcome, CheckpointError> {
            if peer_head.service_id.as_str() == "bloom-signer" {
                return Ok(AppendOutcome::Appended);
            }
            Err(CheckpointError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "forced request checkpoint failure",
            )))
        }
    }

    impl CheckpointSink for FailingSelfCheckpointSink {
        fn append_peer_head(
            &self,
            _peer_head: &SignedJournalHead,
        ) -> Result<AppendOutcome, CheckpointError> {
            Err(CheckpointError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "forced self checkpoint failure",
            )))
        }
    }

    impl CheckpointSink for RetainedRollbackSink {
        fn append_peer_head(
            &self,
            _peer_head: &SignedJournalHead,
        ) -> Result<AppendOutcome, CheckpointError> {
            Err(CheckpointError::SequenceRollback)
        }

        fn latest_peer_head(
            &self,
            service_id: &Token,
        ) -> Result<Option<SignedJournalHead>, CheckpointError> {
            Ok((service_id == &self.0.service_id).then(|| self.0.clone()))
        }
    }

    fn test_engine() -> Arc<SignerEngine> {
        Arc::new(
            SignerEngine::open_in_memory(
                Token::new("broker-app").unwrap(),
                SigningKey::from_bytes(&[7; 32]).verifying_key(),
                SigningKey::from_bytes(&[6; 32]).verifying_key(),
                Token::new("signer-revocation-key").unwrap(),
                SigningKey::from_bytes(&[4; 32]),
                SignerAuditKeys {
                    current_key_id: Token::new("signer-audit-key").unwrap(),
                    current_signing_key: SigningKey::from_bytes(&[14; 32]),
                    historical_verifying_keys: BTreeMap::new(),
                },
                Arc::new(BackendRegistry::from_compiled(vec![]).unwrap()),
            )
            .unwrap(),
        )
    }

    fn broker_head() -> SignedJournalHead {
        SignedJournalHead {
            service_id: Token::new("bloom-broker").unwrap(),
            sequence: DecimalU64::new(1),
            head_hash: Digest32::from_bytes([1; 32]),
            key_id: Token::new("broker-app").unwrap(),
            signature: Base64UrlBytes::from_bytes(&[1; 64]),
        }
    }

    fn signer_identity() -> LocalIdentity {
        LocalIdentity {
            service_id: Token::new("bloom-signer").unwrap(),
            boot_epoch: bloom_signer_api::BootEpoch::new("01".repeat(16)).unwrap(),
            application_key_id: Token::new("signer-app").unwrap(),
            signing_key: Arc::new(SigningKey::from_bytes(&[9; 32])),
        }
    }

    fn peer_acl(identity: &LocalIdentity, effective_uid: u32) -> PeerAcl {
        PeerAcl {
            effective_uid,
            service_id: identity.service_id.clone(),
            boot_epoch: identity.boot_epoch.clone(),
            application_key_id: identity.application_key_id.clone(),
            application_public_key: identity.signing_key.verifying_key().to_bytes(),
        }
    }

    #[tokio::test]
    async fn signer_rejects_authority_protocol_1_0_before_dispatch_or_durable_work() {
        let signer = signer_identity();
        let broker = LocalIdentity {
            service_id: Token::new("bloom-broker").unwrap(),
            boot_epoch: bloom_signer_api::BootEpoch::new("02".repeat(16)).unwrap(),
            application_key_id: Token::new("broker-app").unwrap(),
            signing_key: Arc::new(SigningKey::from_bytes(&[7; 32])),
        };
        let temporary = tempfile::tempdir().unwrap();
        let effective_uid = fs::metadata(temporary.path()).unwrap().uid();
        let signer_acl = peer_acl(&signer, effective_uid);
        let broker_acl = peer_acl(&broker, effective_uid);
        let quota = EndpointQuota::new(1, 10, 1_000, 10, 1_000).unwrap();
        let journals = TrackingJournalExchange {
            touched: std::sync::atomic::AtomicBool::new(false),
        };
        let dispatched = std::sync::atomic::AtomicBool::new(false);
        let (mut server_stream, mut client_stream) = UnixStream::pair().unwrap();
        let rejected_version = ProtocolVersion::new(bloom_signer_api::SIGNER_API_MAJOR, 0);
        let legacy_range = ProtocolVersionRange::new(
            bloom_signer_api::SIGNER_API_MAJOR,
            0,
            bloom_signer_api::SIGNER_API_MINOR_MAX,
        );
        let broker_head = bloom_triad_local_transport::sign_journal_head(
            &broker,
            0,
            Digest32::from_bytes([0; 32]),
        );

        let server = async {
            let result = bloom_triad_local_transport::dispatch_connection_with_journal_heads::<
                BrokerSignerRequest,
                BrokerSignerResponse,
                ProtocolError,
                _,
                _,
            >(
                &mut server_stream,
                &signer,
                &broker_acl,
                bloom_signer_api::SIGNER_API_CURRENT,
                bloom_signer_api::SIGNER_API_RANGE,
                &quota,
                &journals,
                |_request| async {
                    dispatched.store(true, std::sync::atomic::Ordering::SeqCst);
                    Err(ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        "dispatch must not run",
                    ))
                },
            )
            .await;
            drop(server_stream);
            result
        };
        let client = async {
            bloom_triad_local_transport::authenticate_client(
                &mut client_stream,
                &broker,
                &signer_acl,
                bloom_signer_api::SIGNER_API_CURRENT,
                legacy_range,
            )
            .await?;
            let sent_at_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let request = bloom_triad_local_transport::sign_request_with_journal_head(
                &broker,
                signer.service_id.clone(),
                rejected_version,
                legacy_range,
                bloom_signer_api::OperationId::from_bytes([3; 32]),
                BrokerSignerRequest::SignerReadiness(Empty::default()),
                sent_at_ms,
                sent_at_ms + 1_000,
                broker_head,
            )?;
            let result =
                bloom_triad_local_transport::write_frame(&mut client_stream, &request).await;
            drop(client_stream);
            result
        };
        let (server_result, client_result) = tokio::join!(server, client);

        assert_eq!(
            server_result.unwrap_err().code,
            ProtocolErrorCode::UnsupportedVersion
        );
        client_result.unwrap();
        assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!journals.touched.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn signer_rejects_bip39_fields_from_a_pre_1_5_peer() {
        let signer = signer_identity();
        let broker = LocalIdentity {
            service_id: Token::new("bloom-broker").unwrap(),
            boot_epoch: bloom_signer_api::BootEpoch::new("02".repeat(16)).unwrap(),
            application_key_id: Token::new("broker-app").unwrap(),
            signing_key: Arc::new(SigningKey::from_bytes(&[7; 32])),
        };
        let temporary = tempfile::tempdir().unwrap();
        let effective_uid = fs::metadata(temporary.path()).unwrap().uid();
        let signer_acl = peer_acl(&signer, effective_uid);
        let broker_acl = peer_acl(&broker, effective_uid);
        let quota = EndpointQuota::new(1, 10, 1_000, 10, 1_000).unwrap();
        let journals = TrackingJournalExchange {
            touched: std::sync::atomic::AtomicBool::new(false),
        };
        let dispatched = std::sync::atomic::AtomicBool::new(false);
        let (mut server_stream, mut client_stream) = UnixStream::pair().unwrap();
        // The peer negotiates over the full supported range, so it accepts the
        // service's announced 1.5, but signs its request at the 1.4 floor
        // while carrying a minor-5 bip39 field. That mismatch is what the
        // dispatch seam exists to refuse; a peer below the floor never gets
        // that far, because the transport rejects it during negotiation.
        let legacy_version = ProtocolVersion::new(
            bloom_signer_api::SIGNER_API_MAJOR,
            bloom_signer_api::SIGNER_API_MINOR_MIN,
        );
        let legacy_range = ProtocolVersionRange::new(
            bloom_signer_api::SIGNER_API_MAJOR,
            bloom_signer_api::SIGNER_API_MINOR_MIN,
            bloom_signer_api::SIGNER_API_MINOR_MAX,
        );
        let broker_head = bloom_triad_local_transport::sign_journal_head(
            &broker,
            0,
            Digest32::from_bytes([0; 32]),
        );

        let server = async {
            let result = dispatch_authority_connection(
                &mut server_stream,
                &signer,
                &broker_acl,
                &quota,
                &journals,
                |_request, _context| async {
                    dispatched.store(true, std::sync::atomic::Ordering::SeqCst);
                    Err(ProtocolError::new(
                        ProtocolErrorCode::ServiceUnavailable,
                        "dispatch must not run",
                    ))
                },
            )
            .await;
            drop(server_stream);
            result
        };
        let client = async {
            let body = BrokerSignerRequest::WalletRegistrationPrepare(
                bloom_signer_api::CustodyPrepareRequest {
                    ceremony_kind: bloom_signer_api::CeremonyKind::WalletRegistration,
                    custody_operation_id: bloom_signer_api::OperationId::from_bytes([3; 32]),
                    wallet_id: Some(Token::new("wallet").unwrap()),
                    key_ref: None,
                    exact_terms_digest: Digest32::from_bytes([5; 32]),
                    expected_input_class: Token::new("passkey-prf").unwrap(),
                    browser_output_recipient_key: None,
                    petal_key_scope: None,
                    legacy_passkey_migration: None,
                    wallet_seed_profile: Some(
                        bloom_signer_api::WalletSeedProfile::Bip39MulticurveV1,
                    ),
                    derivation_request: None,
                },
            );
            let result = bloom_triad_local_transport::call_with_journal_head::<
                BrokerSignerRequest,
                BrokerSignerResponse,
                ProtocolError,
            >(
                &mut client_stream,
                &broker,
                &signer_acl,
                legacy_version,
                legacy_range,
                body,
                1_000,
                broker_head,
                |_head| Ok(()),
            )
            .await;
            drop(client_stream);
            result
        };
        let (server_result, client_result) = tokio::join!(server, client);

        assert!(server_result.is_ok());
        assert_eq!(
            client_result.unwrap_err().code,
            ProtocolErrorCode::UnsupportedVersion
        );
        assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn signer_control_endpoint_accepts_protocol_1_0_and_dispatches() {
        let signer = signer_identity();
        let control_client = LocalIdentity {
            service_id: Token::new("bloom-revoke-client").unwrap(),
            boot_epoch: bloom_signer_api::BootEpoch::new("03".repeat(16)).unwrap(),
            application_key_id: Token::new("revoke-client-app").unwrap(),
            signing_key: Arc::new(SigningKey::from_bytes(&[8; 32])),
        };
        let temporary = tempfile::tempdir().unwrap();
        let effective_uid = fs::metadata(temporary.path()).unwrap().uid();
        let signer_acl = peer_acl(&signer, effective_uid);
        let control_acl = peer_acl(&control_client, effective_uid);
        let quota = EndpointQuota::new(1, 10, 1_000, 10, 1_000).unwrap();
        let dispatched = std::sync::atomic::AtomicBool::new(false);
        let (mut server_stream, mut client_stream) = UnixStream::pair().unwrap();

        let server = bloom_triad_local_transport::dispatch_connection::<
            ControlRequest,
            ControlResponse,
            ProtocolError,
            _,
            _,
        >(
            &mut server_stream,
            &signer,
            &control_acl,
            bloom_signer_api::SIGNER_CONTROL_CURRENT,
            bloom_signer_api::SIGNER_CONTROL_RANGE,
            &quota,
            |_request| async {
                dispatched.store(true, std::sync::atomic::Ordering::SeqCst);
                Err(ProtocolError::new(
                    ProtocolErrorCode::ServiceUnavailable,
                    "accepted test request",
                ))
            },
        );
        let client =
            bloom_triad_local_transport::call::<ControlRequest, ControlResponse, ProtocolError>(
                &mut client_stream,
                &control_client,
                &signer_acl,
                ProtocolVersion::new(1, 0),
                bloom_signer_api::SIGNER_CONTROL_RANGE,
                ControlRequest::Status(WalletRequest {
                    wallet_id: Token::new("wallet").unwrap(),
                }),
                1_000,
            );
        let (server_result, client_result) = tokio::join!(server, client);

        server_result.unwrap();
        assert_eq!(
            client_result.unwrap_err().code,
            ProtocolErrorCode::ServiceUnavailable
        );
        assert!(dispatched.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn session_disconnect_errors_exit_cleanly_without_keepalive_retry() {
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::NotConnected,
            ErrorKind::UnexpectedEof,
        ] {
            assert!(is_session_disconnect(&std::io::Error::from(kind)));
        }
        assert!(!is_session_disconnect(&std::io::Error::from(
            ErrorKind::PermissionDenied
        )));
    }

    #[tokio::test]
    async fn logout_drain_waits_for_an_accepted_operation() {
        let connections = Arc::new(Semaphore::new(2));
        let accepted = connections.clone().acquire_owned().await.unwrap();
        let drain = tokio::spawn(drain_connections(connections, 2, "test"));
        tokio::task::yield_now().await;
        assert!(!drain.is_finished());
        drop(accepted);
        drain.await.unwrap().unwrap();
    }

    #[test]
    fn request_checkpoint_failure_blocks_mutations_but_keeps_read_heads_available() {
        let engine = test_engine();
        let exchange = SignerJournalExchange {
            engine: engine.clone(),
            checkpoints: Arc::new(FailingCheckpointSink),
            identity: signer_identity(),
            last_verified_head: Mutex::new(None),
        };
        assert!(
            exchange
                .checkpoint_request_head(&Token::new("signer.readiness").unwrap(), &broker_head(),)
                .is_ok()
        );
        assert_eq!(
            exchange
                .local_journal_head(&Token::new("signer.readiness").unwrap())
                .unwrap()
                .0,
            0
        );
        assert_eq!(
            exchange
                .checkpoint_request_head(&Token::new("signer.sign").unwrap(), &broker_head())
                .unwrap_err()
                .code,
            ProtocolErrorCode::ServiceUnavailable
        );
        assert_eq!(
            engine.repair_clock(1).unwrap_err().code,
            ProtocolErrorCode::ServiceUnavailable
        );
    }

    #[test]
    fn production_audit_key_rotation_restarts_with_verification_only_history() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("signer.sqlite3");
        let first_id = Token::new("signer-audit-first").unwrap();
        let previous_id = Token::new("signer-audit-previous").unwrap();
        let current_id = Token::new("signer-audit-current").unwrap();
        let first = SigningKey::from_bytes(&[51; 32]);
        let previous = SigningKey::from_bytes(&[52; 32]);
        let current = SigningKey::from_bytes(&[53; 32]);
        let registry = || Arc::new(BackendRegistry::from_compiled(vec![]).unwrap());
        let initial = SignerEngine::open(
            &path,
            Token::new("broker-app").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[6; 32]).verifying_key(),
            Token::new("revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            SignerAuditKeys {
                current_key_id: first_id.clone(),
                current_signing_key: first.clone(),
                historical_verifying_keys: BTreeMap::new(),
            },
            registry(),
        )
        .unwrap();
        initial
            .rotate_audit_key(previous_id.clone(), previous.clone())
            .unwrap();
        drop(initial);
        let historical = vec![AuditPublicKeyConfig {
            key_id: first_id.as_str().to_owned(),
            public_key_hex: hex::encode(first.verifying_key().to_bytes()),
        }];
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(capture.clone())
            .finish();
        let rotated = tracing::subscriber::with_default(subscriber, || {
            open_operational_signer_engine(
                &path,
                Token::new("broker-app").unwrap(),
                SigningKey::from_bytes(&[7; 32]).verifying_key(),
                SigningKey::from_bytes(&[6; 32]).verifying_key(),
                Token::new("revocation-key").unwrap(),
                SigningKey::from_bytes(&[4; 32]),
                current_id.clone(),
                current.clone(),
                &historical,
                Some((previous_id.clone(), previous.clone())),
                registry(),
            )
        })
        .unwrap();
        assert!(!rotated.audit_is_degraded());
        let output = capture.text();
        assert!(!output.contains("signer.journal_verification_failed"));
        assert!(!output.contains("signer.mutations_disabled"));
        drop(rotated);
        let mut retained = historical;
        retained.push(AuditPublicKeyConfig {
            key_id: previous_id.as_str().to_owned(),
            public_key_hex: hex::encode(previous.verifying_key().to_bytes()),
        });
        let restarted = open_operational_signer_engine(
            &path,
            Token::new("broker-app").unwrap(),
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[6; 32]).verifying_key(),
            Token::new("revocation-key").unwrap(),
            SigningKey::from_bytes(&[4; 32]),
            current_id,
            current,
            &retained,
            None,
            registry(),
        )
        .unwrap();
        assert!(!restarted.audit_is_degraded());
    }

    #[test]
    fn retained_self_head_survives_local_corruption_without_peer_rollback() {
        let temporary = tempfile::tempdir().unwrap();
        let checkpoint_root = temporary.path().join("checkpoints");
        fs::create_dir(&checkpoint_root).unwrap();
        fs::set_permissions(&checkpoint_root, fs::Permissions::from_mode(0o700)).unwrap();
        let identity = signer_identity();
        let broker_key = SigningKey::from_bytes(&[7; 32]);
        let store = Arc::new(
            CheckpointStore::open(
                &checkpoint_root,
                fs::metadata(&checkpoint_root).unwrap().uid(),
                identity.service_id.clone(),
                [
                    PinnedAuditKey {
                        service_id: identity.service_id.clone(),
                        key_id: identity.application_key_id.clone(),
                        verifying_key: identity.signing_key.verifying_key(),
                    },
                    PinnedAuditKey {
                        service_id: Token::new("bloom-broker").unwrap(),
                        key_id: Token::new("broker-app").unwrap(),
                        verifying_key: broker_key.verifying_key(),
                    },
                ],
            )
            .unwrap(),
        );
        let mut peer = broker_head();
        peer.signature =
            Base64UrlBytes::from_bytes(&broker_key.sign(&peer.signature_message()).to_bytes());
        store.append_peer_head(&peer).unwrap();
        let database_path = temporary.path().join("signer.sqlite3");
        let engine = Arc::new(
            SignerEngine::open(
                &database_path,
                Token::new("broker-app").unwrap(),
                SigningKey::from_bytes(&[7; 32]).verifying_key(),
                SigningKey::from_bytes(&[6; 32]).verifying_key(),
                Token::new("signer-revocation-key").unwrap(),
                SigningKey::from_bytes(&[4; 32]),
                SignerAuditKeys {
                    current_key_id: Token::new("signer-audit-key").unwrap(),
                    current_signing_key: SigningKey::from_bytes(&[14; 32]),
                    historical_verifying_keys: BTreeMap::new(),
                },
                Arc::new(BackendRegistry::from_compiled(vec![]).unwrap()),
            )
            .unwrap(),
        );
        engine
            .rotate_audit_key(
                Token::new("signer-audit-next").unwrap(),
                SigningKey::from_bytes(&[61; 32]),
            )
            .unwrap();
        let exchange = SignerJournalExchange {
            engine: engine.clone(),
            checkpoints: store.clone(),
            identity: identity.clone(),
            last_verified_head: Mutex::new(None),
        };
        let retained = exchange
            .local_journal_head(&Token::new("signer.readiness").unwrap())
            .unwrap();
        assert!(retained.0 > 0);
        rusqlite::Connection::open(&database_path)
            .unwrap()
            .execute(
                "UPDATE audit_chain SET payload_jcs = '{}' WHERE sequence = 0",
                [],
            )
            .unwrap();
        let restarted_store = Arc::new(
            CheckpointStore::open(
                &checkpoint_root,
                fs::metadata(&checkpoint_root).unwrap().uid(),
                identity.service_id.clone(),
                [
                    PinnedAuditKey {
                        service_id: identity.service_id.clone(),
                        key_id: identity.application_key_id.clone(),
                        verifying_key: identity.signing_key.verifying_key(),
                    },
                    PinnedAuditKey {
                        service_id: Token::new("bloom-broker").unwrap(),
                        key_id: Token::new("broker-app").unwrap(),
                        verifying_key: broker_key.verifying_key(),
                    },
                ],
            )
            .unwrap(),
        );
        assert_eq!(
            restarted_store
                .latest_peer_head(&Token::new("bloom-broker").unwrap())
                .unwrap(),
            Some(peer)
        );
        let retained_signed = restarted_store
            .latest_peer_head(&identity.service_id)
            .unwrap();
        let degraded_exchange = SignerJournalExchange {
            engine,
            checkpoints: restarted_store,
            identity,
            last_verified_head: Mutex::new(retained_signed),
        };
        assert_eq!(
            degraded_exchange
                .local_journal_head(&Token::new("signer.readiness").unwrap())
                .unwrap(),
            retained
        );
    }

    #[test]
    fn self_checkpoint_failure_preserves_read_head_and_suppresses_mutations() {
        let engine = test_engine();
        let exchange = SignerJournalExchange {
            engine: engine.clone(),
            checkpoints: Arc::new(FailingSelfCheckpointSink),
            identity: signer_identity(),
            last_verified_head: Mutex::new(None),
        };
        assert_eq!(
            exchange
                .local_journal_head(&Token::new("signer.readiness").unwrap())
                .unwrap()
                .0,
            0
        );
        assert_eq!(
            exchange
                .local_journal_head(&Token::new("signer.sign").unwrap())
                .unwrap_err()
                .code,
            ProtocolErrorCode::ServiceUnavailable
        );
        assert!(engine.audit_is_degraded());
        assert_eq!(
            engine.repair_clock(1).unwrap_err().code,
            ProtocolErrorCode::ServiceUnavailable
        );
    }

    #[test]
    fn startup_uses_retained_nonzero_head_and_degrades_on_local_rollback() {
        let engine = test_engine();
        let identity = signer_identity();
        let retained = bloom_triad_local_transport::sign_journal_head(
            &identity,
            9,
            Digest32::from_bytes([9; 32]),
        );
        let selected = select_initial_self_head(
            engine.as_ref(),
            &RetainedRollbackSink(retained.clone()),
            &identity,
        )
        .unwrap();
        assert_eq!(selected, Some(retained));
        assert!(engine.audit_is_degraded());
        assert_eq!(
            engine.repair_clock(1).unwrap_err().code,
            ProtocolErrorCode::ServiceUnavailable
        );
    }

    #[test]
    fn checkpoint_event_has_exact_safe_diagnostics_and_no_marker_secret() {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(capture.clone())
            .finish();
        let marker_secret = "MARKER_PRIVATE_SIGNING_SEED_DO_NOT_LOG";
        let decision = CheckpointDecision {
            recipient_service_id: Some(Token::new("bloom-signer").unwrap()),
            attempted: bloom_audit_checkpoint::CheckpointHeadMetadata {
                service_id: Token::new("bloom-broker").unwrap(),
                key_id: Token::new("broker-audit-1").unwrap(),
                sequence: 7,
                head_digest: "11".repeat(32),
            },
            retained: Some(bloom_audit_checkpoint::CheckpointHeadMetadata {
                service_id: Token::new("bloom-broker").unwrap(),
                key_id: Token::new("broker-audit-1").unwrap(),
                sequence: 8,
                head_digest: "22".repeat(32),
            }),
            outcome: CheckpointDecisionOutcome::SequenceRollback,
        };
        let failure = bloom_audit_checkpoint::CheckpointAppendError {
            source: CheckpointError::Malformed(marker_secret.into()),
            decision,
        };
        tracing::subscriber::with_default(subscriber, || {
            log_checkpoint_decision("peer", None, &failure.decision, true);
        });
        let output = capture.text();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event["fields"]["event"], "signer.checkpoint_decision");
        assert_eq!(event["fields"]["attempted_sequence"], 7);
        assert_eq!(event["fields"]["retained_sequence"], 8);
        assert_eq!(event["fields"]["outcome"], "sequence_rollback");
        assert!(!output.contains(marker_secret));
    }

    #[test]
    fn successful_checkpoint_event_reports_existing_mutation_latch() {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(capture.clone())
            .finish();
        let decision = CheckpointDecision {
            recipient_service_id: Some(Token::new("bloom-signer").unwrap()),
            attempted: bloom_audit_checkpoint::CheckpointHeadMetadata {
                service_id: Token::new("bloom-broker").unwrap(),
                key_id: Token::new("broker-audit-1").unwrap(),
                sequence: 7,
                head_digest: "11".repeat(32),
            },
            retained: None,
            outcome: CheckpointDecisionOutcome::Appended,
        };
        tracing::subscriber::with_default(subscriber, || {
            log_checkpoint_decision("peer", None, &decision, true);
        });
        let event: serde_json::Value = serde_json::from_str(capture.text().trim()).unwrap();
        assert_eq!(event["fields"]["outcome"], "appended");
        assert_eq!(event["fields"]["mutations_disabled"], true);
    }

    #[test]
    fn clock_repair_logs_each_exact_expiring_approval_id() {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(capture.clone())
            .finish();
        let approval_id = Digest32::from_bytes([0x11; 32]);
        let confirmation_digest = Digest32::from_bytes([0x22; 32]);
        tracing::subscriber::with_default(subscriber, || {
            log_clock_repair_expiring_approvals(
                1_234,
                std::slice::from_ref(&approval_id),
                &confirmation_digest,
            );
        });
        let output = capture.text();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(
            event["fields"]["event"],
            "signer.clock_repair_expiring_approval"
        );
        assert_eq!(event["fields"]["approval_id"], approval_id.as_str());
        assert_eq!(
            event["fields"]["confirmation_digest"],
            confirmation_digest.as_str()
        );
        assert!(!output.contains("MARKER_APPROVAL_TERMS_SECRET_DO_NOT_LOG"));
    }

    #[test]
    fn dispatch_event_keeps_operation_and_service_metadata_without_error_text() {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .with_writer(capture.clone())
            .finish();
        let context = AuthenticatedRequestContext {
            method: Token::new("signer.sign").unwrap(),
            operation_id: OperationId::new("aa".repeat(32)).unwrap(),
            caller_service_id: Token::new("bloom-broker").unwrap(),
            caller_boot_epoch: BootEpoch::new("00112233445566778899aabbccddeeff").unwrap(),
            caller_application_key_id: Token::new("broker-key-1").unwrap(),
            sent_at_ms: 10,
            deadline_ms: 20,
        };
        let marker_secret = "MARKER_CEREMONY_BEARER_TOKEN_DO_NOT_LOG";
        let error = ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, marker_secret);
        tracing::subscriber::with_default(subscriber, || {
            let span = bloom_service_observability::service_span(
                "signer",
                "test-version",
                "bloom-signer",
                Some(501),
                Some("release-digest"),
            );
            span.in_scope(|| {
                log_rpc_completion::<()>(&context, false, std::time::Instant::now(), &Err(error));
            });
        });
        let output = capture.text();
        let event: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(event["fields"]["event"], "signer.dispatch_completed");
        assert_eq!(event["fields"]["operation_id"], "aa".repeat(32));
        assert_eq!(event["spans"][0]["service_id"], "bloom-signer", "{output}");
        assert!(!output.contains(marker_secret));
    }

    #[test]
    fn late_fatal_event_retains_trusted_service_metadata() {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let span = bloom_service_observability::service_span(
                "signer",
                "test-version",
                "bloom-signer",
                Some(501),
                Some("release-digest"),
            );
            drop(TrustedFatalGuard::new(span));
        });
        let event: serde_json::Value = serde_json::from_str(capture.text().trim()).unwrap();
        assert_eq!(event["fields"]["event"], "service.fatal_exit");
        assert_eq!(event["spans"][0]["service_id"], "bloom-signer");
    }

    #[test]
    fn disarmed_trusted_fatal_guard_emits_nothing() {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let span = bloom_service_observability::service_span(
                "signer",
                "test-version",
                "bloom-signer",
                Some(501),
                Some("release-digest"),
            );
            let mut guard = TrustedFatalGuard::new(span);
            guard.disarm();
        });
        assert!(capture.text().is_empty());
    }
}
