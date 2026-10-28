//! OS-activated Bloom Signer service process.

#![forbid(unsafe_code)]

mod admin;

use std::{
    collections::BTreeMap,
    fs,
    io::ErrorKind,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
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
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
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
    /// Ceremony window override; production templates omit it and keep the
    /// five-minute default. The developer harness sets thirty minutes.
    #[serde(default)]
    ceremony_ttl_ms: Option<u64>,
    /// Pinned relay receipt keys: a list, or one key in older configuration.
    #[serde(default)]
    relay_receipt_public_key_hex: Option<admin::ReceiptKeysHex>,
    /// Optional ceremony port for an independent development Triad. Missing
    /// keeps the default 18734 (or the development-only legacy environment
    /// fallback); an explicit integer 1 through 65535 always wins and is
    /// rejected before listeners open or ceremony state is touched when
    /// invalid. Hostname/RP ID stay fixed at `localhost` and binds stay on
    /// loopback (`127.0.0.1` and `::1`); only the port varies.
    #[serde(default)]
    ceremony_port: Option<u16>,
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
    let cli = Cli::parse();
    if let Some(Command::Admin(command)) = cli.command {
        if let Err(error) = admin::run_cli(command).await {
            eprintln!("Bloom Signer administration failed: {error}");
            std::process::exit(1);
        }
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
    let mut trusted_fatal = None;
    let result = run(&mut trusted_fatal).await;
    let code = finish_run(result, trusted_fatal);
    if code != 0 {
        std::process::exit(code);
    }
}

/// Report how `run` ended and return the process exit code. The guard is
/// moved in and dropped here, so its fatal event is logged before the caller
/// exits: `std::process::exit` skips destructors.
fn finish_run(result: Result<(), FatalCause>, mut trusted_fatal: Option<TrustedFatalGuard>) -> i32 {
    match result {
        Ok(()) => {
            if let Some(guard) = trusted_fatal.as_mut() {
                guard.disarm();
            }
            0
        }
        Err(cause) => {
            match trusted_fatal.as_mut() {
                Some(guard) => guard.record(cause),
                None => log_fatal_exit(
                    "bootstrap_failure",
                    "Bloom Signer exiting after a bootstrap error",
                    &cause,
                ),
            }
            drop(trusted_fatal);
            1
        }
    }
}

/// Bloom key-custody service and administrative client.
#[derive(Parser)]
#[command(name = "bloom-signer", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect or change the installed Signer's ceremony surface.
    Admin(admin::AdminCli),
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn administration_requires_one_explicit_target() {
        assert!(Cli::try_parse_from(["bloom-signer"]).is_ok());
        assert!(
            Cli::try_parse_from(["bloom-signer", "admin", "status", "--login-uid", "501"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["bloom-signer", "admin", "status", "--signer-uid", "501"]).is_ok()
        );
        assert!(Cli::try_parse_from(["bloom-signer", "admin", "status"]).is_err());
        assert!(
            Cli::try_parse_from([
                "bloom-signer",
                "admin",
                "status",
                "--login-uid",
                "501",
                "--signer-uid",
                "502"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from(["bloom-signer", "admin", "status", "--login-uid", "0"]).is_err()
        );
    }

    #[test]
    fn help_is_resolved_entirely_by_the_parser() {
        for args in [
            vec!["bloom-signer", "--help"],
            vec!["bloom-signer", "admin", "--help"],
            vec!["bloom-signer", "admin", "provision", "--help"],
        ] {
            let error = match Cli::try_parse_from(args) {
                Ok(_) => panic!("help must exit through clap"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        }
    }
}

struct TrustedFatalGuard {
    span: tracing::Span,
    armed: bool,
    cause: Option<FatalCause>,
}

impl TrustedFatalGuard {
    fn new(span: tracing::Span) -> Self {
        Self {
            span,
            armed: true,
            cause: None,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn record(&mut self, cause: FatalCause) {
        self.cause = Some(cause);
    }
}

impl Drop for TrustedFatalGuard {
    fn drop(&mut self) {
        if self.armed {
            let cause = self.cause.take().unwrap_or_else(FatalCause::unrecorded);
            self.span.in_scope(|| {
                log_fatal_exit(
                    "service_failure",
                    "Bloom Signer exiting after a fatal error",
                    &cause,
                );
            });
        }
    }
}

/// Why the Signer is exiting, reduced to fields that are safe to log.
///
/// Error text can carry secrets: `ProtocolError` messages embed serde
/// diagnostics for the identity and config files, which hold private seeds,
/// and peer-supplied text. The fatal event therefore names the failed stage
/// and the error's protocol code or I/O kind, never its `Display`. The only
/// text kept is built from literals in this file: an invariant, a serve-loop
/// failure, or the name of a missing environment variable. Peer UIDs are
/// logged as numbers.
#[derive(Debug)]
struct FatalCause {
    stage: &'static str,
    reason: &'static str,
    error_code: Option<&'static str>,
    io_error_kind: Option<ErrorKind>,
    os_error: Option<i32>,
    peer_uid: Option<u32>,
    expected_peer_uid: Option<u32>,
    detail: Option<String>,
}

impl FatalCause {
    fn invariant(stage: &'static str, detail: &'static str) -> Self {
        Self {
            detail: Some(detail.to_owned()),
            ..Self::bare(stage, "invariant")
        }
    }

    /// The peer on a local socket runs as an unexpected user.
    fn peer_uid_mismatch(stage: &'static str, peer_uid: u32, expected_peer_uid: u32) -> Self {
        Self {
            peer_uid: Some(peer_uid),
            expected_peer_uid: Some(expected_peer_uid),
            ..Self::bare(stage, "peer_uid_mismatch")
        }
    }

    /// A required environment variable is unset. The detail names the
    /// variable, a literal from this file; it never holds a value.
    fn missing_variable(
        stage: &'static str,
        variable: &'static str,
        profile: &'static str,
    ) -> Self {
        Self {
            detail: Some(format!(
                "{variable} is required by the {profile} service profile"
            )),
            ..Self::bare(stage, "invariant")
        }
    }

    fn classify(stage: &'static str, error: &(dyn std::error::Error + 'static)) -> Self {
        if let Some(error) = error.downcast_ref::<ProtocolError>() {
            return Self {
                error_code: Some(error.code.as_str()),
                ..Self::bare(stage, "protocol_error")
            };
        }
        // Identity, manifest, ACL and token checks fail with the transport's
        // wire error; its code is just as safe to log as a protocol code.
        // Map the code alone so the message, which can echo secret input, is
        // never copied.
        if let Some(error) = error.downcast_ref::<bloom_signer_api::WireError>() {
            let code = bloom_signer_api::WireError::new(error.code, String::new());
            return Self {
                error_code: Some(ProtocolError::from(code).code.as_str()),
                ..Self::bare(stage, "protocol_error")
            };
        }
        if let Some(error) = error.downcast_ref::<std::io::Error>() {
            if let Some(ServeInvariant(detail)) = error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<ServeInvariant>())
            {
                return Self::invariant(stage, detail);
            }
            return Self::bare(stage, "io_error").with_io(error);
        }
        // A rejection is an untyped `String` that can hold environment-supplied
        // text such as activation socket names, so only its kind is logged.
        match error.downcast_ref::<bloom_service_activation::ActivationError>() {
            Some(bloom_service_activation::ActivationError::Rejected(_)) => {
                Self::bare(stage, "activation_rejected")
            }
            Some(bloom_service_activation::ActivationError::Io(error)) => {
                Self::bare(stage, "activation_io_error").with_io(error)
            }
            None => Self::bare(stage, "unclassified"),
        }
    }

    fn unrecorded() -> Self {
        let reason = if std::thread::panicking() {
            "panic"
        } else {
            "unrecorded"
        };
        Self::bare("unrecorded", reason)
    }

    fn bare(stage: &'static str, reason: &'static str) -> Self {
        Self {
            stage,
            reason,
            error_code: None,
            io_error_kind: None,
            os_error: None,
            peer_uid: None,
            expected_peer_uid: None,
            detail: None,
        }
    }

    fn with_io(self, error: &std::io::Error) -> Self {
        Self {
            io_error_kind: Some(error.kind()),
            os_error: error.raw_os_error(),
            ..self
        }
    }
}

/// A fixed failure message from a serve loop. It travels inside an
/// `io::Error` so the loops keep their I/O signatures, and `classify` logs
/// it as an invariant.
#[derive(Debug)]
struct ServeInvariant(&'static str);

impl std::fmt::Display for ServeInvariant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ServeInvariant {}

fn serve_invariant(detail: &'static str) -> std::io::Error {
    std::io::Error::other(ServeInvariant(detail))
}

/// Labels a fallible step, during startup or while serving, so a fatal exit
/// names the step that failed.
trait AtStage<T> {
    fn at_stage(self, stage: &'static str) -> Result<T, FatalCause>;
}

impl<T, E: Into<Box<dyn std::error::Error>>> AtStage<T> for Result<T, E> {
    fn at_stage(self, stage: &'static str) -> Result<T, FatalCause> {
        self.map_err(|error| {
            let error: Box<dyn std::error::Error> = error.into();
            FatalCause::classify(stage, error.as_ref())
        })
    }
}

fn log_fatal_exit(error_kind: &'static str, message: &'static str, cause: &FatalCause) {
    tracing::error!(
        event = "service.fatal_exit",
        service_role = "signer",
        error_kind,
        stage = cause.stage,
        reason = cause.reason,
        error_code = cause.error_code,
        io_error_kind = cause.io_error_kind.map(tracing::field::debug),
        os_error = cause.os_error,
        peer_uid = cause.peer_uid,
        expected_peer_uid = cause.expected_peer_uid,
        detail = cause.detail.as_deref(),
        "{message}"
    );
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

async fn run(trusted_fatal: &mut Option<TrustedFatalGuard>) -> Result<(), FatalCause> {
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
        )
        .at_stage("load_identity_and_manifest")?,
        None => load_identity_and_manifest(&identity_path, &manifest_path, "bloom-signer")
            .at_stage("load_identity_and_manifest")?,
    };
    #[cfg(not(feature = "triad-dev-harness"))]
    let loaded_identity =
        load_identity_and_manifest(&identity_path, &manifest_path, "bloom-signer")
            .at_stage("load_identity_and_manifest")?;
    let (identity, manifest) = loaded_identity;
    let trusted_time_source = manifest.trusted_time_source.clone();
    let signer_effective_uid = manifest.signer.effective_uid;
    #[cfg(feature = "triad-dev-harness")]
    let admin_peer_uid = if std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT").is_some() {
        signer_effective_uid
    } else {
        0
    };
    #[cfg(not(feature = "triad-dev-harness"))]
    let admin_peer_uid = 0;
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
        .ok_or_else(|| {
            FatalCause::invariant(
                "load_session_acl",
                "edge manifest has no login-session identity",
            )
        })?
        .into_acl()
        .at_stage("load_session_acl")?;
    let broker_acl = manifest.broker.into_acl().at_stage("load_broker_acl")?;
    let revoke_client_acl = manifest
        .revoke_client
        .into_acl()
        .at_stage("load_revoke_client_acl")?;
    verify_edge_manifest_pins(&broker_acl, &session_acl, &revoke_client_acl)?;
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
    let mut config = load_config(&config_path).at_stage("load_signer_config")?;
    // Resolve the effective ceremony port once at startup, before opening
    // durable state or acquiring listeners, and carry it as instance state
    // from here on. An explicit file value wins over the legacy fallback;
    // an invalid explicit value fails startup here.
    let ceremony_port = bloom_signer::webauthn::resolve_ceremony_port(config.ceremony_port)
        .at_stage("resolve_ceremony_port")?;
    let broker_public_key = verifying_key(&config.broker_signing_public_key_hex)
        .at_stage("decode_broker_public_key")?;
    let ceremony_public_key = verifying_key(&config.ceremony_verifying_public_key_hex)
        .at_stage("decode_ceremony_public_key")?;
    let revocation_signing_key = take_signing_key(&mut config.revocation_signing_seed_hex)
        .at_stage("decode_revocation_signing_key")?;
    let audit_signing_key = take_signing_key(&mut config.audit_signing_seed_hex)
        .at_stage("decode_audit_signing_key")?;
    if config.audit_key_id == config.revocation_key_id
        || audit_signing_key.verifying_key() == revocation_signing_key.verifying_key()
        || audit_signing_key.verifying_key().to_bytes()
            == identity.signing_key.verifying_key().to_bytes()
    {
        return Err(FatalCause::invariant(
            "verify_audit_key_separation",
            "Signer audit key must be distinct from revocation and application keys",
        ));
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
        .transpose()
        .at_stage("decode_previous_audit_signing_key")?;
    let ceremony_signing_key = take_signing_key(&mut config.ceremony_signing_seed_hex)
        .at_stage("decode_ceremony_signing_key")?;
    if config.audit_key_id == config.ceremony_key_id
        || audit_signing_key.verifying_key() == ceremony_signing_key.verifying_key()
    {
        return Err(FatalCause::invariant(
            "verify_audit_key_separation",
            "Signer audit key must be distinct from the ceremony key",
        ));
    }
    let build_digest =
        Digest32::new(config.build_digest.clone()).at_stage("decode_build_digest")?;
    let service_span = bloom_service_observability::service_span(
        "signer",
        env!("CARGO_PKG_VERSION"),
        identity.service_id.as_str(),
        Some(session_acl.effective_uid),
        Some(build_digest.as_str()),
    );
    *trusted_fatal = Some(TrustedFatalGuard::new(service_span.clone()));

    let service_span_guard = service_span.enter();
    let compiled_backends =
        build_aws_backends(&mut config.aws_kms_backends).at_stage("build_aws_kms_backends")?;
    let registry = Arc::new(
        BackendRegistry::from_compiled(compiled_backends).at_stage("build_backend_registry")?,
    );
    let engine = Arc::new(
        open_operational_signer_engine(
            &config.database_path,
            Token::new(config.broker_signing_key_id.clone())
                .at_stage("parse_broker_signing_key_id")?,
            broker_public_key,
            ceremony_public_key,
            Token::new(config.revocation_key_id.clone()).at_stage("parse_revocation_key_id")?,
            revocation_signing_key,
            Token::new(config.audit_key_id.clone()).at_stage("parse_audit_key_id")?,
            audit_signing_key,
            &config.audit_historical_public_keys,
            previous_audit_signing_key,
            registry,
        )
        .at_stage("open_signer_engine")?,
    );
    let migration_root = config
        .database_path
        .parent()
        .ok_or_else(|| {
            FatalCause::invariant(
                "locate_legacy_migrations",
                "Signer database path has no parent directory",
            )
        })?
        .join("legacy-passkey-migrations");
    let migration_store = Arc::new(
        LegacyMigrationStore::create_for_current_process(migration_root, signer_effective_uid)
            .at_stage("open_legacy_migration_store")?,
    );
    let mut ceremony = SignerCeremonyService::new_with_ceremony_port(
        engine.clone(),
        Token::new(config.ceremony_key_id.clone()).at_stage("parse_ceremony_key_id")?,
        ceremony_signing_key,
        ceremony_port,
    )
    .at_stage("open_ceremony_service")?
    .with_legacy_migrations(migration_store);
    if let Some(ttl_ms) = config.ceremony_ttl_ms {
        ceremony = ceremony
            .with_ceremony_ttl_ms(ttl_ms)
            .at_stage("apply_ceremony_ttl")?;
        tracing::warn!(
            ceremony_ttl_ms = ttl_ms,
            "Signer config overrides the ceremony window"
        );
    }
    let ceremony = Arc::new(ceremony);
    let clock = Arc::new(
        SignerClock::new(
            engine.clone(),
            &trusted_time_source,
            identity.boot_epoch.clone(),
        )
        .at_stage("open_signer_clock")?,
    );
    if let Some(accepted_utc_ms) = clock_repair_request()? {
        if !clock.uses_durable_clock_guard() {
            return Err(FatalCause::invariant(
                "repair_clock",
                "clock repair is unavailable when the host wall clock is authoritative",
            ));
        }
        let expiring = engine
            .active_approvals_expiring_by(accepted_utc_ms)
            .at_stage("list_expiring_approvals")?;
        require_clock_repair_confirmation(accepted_utc_ms, &expiring)?;
        let decision = engine
            .repair_clock(accepted_utc_ms)
            .at_stage("repair_clock")?;
        tracing::info!(
            event = "signer.clock_repair_committed",
            effective_utc_ms = decision.effective_now_ms,
            condition = decision.condition.as_str(),
            expiring_live_approval_count = expiring.len(),
            "Signer clock repair committed"
        );
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
        .transpose()
        .at_stage("open_network_containment")?;
    let initial_audit_head =
        select_initial_self_head(engine.as_ref(), checkpoint_store.as_ref(), &identity)
            .at_stage("select_initial_audit_head")?;
    let journal_exchange = Arc::new(SignerJournalExchange {
        engine: engine.clone(),
        checkpoints: checkpoint_store,
        identity: identity.clone(),
        last_verified_head: Mutex::new(initial_audit_head),
    });
    let admin_ceremony = ceremony.clone();
    let expiry_ceremony = ceremony.clone();
    let expiry_clock = clock.clone();
    let admin_receipt_keys = config
        .relay_receipt_public_key_hex
        .as_ref()
        .map(admin::ReceiptKeysHex::decode)
        .transpose()
        .at_stage("decode_relay_receipt_keys")?;
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
        "bind_rpc_socket",
        "BLOOM_SIGNER_SOCKET",
        "BLOOM_SIGNER_ACTIVATION_NAME",
        "signer",
    )?)
    .at_stage("bind_rpc_socket")?;
    let control_listener = UnixListener::from_std(acquire_unix_listener(
        "bind_control_socket",
        "BLOOM_SIGNER_CONTROL_SOCKET",
        "BLOOM_SIGNER_CONTROL_ACTIVATION_NAME",
        "signer-control",
    )?)
    .at_stage("bind_control_socket")?;
    let admin_listener = std::env::var_os("BLOOM_SIGNER_ADMIN_SOCKET")
        .map(PathBuf::from)
        .map(|path| bloom_service_activation::bind_private_unix_listener(&path))
        .transpose()
        .at_stage("bind_admin_socket")?
        .map(UnixListener::from_std)
        .transpose()
        .at_stage("bind_admin_socket")?;
    let rpc_quota = Arc::new(
        EndpointQuota::new(
            config.maximum_in_flight_mutations,
            config.maximum_requests_per_window,
            config.request_window_ms,
            config.maximum_journal_admissions_per_window,
            config.journal_window_ms,
        )
        .at_stage("create_rpc_quota")?,
    );
    let control_quota = Arc::new(
        EndpointQuota::new(
            config.control_maximum_in_flight_mutations,
            config.control_maximum_requests_per_window,
            config.control_request_window_ms,
            config.control_maximum_journal_admissions_per_window,
            config.control_journal_window_ms,
        )
        .at_stage("create_control_quota")?,
    );
    if config.maximum_connections == 0 || config.control_maximum_connections == 0 {
        return Err(FatalCause::invariant(
            "validate_connection_quotas",
            "Signer connection quotas must be nonzero",
        ));
    }
    let session_socket_path = env_path(
        "BLOOM_SESSION_SOCKET",
        "/var/run/bloom/session/session.sock",
    );
    drop(service_span_guard);
    let session_stream =
        connect_authenticated_session(&session_socket_path, &identity, &session_acl)
            .instrument(service_span.clone())
            .await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut rpc_shutdown = shutdown_rx.clone();
    let mut control_shutdown = shutdown_rx;
    let mut admin_shutdown = control_shutdown.clone();
    let expiry_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            match expiry_clock.now_ms_read_only() {
                Ok(now_ms) => expiry_ceremony.expire_cross_surface_pairs(now_ms),
                Err(_) => expiry_ceremony.clear_cross_surface_pairs(),
            }
        }
    });
    async move {
        tracing::info!(
            event = "service.ready",
            service_role = "signer",
            rpc_endpoint = "broker",
            control_endpoint = "revocation",
            "Bloom Signer ready"
        );
        let rpc_identity = identity.clone();
        tokio::try_join!(
            async {
                serve_rpc(
                    rpc_listener,
                    rpc_identity,
                    broker_acl,
                    rpc_quota,
                    service.clone(),
                    journal_exchange,
                    config.maximum_connections,
                    &mut rpc_shutdown,
                )
                .await
                .at_stage("serve_rpc")
            },
            async {
                serve_control(
                    control_listener,
                    identity,
                    revoke_client_acl,
                    control_quota,
                    control_service,
                    config.control_maximum_connections,
                    &mut control_shutdown,
                )
                .await
                .at_stage("serve_control")
            },
            async {
                admin::serve(
                    admin_listener,
                    admin_ceremony,
                    admin_receipt_keys,
                    admin_peer_uid,
                    &mut admin_shutdown,
                )
                .await
                .at_stage("serve_admin")
            },
            monitor_session_sentinel(session_stream, shutdown_tx),
        )?;
        tracing::info!(
            event = "service.shutdown",
            service_role = "signer",
            reason = "session_ended",
            "Bloom Signer stopped"
        );
        Ok::<(), FatalCause>(())
    }
    .instrument(service_span)
    .await?;
    expiry_task.abort();
    Ok(())
}

fn verify_edge_manifest_pins(
    broker_acl: &PeerAcl,
    session_acl: &PeerAcl,
    revoke_client_acl: &PeerAcl,
) -> Result<(), FatalCause> {
    const STAGE: &str = "verify_edge_manifest_pins";
    if broker_acl.service_id.as_str() != "bloom-broker" {
        return Err(FatalCause::invariant(
            STAGE,
            "edge manifest does not pin bloom-broker for the Signer edge",
        ));
    }
    if session_acl.service_id.as_str() != "bloom-session" {
        return Err(FatalCause::invariant(
            STAGE,
            "edge manifest does not pin bloom-session for the login-session sentinel",
        ));
    }
    if revoke_client_acl.service_id.as_str() != "bloom-revoke-client" {
        return Err(FatalCause::invariant(
            STAGE,
            "edge manifest does not pin the dedicated revoke client",
        ));
    }
    Ok(())
}

/// Signal shutdown once the login-session sentinel closes its channel. A
/// read failure keeps its I/O kind and OS error for the fatal event.
async fn monitor_session_sentinel(
    mut session_stream: impl AsyncRead + Unpin,
    shutdown_tx: watch::Sender<bool>,
) -> Result<(), FatalCause> {
    const STAGE: &str = "monitor_session_sentinel";
    let mut unexpected = [0_u8; 1];
    match session_stream.read(&mut unexpected).await {
        Ok(0) => {}
        Err(error) if is_session_disconnect(&error) => {}
        Ok(_) => {
            return Err(FatalCause::invariant(
                STAGE,
                "session sentinel sent unexpected channel data",
            ));
        }
        Err(error) => return Err(error).at_stage(STAGE),
    }
    shutdown_tx
        .send(true)
        .map_err(|_| FatalCause::invariant(STAGE, "Signer shutdown receivers disappeared"))
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
    stage: &'static str,
    path_variable: &'static str,
    _activation_variable: &str,
    _default_activation_name: &str,
) -> Result<std::os::unix::net::UnixListener, FatalCause> {
    let path = std::env::var_os(path_variable)
        .map(PathBuf::from)
        .ok_or_else(|| FatalCause::missing_variable(stage, path_variable, "macOS"))?;
    bloom_service_activation::bind_owned_unix_listener(&path).at_stage(stage)
}

#[cfg(not(target_os = "macos"))]
fn acquire_unix_listener(
    stage: &'static str,
    path_variable: &'static str,
    _activation_variable: &str,
    _default_activation_name: &str,
) -> Result<std::os::unix::net::UnixListener, FatalCause> {
    let path = std::env::var_os(path_variable)
        .map(PathBuf::from)
        .ok_or_else(|| FatalCause::missing_variable(stage, path_variable, "Linux"))?;
    bloom_service_activation::bind_owned_unix_listener(&path).at_stage(stage)
}

fn require_clock_repair_confirmation(
    accepted_utc_ms: u64,
    expiring: &[Digest32],
) -> Result<(), FatalCause> {
    if expiring.is_empty() {
        return Ok(());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"bloom-clock-repair-confirmation/v1");
    hasher.update(accepted_utc_ms.to_be_bytes());
    hasher.update(serde_jcs::to_vec(expiring).at_stage("confirm_clock_repair")?);
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
        return Err(FatalCause::invariant(
            "confirm_clock_repair",
            "clock repair not committed; set BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST to the reported digest",
        ));
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

fn clock_repair_request() -> Result<Option<u64>, FatalCause> {
    std::env::var("BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS")
        .ok()
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                FatalCause::invariant(
                    "parse_clock_repair_request",
                    "BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS must be a whole number of UTC milliseconds",
                )
            })
        })
        .transpose()
}

/// Authority-edge dispatch. The transport negotiates and verifies the
/// request's signed protocol against the supported range before dispatch.
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
                permit.map_err(|_| serve_invariant("Signer RPC connection gate closed"))?
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
    drain_connections(connections, maximum_connections).await
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
                permit.map_err(|_| serve_invariant("Signer control connection gate closed"))?
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
    drain_connections(connections, maximum_connections).await
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

/// Connect to the login-session sentinel and authenticate. A socket failure
/// and a rejected handshake are separate stages, so the fatal event tells a
/// permissions problem (with its OS error) from a sentinel that refused us.
async fn connect_authenticated_session(
    path: &Path,
    identity: &LocalIdentity,
    session_acl: &PeerAcl,
) -> Result<UnixStream, FatalCause> {
    const AUTHENTICATE: &str = "authenticate_session_sentinel";
    loop {
        match UnixStream::connect(path).await {
            Ok(mut stream) => {
                // The handshake repeats this check, but reports only a code;
                // checking first lets the fatal event name both UIDs.
                let peer_uid = stream.peer_cred().at_stage(AUTHENTICATE)?.uid();
                if peer_uid != session_acl.effective_uid {
                    return Err(FatalCause::peer_uid_mismatch(
                        AUTHENTICATE,
                        peer_uid,
                        session_acl.effective_uid,
                    ));
                }
                bloom_triad_local_transport::authenticate_client(
                    &mut stream,
                    identity,
                    session_acl,
                    bloom_service_activation::SESSION_PROTOCOL_CURRENT,
                    bloom_service_activation::SESSION_PROTOCOL_RANGE,
                )
                .await
                .at_stage(AUTHENTICATE)?;
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
            Err(error) => return Err(error).at_stage("connect_session_sentinel"),
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
) -> std::io::Result<()> {
    let permits = u32::try_from(maximum_connections)
        .map_err(|_| serve_invariant("Signer connection quota exceeds u32"))?;
    let _drained = tokio::time::timeout(
        Duration::from_secs(35),
        connections.acquire_many_owned(permits),
    )
    .await
    .map_err(|_| serve_invariant("Signer connections did not drain within 35 seconds"))?
    .map_err(|_| serve_invariant("Signer connection gate closed"))?;
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
        let drain = tokio::spawn(drain_connections(connections, 2));
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
                        verifying_key: VerifyingKey::from_bytes(
                            &broker_key.verifying_key().to_bytes(),
                        )
                        .unwrap(),
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
                        verifying_key: VerifyingKey::from_bytes(
                            &broker_key.verifying_key().to_bytes(),
                        )
                        .unwrap(),
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
        assert_eq!(event["fields"]["error_kind"], "service_failure");
        assert_eq!(event["fields"]["reason"], "unrecorded");
        assert_eq!(event["spans"][0]["service_id"], "bloom-signer");
    }

    fn ceremony_port_config_fixture(port: serde_json::Value) -> serde_json::Value {
        let mut config = serde_json::json!({
            "database_path": "/var/db/bloom/signer/signer.sqlite3",
            "broker_signing_key_id": "broker-app-1",
            "broker_signing_public_key_hex": "00".repeat(32),
            "ceremony_verifying_public_key_hex": "11".repeat(32),
            "revocation_key_id": "signer-revocation-key",
            "revocation_signing_seed_hex": "22".repeat(32),
            "audit_key_id": "signer-audit-key",
            "audit_signing_seed_hex": "33".repeat(32),
            "ceremony_key_id": "signer-ceremony-key",
            "ceremony_signing_seed_hex": "44".repeat(32),
            "build_digest": "55".repeat(32),
            "maximum_connections": 8,
            "maximum_in_flight_mutations": 4,
            "maximum_requests_per_window": 100,
            "request_window_ms": 1000,
            "maximum_journal_admissions_per_window": 10,
            "journal_window_ms": 1000,
            "control_maximum_connections": 4,
            "control_maximum_in_flight_mutations": 2,
            "control_maximum_requests_per_window": 50,
            "control_request_window_ms": 1000,
            "control_maximum_journal_admissions_per_window": 5,
            "control_journal_window_ms": 1000,
            "aws_kms_backends": []
        });
        if !port.is_null() {
            config["ceremony_port"] = port;
        }
        config
    }

    fn parse_ceremony_port_fixture(port: serde_json::Value) -> Result<Option<u16>, String> {
        serde_json::from_value::<SignerConfig>(ceremony_port_config_fixture(port))
            .map(|config| config.ceremony_port)
            .map_err(|error| error.to_string())
    }

    #[test]
    fn ceremony_port_config_missing_means_default() {
        // A missing field parses as absent; resolution (default or legacy
        // fallback) is covered by the webauthn unit tests. This stays
        // environment-independent so the focused harness CI can run it.
        assert_eq!(
            parse_ceremony_port_fixture(serde_json::Value::Null).unwrap(),
            None
        );
    }

    #[test]
    fn ceremony_port_config_explicit_alternate_parses() {
        assert_eq!(
            parse_ceremony_port_fixture(serde_json::json!(28735)).unwrap(),
            Some(28735)
        );
        assert_eq!(
            parse_ceremony_port_fixture(serde_json::json!(1)).unwrap(),
            Some(1)
        );
        assert_eq!(
            parse_ceremony_port_fixture(serde_json::json!(65535)).unwrap(),
            Some(65535)
        );
    }

    #[test]
    fn ceremony_port_config_rejects_non_integer_values() {
        // Wrong JSON types never reach resolution: serde rejects them while
        // parsing the protected config, before listeners or ceremony state.
        for invalid in [
            serde_json::json!("28735"),
            serde_json::json!(28.735),
            serde_json::json!(-1),
            serde_json::json!(65536),
            serde_json::json!(true),
            serde_json::json!([28735]),
        ] {
            assert!(
                parse_ceremony_port_fixture(invalid.clone()).is_err(),
                "ceremony_port value {invalid} must be rejected at parse time"
            );
        }
    }

    #[test]
    fn ceremony_port_config_zero_is_rejected_at_resolution() {
        // Zero parses as a u16 but fails explicit validation, so startup
        // rejects it through the same path as any invalid explicit value.
        let parsed = parse_ceremony_port_fixture(serde_json::json!(0)).unwrap();
        assert_eq!(parsed, Some(0));
        assert_eq!(
            bloom_signer::webauthn::resolve_ceremony_port(parsed)
                .unwrap_err()
                .code,
            ProtocolErrorCode::MalformedFrame
        );
        // And a valid explicit port resolves regardless of resolution order.
        assert_eq!(
            bloom_signer::webauthn::resolve_ceremony_port(Some(28735)).unwrap(),
            28735
        );
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

    fn captured_fatal_exit(emit: impl FnOnce(tracing::Span)) -> (serde_json::Value, String) {
        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            emit(bloom_service_observability::service_span(
                "signer",
                "test-version",
                "bloom-signer",
                Some(501),
                Some("release-digest"),
            ))
        });
        let output = capture.text();
        let event = serde_json::from_str(output.trim()).unwrap();
        (event, output)
    }

    #[test]
    fn recorded_fatal_cause_names_the_stage_without_secret_error_text() {
        let marker_secret = "MARKER_SIGNER_SEED_DO_NOT_LOG";
        let mut config = ceremony_port_config_fixture(serde_json::Value::Null);
        config["maximum_connections"] = serde_json::json!(marker_secret);
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("signer.json");
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        // The parser echoes the rejected value, so the raw error is unsafe.
        assert!(
            load_config(&path)
                .err()
                .unwrap()
                .to_string()
                .contains(marker_secret)
        );
        let cause = load_config(&path)
            .at_stage("load_signer_config")
            .err()
            .unwrap();

        let (event, output) = captured_fatal_exit(|span| {
            TrustedFatalGuard::new(span).record(cause);
        });
        assert_eq!(event["fields"]["event"], "service.fatal_exit");
        assert_eq!(event["fields"]["error_kind"], "service_failure");
        assert_eq!(event["fields"]["stage"], "load_signer_config");
        assert_eq!(event["fields"]["reason"], "protocol_error");
        assert_eq!(event["fields"]["error_code"], "MALFORMED_FRAME");
        assert!(event["fields"].get("detail").is_none(), "{output}");
        assert_eq!(event["spans"][0]["service_id"], "bloom-signer");
        assert!(!output.contains(marker_secret), "{output}");
    }

    #[test]
    fn bootstrap_fatal_exit_omits_unreviewed_error_text() {
        let marker_secret = "MARKER_IDENTITY_SEED_DO_NOT_LOG";
        // Identity loading fails with the transport's wire error, whose
        // message can echo the identity file.
        let wire = bloom_signer_api::WireError::new(
            bloom_signer_api::WireErrorCode::MalformedFrame,
            format!("decode identity seed {marker_secret}"),
        );
        assert!(wire.to_string().contains(marker_secret));
        let cause = Err::<(), _>(wire)
            .at_stage("load_identity_and_manifest")
            .unwrap_err();
        let (event, output) = captured_fatal_exit(|_| {
            log_fatal_exit(
                "bootstrap_failure",
                "Bloom Signer exiting after a bootstrap error",
                &cause,
            );
        });
        assert_eq!(event["fields"]["event"], "service.fatal_exit");
        assert_eq!(event["fields"]["error_kind"], "bootstrap_failure");
        assert_eq!(event["fields"]["stage"], "load_identity_and_manifest");
        assert_eq!(event["fields"]["reason"], "protocol_error");
        assert_eq!(event["fields"]["error_code"], "MALFORMED_FRAME");
        assert!(!output.contains(marker_secret), "{output}");

        // An error of any other type is still reduced to its stage.
        let cause = Err::<(), _>(format!("decode identity seed {marker_secret}"))
            .at_stage("load_identity_and_manifest")
            .unwrap_err();
        let (event, output) = captured_fatal_exit(|_| {
            log_fatal_exit(
                "bootstrap_failure",
                "Bloom Signer exiting after a bootstrap error",
                &cause,
            );
        });
        assert_eq!(event["fields"]["reason"], "unclassified");
        assert!(!output.contains(marker_secret), "{output}");
    }

    /// `main` exits through `finish_run`: a failure records its cause on the
    /// guard and logs exactly one fatal event before the exit code is
    /// returned, and success logs nothing.
    #[test]
    fn finish_run_logs_one_fatal_event_before_returning_the_exit_code() {
        let mut code = None;
        let (event, output) = captured_fatal_exit(|span| {
            code = Some(finish_run(
                Err(FatalCause::invariant(
                    "bind_rpc_socket",
                    "socket owner mismatch",
                )),
                Some(TrustedFatalGuard::new(span)),
            ));
        });
        assert_eq!(code, Some(1));
        assert_eq!(event["fields"]["error_kind"], "service_failure");
        assert_eq!(event["fields"]["stage"], "bind_rpc_socket");
        // The trusted failure is logged by the guard, inside the service span.
        assert_eq!(event["spans"][0]["service_id"], "bloom-signer", "{output}");
        assert_eq!(event["spans"][0]["release_digest"], "release-digest");
        assert_eq!(output.trim().lines().count(), 1, "{output}");

        let mut code = None;
        let (event, _) = captured_fatal_exit(|_| {
            code = Some(finish_run(
                Err(FatalCause::invariant("load_signer_config", "missing")),
                None,
            ));
        });
        assert_eq!(code, Some(1));
        assert_eq!(event["fields"]["error_kind"], "bootstrap_failure");
        assert_eq!(event["fields"]["stage"], "load_signer_config");

        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(capture.clone())
            .finish();
        let code = tracing::subscriber::with_default(subscriber, || {
            finish_run(Ok(()), Some(TrustedFatalGuard::new(tracing::Span::none())))
        });
        assert_eq!(code, 0);
        assert!(capture.text().is_empty(), "{}", capture.text());
    }

    #[test]
    fn fatal_cause_keeps_only_reviewed_detail() {
        let rejection = "endpoint directory /run/bloom must be a non-symlink directory owned by effective UID 0 with mode 0700";
        let boxed: Box<dyn std::error::Error> =
            bloom_service_activation::ActivationError::Rejected(rejection.into()).into();
        let rejected = Err::<(), _>(boxed)
            .at_stage("bind_admin_socket")
            .unwrap_err();
        assert_eq!(rejected.stage, "bind_admin_socket");
        assert_eq!(rejected.reason, "activation_rejected");
        assert_eq!(rejected.detail, None);

        let activation_io = Err::<(), _>(bloom_service_activation::ActivationError::Io(
            std::io::Error::new(ErrorKind::AddrInUse, "socket is live"),
        ))
        .at_stage("bind_rpc_socket")
        .unwrap_err();
        assert_eq!(activation_io.reason, "activation_io_error");
        assert_eq!(activation_io.io_error_kind, Some(ErrorKind::AddrInUse));
        assert_eq!(activation_io.detail, None);

        let (event, output) = captured_fatal_exit(|span| {
            let cause = Err::<(), _>(std::io::Error::from_raw_os_error(13))
                .at_stage("serve_rpc")
                .unwrap_err();
            TrustedFatalGuard::new(span).record(cause);
        });
        assert_eq!(event["fields"]["reason"], "io_error");
        assert_eq!(event["fields"]["io_error_kind"], "PermissionDenied");
        assert_eq!(event["fields"]["os_error"], 13);
        assert!(event["fields"].get("detail").is_none(), "{output}");

        let invariant = FatalCause::invariant(
            "validate_connection_quotas",
            "Signer connection quotas must be nonzero",
        );
        assert_eq!(invariant.reason, "invariant");
        assert_eq!(
            invariant.detail.as_deref(),
            Some("Signer connection quotas must be nonzero")
        );
    }

    #[test]
    fn activation_rejection_text_never_reaches_the_log() {
        let marker_secret = "MARKER_ACTIVATION_SECRET_DO_NOT_LOG";
        // Shaped like a real rejection built from environment-supplied
        // activation names (`LISTEN_FDNAMES`).
        let rejection = format!("activation socket name {marker_secret:?} is duplicated");
        let boxed: Box<dyn std::error::Error> =
            bloom_service_activation::ActivationError::Rejected(rejection).into();
        assert!(boxed.to_string().contains(marker_secret));
        let cause = Err::<(), _>(boxed).at_stage("bind_rpc_socket").unwrap_err();

        let (event, output) = captured_fatal_exit(|span| {
            TrustedFatalGuard::new(span).record(cause);
        });
        assert_eq!(event["fields"]["event"], "service.fatal_exit");
        assert_eq!(event["fields"]["stage"], "bind_rpc_socket");
        assert_eq!(event["fields"]["reason"], "activation_rejected");
        assert!(event["fields"].get("detail").is_none(), "{output}");
        assert!(!output.contains(marker_secret), "{output}");
    }

    #[test]
    fn trusted_fatal_guard_reports_a_panic() {
        let (event, _) = captured_fatal_exit(|span| {
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = TrustedFatalGuard::new(span);
                panic!("forced Signer panic");
            }));
            assert!(panicked.is_err());
        });
        assert_eq!(event["fields"]["error_kind"], "service_failure");
        assert_eq!(event["fields"]["reason"], "panic");
        assert_eq!(event["spans"][0]["service_id"], "bloom-signer");
    }

    #[test]
    fn missing_socket_variable_is_a_named_invariant() {
        let variable = "BLOOM_SIGNER_TEST_SOCKET_THAT_IS_NEVER_SET";
        assert!(std::env::var_os(variable).is_none());
        let cause =
            acquire_unix_listener("bind_rpc_socket", variable, "UNUSED", "unused").unwrap_err();
        assert_eq!(cause.stage, "bind_rpc_socket");
        assert_eq!(cause.reason, "invariant");
        let detail = cause.detail.unwrap();
        assert!(detail.starts_with(variable), "{detail}");
    }

    #[tokio::test]
    async fn sentinel_socket_failure_keeps_its_os_error() {
        let temporary = tempfile::tempdir().unwrap();
        let not_a_directory = temporary.path().join("file");
        fs::write(&not_a_directory, b"").unwrap();
        let identity = signer_identity();
        let cause = connect_authenticated_session(
            &not_a_directory.join("session.sock"),
            &identity,
            &peer_acl(&identity, 0),
        )
        .await
        .unwrap_err();
        assert_eq!(cause.stage, "connect_session_sentinel");
        assert_eq!(cause.reason, "io_error");
        assert_eq!(cause.io_error_kind, Some(ErrorKind::NotADirectory));
        assert!(cause.os_error.is_some());
    }

    #[tokio::test]
    async fn sentinel_that_hangs_up_fails_the_handshake_stage() {
        let temporary = tempfile::tempdir().unwrap();
        let effective_uid = fs::metadata(temporary.path()).unwrap().uid();
        let path = temporary.path().join("session.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let sentinel = tokio::spawn(async move {
            drop(listener.accept().await.unwrap());
        });
        let identity = signer_identity();
        let cause =
            connect_authenticated_session(&path, &identity, &peer_acl(&identity, effective_uid))
                .await
                .unwrap_err();
        sentinel.await.unwrap();
        assert_eq!(cause.stage, "authenticate_session_sentinel");
        assert_eq!(cause.reason, "protocol_error");
        assert_eq!(cause.error_code, Some("SERVICE_UNAVAILABLE"));
    }

    #[tokio::test]
    async fn sentinel_running_as_another_user_names_both_uids() {
        let temporary = tempfile::tempdir().unwrap();
        let effective_uid = fs::metadata(temporary.path()).unwrap().uid();
        let expected_uid = effective_uid.wrapping_add(1);
        let path = temporary.path().join("session.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let sentinel = tokio::spawn(async move { listener.accept().await.unwrap() });
        let identity = signer_identity();
        let cause =
            connect_authenticated_session(&path, &identity, &peer_acl(&identity, expected_uid))
                .await
                .unwrap_err();
        drop(sentinel.await.unwrap());
        assert_eq!(cause.stage, "authenticate_session_sentinel");
        assert_eq!(cause.reason, "peer_uid_mismatch");

        let (event, _) = captured_fatal_exit(|span| {
            TrustedFatalGuard::new(span).record(cause);
        });
        assert_eq!(event["fields"]["peer_uid"], effective_uid);
        assert_eq!(event["fields"]["expected_peer_uid"], expected_uid);
    }

    struct FailingRead(i32);

    impl AsyncRead for FailingRead {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            _buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::from_raw_os_error(self.0)))
        }
    }

    #[tokio::test]
    async fn session_sentinel_read_failure_keeps_its_os_error() {
        const EIO: i32 = 5;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let cause = monitor_session_sentinel(FailingRead(EIO), shutdown_tx)
            .await
            .unwrap_err();
        assert_eq!(cause.stage, "monitor_session_sentinel");
        assert_eq!(cause.reason, "io_error");
        assert_eq!(cause.os_error, Some(EIO));
        assert!(!*shutdown_rx.borrow());
    }

    fn acl_for(service_id: &str) -> PeerAcl {
        PeerAcl {
            service_id: Token::new(service_id).unwrap(),
            ..peer_acl(&signer_identity(), 0)
        }
    }

    #[test]
    fn edge_manifest_pin_checks_name_the_wrong_pin() {
        let broker = acl_for("bloom-broker");
        let session = acl_for("bloom-session");
        let revoke = acl_for("bloom-revoke-client");
        let wrong = acl_for("bloom-machine");
        assert!(verify_edge_manifest_pins(&broker, &session, &revoke).is_ok());
        for (broker, session, revoke, pin) in [
            (&wrong, &session, &revoke, "bloom-broker"),
            (&broker, &wrong, &revoke, "bloom-session"),
            (&broker, &session, &wrong, "revoke client"),
        ] {
            let cause = verify_edge_manifest_pins(broker, session, revoke).unwrap_err();
            assert_eq!(cause.stage, "verify_edge_manifest_pins");
            let detail = cause.detail.unwrap();
            assert!(detail.contains(pin), "{detail}");
        }
    }

    #[test]
    fn serve_loop_failure_is_a_literal_invariant() {
        let cause = Err::<(), _>(serve_invariant(
            "Signer connections did not drain within 35 seconds",
        ))
        .at_stage("serve_control")
        .unwrap_err();
        assert_eq!(cause.stage, "serve_control");
        assert_eq!(cause.reason, "invariant");
        assert_eq!(
            cause.detail.as_deref(),
            Some("Signer connections did not drain within 35 seconds")
        );
    }

    #[tokio::test]
    async fn session_sentinel_monitor_tells_a_close_from_unexpected_data() {
        use tokio::io::AsyncWriteExt as _;

        let (sentinel, signer) = UnixStream::pair().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        drop(sentinel);
        monitor_session_sentinel(signer, shutdown_tx).await.unwrap();
        assert!(*shutdown_rx.borrow());

        let (mut sentinel, signer) = UnixStream::pair().unwrap();
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        sentinel.write_all(b"x").await.unwrap();
        let cause = monitor_session_sentinel(signer, shutdown_tx)
            .await
            .unwrap_err();
        assert_eq!(cause.stage, "monitor_session_sentinel");
        assert_eq!(
            cause.detail.as_deref(),
            Some("session sentinel sent unexpected channel data")
        );
    }
}
