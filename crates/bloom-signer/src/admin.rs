//! Dedicated root-only Signer administration. This socket is separate from
//! signed authority RPC and never accepts wallet secrets or ceremony proofs.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bloom_relay_admin_client::{
    EnrollmentConfig, SecretToken, enroll, issue_credential, register_acme_account,
};
use bloom_relay_protocol::{AllocationReceipt, Scope};
use bloom_signer::ceremony::SignerCeremonyService;
use bloom_signer_api::{Digest32, ExposureMode, SurfaceStatus};
#[cfg(feature = "triad-dev-harness")]
use bloom_triad_local_transport::load_developer_identity_and_manifest;
use bloom_triad_local_transport::require_local_admin_peer;
use clap::{Args, Subcommand};
use ed25519_dalek::{Signer as _, SigningKey};
use rand::{TryRng as _, rngs::SysRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
    sync::watch,
    time::timeout,
};
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

const MAX_FRAME: usize = 16 * 1024;
const ADMIN_IDENTITY_FILE: &str = "relay-admin-seed.hex";

#[derive(Args)]
pub(super) struct AdminCli {
    #[command(subcommand)]
    command: AdminCommand,
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Show the desired and effective ceremony-surface state.
    Status(AdminTarget),
    /// Allocate and install the relay identity and scoped Broker credentials.
    Provision(AdminTarget),
    /// Enable the remotely reachable ceremony surface.
    RemoteEnabled(AdminTarget),
    /// Disable remote ceremonies while retaining localhost ceremonies.
    LocalhostOnly(AdminTarget),
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct AdminTarget {
    /// Login UID of an installed Bloom instance (requires root).
    #[arg(long, value_name = "UID", value_parser = parse_nonzero_uid)]
    login_uid: Option<u32>,

    /// Explicit Signer UID with BLOOM_* paths (root or validated developer harness).
    #[arg(long, value_name = "UID", value_parser = parse_nonzero_uid)]
    signer_uid: Option<u32>,
}

#[derive(Debug)]
struct AdminContext {
    socket: PathBuf,
    signer_uid: u32,
    admin_owner_uid: u32,
    provisioning: Option<ProvisionContext>,
}

#[derive(Debug)]
struct ProvisionContext {
    admin_state: PathBuf,
    relay_config: PathBuf,
    tunnel_credential: PathBuf,
    dns_credential: PathBuf,
    acme_account_uri: PathBuf,
    broker_uid: u32,
    broker_gid: u32,
}

fn parse_nonzero_uid(value: &str) -> Result<u32, String> {
    let uid = value
        .parse::<u32>()
        .map_err(|_| "UID must be a decimal integer".to_owned())?;
    if uid == 0 {
        return Err("UID must be nonzero".to_owned());
    }
    Ok(uid)
}

fn admin_owner_uid(_signer_uid: u32) -> io::Result<u32> {
    #[cfg(feature = "triad-dev-harness")]
    if let Some(root) = std::env::var_os("BLOOM_TRIAD_DEVELOPER_ROOT") {
        let identity = std::env::var_os("BLOOM_SIGNER_IDENTITY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/run/bloom/signer-identity.json"));
        let manifest = std::env::var_os("BLOOM_EDGE_MANIFEST")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/bloom/edge-manifest.json"));
        let (_, manifest) = load_developer_identity_and_manifest(
            Path::new(&root),
            &identity,
            &manifest,
            "bloom-signer",
        )
        .map_err(io::Error::other)?;
        let current_uid = manifest.signer.effective_uid;
        if current_uid == 0 || _signer_uid != current_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "developer administration requires the validated non-root Signer UID",
            ));
        }
        return Ok(current_uid);
    }
    Ok(0)
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum AdminRequest {
    Status,
    RemoteEnabled,
    LocalhostOnly,
    Provision {
        receipt: AllocationReceipt,
        admin_public_key: [u8; 32],
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdminResponse {
    status: Option<SurfaceStatus>,
    error: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayConfig {
    control_ca_pem_path: PathBuf,
    receipt_public_key_hex: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingCredentialIssue {
    installation_id: Uuid,
    operation_id: Uuid,
    token: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AllocationOperation {
    operation_id: Uuid,
}

impl Drop for PendingCredentialIssue {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IssuedCredentialState {
    installation_id: Uuid,
    generation: u64,
    expires_at_ms: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingAcmeBind {
    installation_id: Uuid,
    account_uri: String,
    operation_id: Uuid,
}

/// The Broker's independently owned handoff for relay renewal. The token is
/// deliberately kept in a different file so metadata can be logged safely.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerCredentialMetadata {
    version: u8,
    installation_id: Uuid,
    scope: Scope,
    generation: u64,
    expires_at_ms: u64,
    operation_id: Uuid,
}

pub(super) fn decode_fixed_32(value: &str) -> Result<[u8; 32], io::Error> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected 32-byte hexadecimal public key",
        ));
    }
    let bytes = hex::decode(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid public key"))?;
    bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid public key length"))
}

pub(super) async fn serve(
    listener: Option<UnixListener>,
    ceremony: Arc<SignerCeremonyService>,
    receipt_key: Option<[u8; 32]>,
    admin_peer_uid: u32,
    shutdown: &mut watch::Receiver<bool>,
) -> io::Result<()> {
    let Some(listener) = listener else {
        shutdown.changed().await.map_err(io::Error::other)?;
        return Ok(());
    };
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                changed.map_err(io::Error::other)?;
                return Ok(());
            }
            accepted = listener.accept() => {
                let (mut stream, _) = accepted?;
                if require_local_admin_peer(&stream, admin_peer_uid).is_err() {
                    continue;
                }
                // One bounded operation per connection; a slow root client
                // cannot hold the service event loop indefinitely.
                let result = timeout(Duration::from_secs(5), async {
                    let request: AdminRequest = read_frame(&mut stream).await?;
                    let result = execute(request, &ceremony, receipt_key);
                    let response = match result {
                        Ok(status) => AdminResponse { status: Some(status), error: None },
                        Err(error) => AdminResponse { status: None, error: Some(error) },
                    };
                    write_frame(&mut stream, &response).await
                }).await;
                if let Err(error) = result {
                    tracing::warn!(event = "signer.admin_timeout", %error);
                }
            }
        }
    }
}

fn execute(
    request: AdminRequest,
    ceremony: &SignerCeremonyService,
    receipt_key: Option<[u8; 32]>,
) -> Result<SurfaceStatus, String> {
    match request {
        AdminRequest::Status => ceremony.surface_status().map_err(|e| e.to_string()),
        AdminRequest::RemoteEnabled => ceremony
            .set_exposure_mode(ExposureMode::RemoteEnabled)
            .map_err(|e| e.to_string()),
        AdminRequest::LocalhostOnly => ceremony
            .set_exposure_mode(ExposureMode::LocalhostOnly)
            .map_err(|e| e.to_string()),
        AdminRequest::Provision {
            receipt,
            admin_public_key,
        } => {
            let receipt_key = receipt_key
                .ok_or("relay receipt public key is not pinned in Signer configuration")?;
            receipt.verify_bytes(&receipt_key, receipt.operation_id, &admin_public_key, now_ms())
                .map_err(|_| "relay allocation receipt failed signature, identity, or freshness verification")?;
            if matches!(
                receipt.allocation.state,
                bloom_relay_protocol::AllocationState::Retired
            ) {
                return Err("relay allocation is retired".into());
            }
            let admin_digest = Digest32::from_bytes(Sha256::digest(admin_public_key).into());
            ceremony
                .install_remote_surface(
                    &receipt.allocation.hostname,
                    &receipt.allocation.installation_id.to_string(),
                    admin_digest,
                    receipt.issued_at_ms,
                )
                .map_err(|e| e.to_string())
        }
    }
}

pub(super) async fn run_cli(cli: AdminCli) -> Result<(), Box<dyn std::error::Error>> {
    bloom_signer_process_hardening::harden_process()?;
    let (command, target) = match cli.command {
        AdminCommand::Status(target) => (AdminOperation::Status, target),
        AdminCommand::Provision(target) => (AdminOperation::Provision, target),
        AdminCommand::RemoteEnabled(target) => (AdminOperation::RemoteEnabled, target),
        AdminCommand::LocalhostOnly(target) => (AdminOperation::LocalhostOnly, target),
    };
    let context = resolve_admin_context(target, command == AdminOperation::Provision)?;
    if command == AdminOperation::Provision {
        let status = provision(&context).await?;
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }
    let request = match command {
        AdminOperation::Status => AdminRequest::Status,
        AdminOperation::RemoteEnabled => AdminRequest::RemoteEnabled,
        AdminOperation::LocalhostOnly => AdminRequest::LocalhostOnly,
        AdminOperation::Provision => unreachable!("provision returned above"),
    };
    let requested_mode = match &request {
        AdminRequest::RemoteEnabled => Some(ExposureMode::RemoteEnabled),
        AdminRequest::LocalhostOnly => Some(ExposureMode::LocalhostOnly),
        _ => None,
    };
    let response = request_once(&context.socket, context.signer_uid, &request).await?;
    let mut status = response
        .status
        .ok_or_else(|| response.error.unwrap_or("admin operation failed".into()))?;
    if let Some(mode) = requested_mode {
        // Broker reconciles the authenticated desired revision. A command
        // succeeds only after Signer observes the matching effective state.
        let until = tokio::time::Instant::now() + Duration::from_secs(30);
        while status.effective_mode != mode || status.effective_revision != status.desired_revision
        {
            if tokio::time::Instant::now() >= until {
                return Err(
                    "Broker has not confirmed the requested effective exposure mode; retry status"
                        .into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            let response =
                request_once(&context.socket, context.signer_uid, &AdminRequest::Status).await?;
            status = response
                .status
                .ok_or_else(|| response.error.unwrap_or("admin status failed".into()))?;
        }
    }
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AdminOperation {
    Status,
    Provision,
    RemoteEnabled,
    LocalhostOnly,
}

fn resolve_admin_context(
    target: AdminTarget,
    needs_provisioning: bool,
) -> Result<AdminContext, Box<dyn std::error::Error>> {
    match (target.login_uid, target.signer_uid) {
        (Some(login_uid), None) => installed_admin_context(login_uid),
        (None, Some(signer_uid)) => developer_admin_context(signer_uid, needs_provisioning),
        _ => Err("exactly one administration target is required".into()),
    }
}

fn installed_admin_context(login_uid: u32) -> Result<AdminContext, Box<dyn std::error::Error>> {
    if bloom_signer_process_hardening::effective_uid() != 0 {
        return Err("installed administration requires root (effective UID 0)".into());
    }
    #[cfg(target_os = "linux")]
    let context = installed_admin_context_at(
        login_uid,
        Path::new("/etc/bloom"),
        Path::new("/var/lib/bloom"),
        Path::new("/run/bloom"),
        InstalledPlatform::Linux,
    );
    #[cfg(target_os = "macos")]
    let context = installed_admin_context_at(
        login_uid,
        Path::new("/Library/Application Support/BloomTriad/config"),
        Path::new("/Library/Application Support/BloomTriad/config"),
        Path::new("/private/var/run/bloom"),
        InstalledPlatform::Macos,
    );
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let context = Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "installed administration supports Linux and macOS only",
    ));
    context.map_err(Into::into)
}

#[derive(Clone, Copy)]
// Each production target constructs one variant; tests exercise both layouts.
#[allow(dead_code)]
enum InstalledPlatform {
    Linux,
    Macos,
}

fn installed_admin_context_at(
    login_uid: u32,
    config_root: &Path,
    state_root: &Path,
    runtime_root: &Path,
    platform: InstalledPlatform,
) -> io::Result<AdminContext> {
    let uid = login_uid.to_string();
    let config = config_root.join(&uid);
    let signer = installed_principal(&config.join("signer"), "Signer")?;
    let broker = installed_principal(&config.join("broker"), "Broker")?;
    let signer_uid = signer.uid();
    let broker_uid = broker.uid();
    let broker_gid = broker.gid();
    if signer_uid == 0 || broker_uid == 0 || broker_gid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "installed Signer and Broker principals must be non-root",
        ));
    }
    let (admin_state, broker_relay, socket) = match platform {
        InstalledPlatform::Linux => (
            state_root.join(&uid).join("installer/admin"),
            state_root.join(&uid).join("broker/relay"),
            runtime_root.join(&uid).join("signer/admin/admin.sock"),
        ),
        InstalledPlatform::Macos => (
            config.join("installer/admin"),
            config.join("broker"),
            runtime_root.join(&uid).join("signer-admin/admin.sock"),
        ),
    };
    Ok(AdminContext {
        socket,
        signer_uid,
        admin_owner_uid: 0,
        provisioning: Some(ProvisionContext {
            admin_state,
            relay_config: config.join("relay.json"),
            tunnel_credential: broker_relay.join("relay-tunnel.credential"),
            dns_credential: broker_relay.join("relay-dns.credential"),
            acme_account_uri: broker_relay.join("acme-account-uri"),
            broker_uid,
            broker_gid,
        }),
    })
}

fn installed_principal(path: &Path, label: &str) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{label} enrollment is unavailable: {error}"),
        )
    })?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} enrollment must be a non-symlink directory"),
        ));
    }
    Ok(metadata)
}

fn developer_admin_context(
    signer_uid: u32,
    needs_provisioning: bool,
) -> Result<AdminContext, Box<dyn std::error::Error>> {
    fn path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        std::env::var_os(name)
            .map(PathBuf::from)
            .ok_or_else(|| format!("{name} is required for developer administration").into())
    }
    let admin_owner_uid = admin_owner_uid(signer_uid)?;
    if admin_owner_uid == 0 && bloom_signer_process_hardening::effective_uid() != 0 {
        return Err(
            "explicit --signer-uid administration requires root or the validated developer harness"
                .into(),
        );
    }
    let provisioning = if needs_provisioning {
        let broker_uid = std::env::var("BLOOM_SIGNER_BROKER_UID")?.parse::<u32>()?;
        let broker_gid = std::env::var("BLOOM_SIGNER_BROKER_GID")?.parse::<u32>()?;
        if broker_uid == 0 || broker_gid == 0 {
            return Err("developer Broker UID and GID must be nonzero".into());
        }
        Some(ProvisionContext {
            admin_state: path("BLOOM_SIGNER_ADMIN_STATE_DIR")?,
            relay_config: path("BLOOM_SIGNER_RELAY_CONFIG")?,
            tunnel_credential: path("BLOOM_SIGNER_TUNNEL_CREDENTIAL_PATH")?,
            dns_credential: path("BLOOM_SIGNER_DNS_CREDENTIAL_PATH")?,
            acme_account_uri: path("BLOOM_SIGNER_ACME_ACCOUNT_URI_PATH")?,
            broker_uid,
            broker_gid,
        })
    } else {
        None
    };
    Ok(AdminContext {
        socket: path("BLOOM_SIGNER_ADMIN_SOCKET")?,
        signer_uid,
        admin_owner_uid,
        provisioning,
    })
}

async fn provision(context: &AdminContext) -> Result<SurfaceStatus, Box<dyn std::error::Error>> {
    let provisioning = context
        .provisioning
        .as_ref()
        .ok_or("provisioning context is unavailable")?;
    let root = provisioning.admin_state.clone();
    let signer_uid = context.signer_uid;
    let admin_owner_uid = context.admin_owner_uid;
    let admin_key_existed = root.join(ADMIN_IDENTITY_FILE).exists();
    let config_bytes = read_admin_private_file(&provisioning.relay_config, admin_owner_uid)?;
    let config: RelayConfig = serde_json::from_slice(&config_bytes)?;
    let receipt_key = decode_fixed_32(&config.receipt_public_key_hex)?;
    let ca_pem = read_admin_private_file(&config.control_ca_pem_path, admin_owner_uid)?;
    let response = request_once(&context.socket, signer_uid, &AdminRequest::Status).await?;
    let mut status = response
        .status
        .ok_or_else(|| response.error.unwrap_or("admin status failed".into()))?;
    let key = prepare_admin_identity(&root, admin_owner_uid)?;
    let public_key = key.verifying_key().to_bytes();
    let allocation_path = root.join("allocation-operation.json");
    let installation_id = if allocation_path.exists() || !admin_key_existed {
        // Enrollment is an exact-retry operation. Retain its operation ID
        // across the later certificate/CAA readiness retries so a retry
        // cannot allocate a second hostname.
        let operation_id = allocation_operation(&root, admin_owner_uid, true)?;
        let receipt = enroll(
            EnrollmentConfig {
                control_ca_pem: ca_pem.clone(),
            },
            &public_key,
            &receipt_key,
            operation_id,
            |message| Ok(key.sign(message).to_bytes()),
        )?;
        // Assignment must be installed first: only then can Broker begin the
        // account/certificate worker that publishes its ACME URI.
        let response = request_once(
            &context.socket,
            signer_uid,
            &AdminRequest::Provision {
                receipt: receipt.clone(),
                admin_public_key: public_key,
            },
        )
        .await?;
        status = response.status.ok_or_else(|| {
            response
                .error
                .unwrap_or("Signer rejected relay assignment".into())
        })?;
        receipt.allocation.installation_id
    } else {
        // Builds predating allocation-operation.json may already have
        // installed an assignment. Recover only from Signer's authoritative
        // binding; an unassigned old key is ambiguous and must not allocate.
        let expected_digest = Digest32::from_bytes(Sha256::digest(public_key).into());
        if status.installation_admin_key_sha256.as_ref() != Some(&expected_digest) {
            return Err("existing admin identity lacks a matching Signer assignment; refusing a new relay allocation".into());
        }
        status
            .installation_id
            .as_deref()
            .ok_or(
                "existing admin identity has no Signer assignment; refusing a new relay allocation",
            )?
            .parse::<Uuid>()?
    };
    let broker_uid = provisioning.broker_uid;
    let broker_gid = provisioning.broker_gid;
    let tunnel_path = provisioning.tunnel_credential.clone();
    let broker_parent = require_private_broker_parent(&tunnel_path, broker_uid, broker_gid)?;
    install_broker_file(
        &root,
        &broker_parent.join("relay-control-ca.pem"),
        &ca_pem,
        broker_uid,
        broker_gid,
    )?;
    for (scope, destination, label) in [
        (Scope::Tunnel, &provisioning.tunnel_credential, "tunnel"),
        (Scope::DnsChallenge, &provisioning.dns_credential, "dns"),
    ] {
        ensure_scoped_credential(
            &root,
            destination,
            admin_owner_uid,
            broker_uid,
            broker_gid,
            installation_id,
            scope,
            label,
            &ca_pem,
            &key,
        )?;
    }
    let account_path = provisioning.acme_account_uri.clone();
    if account_path.parent() != tunnel_path.parent()
        || account_path.file_name().and_then(|name| name.to_str()) != Some("acme-account-uri")
    {
        return Err("ACME account URI must use Broker's enrolled credential directory".into());
    }
    let until = tokio::time::Instant::now() + Duration::from_secs(30);
    let account_uri = loop {
        match read_broker_acme_uri(&account_path, broker_uid, broker_gid) {
            Ok(uri) => break uri,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if tokio::time::Instant::now() >= until {
                    return Err("Broker ACME account URI is pending; retry provision after account creation".into());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => return Err(error.into()),
        }
    };
    let bind_path = root.join("acme-bind-pending.json");
    let pending = if bind_path.exists() {
        let pending: PendingAcmeBind =
            serde_json::from_slice(&read_admin_private_file(&bind_path, admin_owner_uid)?)?;
        if pending.installation_id != installation_id || pending.account_uri != account_uri {
            return Err("ACME account changed; ordinary provisioning refuses rebinding".into());
        }
        pending
    } else {
        let pending = PendingAcmeBind {
            installation_id,
            account_uri: account_uri.clone(),
            operation_id: Uuid::new_v4(),
        };
        write_root_state(&root, &bind_path, &pending)?;
        pending
    };
    let bound_path = root.join("acme-account-bound.json");
    if bound_path.exists() {
        let bound: PendingAcmeBind =
            serde_json::from_slice(&read_admin_private_file(&bound_path, admin_owner_uid)?)?;
        if bound.installation_id != pending.installation_id
            || bound.account_uri != pending.account_uri
        {
            return Err("ACME account changed; ordinary provisioning refuses rebinding".into());
        }
    }
    register_acme_account(
        EnrollmentConfig {
            control_ca_pem: ca_pem,
        },
        pending.installation_id,
        pending.account_uri.clone(),
        pending.operation_id,
        |message| Ok(key.sign(message).to_bytes()),
    )?;
    // Retain the bound URI durably. A later provision may repeat the same
    // idempotent operation; a different URI requires explicit admin handling.
    if !bound_path.exists() {
        write_root_state(&root, &bound_path, &pending)?;
    }
    fs::remove_file(&bind_path)?;
    if status.desired_mode == ExposureMode::RemoteEnabled {
        let until = tokio::time::Instant::now() + Duration::from_secs(30);
        while status.effective_mode != ExposureMode::RemoteEnabled
            || status.effective_revision != status.desired_revision
        {
            if tokio::time::Instant::now() >= until {
                return Err(
                    "remote certificate and routing are pending; retry status or provision".into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            let response = request_once(&context.socket, signer_uid, &AdminRequest::Status).await?;
            status = response
                .status
                .ok_or_else(|| response.error.unwrap_or("admin status failed".into()))?;
        }
    }
    Ok(status)
}

fn read_broker_acme_uri(path: &Path, uid: u32, gid: u32) -> io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > 256
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Broker ACME account file is not owner-private",
        ));
    }
    use std::io::Read as _;
    let mut bytes = Vec::new();
    file.take(257).read_to_end(&mut bytes)?;
    let uri = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
    let prefix = "https://acme-v02.api.letsencrypt.org/acme/acct/";
    let suffix = uri.strip_prefix(prefix).ok_or(io::Error::new(
        io::ErrorKind::InvalidData,
        "ACME URI must name Let's Encrypt production",
    ))?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ACME account URI has invalid account number",
        ));
    }
    Ok(uri.to_owned())
}

#[allow(clippy::too_many_arguments)]
fn ensure_scoped_credential(
    root: &Path,
    destination: &Path,
    admin_owner_uid: u32,
    broker_uid: u32,
    broker_gid: u32,
    installation_id: Uuid,
    scope: Scope,
    label: &str,
    ca_pem: &[u8],
    key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    require_private_broker_parent(destination, broker_uid, broker_gid)?;
    let state_path = root.join(format!("{label}-credential-state.json"));
    let metadata_path = destination.with_file_name(format!("relay-{label}.metadata.json"));
    let installed = if state_path.exists() && destination.exists() && metadata_path.exists() {
        let state: IssuedCredentialState =
            serde_json::from_slice(&read_admin_private_file(&state_path, admin_owner_uid)?)?;
        let token = fs::symlink_metadata(destination)?;
        let handoff = fs::symlink_metadata(&metadata_path)?;
        let handoff_state = if handoff.len() <= 512 {
            fs::read(&metadata_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<BrokerCredentialMetadata>(&bytes).ok())
        } else {
            None
        };
        token.file_type().is_file()
            && token.uid() == broker_uid
            && token.gid() == broker_gid
            && token.mode() & 0o077 == 0
            && token.nlink() == 1
            && handoff.file_type().is_file()
            && handoff.uid() == broker_uid
            && handoff.gid() == broker_gid
            && handoff.mode() & 0o077 == 0
            && handoff.nlink() == 1
            && state.installation_id == installation_id
            && handoff_state.is_some_and(|metadata| {
                metadata.version == 1
                    && metadata.installation_id == installation_id
                    && metadata.scope == scope
                    && metadata.generation >= state.generation
                    && now_ms().saturating_add(60 * 60 * 1_000) < metadata.expires_at_ms
            })
    } else {
        false
    };
    if installed {
        return Ok(());
    }

    let pending_path = root.join(format!("{label}-credential-pending.json"));
    let pending = if pending_path.exists() {
        let bytes = Zeroizing::new(read_admin_private_file(&pending_path, admin_owner_uid)?);
        let pending: PendingCredentialIssue = serde_json::from_slice(&bytes)?;
        if pending.installation_id != installation_id {
            return Err("pending relay credential belongs to another installation".into());
        }
        pending
    } else {
        let token = SecretToken::generate();
        let pending = PendingCredentialIssue {
            installation_id,
            operation_id: Uuid::new_v4(),
            token: token.expose().to_owned(),
        };
        write_root_state(root, &pending_path, &pending)?;
        pending
    };
    let token = SecretToken::from_encoded(pending.token.clone())?;
    let receipt = issue_credential(
        EnrollmentConfig {
            control_ca_pem: ca_pem.to_vec(),
        },
        installation_id,
        scope,
        &token,
        pending.operation_id,
        |message| Ok(key.sign(message).to_bytes()),
    )?;
    install_broker_file(
        root,
        destination,
        token.expose().as_bytes(),
        broker_uid,
        broker_gid,
    )?;
    let handoff = BrokerCredentialMetadata {
        version: 1,
        installation_id,
        scope,
        generation: receipt.generation,
        expires_at_ms: receipt.expires_at_ms,
        operation_id: pending.operation_id,
    };
    let metadata_bytes = serde_json::to_vec(&handoff)?;
    install_broker_file(
        root,
        &metadata_path,
        &metadata_bytes,
        broker_uid,
        broker_gid,
    )?;
    let state = IssuedCredentialState {
        installation_id,
        generation: receipt.generation,
        expires_at_ms: receipt.expires_at_ms,
    };
    write_root_state(root, &state_path, &state)?;
    fs::remove_file(pending_path)?;
    Ok(())
}

fn require_private_broker_parent(
    destination: &Path,
    broker_uid: u32,
    broker_gid: u32,
) -> Result<&Path, Box<dyn std::error::Error>> {
    let parent = destination
        .parent()
        .ok_or("Broker destination has no parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != broker_uid
        || metadata.gid() != broker_gid
        || metadata.mode() & 0o077 != 0
    {
        return Err(
            "Broker credential directory must be Broker-owned, private, and not a symlink".into(),
        );
    }
    Ok(parent)
}

fn write_root_state<T: Serialize>(root: &Path, destination: &Path, value: &T) -> io::Result<()> {
    let stage = root.join(format!(".stage-{}", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stage)?;
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(io::Error::other)?);
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&stage, destination)?;
    fs::File::open(root)?.sync_all()
}

fn allocation_operation(root: &Path, owner_uid: u32, allow_create: bool) -> io::Result<Uuid> {
    let path = root.join("allocation-operation.json");
    if path.exists() {
        let state: AllocationOperation =
            serde_json::from_slice(&read_admin_private_file(&path, owner_uid)?)
                .map_err(io::Error::other)?;
        return Ok(state.operation_id);
    }
    if !allow_create {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "existing administrator has no durable relay allocation operation",
        ));
    }
    let state = AllocationOperation {
        operation_id: Uuid::new_v4(),
    };
    write_root_state(root, &path, &state)?;
    Ok(state.operation_id)
}

fn install_broker_file(
    root: &Path,
    destination: &Path,
    contents: &[u8],
    broker_uid: u32,
    broker_gid: u32,
) -> io::Result<()> {
    let stage = root.join(format!(".broker-file-{}", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stage)?;
    file.write_all(contents)?;
    bloom_signer_process_hardening::set_open_file_owner(&file, broker_uid, broker_gid)?;
    file.sync_all()?;
    fs::rename(&stage, destination)?;
    fs::File::open(
        destination
            .parent()
            .ok_or(io::Error::other("credential has no parent"))?,
    )?
    .sync_all()
}

fn load_or_create_admin_key(root: &Path, owner_uid: u32) -> io::Result<SigningKey> {
    if !root.exists() {
        fs::create_dir(root)?;
        fs::set_permissions(root, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    }
    require_admin_private(root, true, owner_uid)?;
    let path = root.join(ADMIN_IDENTITY_FILE);
    if !path.exists() {
        let mut seed = Zeroizing::new([0_u8; 32]);
        SysRng
            .try_fill_bytes(&mut *seed)
            .map_err(io::Error::other)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(hex::encode(*seed).as_bytes())?;
        file.sync_all()?;
        fs::File::open(root)?.sync_all()?;
    }
    let seed = Zeroizing::new(read_admin_private_file(&path, owner_uid)?);
    let text = std::str::from_utf8(&seed).map_err(io::Error::other)?;
    let bytes = Zeroizing::new(decode_fixed_32(text)?);
    Ok(SigningKey::from_bytes(&bytes))
}

fn prepare_admin_identity(root: &Path, owner_uid: u32) -> io::Result<SigningKey> {
    if !root.exists() {
        fs::create_dir(root)?;
        fs::set_permissions(root, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    }
    require_admin_private(root, true, owner_uid)?;
    if !root.join(ADMIN_IDENTITY_FILE).exists() {
        // Persist the retry identity before creating the administration key.
        // A crash at either step must never strand a new key without its
        // allocation operation, or allocate a second hostname on retry.
        allocation_operation(root, owner_uid, true)?;
    }
    load_or_create_admin_key(root, owner_uid)
}

fn read_admin_private_file(path: &Path, owner_uid: u32) -> io::Result<Vec<u8>> {
    require_admin_private(path, false, owner_uid)?;
    let bytes = fs::read(path)?;
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "admin file exceeds size limit",
        ));
    }
    Ok(bytes)
}

fn require_admin_private(path: &Path, directory: bool, owner_uid: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != owner_uid
        || metadata.mode() & 0o077 != 0
        || if directory {
            !metadata.file_type().is_dir()
        } else {
            !metadata.file_type().is_file()
        }
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "admin state and relay pins must be expected-owner non-symlinks with private permissions",
        ));
    }
    Ok(())
}

async fn request_once(
    path: &Path,
    signer_uid: u32,
    request: &AdminRequest,
) -> io::Result<AdminResponse> {
    let mut stream = UnixStream::connect(path).await?;
    require_local_admin_peer(&stream, signer_uid)?;
    timeout(Duration::from_secs(5), async {
        write_frame(&mut stream, request).await?;
        read_frame(&mut stream).await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Signer admin response timed out"))?
}

async fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> io::Result<T> {
    let count = stream.read_u32().await? as usize;
    if count == 0 || count > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "admin frame length is invalid",
        ));
    }
    let mut frame = vec![0; count];
    stream.read_exact(&mut frame).await?;
    serde_json::from_slice(&frame).map_err(io::Error::other)
}

async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> io::Result<()> {
    let frame = serde_json::to_vec(value).map_err(io::Error::other)?;
    if frame.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "admin frame exceeds size limit",
        ));
    }
    stream.write_u32(frame.len() as u32).await?;
    stream.write_all(&frame).await
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn missing_relay_configuration_does_not_create_admin_identity() {
        let root = tempfile::tempdir().unwrap();
        let uid = bloom_signer_process_hardening::effective_uid();
        let context = AdminContext {
            socket: root.path().join("absent.sock"),
            signer_uid: uid,
            admin_owner_uid: uid,
            provisioning: Some(ProvisionContext {
                admin_state: root.path().join("admin"),
                relay_config: root.path().join("missing.json"),
                tunnel_credential: root.path().join("tunnel"),
                dns_credential: root.path().join("dns"),
                acme_account_uri: root.path().join("acme"),
                broker_uid: uid,
                broker_gid: fs::metadata(root.path()).unwrap().gid(),
            }),
        };
        assert!(provision(&context).await.is_err());
        assert!(!root.path().join("admin").exists());
    }

    #[test]
    fn new_admin_identity_has_durable_operation_before_retry() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = bloom_signer_process_hardening::effective_uid();
        let operation = super::allocation_operation(root.path(), uid, true).unwrap();
        // Models interruption after the operation is committed, before key creation.
        let first = super::prepare_admin_identity(root.path(), uid).unwrap();
        let retry = super::prepare_admin_identity(root.path(), uid).unwrap();
        assert_eq!(first.verifying_key(), retry.verifying_key());
        assert_eq!(
            super::allocation_operation(root.path(), uid, false).unwrap(),
            operation
        );
    }
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    #[test]
    fn installed_layout_derives_fixed_linux_and_macos_paths() {
        let root = tempfile::tempdir().unwrap();
        let config_root = root.path().join("config");
        let state_root = root.path().join("state");
        let runtime_root = root.path().join("run");
        let signer = config_root.join("501/signer");
        let broker = config_root.join("501/broker");
        fs::create_dir_all(&signer).unwrap();
        fs::create_dir_all(&broker).unwrap();
        if bloom_signer_process_hardening::effective_uid() == 0 {
            for path in [&signer, &broker] {
                let directory = fs::File::open(path).unwrap();
                bloom_signer_process_hardening::set_open_file_owner(&directory, 501, 501).unwrap();
            }
        }

        let linux = installed_admin_context_at(
            501,
            &config_root,
            &state_root,
            &runtime_root,
            InstalledPlatform::Linux,
        )
        .unwrap();
        let linux_provisioning = linux.provisioning.unwrap();
        assert_eq!(
            linux_provisioning.relay_config,
            config_root.join("501/relay.json")
        );
        assert_eq!(
            linux_provisioning.admin_state,
            state_root.join("501/installer/admin")
        );
        assert_eq!(
            linux_provisioning.tunnel_credential,
            state_root.join("501/broker/relay/relay-tunnel.credential")
        );
        assert_eq!(
            linux.socket,
            runtime_root.join("501/signer/admin/admin.sock")
        );

        let macos = installed_admin_context_at(
            501,
            &config_root,
            &state_root,
            &runtime_root,
            InstalledPlatform::Macos,
        )
        .unwrap();
        let macos_provisioning = macos.provisioning.unwrap();
        assert_eq!(
            macos_provisioning.admin_state,
            config_root.join("501/installer/admin")
        );
        assert_eq!(
            macos_provisioning.tunnel_credential,
            config_root.join("501/broker/relay-tunnel.credential")
        );
        assert_eq!(
            macos.socket,
            runtime_root.join("501/signer-admin/admin.sock")
        );
    }

    #[test]
    fn installed_principal_rejects_symlinks_and_files() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("directory");
        fs::create_dir(&directory).unwrap();
        assert!(installed_principal(&directory, "Signer").is_ok());

        let link = root.path().join("link");
        symlink(&directory, &link).unwrap();
        assert!(installed_principal(&link, "Signer").is_err());

        let file = root.path().join("file");
        fs::write(&file, b"not a principal directory").unwrap();
        assert!(installed_principal(&file, "Signer").is_err());
    }

    #[test]
    fn broker_acme_uri_handoff_checks_owner_mode_link_and_production_uri() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme-account-uri");
        fs::write(
            &path,
            b"https://acme-v02.api.letsencrypt.org/acme/acct/12345",
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let owner = fs::metadata(&path).unwrap();
        let uid = owner.uid();
        let gid = owner.gid();
        assert!(read_broker_acme_uri(&path, uid, gid).is_ok());
        assert!(read_broker_acme_uri(&path, uid.saturating_add(1), gid).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_broker_acme_uri(&path, uid, gid).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let hardlink = dir.path().join("second-name");
        fs::hard_link(&path, &hardlink).unwrap();
        assert!(read_broker_acme_uri(&path, uid, gid).is_err());
        fs::remove_file(hardlink).unwrap();
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_broker_acme_uri(&link, uid, gid).is_err());
        fs::write(
            &path,
            b"https://acme-staging-v02.api.letsencrypt.org/acme/acct/12345",
        )
        .unwrap();
        assert!(read_broker_acme_uri(&path, uid, gid).is_err());
    }

    #[test]
    fn broker_public_ca_handoff_is_atomic_private_and_owner_checked() {
        let root = tempfile::tempdir().unwrap();
        let broker = tempfile::tempdir().unwrap();
        fs::set_permissions(broker.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::metadata(broker.path()).unwrap();
        let destination = broker.path().join("relay-control-ca.pem");
        require_private_broker_parent(&destination, owner.uid(), owner.gid()).unwrap();
        install_broker_file(
            root.path(),
            &destination,
            b"public pinned CA",
            owner.uid(),
            owner.gid(),
        )
        .unwrap();
        let published = fs::symlink_metadata(&destination).unwrap();
        assert!(published.file_type().is_file());
        assert_eq!(published.uid(), owner.uid());
        assert_eq!(published.gid(), owner.gid());
        assert_eq!(published.mode() & 0o777, 0o600);
        assert_eq!(fs::read(&destination).unwrap(), b"public pinned CA");
        fs::set_permissions(broker.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(require_private_broker_parent(&destination, owner.uid(), owner.gid()).is_err());
    }

    #[test]
    fn allocation_enrollment_reuses_operation_across_retry_and_restart() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(root.path()).unwrap().uid();
        let first = allocation_operation(root.path(), uid, true).unwrap();
        let retry = allocation_operation(root.path(), uid, false).unwrap();
        assert_eq!(retry, first);
        let state = root.path().join("allocation-operation.json");
        let metadata = fs::symlink_metadata(state).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), uid);
    }

    #[test]
    fn malformed_allocation_operation_fails_without_replacing_state() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(root.path()).unwrap().uid();
        let path = root.path().join("allocation-operation.json");
        let malformed = b"{\"operation_id\":\"not-a-uuid\"}";
        fs::write(&path, malformed).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(allocation_operation(root.path(), uid, true).is_err());
        assert_eq!(fs::read(path).unwrap(), malformed);
    }

    #[test]
    fn existing_administrator_cannot_create_missing_allocation_operation() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(root.path()).unwrap().uid();
        assert!(allocation_operation(root.path(), uid, false).is_err());
        assert!(!root.path().join("allocation-operation.json").exists());
    }
}
