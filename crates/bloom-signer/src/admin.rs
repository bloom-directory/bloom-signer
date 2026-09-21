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

pub(super) async fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    bloom_signer_process_hardening::harden_process()?;
    let mut args = std::env::args().skip(2);
    let command = args.next().ok_or("expected admin command")?;
    if args.next().as_deref() != Some("--signer-uid") {
        return Err("expected --signer-uid UID".into());
    }
    let signer_uid: u32 = args.next().ok_or("missing Signer UID")?.parse()?;
    if args.next().is_some() {
        return Err("unexpected admin argument".into());
    }
    let socket = std::env::var_os("BLOOM_SIGNER_ADMIN_SOCKET")
        .map(PathBuf::from)
        .ok_or("BLOOM_SIGNER_ADMIN_SOCKET is required")?;
    let admin_owner_uid = admin_owner_uid(signer_uid)?;
    if command == "provision" {
        let status = provision(&socket, signer_uid, admin_owner_uid).await?;
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }
    let request = match command.as_str() {
        "status" => AdminRequest::Status,
        "remote-enabled" => AdminRequest::RemoteEnabled,
        "localhost-only" => AdminRequest::LocalhostOnly,
        _ => return Err("unknown admin command".into()),
    };
    let requested_mode = match &request {
        AdminRequest::RemoteEnabled => Some(ExposureMode::RemoteEnabled),
        AdminRequest::LocalhostOnly => Some(ExposureMode::LocalhostOnly),
        _ => None,
    };
    let response = request_once(&socket, signer_uid, &request).await?;
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
            let response = request_once(&socket, signer_uid, &AdminRequest::Status).await?;
            status = response
                .status
                .ok_or_else(|| response.error.unwrap_or("admin status failed".into()))?;
        }
    }
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

async fn provision(
    socket: &Path,
    signer_uid: u32,
    admin_owner_uid: u32,
) -> Result<SurfaceStatus, Box<dyn std::error::Error>> {
    let root = std::env::var_os("BLOOM_SIGNER_ADMIN_STATE_DIR")
        .map(PathBuf::from)
        .ok_or("BLOOM_SIGNER_ADMIN_STATE_DIR is required")?;
    let admin_key_existed = root.join(ADMIN_IDENTITY_FILE).exists();
    let key = load_or_create_admin_key(&root, admin_owner_uid)?;
    let config_path = std::env::var_os("BLOOM_SIGNER_RELAY_CONFIG")
        .map(PathBuf::from)
        .ok_or("BLOOM_SIGNER_RELAY_CONFIG is required")?;
    let config_bytes = read_admin_private_file(&config_path, admin_owner_uid)?;
    let config: RelayConfig = serde_json::from_slice(&config_bytes)?;
    let receipt_key = decode_fixed_32(&config.receipt_public_key_hex)?;
    let ca_pem = read_admin_private_file(&config.control_ca_pem_path, admin_owner_uid)?;
    let public_key = key.verifying_key().to_bytes();
    let response = request_once(socket, signer_uid, &AdminRequest::Status).await?;
    let mut status = response
        .status
        .ok_or_else(|| response.error.unwrap_or("admin status failed".into()))?;
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
            socket,
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
    let broker_uid: u32 = std::env::var("BLOOM_SIGNER_BROKER_UID")
        .map_err(|_| "BLOOM_SIGNER_BROKER_UID is required")?
        .parse()?;
    let broker_gid: u32 = std::env::var("BLOOM_SIGNER_BROKER_GID")
        .map_err(|_| "BLOOM_SIGNER_BROKER_GID is required")?
        .parse()?;
    let tunnel_path = std::env::var_os("BLOOM_SIGNER_TUNNEL_CREDENTIAL_PATH")
        .map(PathBuf::from)
        .ok_or("BLOOM_SIGNER_TUNNEL_CREDENTIAL_PATH is required")?;
    let broker_parent = require_private_broker_parent(&tunnel_path, broker_uid, broker_gid)?;
    install_broker_file(
        &root,
        &broker_parent.join("relay-control-ca.pem"),
        &ca_pem,
        broker_uid,
        broker_gid,
    )?;
    for (scope, variable, label) in [
        (
            Scope::Tunnel,
            "BLOOM_SIGNER_TUNNEL_CREDENTIAL_PATH",
            "tunnel",
        ),
        (
            Scope::DnsChallenge,
            "BLOOM_SIGNER_DNS_CREDENTIAL_PATH",
            "dns",
        ),
    ] {
        let destination = if scope == Scope::Tunnel {
            tunnel_path.clone()
        } else {
            std::env::var_os(variable)
                .map(PathBuf::from)
                .ok_or_else(|| format!("{variable} is required"))?
        };
        ensure_scoped_credential(
            &root,
            &destination,
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
    let account_path = std::env::var_os("BLOOM_SIGNER_ACME_ACCOUNT_URI_PATH")
        .map(PathBuf::from)
        .ok_or("BLOOM_SIGNER_ACME_ACCOUNT_URI_PATH is required")?;
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
            let response = request_once(socket, signer_uid, &AdminRequest::Status).await?;
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
    }
    let seed = Zeroizing::new(read_admin_private_file(&path, owner_uid)?);
    let text = std::str::from_utf8(&seed).map_err(io::Error::other)?;
    let bytes = Zeroizing::new(decode_fixed_32(text)?);
    Ok(SigningKey::from_bytes(&bytes))
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
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

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
