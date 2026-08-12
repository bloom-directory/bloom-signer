//! Administrative staging utility for one-time legacy passkey conversion.

#![forbid(unsafe_code)]

use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _, path::PathBuf, process::ExitCode};

use bloom_signer::legacy_passkey::stage_legacy_wallet;
use serde::Deserialize;

#[derive(Deserialize)]
struct ConfigPath {
    database_path: PathBuf,
}

struct StageArgs {
    source: PathBuf,
    migration_root: PathBuf,
    source_uid: u32,
    signer_uid: u32,
    signer_gid: u32,
    receipt: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("bloom-signer-migrate: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut version_probe = std::env::args_os().skip(1);
    if version_probe.next().as_deref() == Some(std::ffi::OsStr::new("--version"))
        && version_probe.next().is_none()
    {
        println!("bloom-signer-migrate {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let args = parse_args()?;
    let receipt = stage_legacy_wallet(
        &args.source,
        &args.migration_root,
        args.source_uid,
        args.signer_uid,
        args.signer_gid,
    )?;
    let encoded = serde_json::to_vec_pretty(&receipt)?;
    if let Some(path) = args.receipt {
        if path.exists() {
            return Err("migration receipt already exists".into());
        }
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".legacy-migration-receipt-{}", std::process::id()));
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        output.write_all(&encoded)?;
        output.sync_all()?;
        std::fs::rename(temporary, path)?;
    } else {
        println!("{}", std::str::from_utf8(&encoded)?);
    }
    Ok(())
}

fn parse_args() -> Result<StageArgs, Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("stage")) {
        return Err(usage().into());
    }
    let mut source = None;
    let mut migration_root = None;
    let mut config = None;
    let mut source_uid = None;
    let mut signer_uid = None;
    let mut signer_gid = None;
    let mut receipt = None;
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{} requires a value", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--source") => source = Some(PathBuf::from(value)),
            Some("--migration-root") => migration_root = Some(PathBuf::from(value)),
            Some("--config") => config = Some(PathBuf::from(value)),
            Some("--source-uid") => source_uid = Some(parse_uid(value, "--source-uid")?),
            Some("--signer-uid") => signer_uid = Some(parse_uid(value, "--signer-uid")?),
            Some("--signer-gid") => signer_gid = Some(parse_uid(value, "--signer-gid")?),
            Some("--receipt") => receipt = Some(PathBuf::from(value)),
            _ => return Err(usage().into()),
        }
    }
    if migration_root.is_some() && config.is_some() {
        return Err("--config and --migration-root are mutually exclusive".into());
    }
    let migration_root = match migration_root {
        Some(path) => path,
        None => {
            let config = config
                .or_else(|| std::env::var_os("BLOOM_SIGNER_CONFIG").map(PathBuf::from))
                .ok_or("--config or --migration-root is required")?;
            let config: ConfigPath = serde_json::from_slice(&std::fs::read(config)?)?;
            config
                .database_path
                .parent()
                .ok_or("Signer database path has no parent")?
                .join("legacy-passkey-migrations")
        }
    };
    Ok(StageArgs {
        source: source.ok_or("--source is required")?,
        migration_root,
        source_uid: source_uid.ok_or("--source-uid is required")?,
        signer_uid: signer_uid.ok_or("--signer-uid is required")?,
        signer_gid: signer_gid.ok_or("--signer-gid is required")?,
        receipt,
    })
}

fn parse_uid(value: std::ffi::OsString, name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(value
        .to_str()
        .ok_or_else(|| format!("{name} must be UTF-8"))?
        .parse::<u32>()?)
}

fn usage() -> &'static str {
    "usage: bloom-signer-migrate stage --source PATH (--migration-root PATH | --config PATH) \
     --source-uid UID --signer-uid UID --signer-gid GID [--receipt PATH]"
}
