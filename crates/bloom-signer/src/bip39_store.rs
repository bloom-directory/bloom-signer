//! SQLite custody storage for the `bip39-multicurve-v1` wallet profile.
//!
//! The new profile persists exclusively in the Signer's SQLite authority —
//! never in the legacy backend-local JSON. The only persisted root secret
//! is the WKEK-wrapped BIP-39 entropy plus profile metadata; the mnemonic
//! phrase, PBKDF2 seed, XPrvs, derived private keys, and any second copy of
//! the entropy are deliberately unrepresentable in this schema. Custody
//! owns wrap/unwrap; this module persists the resulting blobs atomically.
//!
//! Every mutating function composes into a caller-supplied transaction so
//! root, wraps, registry, counters, tombstones, and the audit event commit
//! together. No function here performs I/O outside the database.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use bloom_signer_api::{Digest32, ProtocolError, ProtocolErrorCode, Token};

use crate::engine::storage;


pub const ROOT_PROFILE_BIP39_MULTICURVE_V1: &str = "bip39-multicurve-v1";
pub const WRAP_KIND_CREDENTIAL: &str = "credential";
pub const WRAP_KIND_RECOVERY: &str = "recovery";

/// WAL + explicit durability for the file-backed database. In-memory
/// connections (tests) skip journal configuration, which is a no-op there.
pub fn configure_durability(connection: &Connection) -> Result<(), ProtocolError> {
    // Journal configuration is meaningful only for file-backed databases;
    // in-memory connections (tests) keep their default journal.
    let file_backed = connection.path().is_some_and(|path| !path.is_empty());
    if file_backed {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(storage)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(storage)?;
    }
    connection
        .pragma_update(None, "busy_timeout", 5_000)
        .map_err(storage)?;
    Ok(())
}

pub fn migrate(connection: &Connection) -> Result<(), ProtocolError> {
    connection
        .execute_batch(
            "
            CREATE TABLE IF NOT EXISTS wallet_roots (
                wallet_id TEXT PRIMARY KEY,
                profile TEXT NOT NULL CHECK (profile = 'bip39-multicurve-v1'),
                profile_version INTEGER NOT NULL CHECK (profile_version >= 1),
                entropy_bits INTEGER NOT NULL CHECK (entropy_bits IN (128, 160, 192, 224, 256)),
                language TEXT NOT NULL CHECK (language = 'english'),
                wrap_format_version INTEGER NOT NULL CHECK (wrap_format_version >= 1),
                entropy_nonce TEXT NOT NULL,
                entropy_ciphertext BLOB NOT NULL CHECK (length(entropy_ciphertext) > 16),
                root_ciphertext_fingerprint TEXT NOT NULL,
                snapshot_epoch INTEGER NOT NULL CHECK (snapshot_epoch >= 1),
                revision INTEGER NOT NULL CHECK (revision >= 1),
                created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
            );
            CREATE TABLE IF NOT EXISTS wallet_root_wraps (
                wrap_id TEXT NOT NULL,
                wallet_id TEXT NOT NULL REFERENCES wallet_roots(wallet_id),
                wrap_kind TEXT NOT NULL CHECK (wrap_kind IN ('credential', 'recovery')),
                active INTEGER NOT NULL CHECK (active IN (0, 1)),
                wrap_format_version INTEGER NOT NULL CHECK (wrap_format_version >= 1),
                wkek_nonce TEXT NOT NULL,
                wkek_ciphertext BLOB NOT NULL CHECK (length(wkek_ciphertext) > 16),
                snapshot_epoch INTEGER NOT NULL CHECK (snapshot_epoch >= 1),
                created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
                PRIMARY KEY (wallet_id, wrap_id)
            );
            ",
        )
        .map_err(storage)?;
    Ok(())
}

/// A WKEK-wrapped blob as persisted (AEAD nonce + ciphertext).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WrappedBlob {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl WrappedBlob {
    /// SHA-256 over nonce || ciphertext — integrity bookkeeping for the
    /// stored root, checked on every load.
    pub fn fingerprint(&self) -> Digest32 {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.nonce);
        hasher.update(&self.ciphertext);
        Digest32::from_bytes(hasher.finalize().into())
    }
}

/// A new wallet root to persist exactly once.
pub struct NewWalletRoot {
    pub wallet_id: Token,
    pub profile_version: u32,
    pub entropy_bits: usize,
    pub language: &'static str,
    pub wrap_format_version: u32,
    pub wrapped_entropy: WrappedBlob,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletRootRecord {
    pub wallet_id: Token,
    pub profile: &'static str,
    pub profile_version: u32,
    pub entropy_bits: usize,
    pub language: &'static str,
    pub wrap_format_version: u32,
    pub wrapped_entropy: WrappedBlob,
    pub root_ciphertext_fingerprint: Digest32,
    pub snapshot_epoch: u64,
    pub revision: u64,
}

pub struct WrapRecord {
    pub wrap_id: String,
    pub wallet_id: Token,
    pub wrap_kind: &'static str,
    pub active: bool,
    pub wrap_format_version: u32,
    pub wrapped_wkek: WrappedBlob,
    pub snapshot_epoch: u64,
    pub created_at_ms: u64,
}

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::MalformedFrame, message)
}

/// Persist a new wallet root. Fails closed on duplicate wallet ids.
pub fn insert_root(
    transaction: &Transaction<'_>,
    root: &NewWalletRoot,
) -> Result<(), ProtocolError> {
    if root.profile_version < 1
        || root.wrap_format_version < 1
        || root.language != "english"
        || !matches!(root.entropy_bits, 128 | 160 | 192 | 224 | 256)
    {
        return Err(invalid("wallet root profile metadata is invalid"));
    }
    let fingerprint = root.wrapped_entropy.fingerprint();
    transaction
        .execute(
            "INSERT INTO wallet_roots (
                wallet_id, profile, profile_version, entropy_bits, language,
                wrap_format_version, entropy_nonce, entropy_ciphertext,
                root_ciphertext_fingerprint, snapshot_epoch, revision, created_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, 1, ?10)",
            rusqlite::params![
                root.wallet_id.as_str(),
                ROOT_PROFILE_BIP39_MULTICURVE_V1,
                root.profile_version as i64,
                root.entropy_bits as i64,
                root.language,
                root.wrap_format_version as i64,
                root.wrapped_entropy.nonce,
                root.wrapped_entropy.ciphertext,
                fingerprint.as_str(),
                root.created_at_ms as i64,
            ],
        )
        .map_err(storage)?;
    Ok(())
}

pub fn load_root(
    connection: &Connection,
    wallet_id: &Token,
) -> Result<Option<WalletRootRecord>, ProtocolError> {
    struct Row {
        profile_version: i64,
        entropy_bits: i64,
        language: String,
        wrap_format_version: i64,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        stored_fingerprint: String,
        snapshot_epoch: i64,
        revision: i64,
    }
    let row = connection
        .query_row(
            "SELECT profile_version, entropy_bits, language, wrap_format_version,
                    entropy_nonce, entropy_ciphertext, root_ciphertext_fingerprint,
                    snapshot_epoch, revision
             FROM wallet_roots WHERE wallet_id = ?1",
            [wallet_id.as_str()],
            |row| {
                Ok(Row {
                    profile_version: row.get(0)?,
                    entropy_bits: row.get(1)?,
                    language: row.get(2)?,
                    wrap_format_version: row.get(3)?,
                    nonce: row.get(4)?,
                    ciphertext: row.get(5)?,
                    stored_fingerprint: row.get(6)?,
                    snapshot_epoch: row.get(7)?,
                    revision: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.language != "english" {
        return Err(invalid("stored wallet root language is unsupported"));
    }
    let wrapped_entropy = WrappedBlob {
        nonce: row.nonce,
        ciphertext: row.ciphertext,
    };
    let root_ciphertext_fingerprint = Digest32::new(&row.stored_fingerprint)
        .map_err(|_| invalid("stored root fingerprint is malformed"))?;
    if wrapped_entropy.fingerprint() != root_ciphertext_fingerprint {
        return Err(invalid(
            "wallet root ciphertext fingerprint does not match stored bytes",
        ));
    }
    Ok(Some(WalletRootRecord {
        wallet_id: wallet_id.clone(),
        profile: ROOT_PROFILE_BIP39_MULTICURVE_V1,
        profile_version: row.profile_version as u32,
        entropy_bits: row.entropy_bits as usize,
        language: "english",
        wrap_format_version: row.wrap_format_version as u32,
        wrapped_entropy,
        root_ciphertext_fingerprint,
        snapshot_epoch: row.snapshot_epoch as u64,
        revision: row.revision as u64,
    }))
}

/// Replace the wrapped entropy (WKEK rekey) under compare-and-set on the
/// root revision, bumping snapshot epoch and revision atomically. The
/// caller composes wrap replacement into the same transaction.
pub fn replace_wrapped_entropy(
    transaction: &Transaction<'_>,
    wallet_id: &Token,
    replacement: &WrappedBlob,
    expected_revision: u64,
) -> Result<(), ProtocolError> {
    let fingerprint = replacement.fingerprint();
    let updated = transaction
        .execute(
            "UPDATE wallet_roots SET
                entropy_nonce = ?2, entropy_ciphertext = ?3,
                root_ciphertext_fingerprint = ?4,
                snapshot_epoch = snapshot_epoch + 1, revision = revision + 1
             WHERE wallet_id = ?1 AND revision = ?5",
            rusqlite::params![
                wallet_id.as_str(),
                replacement.nonce,
                replacement.ciphertext,
                fingerprint.as_str(),
                expected_revision as i64,
            ],
        )
        .map_err(storage)?;
    if updated != 1 {
        return Err(ProtocolError::new(
            ProtocolErrorCode::PolicyBaselineStale,
            "wallet root revision moved; re-read and retry",
        ));
    }
    Ok(())
}

/// Insert or replace one WKEK wrap in place. A credential replace
/// overwrites its wrap row with the new generation; removal sets
/// `active = false` via [`deactivate_wrap`].
pub fn put_wrap(transaction: &Transaction<'_>, wrap: &WrapRecord) -> Result<(), ProtocolError> {
    if !matches!(wrap.wrap_kind, WRAP_KIND_CREDENTIAL | WRAP_KIND_RECOVERY) {
        return Err(invalid("unknown wrap kind"));
    }
    transaction
        .execute(
            "INSERT INTO wallet_root_wraps (
                wrap_id, wallet_id, wrap_kind, active, wrap_format_version,
                wkek_nonce, wkek_ciphertext, snapshot_epoch, created_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT (wallet_id, wrap_id) DO UPDATE SET
                active = excluded.active,
                wrap_format_version = excluded.wrap_format_version,
                wkek_nonce = excluded.wkek_nonce,
                wkek_ciphertext = excluded.wkek_ciphertext,
                snapshot_epoch = excluded.snapshot_epoch,
                created_at_ms = excluded.created_at_ms",
            rusqlite::params![
                wrap.wrap_id,
                wrap.wallet_id.as_str(),
                wrap.wrap_kind,
                i64::from(wrap.active),
                wrap.wrap_format_version as i64,
                wrap.wrapped_wkek.nonce,
                wrap.wrapped_wkek.ciphertext,
                wrap.snapshot_epoch as i64,
                wrap.created_at_ms as i64,
            ],
        )
        .map_err(storage)?;
    Ok(())
}

/// Deactivate one wrap (credential removal) without deleting history.
pub fn deactivate_wrap(
    transaction: &Transaction<'_>,
    wallet_id: &Token,
    wrap_id: &str,
) -> Result<(), ProtocolError> {
    let updated = transaction
        .execute(
            "UPDATE wallet_root_wraps SET active = 0
             WHERE wallet_id = ?1 AND wrap_id = ?2",
            rusqlite::params![wallet_id.as_str(), wrap_id],
        )
        .map_err(storage)?;
    if updated != 1 {
        return Err(invalid("wrap to deactivate was not found"));
    }
    Ok(())
}

pub fn wraps(
    connection: &Connection,
    wallet_id: &Token,
) -> Result<Vec<WrapRecord>, ProtocolError> {
    let mut statement = connection
        .prepare(
            "SELECT wrap_id, wrap_kind, active, wrap_format_version,
                    wkek_nonce, wkek_ciphertext, snapshot_epoch, created_at_ms
             FROM wallet_root_wraps WHERE wallet_id = ?1 ORDER BY created_at_ms, wrap_id",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map([wallet_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })
        .map_err(storage)?;
    let mut records = Vec::new();
    for row in rows {
        let (wrap_id, kind, active, version, nonce, ciphertext, epoch, created) =
            row.map_err(storage)?;
        let wrap_kind = match kind.as_str() {
            WRAP_KIND_CREDENTIAL => WRAP_KIND_CREDENTIAL,
            WRAP_KIND_RECOVERY => WRAP_KIND_RECOVERY,
            _ => return Err(invalid("stored wrap has an unknown kind")),
        };
        records.push(WrapRecord {
            wrap_id,
            wallet_id: wallet_id.clone(),
            wrap_kind,
            active: active == 1,
            wrap_format_version: version as u32,
            wrapped_wkek: WrappedBlob { nonce, ciphertext },
            snapshot_epoch: epoch as u64,
            created_at_ms: created as u64,
        });
    }
    Ok(records)
}

/// Refuse to restore when any refusal condition holds. Checked against the
/// source database *before* anything is copied.
pub fn validate_restore_source(
    source: &Connection,
    wallet_id: &Token,
    target_epoch: Option<u64>,
) -> Result<WalletRootRecord, ProtocolError> {
    let root = load_root(source, wallet_id)?
        .ok_or_else(|| invalid("restore source is missing the wallet root"))?;
    if let Some(target) = target_epoch {
        // A restore may only move the wallet forward, never backward.
        if root.snapshot_epoch < target {
            return Err(ProtocolError::new(
                ProtocolErrorCode::PolicyBaselineStale,
                "restore source epoch is older than the local wallet epoch",
            ));
        }
    }
    // Root/wrap epoch agreement: every wrap must reference an epoch at or
    // below the root's current snapshot epoch (a wrap cannot be newer than
    // the root it protects).
    for wrap in wraps(source, wallet_id)? {
        if wrap.snapshot_epoch > root.snapshot_epoch {
            return Err(invalid(
                "restore source wrap epoch disagrees with the root epoch",
            ));
        }
    }
    Ok(root)
}

/// Consistent snapshot of a file-backed database via SQLite's backup API.
/// Copying only the main database file is not a valid WAL-mode backup.
pub fn backup_database(source: &Connection, destination: &Path) -> Result<(), ProtocolError> {
    source
        .backup(rusqlite::MAIN_DB, destination, None)
        .map_err(storage)
}

/// Restore a source database file into an open connection after refusing
/// stale or inconsistent snapshots. Overwrite-in-place checks against the
/// pre-restore local epoch: a restore may only move the wallet forward.
pub fn restore_database(
    source: &Connection,
    source_path: &Path,
    target: &mut Connection,
    wallet_id: &Token,
) -> Result<(), ProtocolError> {
    let target_epoch = load_root(target, wallet_id)?.map(|root| root.snapshot_epoch);
    validate_restore_source(source, wallet_id, target_epoch)?;
    let progress: Option<fn(rusqlite::backup::Progress)> = None;
    target
        .restore(rusqlite::MAIN_DB, source_path, progress)
        .map_err(storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        configure_durability(&connection).unwrap();
        migrate(&connection).unwrap();
        connection
    }

    fn root(wallet_id: &str) -> NewWalletRoot {
        NewWalletRoot {
            wallet_id: Token::new(wallet_id).unwrap(),
            profile_version: 1,
            entropy_bits: 256,
            language: "english",
            wrap_format_version: 1,
            wrapped_entropy: WrappedBlob {
                nonce: vec![1; 24],
                ciphertext: vec![2; 48],
            },
            created_at_ms: 1_000,
        }
    }

    #[test]
    fn root_round_trips_and_rejects_duplicates() {
        let connection = connection();
        let transaction = connection.unchecked_transaction().unwrap();
        insert_root(&transaction, &root("primary")).unwrap();
        transaction.commit().unwrap();

        let record = load_root(&connection, &Token::new("primary").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(record.entropy_bits, 256);
        assert_eq!(record.snapshot_epoch, 1);
        assert_eq!(record.revision, 1);

        let transaction = connection.unchecked_transaction().unwrap();
        assert!(insert_root(&transaction, &root("primary")).is_err());
        transaction.commit().unwrap();
    }

    #[test]
    fn entropy_rekey_is_compare_and_set_and_bumps_epoch() {
        let connection = connection();
        let transaction = connection.unchecked_transaction().unwrap();
        insert_root(&transaction, &root("primary")).unwrap();
        transaction.commit().unwrap();

        let stale = WrappedBlob {
            nonce: vec![9; 24],
            ciphertext: vec![9; 64],
        };
        let transaction = connection.unchecked_transaction().unwrap();
        // Wrong expected revision must fail without effect.
        assert!(replace_wrapped_entropy(&transaction, &Token::new("primary").unwrap(), &stale, 99)
            .is_err());
        transaction.commit().unwrap();
        let record = load_root(&connection, &Token::new("primary").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(record.revision, 1);

        let transaction = connection.unchecked_transaction().unwrap();
        replace_wrapped_entropy(&transaction, &Token::new("primary").unwrap(), &stale, 1).unwrap();
        transaction.commit().unwrap();
        let record = load_root(&connection, &Token::new("primary").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(record.revision, 2);
        assert_eq!(record.snapshot_epoch, 2);
        assert_eq!(record.wrapped_entropy, stale);
    }

    #[test]
    fn wraps_replace_deactivating_the_prior_generation() {
        let connection = connection();
        let wallet = Token::new("primary").unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        insert_root(&transaction, &root("primary")).unwrap();
        put_wrap(
            &transaction,
            &WrapRecord {
                wrap_id: "cred-1".into(),
                wallet_id: wallet.clone(),
                wrap_kind: WRAP_KIND_CREDENTIAL,
                active: true,
                wrap_format_version: 1,
                wrapped_wkek: WrappedBlob {
                    nonce: vec![3; 24],
                    ciphertext: vec![4; 48],
                },
                snapshot_epoch: 1,
                created_at_ms: 1_001,
            },
        )
        .unwrap();
        transaction.commit().unwrap();

        let transaction = connection.unchecked_transaction().unwrap();
        put_wrap(
            &transaction,
            &WrapRecord {
                wrap_id: "cred-1".into(),
                wallet_id: wallet.clone(),
                wrap_kind: WRAP_KIND_CREDENTIAL,
                active: true,
                wrap_format_version: 1,
                wrapped_wkek: WrappedBlob {
                    nonce: vec![5; 24],
                    ciphertext: vec![6; 48],
                },
                snapshot_epoch: 1,
                created_at_ms: 1_002,
            },
        )
        .unwrap();
        transaction.commit().unwrap();

        let records = wraps(&connection, &wallet).unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].active);
        assert_eq!(records[0].wrapped_wkek.nonce, vec![5; 24]);

        let transaction = connection.unchecked_transaction().unwrap();
        deactivate_wrap(&transaction, &wallet, "cred-1").unwrap();
        transaction.commit().unwrap();
        let records = wraps(&connection, &wallet).unwrap();
        assert_eq!(records.len(), 1);
        assert!(!records[0].active);
    }

    #[test]
    fn schema_constraints_reject_invalid_profiles() {
        let connection = connection();
        let mut bad = root("bad");
        bad.entropy_bits = 100;
        let transaction = connection.unchecked_transaction().unwrap();
        assert!(insert_root(&transaction, &bad).is_err());

        let mut wrong_language = root("bad-language");
        wrong_language.language = "korean";
        assert!(insert_root(&transaction, &wrong_language).is_err());
        transaction.commit().unwrap();
    }

    #[test]
    fn backup_and_restore_round_trip_with_epoch_refusal() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("signer-a.db");
        let source = Connection::open(&source_path).unwrap();
        configure_durability(&source).unwrap();
        migrate(&source).unwrap();
        let transaction = source.unchecked_transaction().unwrap();
        insert_root(&transaction, &root("primary")).unwrap();
        transaction.commit().unwrap();
        // Ensure WAL contents are represented in the backup.
        // The backup API reads through WAL; no manual checkpoint is needed.

        let backup_path = directory.path().join("backup.db");
        let reopened = Connection::open(&source_path).unwrap();
        backup_database(&reopened, &backup_path).unwrap();
        let backup = Connection::open(&backup_path).unwrap();
        assert!(load_root(&backup, &Token::new("primary").unwrap())
            .unwrap()
            .is_some());

        // Restoring the older backup over a newer local wallet is refused.
        let target_path = directory.path().join("signer-b.db");
        let mut target = Connection::open(&target_path).unwrap();
        configure_durability(&target).unwrap();
        migrate(&target).unwrap();
        let transaction = target.unchecked_transaction().unwrap();
        insert_root(&transaction, &root("primary")).unwrap();
        transaction.commit().unwrap();
        let transaction = target.unchecked_transaction().unwrap();
        replace_wrapped_entropy(
            &transaction,
            &Token::new("primary").unwrap(),
            &WrappedBlob {
                nonce: vec![7; 24],
                ciphertext: vec![8; 64],
            },
            1,
        )
        .unwrap();
        transaction.commit().unwrap();

        let stale_backup = Connection::open(&backup_path).unwrap();
        assert!(restore_database(
            &stale_backup,
            &backup_path,
            &mut target,
            &Token::new("primary").unwrap()
        )
        .is_err());
    }
}
