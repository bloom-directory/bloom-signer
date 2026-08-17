//! Atomic derivation registry for `bip39-multicurve-v1` wallets.
//!
//! Implements the ratified lifecycle
//!
//! ```text
//! PREPARED → INDEX_COMMITTED → ACCOUNT_COMMITTED → ACTIVATED
//!                       ↘ TOMBSTONED
//! ```
//!
//! Each transition is its own `BEGIN IMMEDIATE` transaction because
//! external ceremonies run between transitions; no database transaction is
//! ever held across an RPC or ceremony boundary. Invariants enforced here
//! and pinned by tests:
//!
//! - an `operation_id` retry returns the same reservation;
//! - concurrent different operations can never receive the same index
//!   (unique constraints are the final defense; IMMEDIATE serializes);
//! - counter advancement and invalid-index tombstones commit together;
//! - public listings expose only ACTIVATED accounts;
//! - abandoned reservations never make an index reusable: PREPARED rows
//!   that never commit still advance nothing, but any tombstone or
//!   committed index is permanent;
//! - callers select profile + role only — Signer resolves every path;
//! - a crash between transitions reloads into exactly one valid state.
//!
//! Invalid-child detection is caller-supplied as a pure closure over
//! (account, index): the registry owns persistence, the wallet layer owns
//! the unlocked-entropy derivation needed to evaluate BIP-32 validity.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use bloom_signer_api::{Digest32, ProtocolError, ProtocolErrorCode, Token};

use crate::engine::storage;

/// Canonical audit recorder. Every registry transition must invoke this in
/// the same SQLite transaction as the mutation; the canonical audit chain is
/// the authoritative continuity record. `derivation_events` is a local
/// integrity convenience only and must never be treated as a second audit
/// authority.
pub type AuditRecorder<'a> =
    &'a dyn Fn(&rusqlite::Transaction<'_>, &str, serde_json::Value) -> Result<(), ProtocolError>;

#[allow(clippy::too_many_arguments)]
fn transition_payload(
    wallet_id: &Token,
    operation_id: &str,
    profile: &str,
    role: &str,
    account: u32,
    index: u32,
    path: &str,
    from_state: Option<&str>,
    to_state: &str,
) -> serde_json::Value {
    serde_json::json!({
        "wallet_id": wallet_id.as_str(),
        "operation_id": operation_id,
        "profile": profile,
        "role": role,
        "account": account,
        "index": index,
        "path": path,
        "from_state": from_state,
        "to_state": to_state,
    })
}

pub const PROFILE_EVM: &str = "bip44-evm-secp256k1-v1";
pub const PROFILE_SOLANA: &str = "bip44-solana-slip10-ed25519-v1";

pub const STATE_PREPARED: &str = "PREPARED";
pub const STATE_INDEX_COMMITTED: &str = "INDEX_COMMITTED";
pub const STATE_ACCOUNT_COMMITTED: &str = "ACCOUNT_COMMITTED";
pub const STATE_ACTIVATED: &str = "ACTIVATED";
pub const STATE_TOMBSTONED: &str = "TOMBSTONED";

pub const ROLE_EVM_ACCOUNT: &str = "evm-account";
pub const ROLE_SOLANA_ACCOUNT: &str = "solana-account";

pub const DEFAULT_NAMESPACE_CAP: u64 = 100;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicAccount {
    pub wallet_id: Token,
    pub operation_id: String,
    pub profile: String,
    pub role: String,
    pub path: String,
    pub account: u32,
    pub index: u32,
    pub key_spec: String,
    pub public_key_spki_der: String,
    pub public_key_fingerprint: String,
}

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::MalformedFrame, message)
}

fn conflict(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::OperationIdConflict, message)
}

pub fn migrate(connection: &Connection) -> Result<(), ProtocolError> {
    connection
        .execute_batch(
            "
            CREATE TABLE IF NOT EXISTS derivation_namespaces (
                wallet_id TEXT NOT NULL,
                profile TEXT NOT NULL CHECK (profile IN ('bip44-evm-secp256k1-v1',
                                                         'bip44-solana-slip10-ed25519-v1')),
                role TEXT NOT NULL,
                next_index INTEGER NOT NULL CHECK (next_index >= 0),
                maximum_children INTEGER NOT NULL CHECK (maximum_children >= 1),
                PRIMARY KEY (wallet_id, profile, role)
            );
            CREATE TABLE IF NOT EXISTS derivation_allocations (
                wallet_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                profile TEXT NOT NULL,
                role TEXT NOT NULL,
                account INTEGER NOT NULL CHECK (account >= 0),
                \"index\" INTEGER NOT NULL CHECK (\"index\" >= 0),
                path TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('PREPARED', 'INDEX_COMMITTED',
                                                     'ACCOUNT_COMMITTED', 'ACTIVATED',
                                                     'TOMBSTONED')),
                key_spec TEXT NOT NULL,
                public_key_spki_der TEXT,
                public_key_fingerprint TEXT,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY (wallet_id, operation_id),
                UNIQUE (wallet_id, profile, role, account, \"index\"),
                UNIQUE (wallet_id, profile, role, path)
            );
            CREATE TABLE IF NOT EXISTS derivation_tombstones (
                wallet_id TEXT NOT NULL,
                profile TEXT NOT NULL,
                role TEXT NOT NULL,
                account INTEGER NOT NULL,
                \"index\" INTEGER NOT NULL,
                reason TEXT NOT NULL CHECK (reason IN ('invalid-child', 'retired',
                                                       'abandoned')),
                created_at_ms INTEGER NOT NULL,
                PRIMARY KEY (wallet_id, profile, role, account, \"index\")
            );
            CREATE TABLE IF NOT EXISTS derivation_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                recorded_at_ms INTEGER NOT NULL
            );
            ",
        )
        .map_err(storage)?;
    Ok(())
}

fn immediate_transaction(
    connection: &mut Connection,
) -> Result<rusqlite::Transaction<'_>, ProtocolError> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)
}

fn append_event(
    transaction: &rusqlite::Transaction<'_>,
    wallet_id: &Token,
    operation_id: &str,
    from_state: Option<&str>,
    to_state: &str,
    recorded_at_ms: u64,
) -> Result<(), ProtocolError> {
    use sha2::Digest as _;
    let previous_hash: String = transaction
        .query_row(
            "SELECT entry_hash FROM derivation_events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?
        .unwrap_or_else(|| "0".repeat(64));
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"bloom-derivation-event/v1");
    hasher.update(wallet_id.as_str().as_bytes());
    hasher.update(operation_id.as_bytes());
    hasher.update(from_state.unwrap_or("-").as_bytes());
    hasher.update(to_state.as_bytes());
    hasher.update(previous_hash.as_bytes());
    let entry_hash = Digest32::from_bytes(hasher.finalize().into());
    transaction
        .execute(
            "INSERT INTO derivation_events (
                wallet_id, operation_id, from_state, to_state,
                previous_hash, entry_hash, recorded_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                wallet_id.as_str(),
                operation_id,
                from_state,
                to_state,
                previous_hash,
                entry_hash.as_str(),
                recorded_at_ms as i64,
            ],
        )
        .map_err(storage)?;
    Ok(())
}

/// Verify the digest chain end to end; restore and reload refuse a broken
/// chain.
pub fn verify_event_chain(connection: &Connection) -> Result<(), ProtocolError> {
    use sha2::Digest as _;
    let mut statement = connection
        .prepare(
            "SELECT wallet_id, operation_id, from_state, to_state, previous_hash, entry_hash
             FROM derivation_events ORDER BY sequence",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(storage)?;
    let mut expected_previous = "0".repeat(64);
    for row in rows {
        let (wallet_id, operation_id, from_state, to_state, previous_hash, entry_hash) =
            row.map_err(storage)?;
        if previous_hash != expected_previous {
            return Err(invalid("derivation event chain has a broken link"));
        }
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"bloom-derivation-event/v1");
        hasher.update(wallet_id.as_bytes());
        hasher.update(operation_id.as_bytes());
        hasher.update(from_state.as_deref().unwrap_or("-").as_bytes());
        hasher.update(to_state.as_bytes());
        hasher.update(previous_hash.as_bytes());
        let computed = Digest32::from_bytes(hasher.finalize().into());
        if computed.as_str() != entry_hash {
            return Err(invalid("derivation event entry hash mismatch"));
        }
        expected_previous = entry_hash;
    }
    Ok(())
}

struct AllocationRow {
    profile: String,
    role: String,
    account: i64,
    index: i64,
    path: String,
    state: String,
    key_spec: String,
    public_key_spki_der: Option<String>,
    public_key_fingerprint: Option<String>,
}

fn load_allocation(
    connection: &Connection,
    wallet_id: &Token,
    operation_id: &str,
) -> Result<Option<AllocationRow>, ProtocolError> {
    connection
        .query_row(
            "SELECT profile, role, account, \"index\", path, state, key_spec,
                    public_key_spki_der, public_key_fingerprint
             FROM derivation_allocations WHERE wallet_id = ?1 AND operation_id = ?2",
            rusqlite::params![wallet_id.as_str(), operation_id],
            |row| {
                Ok(AllocationRow {
                    profile: row.get(0)?,
                    role: row.get(1)?,
                    account: row.get(2)?,
                    index: row.get(3)?,
                    path: row.get(4)?,
                    state: row.get(5)?,
                    key_spec: row.get(6)?,
                    public_key_spki_der: row.get(7)?,
                    public_key_fingerprint: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(storage)
}

fn ensure_namespace(
    transaction: &rusqlite::Transaction<'_>,
    wallet_id: &Token,
    profile: &str,
    role: &str,
) -> Result<(), ProtocolError> {
    if !matches!(profile, PROFILE_EVM | PROFILE_SOLANA) {
        return Err(invalid("unknown derivation profile"));
    }
    transaction
        .execute(
            "INSERT OR IGNORE INTO derivation_namespaces
                (wallet_id, profile, role, next_index, maximum_children)
             VALUES (?1, ?2, ?3, 0, ?4)",
            rusqlite::params![
                wallet_id.as_str(),
                profile,
                role,
                DEFAULT_NAMESPACE_CAP as i64
            ],
        )
        .map_err(storage)?;
    Ok(())
}

/// Reserve the next index for `operation_id`. Retrying an existing
/// operation returns its original reservation unchanged; no caller input
/// can influence the resolved path.
///
/// `invalid` evaluates BIP-32 invalid-child status for (account, index)
/// using the caller's unlocked entropy; tombstones for skipped indices and
/// the counter advance commit together with the reservation.
#[allow(clippy::too_many_arguments)]
pub fn prepare_allocation(
    connection: &mut Connection,
    wallet_id: &Token,
    profile: &str,
    role: &str,
    account: u32,
    operation_id: &str,
    invalid_child: impl Fn(u32, u32) -> bool,
    now_ms: u64,
    audit: AuditRecorder<'_>,
) -> Result<Reservation, ProtocolError> {
    if let Some(existing) = load_allocation(connection, wallet_id, operation_id)? {
        // Idempotent retry: identical request returns the same reservation.
        if existing.profile == profile
            && existing.role == role
            && existing.account == i64::from(account)
        {
            return Ok(Reservation {
                operation_id: operation_id.to_owned(),
                profile: existing.profile,
                role: existing.role,
                account,
                index: existing.index as u32,
                path: existing.path,
                state: existing.state,
            });
        }
        return Err(conflict(
            "operation id was already used for a different reservation",
        ));
    }

    let transaction = immediate_transaction(connection)?;
    ensure_namespace(&transaction, wallet_id, profile, role)?;
    let capacity: (i64, i64) = transaction
        .query_row(
            "SELECT maximum_children,
                    (SELECT COUNT(*) FROM derivation_allocations
                      WHERE wallet_id = ?1 AND profile = ?2 AND role = ?3
                        AND state != 'TOMBSTONED')
             FROM derivation_namespaces WHERE wallet_id = ?1 AND profile = ?2 AND role = ?3",
            rusqlite::params![wallet_id.as_str(), profile, role],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(storage)?;
    if capacity.1 >= capacity.0 {
        return Err(ProtocolError::new(
            ProtocolErrorCode::LimitExceededOperations,
            "derivation namespace is at its allocation cap",
        ));
    }

    // Deterministic skip of invalid children, with tombstones.
    let mut start: u32 = transaction
        .query_row(
            "SELECT next_index FROM derivation_namespaces
             WHERE wallet_id = ?1 AND profile = ?2 AND role = ?3",
            rusqlite::params![wallet_id.as_str(), profile, role],
            |row| row.get::<_, i64>(0),
        )
        .map_err(storage)? as u32;
    let tombstoned: std::collections::HashSet<i64> = {
        let mut statement = transaction
            .prepare(
                "SELECT \"index\" FROM derivation_tombstones
                  WHERE wallet_id = ?1 AND profile = ?2 AND role = ?3 AND account = ?4",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map(
                rusqlite::params![wallet_id.as_str(), profile, role, i64::from(account)],
                |row| row.get::<_, i64>(0),
            )
            .map_err(storage)?;
        let mut set = std::collections::HashSet::new();
        for row in rows {
            set.insert(row.map_err(storage)?);
        }
        set
    };
    let mut skipped: Vec<u32> = Vec::new();
    while tombstoned.contains(&i64::from(start)) || invalid_child(account, start) {
        skipped.push(start);
        start += 1;
    }

    let path = resolve_canonical_path(profile, account, start)?;
    for skipped_index in &skipped {
        transaction
            .execute(
                "INSERT OR IGNORE INTO derivation_tombstones
                    (wallet_id, profile, role, account, \"index\", reason, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'invalid-child', ?6)",
                rusqlite::params![
                    wallet_id.as_str(),
                    profile,
                    role,
                    i64::from(account),
                    i64::from(*skipped_index),
                    now_ms as i64
                ],
            )
            .map_err(storage)?;
    }
    transaction
        .execute(
            "UPDATE derivation_namespaces SET next_index = ?4
              WHERE wallet_id = ?1 AND profile = ?2 AND role = ?3
                AND next_index = ?5",
            rusqlite::params![
                wallet_id.as_str(),
                profile,
                role,
                i64::from(start) + 1,
                i64::from(start) - skipped.len() as i64,
            ],
        )
        .map_err(storage)?;
    transaction
        .execute(
            "INSERT INTO derivation_allocations (
                wallet_id, operation_id, profile, role, account, \"index\", path,
                state, key_spec, created_at_ms, updated_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'PREPARED', ?8, ?9, ?9)",
            rusqlite::params![
                wallet_id.as_str(),
                operation_id,
                profile,
                role,
                i64::from(account),
                i64::from(start),
                path,
                key_spec_for_profile(profile)?,
                now_ms as i64,
            ],
        )
        .map_err(storage)?;
    append_event(
        &transaction,
        wallet_id,
        operation_id,
        None,
        STATE_PREPARED,
        now_ms,
    )?;
    audit(
        &transaction,
        "derivation.prepared",
        transition_payload(wallet_id, operation_id, profile, role, account, start, &path, None, STATE_PREPARED),
    )?;
    transaction.commit().map_err(storage)?;
    Ok(Reservation {
        operation_id: operation_id.to_owned(),
        profile: profile.to_owned(),
        role: role.to_owned(),
        account,
        index: start,
        path,
        state: STATE_PREPARED.to_owned(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reservation {
    pub operation_id: String,
    pub profile: String,
    pub role: String,
    pub account: u32,
    pub index: u32,
    pub path: String,
    pub state: String,
}

/// Advance PREPARED → INDEX_COMMITTED. The index is already durably
/// reserved by prepare; this transition records the caller-visible
/// commitment point after any ceremony contribution.
pub fn commit_index(
    connection: &mut Connection,
    wallet_id: &Token,
    operation_id: &str,
    now_ms: u64,
    audit: AuditRecorder<'_>,
) -> Result<Reservation, ProtocolError> {
    let transaction = immediate_transaction(connection)?;
    let (profile, role, account, index, path) = allocation_keys(&transaction, wallet_id, operation_id)?;
    transition(
        &transaction,
        wallet_id,
        operation_id,
        STATE_PREPARED,
        STATE_INDEX_COMMITTED,
        now_ms,
    )?;
    audit(
        &transaction,
        "derivation.index_committed",
        transition_payload(wallet_id, operation_id, &profile, &role, account, index, &path, Some(STATE_PREPARED), STATE_INDEX_COMMITTED),
    )?;
    let reservation = reservation_of(&transaction, wallet_id, operation_id)?;
    transaction.commit().map_err(storage)?;
    Ok(reservation)
}

/// Advance INDEX_COMMITTED → ACCOUNT_COMMITTED, storing the public
/// descriptor produced by deriving the exact registered child. The
/// fingerprint is checked against the SPKI bytes before storing.
pub fn commit_account(
    connection: &mut Connection,
    wallet_id: &Token,
    operation_id: &str,
    public_key_spki_der: &str,
    public_key_fingerprint: &Digest32,
    now_ms: u64,
    audit: AuditRecorder<'_>,
) -> Result<Reservation, ProtocolError> {
    use sha2::Digest as _;
    let spki = hex_decode(public_key_spki_der)?;
    let computed = Digest32::from_bytes(sha2::Sha256::digest(&spki).into());
    if computed != *public_key_fingerprint {
        return Err(invalid(
            "public key fingerprint does not match the descriptor bytes",
        ));
    }
    let transaction = immediate_transaction(connection)?;
    let updated = transaction
        .execute(
            "UPDATE derivation_allocations SET
                state = 'ACCOUNT_COMMITTED', public_key_spki_der = ?3,
                public_key_fingerprint = ?4, updated_at_ms = ?5
              WHERE wallet_id = ?1 AND operation_id = ?2
                AND state = 'INDEX_COMMITTED'",
            rusqlite::params![
                wallet_id.as_str(),
                operation_id,
                public_key_spki_der,
                public_key_fingerprint.as_str(),
                now_ms as i64
            ],
        )
        .map_err(storage)?;
    if updated != 1 {
        return Err(invalid("allocation is not in INDEX_COMMITTED state"));
    }
    append_event(
        &transaction,
        wallet_id,
        operation_id,
        Some(STATE_INDEX_COMMITTED),
        STATE_ACCOUNT_COMMITTED,
        now_ms,
    )?;
    let (profile, role, account, index, path) =
        allocation_keys(&transaction, wallet_id, operation_id)?;
    audit(
        &transaction,
        "derivation.account_committed",
        transition_payload(wallet_id, operation_id, &profile, &role, account, index, &path, Some(STATE_INDEX_COMMITTED), STATE_ACCOUNT_COMMITTED),
    )?;
    let reservation = reservation_of(&transaction, wallet_id, operation_id)?;
    transaction.commit().map_err(storage)?;
    Ok(reservation)
}

/// Advance ACCOUNT_COMMITTED → ACTIVATED. The account becomes publicly
/// visible only when this transaction commits.
pub fn activate(
    connection: &mut Connection,
    wallet_id: &Token,
    operation_id: &str,
    now_ms: u64,
    audit: AuditRecorder<'_>,
) -> Result<PublicAccount, ProtocolError> {
    let transaction = immediate_transaction(connection)?;
    let (profile, role, account, index, path) = allocation_keys(&transaction, wallet_id, operation_id)?;
    transition(
        &transaction,
        wallet_id,
        operation_id,
        STATE_ACCOUNT_COMMITTED,
        STATE_ACTIVATED,
        now_ms,
    )?;
    audit(
        &transaction,
        "derivation.activated",
        transition_payload(wallet_id, operation_id, &profile, &role, account, index, &path, Some(STATE_ACCOUNT_COMMITTED), STATE_ACTIVATED),
    )?;
    let public = public_of(&transaction, wallet_id, operation_id)?;
    transaction.commit().map_err(storage)?;
    Ok(public)
}

/// Tombstone an allocation from any non-terminal state ('retired' when the
/// account was live, 'abandoned' otherwise). Tombstoned indices are never
/// reusable: the counter never moves backward and the tombstone row is
/// permanent.
pub fn tombstone(
    connection: &mut Connection,
    wallet_id: &Token,
    operation_id: &str,
    now_ms: u64,
    audit: AuditRecorder<'_>,
) -> Result<(), ProtocolError> {
    let transaction = immediate_transaction(connection)?;
    let row = transaction
        .query_row(
            "SELECT profile, role, account, \"index\", state
             FROM derivation_allocations WHERE wallet_id = ?1 AND operation_id = ?2",
            rusqlite::params![wallet_id.as_str(), operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?
        .ok_or_else(|| invalid("allocation was not found"))?;
    let (profile, role, account, index, state) = row;
    if state == STATE_TOMBSTONED {
        return Ok(());
    }
    let reason = if state == STATE_ACTIVATED {
        "retired"
    } else {
        "abandoned"
    };
    transaction
        .execute(
            "UPDATE derivation_allocations SET state = 'TOMBSTONED', updated_at_ms = ?3
              WHERE wallet_id = ?1 AND operation_id = ?2",
            rusqlite::params![wallet_id.as_str(), operation_id, now_ms as i64],
        )
        .map_err(storage)?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO derivation_tombstones
                (wallet_id, profile, role, account, \"index\", reason, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                wallet_id.as_str(),
                profile,
                role,
                account,
                index,
                reason,
                now_ms as i64
            ],
        )
        .map_err(storage)?;
    append_event(
        &transaction,
        wallet_id,
        operation_id,
        Some(&state),
        STATE_TOMBSTONED,
        now_ms,
    )?;
    let path = transaction
        .query_row(
            "SELECT path FROM derivation_allocations WHERE wallet_id = ?1 AND operation_id = ?2",
            rusqlite::params![wallet_id.as_str(), operation_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(storage)?;
    audit(
        &transaction,
        "derivation.tombstoned",
        transition_payload(wallet_id, operation_id, &profile, &role, account as u32, index as u32, &path, Some(&state), STATE_TOMBSTONED),
    )?;
    transaction.commit().map_err(storage)?;
    Ok(())
}

/// Public (Machine-visible) accounts: ACTIVATED only.
pub fn public_accounts(
    connection: &Connection,
    wallet_id: &Token,
) -> Result<Vec<PublicAccount>, ProtocolError> {
    let mut statement = connection
        .prepare(
            "SELECT operation_id, profile, role, path, account, \"index\", key_spec,
                    public_key_spki_der, public_key_fingerprint
             FROM derivation_allocations
              WHERE wallet_id = ?1 AND state = 'ACTIVATED'
              ORDER BY created_at_ms, operation_id",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map([wallet_id.as_str()], |row| {
            Ok(PublicAccount {
                wallet_id: wallet_id.clone(),
                operation_id: row.get(0)?,
                profile: row.get(1)?,
                role: row.get(2)?,
                path: row.get(3)?,
                account: row.get::<_, i64>(4)? as u32,
                index: row.get::<_, i64>(5)? as u32,
                key_spec: row.get(6)?,
                public_key_spki_der: row.get(7)?,
                public_key_fingerprint: row.get(8)?,
            })
        })
        .map_err(storage)?;
    let mut accounts = Vec::new();
    for row in rows {
        accounts.push(row.map_err(storage)?);
    }
    Ok(accounts)
}

/// Resolve the canonical path for a profile. The only path source in the
/// system: caller-supplied paths are unrepresentable.
fn resolve_canonical_path(profile: &str, account: u32, index: u32) -> Result<String, ProtocolError> {
    match profile {
        PROFILE_EVM => Ok(format!("m/44'/60'/{account}'/0/{index}")),
        PROFILE_SOLANA => Ok(format!("m/44'/501'/{account}'/0'")),
        _ => Err(invalid("unknown derivation profile")),
    }
}

fn key_spec_for_profile(profile: &str) -> Result<&'static str, ProtocolError> {
    match profile {
        PROFILE_EVM => Ok("secp256k1"),
        PROFILE_SOLANA => Ok("ed25519"),
        _ => Err(invalid("unknown derivation profile")),
    }
}

fn transition(
    transaction: &rusqlite::Transaction<'_>,
    wallet_id: &Token,
    operation_id: &str,
    from: &str,
    to: &str,
    now_ms: u64,
) -> Result<(), ProtocolError> {
    let updated = transaction
        .execute(
            "UPDATE derivation_allocations SET state = ?3, updated_at_ms = ?4
              WHERE wallet_id = ?1 AND operation_id = ?2 AND state = ?5",
            rusqlite::params![
                wallet_id.as_str(),
                operation_id,
                to,
                now_ms as i64,
                from
            ],
        )
        .map_err(storage)?;
    if updated != 1 {
        return Err(invalid(format!(
            "allocation is not in the {from} state"
        )));
    }
    append_event(transaction, wallet_id, operation_id, Some(from), to, now_ms)?;
    Ok(())
}

fn allocation_keys(
    connection: &Connection,
    wallet_id: &Token,
    operation_id: &str,
) -> Result<(String, String, u32, u32, String), ProtocolError> {
    let row = load_allocation(connection, wallet_id, operation_id)?
        .ok_or_else(|| invalid("allocation was not found"))?;
    Ok((
        row.profile,
        row.role,
        row.account as u32,
        row.index as u32,
        row.path,
    ))
}

fn reservation_of(
    connection: &Connection,
    wallet_id: &Token,
    operation_id: &str,
) -> Result<Reservation, ProtocolError> {
    let row = load_allocation(connection, wallet_id, operation_id)?
        .ok_or_else(|| invalid("allocation was not found"))?;
    Ok(Reservation {
        operation_id: operation_id.to_owned(),
        profile: row.profile,
        role: row.role,
        account: row.account as u32,
        index: row.index as u32,
        path: row.path,
        state: row.state,
    })
}

fn public_of(
    connection: &Connection,
    wallet_id: &Token,
    operation_id: &str,
) -> Result<PublicAccount, ProtocolError> {
    let row = load_allocation(connection, wallet_id, operation_id)?
        .ok_or_else(|| invalid("allocation was not found"))?;
    if row.state != STATE_ACTIVATED {
        return Err(invalid("allocation is not activated"));
    }
    Ok(PublicAccount {
        wallet_id: wallet_id.clone(),
        operation_id: operation_id.to_owned(),
        profile: row.profile,
        role: row.role,
        path: row.path,
        account: row.account as u32,
        index: row.index as u32,
        key_spec: row.key_spec,
        public_key_spki_der: row
            .public_key_spki_der
            .ok_or_else(|| invalid("activated allocation is missing its descriptor"))?,
        public_key_fingerprint: row
            .public_key_fingerprint
            .ok_or_else(|| invalid("activated allocation is missing its fingerprint"))?,
    })
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ProtocolError> {
    hex::decode(value).map_err(|_| invalid("descriptor is not valid hex"))
}
