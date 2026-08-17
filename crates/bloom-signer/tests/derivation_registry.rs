//! Registry state-machine tests: lifecycle, invariants, concurrency, and
//! crash-at-every-transition reload semantics.

use bloom_signer::derivation_registry as registry;
use bloom_signer_api::{Digest32, Token};
use rusqlite::Connection;

fn connection() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    registry::migrate(&connection).unwrap();
    connection
}

fn primary() -> Token {
    Token::new("primary").unwrap()
}

/// A no-op canonical audit recorder for tests that do not exercise audit
/// semantics directly.
fn noop(
    _transaction: &rusqlite::Transaction<'_>,
    _event_type: &str,
    _payload: serde_json::Value,
) -> Result<(), bloom_signer_api::ProtocolError> {
    Ok(())
}

fn spki_fixture(byte: u8) -> (String, Digest32) {
    use sha2::Digest as _;
    let spki = vec![byte; 44];
    let fingerprint = Digest32::from_bytes(sha2::Sha256::digest(&spki).into());
    (hex::encode(spki), fingerprint)
}

/// Drive an allocation fully through the lifecycle.
fn allocate_activated(
    connection: &mut Connection,
    operation: &str,
    index_offset: u32,
) -> registry::PublicAccount {
    let wallet = primary();
    let reservation = registry::prepare_allocation(
        connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        operation,
        |_, _| false,
        1_000,
        &noop,
    )
    .unwrap();
    assert_eq!(reservation.index, index_offset);
    assert_eq!(reservation.path, format!("m/44'/60'/0'/0/{index_offset}"));
    registry::commit_index(connection, &wallet, operation, 1_100, &noop).unwrap();
    let (spki, fingerprint) = spki_fixture(2);
    registry::commit_account(connection, &wallet, operation, &spki, &fingerprint, 1_200, &noop)
        .unwrap();
    registry::activate(connection, &wallet, operation, 1_300, &noop).unwrap()
}

#[test]
fn lifecycle_walks_the_ratified_states_in_order() {
    let mut connection = connection();
    let public = allocate_activated(&mut connection, "op-1", 0);
    assert_eq!(public.path, "m/44'/60'/0'/0/0");
    let listed = registry::public_accounts(&connection, &primary()).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].operation_id, "op-1");
    registry::verify_event_chain(&connection).unwrap();
}

#[test]
fn operation_retry_returns_the_same_reservation() {
    let mut connection = connection();
    let wallet = primary();
    let first = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-1",
        |_, _| false,
        1_000,
        &noop,
    )
    .unwrap();
    let retry = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-1",
        |_, _| false,
        2_000,
        &noop,
    )
    .unwrap();
    assert_eq!(first, retry);
    assert_eq!(first.index, 0);

    let second = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-2",
        |_, _| false,
        2_100,
        &noop,
    )
    .unwrap();
    assert_eq!(second.index, 1);

    assert!(registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_SOLANA,
        registry::ROLE_SOLANA_ACCOUNT,
        0,
        "op-1",
        |_, _| false,
        2_200,
        &noop,
    )
    .is_err());
}

#[test]
fn invalid_children_are_tombstoned_and_never_reused() {
    let mut connection = connection();
    let wallet = primary();
    let first = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-1",
        |_, index| matches!(index, 0 | 2),
        1_000,
        &noop,
    )
    .unwrap();
    assert_eq!(first.index, 1);
    let second = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-2",
        |_, index| matches!(index, 0 | 2),
        1_100,
        &noop,
    )
    .unwrap();
    assert_eq!(second.index, 3, "tombstoned 0 and 2 must be skipped forever");

    let third = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-3",
        |_, index| matches!(index, 0 | 2),
        1_200,
        &noop,
    )
    .unwrap();
    assert_eq!(third.index, 4);
}

#[test]
fn public_accounts_are_invisible_before_activation() {
    let mut connection = connection();
    let wallet = primary();
    registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-1",
        |_, _| false,
        1_000,
        &noop,
    )
    .unwrap();
    assert!(registry::public_accounts(&connection, &primary()).unwrap().is_empty());
    registry::commit_index(&mut connection, &wallet, "op-1", 1_100, &noop).unwrap();
    assert!(registry::public_accounts(&connection, &primary()).unwrap().is_empty());
    let (spki, fingerprint) = spki_fixture(4);
    registry::commit_account(&mut connection, &wallet, "op-1", &spki, &fingerprint, 1_200, &noop)
        .unwrap();
    assert!(registry::public_accounts(&connection, &primary()).unwrap().is_empty());
    registry::activate(&mut connection, &wallet, "op-1", 1_300, &noop).unwrap();
    assert_eq!(registry::public_accounts(&connection, &primary()).unwrap().len(), 1);
}

#[test]
fn transitions_refuse_out_of_order_advancement() {
    let mut connection = connection();
    let wallet = primary();
    registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-1",
        |_, _| false,
        1_000,
        &noop,
    )
    .unwrap();
    let (spki, fingerprint) = spki_fixture(6);
    assert!(
        registry::commit_account(&mut connection, &wallet, "op-1", &spki, &fingerprint, 1_100, &noop)
            .is_err()
    );
    assert!(registry::activate(&mut connection, &wallet, "op-1", 1_100, &noop).is_err());
    registry::commit_index(&mut connection, &wallet, "op-1", 1_100, &noop).unwrap();
    assert!(registry::commit_index(&mut connection, &wallet, "op-1", 1_150, &noop).is_err());
}

#[test]
fn descriptor_fingerprint_mismatch_is_refused() {
    let mut connection = connection();
    let wallet = primary();
    registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-1",
        |_, _| false,
        1_000,
        &noop,
    )
    .unwrap();
    registry::commit_index(&mut connection, &wallet, "op-1", 1_100, &noop).unwrap();
    let (spki, _) = spki_fixture(8);
    let wrong_fingerprint = Digest32::from_bytes([0x11; 32]);
    assert!(
        registry::commit_account(&mut connection, &wallet, "op-1", &spki, &wrong_fingerprint, 1_200, &noop)
            .is_err()
    );
}

#[test]
fn tombstoned_accounts_leave_public_list_and_chain_stays_verified() {
    let mut connection = connection();
    let wallet = primary();
    allocate_activated(&mut connection, "op-1", 0);
    registry::tombstone(&mut connection, &wallet, "op-1", 2_000, &noop).unwrap();
    assert!(registry::public_accounts(&connection, &primary()).unwrap().is_empty());
    registry::verify_event_chain(&connection).unwrap();

    let next = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-2",
        |_, _| false,
        2_100,
        &noop,
    )
    .unwrap();
    assert_eq!(next.index, 1);
}

#[test]
fn abandoned_reservations_never_release_their_index() {
    let mut connection = connection();
    let wallet = primary();
    registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-abandoned",
        |_, _| false,
        1_000,
        &noop,
    )
    .unwrap();
    registry::tombstone(&mut connection, &wallet, "op-abandoned", 1_500, &noop).unwrap();
    let next = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-2",
        |_, _| false,
        1_600,
        &noop,
    )
    .unwrap();
    assert_eq!(next.index, 1, "the abandoned index 0 is not reusable");
}

#[test]
fn crash_at_every_transition_reloads_into_one_valid_state() {
    for stop_after in ["PREPARED", "INDEX_COMMITTED", "ACCOUNT_COMMITTED", "ACTIVATED"] {
        let mut connection = connection();
        let wallet = primary();
        registry::prepare_allocation(
            &mut connection,
            &wallet,
            registry::PROFILE_EVM,
            registry::ROLE_EVM_ACCOUNT,
            0,
            "op-1",
            |_, _| false,
            1_000,
            &noop,
        )
        .unwrap();
        if stop_after == "PREPARED" {
            assert!(registry::public_accounts(&connection, &primary()).unwrap().is_empty());
            continue;
        }
        registry::commit_index(&mut connection, &wallet, "op-1", 1_100, &noop).unwrap();
        if stop_after == "INDEX_COMMITTED" {
            assert!(registry::public_accounts(&connection, &primary()).unwrap().is_empty());
            continue;
        }
        let (spki, fingerprint) = spki_fixture(3);
        registry::commit_account(&mut connection, &wallet, "op-1", &spki, &fingerprint, 1_200, &noop)
            .unwrap();
        if stop_after == "ACCOUNT_COMMITTED" {
            assert!(registry::public_accounts(&connection, &primary()).unwrap().is_empty());
            continue;
        }
        registry::activate(&mut connection, &wallet, "op-1", 1_300, &noop).unwrap();
        assert_eq!(registry::public_accounts(&connection, &primary()).unwrap().len(), 1);
        registry::verify_event_chain(&connection).unwrap();
    }
}

#[test]
fn concurrent_operations_never_share_an_index() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("registry.db");
    {
        let connection = Connection::open(&path).unwrap();
        bloom_signer::bip39_store::configure_durability(&connection).unwrap();
        registry::migrate(&connection).unwrap();
    }
    let mut handles = Vec::new();
    for worker in 0..8u32 {
        let path = path.clone();
        handles.push(std::thread::spawn(move || {
            let mut connection = Connection::open(&path).unwrap();
            let wallet = Token::new("primary").unwrap();
            let operation = format!("op-{worker}");
            let reservation = registry::prepare_allocation(
                &mut connection,
                &wallet,
                registry::PROFILE_EVM,
                registry::ROLE_EVM_ACCOUNT,
                0,
                &operation,
                |_, _| false,
                1_000 + u64::from(worker),
                &noop,
            )
            .unwrap();
            reservation.index
        }));
    }
    let mut indices = Vec::new();
    for handle in handles {
        indices.push(handle.join().unwrap());
    }
    indices.sort_unstable();
    let unique: std::collections::HashSet<u32> = indices.iter().copied().collect();
    assert_eq!(unique.len(), indices.len(), "indices must be unique");
    assert_eq!(indices, (0..8).collect::<Vec<u32>>());
}

#[test]
fn audit_failure_rolls_back_the_transition() {
    let mut connection = connection();
    let wallet = primary();
    let failing = |_tx: &rusqlite::Transaction<'_>, _et: &str, _p: serde_json::Value| {
        Err::<(), _>(bloom_signer_api::ProtocolError::new(
            bloom_signer_api::ProtocolErrorCode::ServiceUnavailable,
            "audit unavailable",
        ))
    };
    let result = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-1",
        |_, _| false,
        1_000,
        &failing,
    );
    assert!(result.is_err());
    // Nothing persisted: the reservation is absent and can be retried cleanly.
    let retry = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-1",
        |_, _| false,
        1_100,
        &noop,
    )
    .unwrap();
    assert_eq!(retry.index, 0);
}

#[test]
fn tampered_event_chain_is_refused() {
    let mut connection = connection();
    allocate_activated(&mut connection, "op-1", 0);
    connection
        .execute("UPDATE derivation_events SET to_state = 'HACKED' WHERE sequence = 1", [])
        .unwrap();
    assert!(registry::verify_event_chain(&connection).is_err());
}

#[test]
fn namespace_cap_is_enforced() {
    let mut connection = connection();
    let wallet = primary();
    for operation in 0..registry::DEFAULT_NAMESPACE_CAP {
        registry::prepare_allocation(
            &mut connection,
            &wallet,
            registry::PROFILE_EVM,
            registry::ROLE_EVM_ACCOUNT,
            0,
            &format!("op-{operation}"),
            |_, _| false,
            1_000 + operation,
            &noop,
        )
        .unwrap();
    }
    let error = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-over",
        |_, _| false,
        9_999,
        &noop,
    )
    .unwrap_err();
    assert!(error.message.contains("cap"));
}
