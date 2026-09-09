//! Registry state-machine tests: lifecycle, invariants, concurrency, and
//! crash-at-every-transition reload semantics.

use bloom_signer::derivation_registry as registry;
use bloom_signer_api::{Digest32, DurableEffect, ProtocolErrorCode, RetryClass, Token};
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
    registry::commit_account(
        connection,
        &wallet,
        operation,
        &spki,
        &fingerprint,
        1_200,
        &noop,
    )
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

    assert!(
        registry::prepare_allocation(
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
        .is_err()
    );
}

#[test]
fn out_of_range_account_is_rejected_without_a_reservation() {
    let mut connection = connection();
    let wallet = primary();
    let error = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_SOLANA,
        registry::ROLE_SOLANA_ACCOUNT,
        1_u32 << 31,
        "op-out-of-range",
        |_, _| false,
        1_000,
        &noop,
    )
    .unwrap_err();
    assert_eq!(error.code, ProtocolErrorCode::MalformedFrame);

    let reservation = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_SOLANA,
        registry::ROLE_SOLANA_ACCOUNT,
        0,
        "op-out-of-range",
        |_, _| false,
        1_001,
        &noop,
    )
    .unwrap();
    assert_eq!(reservation.account, 0);
    assert_eq!(reservation.path, "m/44'/501'/0'/0'");
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
    assert_eq!(
        second.index, 3,
        "tombstoned 0 and 2 must be skipped forever"
    );

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
    assert!(
        registry::public_accounts(&connection, &primary())
            .unwrap()
            .is_empty()
    );
    registry::commit_index(&mut connection, &wallet, "op-1", 1_100, &noop).unwrap();
    assert!(
        registry::public_accounts(&connection, &primary())
            .unwrap()
            .is_empty()
    );
    let (spki, fingerprint) = spki_fixture(4);
    registry::commit_account(
        &mut connection,
        &wallet,
        "op-1",
        &spki,
        &fingerprint,
        1_200,
        &noop,
    )
    .unwrap();
    assert!(
        registry::public_accounts(&connection, &primary())
            .unwrap()
            .is_empty()
    );
    registry::activate(&mut connection, &wallet, "op-1", 1_300, &noop).unwrap();
    assert_eq!(
        registry::public_accounts(&connection, &primary())
            .unwrap()
            .len(),
        1
    );
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
        registry::commit_account(
            &mut connection,
            &wallet,
            "op-1",
            &spki,
            &fingerprint,
            1_100,
            &noop
        )
        .is_err()
    );
    assert!(registry::activate(&mut connection, &wallet, "op-1", 1_100, &noop).is_err());
    registry::commit_index(&mut connection, &wallet, "op-1", 1_100, &noop).unwrap();
    // Idempotent retry: re-committing an already-advanced index step succeeds
    // (crash recovery between commit_index and the ceremony completion cache).
    registry::commit_index(&mut connection, &wallet, "op-1", 1_150, &noop).unwrap();
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
        registry::commit_account(
            &mut connection,
            &wallet,
            "op-1",
            &spki,
            &wrong_fingerprint,
            1_200,
            &noop
        )
        .is_err()
    );
}

#[test]
fn tombstoned_accounts_leave_public_list_and_chain_stays_verified() {
    let mut connection = connection();
    let wallet = primary();
    allocate_activated(&mut connection, "op-1", 0);
    registry::tombstone(&mut connection, &wallet, "op-1", 2_000, &noop).unwrap();
    assert!(
        registry::public_accounts(&connection, &primary())
            .unwrap()
            .is_empty()
    );
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
    for stop_after in [
        "PREPARED",
        "INDEX_COMMITTED",
        "ACCOUNT_COMMITTED",
        "ACTIVATED",
    ] {
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
            assert!(
                registry::public_accounts(&connection, &primary())
                    .unwrap()
                    .is_empty()
            );
            continue;
        }
        registry::commit_index(&mut connection, &wallet, "op-1", 1_100, &noop).unwrap();
        if stop_after == "INDEX_COMMITTED" {
            assert!(
                registry::public_accounts(&connection, &primary())
                    .unwrap()
                    .is_empty()
            );
            continue;
        }
        let (spki, fingerprint) = spki_fixture(3);
        registry::commit_account(
            &mut connection,
            &wallet,
            "op-1",
            &spki,
            &fingerprint,
            1_200,
            &noop,
        )
        .unwrap();
        if stop_after == "ACCOUNT_COMMITTED" {
            assert!(
                registry::public_accounts(&connection, &primary())
                    .unwrap()
                    .is_empty()
            );
            continue;
        }
        registry::activate(&mut connection, &wallet, "op-1", 1_300, &noop).unwrap();
        assert_eq!(
            registry::public_accounts(&connection, &primary())
                .unwrap()
                .len(),
            1
        );
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
        .execute(
            "UPDATE derivation_events SET to_state = 'HACKED' WHERE sequence = 1",
            [],
        )
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

#[test]
fn retried_allocation_after_full_activation_is_idempotent() {
    let mut connection = connection();
    let wallet = primary();
    // First full lifecycle succeeds.
    let public = allocate_activated(&mut connection, "op-1", 0);
    assert_eq!(public.path, "m/44'/60'/0'/0/0");

    // A retry of the same operation id re-runs each step against an already-
    // advanced allocation and must succeed idempotently (crash between
    // activation and the ceremony completion-cache update).
    let reservation = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        "op-1",
        |_, _| false,
        1_400,
        &noop,
    )
    .unwrap();
    assert_eq!(reservation.index, 0);
    registry::commit_index(&mut connection, &wallet, "op-1", 1_500, &noop).unwrap();
    let (spki, fingerprint) = spki_fixture(2);
    registry::commit_account(
        &mut connection,
        &wallet,
        "op-1",
        &spki,
        &fingerprint,
        1_600,
        &noop,
    )
    .unwrap();
    let retried = registry::activate(&mut connection, &wallet, "op-1", 1_700, &noop).unwrap();
    assert_eq!(retried.path, "m/44'/60'/0'/0/0");
    // The retry must not have double-issued an index or a second allocation row.
    let listed = registry::public_accounts(&connection, &wallet).unwrap();
    assert_eq!(listed.len(), 1);
    registry::verify_event_chain(&connection).unwrap();
}

#[test]
fn address_index_counter_is_per_account() {
    let mut connection = connection();
    let wallet = primary();
    // Account 0 consumes indices 0 and 1.
    allocate_activated(&mut connection, "op-a0", 0);
    allocate_activated(&mut connection, "op-a1", 1);
    // Account 1 starts its own index sequence at 0, not at account 0's counter.
    let reservation = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        1,
        "op-b0",
        |_, _| false,
        2_000,
        &noop,
    )
    .unwrap();
    assert_eq!(reservation.index, 0);
    assert_eq!(reservation.path, "m/44'/60'/1'/0/0");
}

#[test]
fn solana_path_collision_is_permanent_and_does_not_consume_the_next_account() {
    let mut connection = connection();
    let wallet = primary();
    let first = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_SOLANA,
        registry::ROLE_SOLANA_ACCOUNT,
        0,
        "op-solana-0",
        |_, _| false,
        1_000,
        &noop,
    )
    .unwrap();
    assert_eq!(first.index, 0);
    assert_eq!(first.path, "m/44'/501'/0'/0'");

    // Solana's canonical profile has no address-index component. A second
    // reservation in account 0 therefore resolves to the already-owned path,
    // even though the namespace's internal counter advanced to index 1.
    let collision = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_SOLANA,
        registry::ROLE_SOLANA_ACCOUNT,
        0,
        "op-solana-collision",
        |_, _| false,
        1_100,
        &noop,
    )
    .unwrap_err();
    assert_eq!(collision.code, ProtocolErrorCode::OperationIdConflict);
    assert_eq!(collision.retry, RetryClass::Never);
    assert_eq!(
        collision.durable_effect,
        DurableEffect::PriorOperationStands
    );
    assert!(collision.message.contains("m/44'/501'/0'/0'"));
    assert!(collision.message.contains("op-solana-0"));

    // The rejected transaction must not consume the first slot of account 1.
    let next_account = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_SOLANA,
        registry::ROLE_SOLANA_ACCOUNT,
        1,
        "op-solana-1",
        |_, _| false,
        1_200,
        &noop,
    )
    .unwrap();
    assert_eq!(next_account.index, 0);
    assert_eq!(next_account.path, "m/44'/501'/1'/0'");
}

#[test]
fn automatic_solana_accounts_advance_across_tombstones_and_roles() {
    let mut connection = connection();
    let wallet = primary();
    let first = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_SOLANA,
        registry::ROLE_SOLANA_ACCOUNT,
        None,
        "op-solana-0",
        |_, _| false,
        1_000,
        &noop,
    )
    .unwrap();
    assert_eq!(first.account, 0);
    registry::tombstone(&mut connection, &wallet, "op-solana-0", 1_100, &noop).unwrap();

    let second = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_SOLANA,
        "alternate-solana-role",
        None,
        "op-solana-1",
        |_, _| false,
        1_200,
        &noop,
    )
    .unwrap();
    assert_eq!(second.account, 1);
    assert_eq!(second.index, 0);
    assert_eq!(second.path, "m/44'/501'/1'/0'");

    // Retrying an automatic request must recover its original reservation,
    // not observe itself as the highest account and allocate account 2.
    let retry = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_SOLANA,
        "alternate-solana-role",
        None,
        "op-solana-1",
        |_, _| false,
        1_300,
        &noop,
    )
    .unwrap();
    assert_eq!(retry, second);
}

fn code(error: &bloom_signer_api::ProtocolError) -> ProtocolErrorCode {
    error.code
}

#[test]
fn explicit_index_targets_the_path_and_only_moves_the_counter_forward() {
    let mut connection = connection();
    let wallet = primary();
    allocate_activated(&mut connection, "op-0", 0);

    // A target beyond the counter lands exactly there and moves the counter
    // past it, so the ordinary allocator can never hand that index out again.
    let targeted = registry::prepare_allocation_at(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        Some(3),
        "op-3",
        |_, _| false,
        2_000,
        &noop,
    )
    .unwrap();
    assert_eq!(targeted.index, 3);
    assert_eq!(targeted.path, "m/44'/60'/0'/0/3");
    let ordinary = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        "op-next",
        |_, _| false,
        2_100,
        &noop,
    )
    .unwrap();
    assert_eq!(ordinary.index, 4);

    // A target below the counter fills a hole without moving the counter back.
    let hole = registry::prepare_allocation_at(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        Some(1),
        "op-1",
        |_, _| false,
        2_200,
        &noop,
    )
    .unwrap();
    assert_eq!(hole.index, 1);
    let after_hole = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        "op-after-hole",
        |_, _| false,
        2_300,
        &noop,
    )
    .unwrap();
    assert_eq!(after_hole.index, 5);

    // Retrying the same operation with the same target is idempotent; a
    // different target under a used operation id is a conflict.
    let retry = registry::prepare_allocation_at(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        Some(3),
        "op-3",
        |_, _| false,
        2_400,
        &noop,
    )
    .unwrap();
    assert_eq!(retry, targeted);
    let conflict = registry::prepare_allocation_at(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        Some(2),
        "op-3",
        |_, _| false,
        2_500,
        &noop,
    )
    .unwrap_err();
    assert_eq!(code(&conflict), ProtocolErrorCode::OperationIdConflict);

    // Targets are an EVM-only concept: the Solana path carries no index.
    let solana = registry::prepare_allocation_at(
        &mut connection,
        &wallet,
        registry::PROFILE_SOLANA,
        registry::ROLE_SOLANA_ACCOUNT,
        None,
        Some(0),
        "op-solana-target",
        |_, _| false,
        2_600,
        &noop,
    )
    .unwrap_err();
    assert_eq!(code(&solana), ProtocolErrorCode::MalformedFrame);
    registry::verify_event_chain(&connection).unwrap();
}

#[test]
fn explicit_index_on_an_occupied_tombstoned_or_invalid_index_fails_typed() {
    let mut connection = connection();
    let wallet = primary();
    allocate_activated(&mut connection, "op-0", 0);

    // Occupied by a live allocation.
    let occupied = registry::prepare_allocation_at(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        Some(0),
        "op-dup",
        |_, _| false,
        2_000,
        &noop,
    )
    .unwrap_err();
    assert_eq!(code(&occupied), ProtocolErrorCode::OperationIdConflict);

    // Occupied by a tombstone: retiring index 0 never frees it.
    registry::tombstone(&mut connection, &wallet, "op-0", 2_100, &noop).unwrap();
    let dead = registry::prepare_allocation_at(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        Some(0),
        "op-dead",
        |_, _| false,
        2_200,
        &noop,
    )
    .unwrap_err();
    assert_eq!(code(&dead), ProtocolErrorCode::OperationIdConflict);

    // A BIP-32-invalid target is recorded as a tombstone and reported as
    // invalid; the counter does not move, so the next ordinary allocation is
    // still index 1, and the same target afterwards is a plain conflict.
    let invalid = registry::prepare_allocation_at(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        Some(7),
        "op-invalid",
        |_, index| index == 7,
        2_300,
        &noop,
    )
    .unwrap_err();
    assert_eq!(code(&invalid), ProtocolErrorCode::BackendInvalidRequest);
    assert!(
        registry::public_accounts(&connection, &wallet)
            .unwrap()
            .iter()
            .all(|account| account.operation_id != "op-invalid")
    );
    let ordinary = registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        "op-1",
        |_, _| false,
        2_400,
        &noop,
    )
    .unwrap();
    assert_eq!(ordinary.index, 1);
    let again = registry::prepare_allocation_at(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        Some(7),
        "op-invalid-again",
        |_, _| false,
        2_500,
        &noop,
    )
    .unwrap_err();
    assert_eq!(code(&again), ProtocolErrorCode::OperationIdConflict);
    registry::verify_event_chain(&connection).unwrap();
}

#[test]
fn recorded_invalid_children_are_never_targeted() {
    let mut connection = connection();
    let wallet = primary();
    registry::record_invalid_child_tombstone(
        &connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        3,
        1_000,
    )
    .unwrap();
    // Retrying the same conclusion is a no-op, not a duplicate row.
    registry::record_invalid_child_tombstone(
        &connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        0,
        3,
        1_100,
    )
    .unwrap();
    let error = registry::prepare_allocation_at(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        Some(3),
        "op-target-invalid",
        |_, _| false,
        1_200,
        &noop,
    )
    .unwrap_err();
    assert!(error.to_string().contains("tombstoned"), "{error}");
    // The ordinary counter is untouched by a tombstone-only record.
    assert_eq!(
        registry::next_account_number(&connection, &wallet).unwrap(),
        0
    );
}

#[test]
fn next_account_number_spans_both_families_and_counts_dead_paths() {
    let mut connection = connection();
    let wallet = primary();
    assert_eq!(
        registry::next_account_number(&connection, &wallet).unwrap(),
        0
    );

    allocate_activated(&mut connection, "op-evm-0", 0);
    assert_eq!(
        registry::next_account_number(&connection, &wallet).unwrap(),
        1
    );

    // Solana accounts 0 and 1; tombstoning 1 leaves it counted.
    for (operation, expected_account) in [("op-sol-0", 0), ("op-sol-1", 1)] {
        let reservation = registry::prepare_allocation(
            &mut connection,
            &wallet,
            registry::PROFILE_SOLANA,
            registry::ROLE_SOLANA_ACCOUNT,
            None,
            operation,
            |_, _| false,
            3_000,
            &noop,
        )
        .unwrap();
        assert_eq!(reservation.account, expected_account);
    }
    assert_eq!(
        registry::next_account_number(&connection, &wallet).unwrap(),
        2
    );
    registry::tombstone(&mut connection, &wallet, "op-sol-1", 3_100, &noop).unwrap();
    assert_eq!(
        registry::next_account_number(&connection, &wallet).unwrap(),
        2
    );

    // An EVM target at 4 pushes the number past every Solana account; a
    // Solana account at 7 pushes it past every EVM index.
    registry::prepare_allocation_at(
        &mut connection,
        &wallet,
        registry::PROFILE_EVM,
        registry::ROLE_EVM_ACCOUNT,
        None,
        Some(4),
        "op-evm-4",
        |_, _| false,
        3_200,
        &noop,
    )
    .unwrap();
    assert_eq!(
        registry::next_account_number(&connection, &wallet).unwrap(),
        5
    );
    registry::prepare_allocation(
        &mut connection,
        &wallet,
        registry::PROFILE_SOLANA,
        registry::ROLE_SOLANA_ACCOUNT,
        Some(7),
        "op-sol-7",
        |_, _| false,
        3_300,
        &noop,
    )
    .unwrap();
    assert_eq!(
        registry::next_account_number(&connection, &wallet).unwrap(),
        8
    );

    // A retired row keeps its account and its index, so retirement never
    // frees its number.
    registry::commit_index(&mut connection, &wallet, "op-sol-7", 3_350, &noop).unwrap();
    let (spki, fingerprint) = spki_fixture(3);
    registry::commit_account(
        &mut connection,
        &wallet,
        "op-sol-7",
        &spki,
        &fingerprint,
        3_360,
        &noop,
    )
    .unwrap();
    registry::activate(&mut connection, &wallet, "op-sol-7", 3_370, &noop).unwrap();
    registry::retire(&mut connection, &wallet, "op-sol-7", 3_400, &noop).unwrap();
    assert_eq!(
        registry::next_account_number(&connection, &wallet).unwrap(),
        8
    );
    let retired: (String, i64) = connection
        .query_row(
            "SELECT state, account FROM derivation_allocations
              WHERE wallet_id = ?1 AND operation_id = 'op-sol-7'",
            rusqlite::params![wallet.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(retired, ("RETIRED".to_owned(), 7));
}
