//! Deterministic index allocation for derivation registries.
//!
//! When a BIP-32 child derivation is invalid (`I_L >= n` or a zero scalar
//! — probability ~2^-127 per index), the registry must skip the index
//! deterministically, tombstone it so it is never revisited, and advance.
//! [`next_valid_index`] is that loop, parameterized over the validity
//! predicate so the derivation rules and the allocation policy stay
//! independently testable.

/// Walk indices from `start`, returning the first index for which
/// `invalid` is false together with every skipped index (in visit order)
/// that must be tombstoned.
///
/// The walk is deterministic: the same `start` and the same `invalid`
/// answers always select the same index, so a restart that replays the
/// persisted tombstone set converges on the same allocation.
pub fn next_valid_index(start: u32, invalid: impl Fn(u32) -> bool) -> (u32, Vec<u32>) {
    let mut tombstones = Vec::new();
    let mut candidate = start;
    loop {
        if invalid(candidate) {
            tombstones.push(candidate);
            candidate = candidate
                .checked_add(1)
                .expect("BIP-44 index space is bounded below 2^31 by the profiles");
            continue;
        }
        return (candidate, tombstones);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_invalid_indices_deterministically() {
        let (index, tombstones) = next_valid_index(0, |candidate| candidate < 3);
        assert_eq!(index, 3);
        assert_eq!(tombstones, vec![0, 1, 2]);

        // A restart that replays the tombstones as already-consumed
        // indices advances past them without revisiting.
        let consumed: std::collections::HashSet<u32> = tombstones.iter().copied().collect();
        let (next, _) = next_valid_index(0, |candidate| consumed.contains(&candidate));
        assert_eq!(next, 3);
    }

    #[test]
    fn valid_start_allocates_itself() {
        let (index, tombstones) = next_valid_index(7, |_| false);
        assert_eq!(index, 7);
        assert!(tombstones.is_empty());
    }
}
