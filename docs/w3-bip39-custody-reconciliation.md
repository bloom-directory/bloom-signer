# BIP-39 custody reconciliation decision

Status: accepted (pre-implementation)

## Problem

The BIP-39 work introduced `bip39_store.rs` (`wallet_roots` / `wallet_root_wraps`)
and `bip39_custody.rs` (credential/recovery/rekey/export/import/delete/backup
orchestration) as a parallel custody path alongside the existing `custody.rs`
(`WalletCustody` / `WalletCustodyBackup`, persisted by the engine into
`wallet_state.backup_set_jcs` and `ceremony_wallets.custody_jcs`).

This duplicates wrap crypto, recovery, rekey, backup/restore, and delete —
exactly the kind of second custody authority that produces divergence.

## Decision: (A) fold the BIP-39 root into the existing custody record

`WalletCustodyBackup` gains a root-material profile and entropy-length
metadata:

```text
RootMaterialProfile
  LegacyBip32Seed          // unchanged legacy profile
  LegacySecp256k1Scalar    // unchanged legacy profile
  Bip39MulticurveV1        // new: encrypted_root = WKEK-wrapped entropy
```

Rationale:

- Custody's `encrypted_root` is already opaque bytes wrapped by the WKEK; the
  credential/recovery wraps, rekey, export, import, delete, and backup are all
  profile-independent. Only three things are profile-specific: what the root
  plaintext means, unlock-time length validation, and the export format.
- One code path per ceremony kind, dispatching on the seed profile, satisfies
  the "no second custody authority" rule and keeps the loss matrix parameterized
  over `{legacy-secp, bip39-multicurve-v1}`.
- Derivation stays profile-dispatched: legacy secp derives in the backend-local
  backend (BIP-32 from a raw seed); BIP-39 derives engine-side through
  `bloom-signer-derive` (entropy -> mnemonic -> PBKDF2 seed -> BIP-32/SLIP-10),
  surfaced through `bip39_signing` / the `Unlocked` sign methods.

## What is removed vs. kept

- **Removed**: `bip39_store`'s `wallet_roots` / `wallet_root_wraps` tables and
  `bip39_custody`'s parallel orchestration. Their behavior folds into
  `custody.rs` (wraps, recovery, rekey, delete, export) and into the ceremony
  dispatch (single path per `CeremonyKind`, dispatched on seed profile).
- **Kept**: `derivation_registry` (profile-agnostic allocation state machine,
  counters, tombstones, event chain), `bip39_signing` (entropy -> seed -> derive
  -> verify -> sign -> verify -> zeroize), the WAL/durability configuration, the
  SQLite backup API, and the decrypt-time entropy-length validation (moved into
  custody's unlock path).

## Mandatory parameterized tests

Every test below runs for both `legacy-secp` and `bip39-multicurve-v1`:

- registration; unlock with each of two passkeys and the recovery factor
  (same WKEK/root, byte-identical children);
- credential add/replace/remove; recovery install; rekey; export; delete
  (tombstones root + registry + wraps atomically);
- backup -> restore round-trip with identical descriptors; mixed-epoch restore
  rejected; restore-with-missing-registry refuses new derivation;
- crash between INDEX_COMMITTED and ACCOUNT_COMMITTED reconciles by op-ID
  replay; concurrent allocation never double-issues an index.
