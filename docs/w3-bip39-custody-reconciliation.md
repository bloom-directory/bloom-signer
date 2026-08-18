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
  Bip39MulticurveV1        // encrypted_root = WKEK-wrapped entropy (16/20/24/28/32 bytes)
  ImportedSecp256k1Scalar  // encrypted_root = one WKEK-wrapped secp256k1 scalar (32 bytes)
```

> **Supersession (2026-08-18).** The profile set above was later collapsed from
> three (raw-seed HD, raw-scalar, entropy) to the two permanent profiles above.
> Human decisions, recorded here so they are not reconstructed from git-blame:
>
> - **`Bip32Seed` / the generic `WalletCustody::register()` / the local backend's
>   raw-seed `provision()` are deleted** — "create a new HD wallet directly from a
>   raw seed, no mnemonic, no import" has no remaining use case. New wallets are
>   BIP-39; raw-key import is the imported-scalar profile. The `bip32` (iqlusion)
>   crate remains a *dev-only* differential-testing dependency of
>   `bloom-signer-derive` (see the BIP-32 note below), not a production path.
> - **The pre-triad single-passkey migration (`legacy_passkey.rs` /
>   `bloom-signer-migrate`) is retained, not deleted.** A small number of real
>   accounts are still on the pre-triad format; migration is an ops action. A
>   migrated pre-triad wallet is a single 32-byte scalar (validated against one
>   address), so it lands in `ImportedSecp256k1Scalar`, never in a raw-seed HD
>   tree. Delete the migration only after migration is confirmed complete (tracked
>   follow-up).
> - **The petal/agent subkey derivation subsystem is dormant, not deleted.** With
>   `Bip32Seed` gone there is no backend that can anchor a derivation namespace, so
>   no current caller reaches it; the code stays compiling as scaffolding for the
>   "agent authority" principle, with a tracked follow-up to either re-anchor it or
>   remove it. Said plainly in the Signer PR body.

### BIP-32 / SLIP-10 crate decisions (2026-08-18)

- **`coins-bip32` was evaluated and rejected as the production BIP-32
  implementation.** Both 0.8.7 and 0.13.1 contain `_ => return
  self.derive_child(index + 1)` at `xkeys.rs:231`: an invalid child (`I_L >= n` or
  zero scalar) is silently retried at the next index rather than surfaced as a
  distinguishable error. Bloom's `allocation::next_valid_index` tombstone/skip
  allocator depends on `Secp256k1DeriveError::InvalidChild` being catchable so path
  labels stay accurate; the silent reindex would mislabel index+1's key as index.
  Keep the hand-rolled `bip32.rs` (k256-backed) and its permanent differential test
  against the external `bip32` crate — the project shipped a real scalar-arithmetic
  ordering bug (`601d905` → `85f0013`) that only that differential caught, which is
  why the dev-dependency stays.
- **`slip10.rs` is kept hand-rolled** after a freshness check: the two candidate
  crates are both 5+ years unmaintained (checked 2026-08-18), and the 167-line
  vector-pinned implementation has no known caught-bug history. Re-check freshness
  before reconsidering.
- **`bip39` (mnemonic) stays as-is** — `coins-bip39` is a lateral move with no
  capability gain.

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

Every test below runs for both `imported-secp256k1-scalar` and
`bip39-multicurve-v1` (the raw-seed-HD profile is retired — see supersession
above):

- registration; unlock with each of two passkeys and the recovery factor
  (same WKEK/root, byte-identical children for the bip39 profile);
- credential add/replace/remove; recovery install; rekey; export; delete
  (tombstones root + registry + wraps atomically);
- backup -> restore round-trip with identical descriptors; mixed-epoch restore
  rejected; restore-with-missing-registry refuses new derivation;
- crash between INDEX_COMMITTED and ACCOUNT_COMMITTED reconciles by op-ID
  replay; concurrent allocation never double-issues an index.
