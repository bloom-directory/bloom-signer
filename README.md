# bloom-signer

Bloom's key custody and cryptographic-operation boundary.

The normative architecture is
[`2026-07-23-triad-process-architecture.md`](https://gist.github.com/josh-richardson/031521a48b6e044c443bc1e96e3703d2).

## Backend key support

This matrix describes the capabilities implemented by Bloom's signer backends.
Update it when backend key types or derivation support change.

| Capability | Local backend | AWS KMS backend |
| --- | --- | --- |
| secp256k1 signing | Yes | Yes |
| Ed25519 signing | Yes, for BIP-39 derived accounts | No |
| BIP-39 seed custody | Yes | No |
| BIP-32 secp256k1 accounts from BIP-39 | Yes, EVM profile | No |
| SLIP-10 Ed25519 accounts from BIP-39 | Yes, Solana profile | No |

New local wallets use the `bip39-multicurve-v1` profile: one seed can back both
EVM and Solana accounts, and only its registered derived accounts can sign.
Imported raw secp256k1 keys remain single-key wallets without HD derivation.
Legacy raw BIP-32 seed wallets remain supported for existing custody; new
wallet creation does not use that profile.

The AWS KMS backend signs with existing secp256k1 KMS keys and exposes no HD
derivation. AWS service capabilities and Bloom adapter support are separate:
adding another signing curve to the adapter would not by itself provide
BIP-39 seed custody or shared-seed account derivation.

## Ceremony surface administration

The installed Signer binary is the administrative interface for inspecting,
provisioning, enabling, and disabling the remote ceremony surface:

```text
sudo /usr/libexec/bloom/current/bloom-signer admin status --login-uid UID
sudo /usr/libexec/bloom/current/bloom-signer admin provision --login-uid UID
sudo /usr/libexec/bloom/current/bloom-signer admin remote-enabled --login-uid UID
sudo /usr/libexec/bloom/current/bloom-signer admin localhost-only --login-uid UID
```

On macOS the installed binary is
`/usr/local/libexec/bloom/current/bloom-signer`. Installed administration does
not elevate itself: callers must invoke it with effective UID 0. The login UID
selects only the fixed per-login installation layout. Signer and Broker
principal IDs are read from their non-symlink configuration directories, not
accepted from the command line or environment. `--help` is always available
without privileges.

The explicit path-selected form takes its paths and principal IDs from the
existing `BLOOM_*` environment variables. It requires root unless the binary
was built with the developer harness and validates that harness's identity and
Signer UID. The triad developer launcher continues to use this form:

```text
bloom-signer admin status --signer-uid UID
```

## One-time legacy passkey conversion

`bloom-signer-migrate` is the administrative staging tool for the single
supported v1 passkey-wallet format. Run it as an administrator with an
explicit legacy wallet directory, the installed Signer config, and the exact
login and Signer principal IDs. It writes secret-bearing staged data only into
Signer's private state and emits a public receipt:

```text
bloom-signer-migrate stage --source PATH --config SIGNER_CONFIG \
  --source-uid UID --signer-uid UID --signer-gid GID --receipt RECEIPT.json
bloom wallet migrate-passkey RECEIPT.json
```

The second command opens the normal Broker ceremony. The existing passkey must
authenticate and return its PRF result before Signer can decrypt the old
envelope and commit it through current WKEK custody. Machine and Broker never
read the legacy private-key envelope, and the original source directory is not
modified.

## Durable-clock recovery and repair

Signer will not sign while its durable clock is untrusted. Linux always rejects
a wall-clock rollback below the persisted effective-time floor. Within one
confirmed boot it also compares the wall clock with a persisted,
suspend-aware monotonic anchor and rejects an unexplained forward step larger
than the compiled limit.

A **process stop, crash, or restart** does not interrupt service recovery. The
absolute monotonic anchor survives in Signer's state, so elapsed downtime in
the same boot is credited automatically even when the process-relative sampler
restarts at zero. Suspend time is credited by the same kernel clock.

After a **confirmed host reboot**, the old and new monotonic anchors are in
different domains and cannot measure powered-off time. Signer therefore accepts
a nondecreasing host wall clock and establishes a new anchor without operator
repair. This is an explicit availability tradeoff: a privileged actor who can
change the host clock across a reboot can expire time-bounded state early, but
cannot move effective time backwards to extend existing lifetimes. Correct host
time at boot is part of the deployment boundary now that Linux has no Chrony
dependency.

Missing legacy boot-epoch state is not treated as proof of reboot. An
unexplained large forward step on that one-time upgrade path remains
`FORWARD_JUMP_REJECTED` until an operator vouches for the clock.

Repair is an explicit, audited operator action taken at startup.

```text
BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS=<unix-ms> bloom-signer …
```

`<unix-ms>` is the UTC time the operator vouches for. It may not be earlier than
the current effective time; moving effective time backwards is refused with
`CLOCK_ROLLBACK`. Repair also requires initialised clock state and is
unavailable on profiles that do not use the durable guard, currently macOS.

If repairing would expire live approvals, Signer refuses on the first attempt
and logs the accepted time, one `signer.clock_repair_expiring_approval` event
for each exact approval ID that would expire, and a confirmation digest over
both. Approval IDs and the confirmation digest are operational identifiers;
approval terms, policies, credentials, and signatures remain forbidden from
logs.

```text
event=signer.clock_repair_expiring_approval accepted_utc_ms=… approval_id=… confirmation_digest=…
```

Re-run with that digest to commit, so an operator cannot expire approvals
without having been shown which ones:

```text
BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS=<unix-ms> \
BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST=<digest> bloom-signer …
```

The digest is bound to the accepted time and that exact approval set, so it
cannot be reused if either changes. On success the clock condition becomes
`REPAIRED` and a `clock.repaired` record is appended to the audit journal with
the prior and accepted times, the anchor, and the boot epoch.


## Owner-reviewed session authority

The session extension uses Machine–Broker protocol 1.8 and Broker–Signer
protocol 1.7. It reuses Sealed Approval activation and the existing custody
backend. An onboarding label or local `under_policy` choice creates no signing
authority. Every member grant requires an owner passkey activation.

A typed System session currently supports canonical legacy/EIP-1559 EVM
native transfers and ERC-20 `transfer(address,uint256)` only. Broker decodes the
complete unsigned preimage at signing, binds numeric chain ID (`evm-N`), token,
recipient, amount and maximum gas fee, and refuses arbitrary calldata,
approvals and contract creation. Token contract effects are not proved by an
ABI decoder. Reusable native Solana authority is refused until trusted cluster
and freshness observations are available; the existing exact Solana path is
unchanged.

A signed `session_budget` descriptor binds wallet, policy snapshot, epoch,
member keys, asset conversion scales, per-action/lifetime/rolling/count/rate
caps and validity. Its ID is the SHA-256 domain-separated canonical descriptor,
not a caller-selected alias. Every child approval shares its ledger. Broker
and Signer reserve within their existing SQLite write transactions; pending,
committed and ambiguous uses consume capacity, and only definitively released
uses stop counting. Per-action split quantities are coalesced before checking.

Nominal stablecoin collateral units use owner-reviewed integer conversion
scales, conservatively rounded upward to micro-units. These are not mutable
Machine price hints, current USD prices or a guarantee against depegging.
Unknown assets are refused. Native fees or transfers require separately stated
raw-unit caps and are not silently converted into nominal dollars. Existing
Petal selectors can join a group, but their claim assurance remains explicit:
`machine_asserted` trusts the installed Petal/Machine economic projection and
does not independently decode arbitrary payload effects. Grouped monetary
Petal actions with no positive debit are refused.

The existing limit-state RPC exposes group usage, including reservations and
ambiguous outcomes, at a trusted observation time. If the clock cannot supply
that observation, group usage is unavailable; clients must not invent remaining
capacity. Policy changes, expiry and revocation continue to invalidate new use.
An identical completed session operation can retrieve its original result
without a new reservation or signature; altered bytes, keys, claims or
provenance cannot retrieve that result.

Boot-bound grants stop signing after Signer logout/restart. The current persona
workflow does not rearm an orphaned grant: end it and review a new session with
its separately reviewed budget. Retaining old accounting records is not an
automatic rearm or a global cap across newly owner-approved budgets.

Adoption requires the matching Signer commit first, then Broker's API, test
fixture and locked dependency pins, then Machine's Broker/Signer/runtime pins.
The new accounted Polymarket package must also be built, reviewed and registered
with its immutable hash; older zero-debit packages remain exact-approval-only.
Local sibling patches used for verification are not release pins. No release
or service deployment is implied by this work.

Selective Signer backup recovery does not restore a complete shared session spending
ledger. Restore therefore deactivates grouped approvals and durably blocks their
canonical budget descriptors from activation or new reservations. A nonce-only
renewal cannot recreate their lifetime capacity. Recovery requires newly reviewed
terms with a fresh budget descriptor; cached completed results remain recoverable.
Reusable native EVM sessions currently support Ethereum (1), Polygon (137), and
local development (31337) only. Other chains, including OP Stack networks whose
L1 fees are absent from the typed fee projection, require exact approval.
