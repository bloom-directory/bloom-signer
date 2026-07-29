# W3 Signer seam decisions

This package implements the Signer-side security boundary defined by the triad
architecture specification.

- Sign requests are accepted only after structural digest validation, an
  Ed25519 signature over the raw `attempt_digest`, exact issuer/audience/key/
  suite/selector/policy/validity checks, durable replay checks, independent
  parser-free limits, and an enrolled-key availability check.
- Compiled backends are routed by the full `(backend, backend_instance)` pair,
  allowing multiple independently pinned instances of the same implementation.
- Replacement attempts may vary only in attempt identity, Broker boot epoch,
  and attempt validity. A separate stable retry-binding digest closes every
  other field.
- Local secp256k1 keys use one encrypted BIP32 root. Arbitrary path
  registration is closed; callers configure a canonical namespace and allocate
  its next index under a policy or ceremony grant signed by the authority key
  pinned in the encrypted backend backup. Allocation,
  next-index advancement, pinned public metadata, and tombstones publish in
  one atomic file replacement when the persistent constructor is used.
- Wallet custody uses one WKEK for the root and the per-wallet policy-signing
  key. Credential and recovery wraps use the exact JCS AAD specified in
  sections 13.2 and 13.5, including the encrypted-root ciphertext fingerprint.
  Persistent custody mutations likewise publish by atomic file replacement.
- Policy authorization stores the JCS of the complete compare-and-swap
  request only after an independent ceremony-verifier signature succeeds. The
  installed wallet-specific policy public key must match both the wallet ID and the
  unlocked WKEK-wrapped signing key before Signer signs and commits a new
  snapshot.
- The backup set aggregates encrypted custody, backend enrollment records and
  pinned keys, signed policy, the complete derivation registry
  (namespaces/next indices/allocated keys/tombstones), revocation epoch, and
  parser-free counters, approval records/tombstones, consumed attempts, and
  normalized operation results. Restore is self-contained and monotonic; a
  missing derivation registry disables new derivation. Backend availability is
  read live from the compiled backend registry, so restart-cleared activation
  cannot be overridden by stale database metadata.
- The top-level derivation registry is reconstructed from encrypted backend
  enrollment records and must match exactly on restore; independently supplied
  registry state cannot mark a wallet ready.
- Per-approval revoke and revoke-all write signed tombstones. Revoke-all
  atomically increments the wallet epoch, and `revocation_state` returns a
  Signer-signed digest/count tuple for Broker reconciliation. Revocation
  mutations share an operation-ID journal with their canonical signed result,
  so retries are stable and changed operation reuse is rejected.

The in-memory constructors are retained for deterministic unit tests. Service
wiring must use `WalletCustody::register_at`/`open_at` and
`LocalSignerBackend::provision_at`/`open_at`.
