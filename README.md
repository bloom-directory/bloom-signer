# bloom-signer

Bloom's key custody and cryptographic-operation boundary.

The normative architecture is
[`2026-07-23-triad-process-architecture.md`](https://gist.github.com/josh-richardson/031521a48b6e044c443bc1e96e3703d2).

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

## Recovering a fail-closed clock after a restart

Signer will not sign while its durable clock is untrusted. The clock is trusted
only when the wall clock agrees with elapsed time that Signer can account for,
so any gap it cannot explain is rejected rather than assumed benign.

A **process** restart is credited automatically. The absolute monotonic anchor is
persisted, and elapsed time is taken from it, so downtime is recovered without
operator involvement.

A **reboot** is not. The kernel's suspend-aware clock restarts at zero, so the
persisted anchor belongs to a domain that no longer exists and cannot vouch for
the gap. If the wall clock has moved on by more than the maximum forward step,
the next observation is `FORWARD_JUMP_REJECTED` and requests fail with
`CLOCK_UNTRUSTED` until an operator repairs the clock. This is deliberate: the
alternative is accepting an unexplained forward jump, which is
indistinguishable from an attacker moving the clock to expire approvals or
extend a grant.

Repair is an explicit, audited operator action taken at startup.

```text
BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS=<unix-ms> bloom-signer …
```

`<unix-ms>` is the UTC time the operator vouches for. It may not be earlier than
the current effective time; moving effective time backwards is refused with
`CLOCK_ROLLBACK`. Repair also requires initialised clock state, and is
unavailable when the host wall clock is authoritative rather than the trusted
time source.

If repairing would expire live approvals, Signer refuses on the first attempt
and prints the accepted time, the approvals that would expire, and a
confirmation digest over both:

```text
Bloom Signer clock repair requires confirmation before mutation:
accepted_utc_ms=…, expiring_live_approvals=[…], confirmation_digest=…
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
