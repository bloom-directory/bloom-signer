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
