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
