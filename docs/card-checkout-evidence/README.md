# Card custody checkpoint, 2026-10-08

Production custody was validated at
`bfa213789dd3422ba25a5377369a3ef5b5d3c0f6` using
`cargo test --workspace --features triad-dev-harness --locked`, workspace /
all-target strict Clippy, formatting and committed dependency checks.
The retained test log contains 270 passing tests, zero failures and two ignored.

The first CI run exposed a fixture error under
`BLOOM_TRIAD_DEV_CEREMONY_PORT=28735`: the new test service hard-coded the
canonical port while its authenticator correctly used the configured dev
origin. The fixture now derives that same origin. Production origin checks
remain strict. Separate logs record the corrected dev-port and shipped-feature
test runs; do not treat the first failed CI run as passed.

The released-reader test uses compiled Signer engine/custody code from
`97b9ac7e47ee682e59804d04f6288419f3598a58`. It generates a released wallet,
opens it with current code, adds/releases a synthetic card in a separate file,
then reopens/decrypts the wallet with the released reader. This is not installed
daemon conformance. The initial failure log shows a pre-existing upstream
rollback limit when the wallet is instead freshly written by current Signer.
Reproduction source is `scripts/card-checkout-rollback-reader.rs`; the released
witness branch is `card-checkout-rollback` at
`837c8c60245e1e89d38fca45afa0e421ef653699`.

[Broker dependency decision](broker-dependency-decision.md) records why the
dependent Broker milestone cannot currently be stacked within the workspace's
one-unmerged-parent rule. Full checkout, packaging, UID isolation, release
conformance and live purchase tests remain unimplemented/unverified. This PR
provides Signer custody only and must not be described as enabling purchases.
