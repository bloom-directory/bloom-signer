# Broker dependency decision — rev 2

Implementation has reached a merge/dependency gate before milestone 2. This
is not a request to change the payment design or relax principal separation.

## Observed revisions

- Broker default: `85e9a99985b2d103a084fb2720015f2d61220093`.
- Current Signer default: `bc88ad690757165ebf1978410ea5c7ec652215d3`.
- Card Signer: `bfa213789dd3422ba25a5377369a3ef5b5d3c0f6`,
  [Signer #65](https://github.com/bloom-directory/bloom-signer/pull/65).
- Existing Broker compatibility work:
  [Broker #73](https://github.com/bloom-directory/bloom-broker/pull/73),
  head `5095af43ad22994cb0a0bdad07a1d7adcf2410eb`.

Broker default pins released Signer `97b9ac7e…` and service-runtime
`5db670e1…`. Current Signer uses landed runtime `ad007251…` and the
surface-bound ceremony protocol introduced by existing Signer #58.

## Executed diagnostic

In the initially clean, owned Broker worktree, temporarily pin the card
Signer API/vectors, then align the runtime to Signer's revision. Run
`cargo check -p bloom-broker --features triad-dev-harness`.

It fails with ten errors. Three are missing `surface` fields in existing
approval/custody requests; another is the existing RP identifier type change.
There is also the existing `AlreadyRegistered` state absent from Broker's
closed enum mapping. The remaining errors are the expected new card enum
arms. The debug driver separately lacks credential `surface` and uses the
old RP type. See [compiler output](broker-current-signer-incompatibility.log).

This is more than filling in compile-time defaults: current Signer's
`CustodyResult` and `CredentialSummary` include optional signed surface and
authority-generation fields, and contribution/challenge/HPKE bindings include
the surface. Broker default's public projection and canonical receipt bytes
omit these fields. An integration must preserve the signed identity rather
than discard it. Source anchors: Signer `ceremony.rs` in the API at lines
815–874; Broker API `ceremony.rs` at lines 630–682; Broker translation
`custody.rs` at lines 104–138, at the revisions above.

Existing Broker #73 implements this compatibility and surface handling.
Its fetched head was approved and CI-green, but the workspace `ready` gate
reported no recorded writer. It has open children #93 and #94; its description
also says no merge is requested by that stack and notes incomplete macOS
conformance. Approval alone does not establish authority to take over or
merge another owner's stack, or completion of its release gates.

## Decision

Do not duplicate the remote-ceremony implementation, erase signed bindings,
pin a pre-current Signer to avoid the issue, or build the card Broker above
both an unmerged Broker #73 and unmerged card Signer #65. The last option
violates the workspace's one-unmerged-parent rule, including Cargo pins.

The next integration checkpoint therefore requires the existing Broker
compatibility stack to land through its responsible owner's required gates.
Then fetch the landed revision, advance the owned Broker checkout, and build
the three card ceremonies with a single dependency on card Signer #65.
No other owner's checkout, branch, claim or service was changed.

The temporary manifest/lockfile diagnostic changes were restored to their
original committed contents. The Broker worktree is clean. This is a stop at
the mandate's merging gate; milestones 2–7 are not implemented or verified.
No dev Triad is ready and no live purchase session should be attempted.
