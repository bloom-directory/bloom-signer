#!/bin/sh
set -eu

released_commit=ccc9adb3866b17b87d2774018dcfa015184b1918
workspace=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/bloom-signer-schema1.XXXXXX")
old_checkout="$scratch/released"
database="$scratch/released-schema1.sqlite3"
old_target="$workspace/target/released-schema1-$released_commit"

cleanup() {
  rm -f -- "$old_checkout/crates/bloom-signer/tests/released_schema1_fixture.rs"
  git -C "$workspace" worktree remove "$old_checkout" >/dev/null 2>&1 || true
  rm -rf -- "$scratch"
}
trap cleanup EXIT HUP INT TERM

git -C "$workspace" worktree add --detach "$old_checkout" "$released_commit" >/dev/null
cp "$workspace/scripts/released_schema1_fixture.rs" \
  "$old_checkout/crates/bloom-signer/tests/released_schema1_fixture.rs"

(
  cd "$old_checkout"
  RELEASED_SIGNER_COMMIT="$released_commit" \
  BLOOM_RELEASED_SCHEMA1_DB="$database" \
  BLOOM_RELEASED_SCHEMA1_ACTION=generate \
  CARGO_TARGET_DIR="$old_target" \
    cargo test --locked -p bloom-signer --test released_schema1_fixture -- released_schema1_fixture_action
)

(
  cd "$workspace"
  BLOOM_RELEASED_SCHEMA1_DB="$database" \
    cargo test --locked -p bloom-signer --test released_schema1_compat -- released_schema1_state_migrates_and_preserves_wallet_access
)

(
  cd "$old_checkout"
  RELEASED_SIGNER_COMMIT="$released_commit" \
  BLOOM_RELEASED_SCHEMA1_DB="$database" \
  BLOOM_RELEASED_SCHEMA1_ACTION=rollback-open \
  CARGO_TARGET_DIR="$old_target" \
    cargo test --locked -p bloom-signer --test released_schema1_fixture -- released_schema1_fixture_action
)
