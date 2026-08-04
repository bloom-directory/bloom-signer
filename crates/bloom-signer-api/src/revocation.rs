use serde::{Deserialize, Serialize};

use crate::{Base64UrlBytes, DecimalU64, Digest32, OperationId, Token};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalTombstone {
    pub approval_id: Digest32,
    pub wallet_id: Token,
    pub wallet_revocation_epoch: DecimalU64,
    pub reason: String,
    pub operation_id: OperationId,
    pub revoked_at_ms: DecimalU64,
    pub issuer_service_id: Token,
    pub key_id: Token,
    pub signature: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletTombstone {
    pub wallet_id: Token,
    pub wallet_revocation_epoch: DecimalU64,
    pub operation_id: OperationId,
    pub revoked_at_ms: DecimalU64,
    pub issuer_service_id: Token,
    pub key_id: Token,
    pub signature: Base64UrlBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationState {
    pub wallet_id: Token,
    pub wallet_revocation_epoch: DecimalU64,
    pub wallet_tombstone: Option<WalletTombstone>,
    pub approval_tombstone_digest: Digest32,
    pub approval_tombstone_count: DecimalU64,
    pub observed_at_ms: DecimalU64,
    pub issuer_service_id: Token,
    pub key_id: Token,
    pub signature: Base64UrlBytes,
}

/// Signed revocation summary plus the exact append-only approval tombstone
/// union whose count and digest the summary authenticates.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationSnapshot {
    pub state: RevocationState,
    pub approval_tombstones: Vec<ApprovalTombstone>,
}
