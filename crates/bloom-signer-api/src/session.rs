//! Owner-reviewed session scopes and exact asset-unit accounting. Nominal units
//! are a reviewed conversion convention, never an oracle claim about USD value.
use crate::{
    ApprovalLimits, AssetId, DecimalU64, DecimalU256, Digest32, KeyRef, PolicyDestination,
    ProtocolError, ProtocolErrorCode, Token, ValueWindow,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemSessionAction {
    NativeTransfer,
    Erc20Transfer,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SystemSessionChain {
    Evm { chain: Token, chain_id: DecimalU64 },
    Solana { chain: Token, genesis_hash: String },
}
impl SystemSessionChain {
    pub fn chain(&self) -> &Token {
        match self {
            Self::Evm { chain, .. } | Self::Solana { chain, .. } => chain,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionValueCeiling {
    pub asset: AssetId,
    pub maximum: DecimalU256,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSessionScope {
    pub component_id: Token,
    pub actions: Vec<SystemSessionAction>,
    pub chains: Vec<SystemSessionChain>,
    pub destinations: Vec<PolicyDestination>,
    pub tokens: Vec<AssetId>,
    pub per_action_value_limits: Vec<SessionValueCeiling>,
}
impl SystemSessionScope {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self
            .chains
            .iter()
            .any(|c| matches!(c, SystemSessionChain::Solana { .. }))
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SelectorMismatch,
                "reusable Solana sessions require a trusted cluster/freshness gate; use exact approval",
            ));
        }
        if self.component_id.as_str() != "bloom-machine"
            || self.actions.is_empty()
            || self.actions.len() > 2
            || self.chains.is_empty()
            || self.chains.len() > 64
            || self.destinations.is_empty()
            || self.destinations.len() > 256
            || self.per_action_value_limits.is_empty()
            || self.per_action_value_limits.len() > 128
            || self
                .actions
                .iter()
                .enumerate()
                .any(|(i, a)| self.actions[..i].contains(a))
            || self.chains.iter().any(|c| match c {
                SystemSessionChain::Evm { chain, chain_id } => {
                    !matches!(chain_id.get(), 1 | 137 | 31337)
                        || chain.as_str() != format!("evm-{}", chain_id.get())
                }
                SystemSessionChain::Solana { genesis_hash, .. } => {
                    genesis_hash.is_empty() || genesis_hash.len() > 64
                }
            })
            || self
                .destinations
                .iter()
                .any(|d| !self.chains.iter().any(|c| c.chain() == &d.chain))
            || self
                .per_action_value_limits
                .iter()
                .any(|c| c.maximum.as_str() == "0")
        {
            return Err(invalid("invalid typed System session scope"));
        }
        Ok(())
    }
}

/// The caller's semantic projection. Broker independently reconstructs this
/// from the complete signing preimage; the projection cannot authorize bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSessionUse {
    pub action: SystemSessionAction,
    pub chain: SystemSessionChain,
    pub token: Option<AssetId>,
    pub recipient: String,
    pub amount: DecimalU256,
    pub maximum_fee: DecimalU256,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAssetAmount {
    pub asset: AssetId,
    pub amount: DecimalU256,
}

/// Base units representing one reviewed nominal collateral unit. E.g. USDC
/// with six decimals uses 1_000_000. Accounting rounds upward to micro-units.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAssetScale {
    pub asset: AssetId,
    pub units_per_nominal_unit: DecimalU256,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionNominalLimits {
    pub per_action: DecimalU256,
    pub lifetime: DecimalU256,
    pub rolling_windows: Vec<ValueWindow>,
}

/// Every member approval signs this complete descriptor. The identifier is
/// derived from it, so a caller cannot reuse a chosen alias with different caps.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBudget {
    pub wallet_id: Token,
    pub policy_version: DecimalU64,
    pub policy_digest: Digest32,
    pub wallet_revocation_epoch: DecimalU64,
    pub member_keys: Vec<KeyRef>,
    pub limits: ApprovalLimits,
    pub nominal_asset_scales: Vec<SessionAssetScale>,
    pub nominal_limits: SessionNominalLimits,
    /// Includes separately stated native-fee/transfer caps. Unknown assets
    /// never count as free merely because they lack a nominal conversion.
    pub per_action_value_limits: Vec<SessionValueCeiling>,
    pub not_before_ms: DecimalU64,
    pub expires_at_ms: DecimalU64,
}
impl SessionBudget {
    pub fn budget_id(&self) -> Result<Digest32, ProtocolError> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(b"bloom-session-budget/v1");
        h.update(
            serde_jcs::to_vec(self)
                .map_err(|_| invalid("session budget cannot be canonicalized"))?,
        );
        Ok(Digest32::from_bytes(h.finalize().into()))
    }
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.member_keys.is_empty()
            || self.member_keys.len() > 128
            || self.expires_at_ms.get() <= self.not_before_ms.get()
            || self.limits.max_operations.get() == 0
            || self.limits.max_signatures.get() == 0
            || self.nominal_limits.per_action.as_str() == "0"
            || self.nominal_limits.lifetime.as_str() == "0"
            || self.nominal_asset_scales.len() > 128
            || self.per_action_value_limits.is_empty()
            || self.per_action_value_limits.len() > 128
            || self
                .nominal_asset_scales
                .iter()
                .any(|s| s.units_per_nominal_unit.as_str() == "0")
            || self.nominal_asset_scales.iter().enumerate().any(|(i, s)| {
                self.nominal_asset_scales[..i]
                    .iter()
                    .any(|x| x.asset == s.asset)
            })
            || self
                .per_action_value_limits
                .iter()
                .enumerate()
                .any(|(i, s)| {
                    s.maximum.as_str() == "0"
                        || self.per_action_value_limits[..i]
                            .iter()
                            .any(|x| x.asset == s.asset)
                })
            || self
                .nominal_limits
                .rolling_windows
                .iter()
                .any(|w| w.maximum.as_str() == "0" || w.duration_ms.get() == 0)
        {
            return Err(invalid("invalid immutable session budget"));
        }
        crate::approval::validate_limits(&self.limits)?;
        if self
            .member_keys
            .iter()
            .enumerate()
            .any(|(i, k)| self.member_keys[..i].contains(k))
        {
            return Err(invalid("duplicate session member key"));
        }
        for k in &self.member_keys {
            k.validate()?;
        }
        Ok(())
    }
}

/// Authenticated Broker projection consumed by Signer's parser-free backstop.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAccounting {
    pub system_use: Option<SystemSessionUse>,
    pub values: Vec<SessionAssetAmount>,
    pub budget_id: Option<Digest32>,
}
fn invalid(message: &str) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::MalformedFrame, message)
}

impl SessionAccounting {
    pub fn digest(&self) -> Digest32 {
        let bytes = serde_jcs::to_vec(self).expect("closed session accounting serializes");
        Digest32::from_bytes(Sha256::digest(bytes).into())
    }
}
impl SystemSessionUse {
    pub fn accounting(
        &self,
        budget: Option<&SessionBudget>,
    ) -> Result<SessionAccounting, ProtocolError> {
        let chain = self.chain.chain().clone();
        let asset = self.token.clone().unwrap_or_else(|| AssetId {
            chain: chain.clone(),
            asset: "native".into(),
        });
        if asset.chain != chain {
            return Err(invalid("session token belongs to another chain"));
        }
        let mut values = vec![SessionAssetAmount {
            asset,
            amount: self.amount.clone(),
        }];
        if self.maximum_fee.as_str() != "0" {
            values.push(SessionAssetAmount {
                asset: AssetId {
                    chain,
                    asset: "native".into(),
                },
                amount: self.maximum_fee.clone(),
            });
        }
        Ok(SessionAccounting {
            system_use: Some(self.clone()),
            values: SessionAccounting::canonical_values(&values)?,
            budget_id: budget.map(SessionBudget::budget_id).transpose()?,
        })
    }
}

impl SessionBudget {
    /// Checked conservative conversion and per-action limits. Returns nominal
    /// micro-units; unscaled assets require separately signed raw-unit caps.
    pub fn action_nominal_quantity(
        &self,
        values: &[SessionAssetAmount],
    ) -> Result<DecimalU256, ProtocolError> {
        use num_bigint::BigUint;
        use std::str::FromStr;
        self.validate()?;
        let mut totals: Vec<(AssetId, BigUint)> = Vec::new();
        for v in values {
            let n = BigUint::from_str(v.amount.as_str())
                .map_err(|_| invalid("invalid session amount"))?;
            if let Some((_, total)) = totals.iter_mut().find(|(a, _)| a == &v.asset) {
                *total += n;
            } else {
                totals.push((v.asset.clone(), n));
            }
        }
        let mut nominal = BigUint::from(0u8);
        for (asset, amount) in totals {
            let cap = self
                .per_action_value_limits
                .iter()
                .find(|v| v.asset == asset)
                .ok_or_else(|| invalid("asset has no signed per-action session ceiling"))?;
            if amount
                > BigUint::from_str(cap.maximum.as_str())
                    .map_err(|_| invalid("invalid session ceiling"))?
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::LimitExceededValue,
                    "session per-action asset ceiling exceeded",
                ));
            }
            if let Some(scale) = self.nominal_asset_scales.iter().find(|s| s.asset == asset) {
                let divisor = BigUint::from_str(scale.units_per_nominal_unit.as_str())
                    .map_err(|_| invalid("invalid nominal scale"))?;
                nominal += (amount * BigUint::from(1_000_000u64) + &divisor - BigUint::from(1u8))
                    / divisor;
            } else if !self.limits.value_limits.iter().any(|v| v.asset == asset) {
                return Err(invalid(
                    "unscaled asset has no separately signed unit budget",
                ));
            }
        }
        if nominal
            > BigUint::from_str(self.nominal_limits.per_action.as_str())
                .map_err(|_| invalid("invalid nominal ceiling"))?
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::LimitExceededValue,
                "session nominal per-action ceiling exceeded",
            ));
        }
        DecimalU256::parse(nominal.to_string())
            .map_err(|_| invalid("nominal session quantity overflow"))
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRecordedUse {
    pub accepted_at_ms: u64,
    pub signature_count: u64,
    pub values: Vec<SessionAssetAmount>,
}
impl SessionBudget {
    /// Called while the authoritative ledger's write transaction is held.
    /// Reserved, committed and ambiguous records all remain in `previous`.
    pub fn check_reservation(
        &self,
        previous: &[SessionRecordedUse],
        current: &SessionRecordedUse,
    ) -> Result<(), ProtocolError> {
        use num_bigint::BigUint;
        use std::str::FromStr;
        self.validate()?;
        if current.accepted_at_ms < self.not_before_ms.get()
            || current.accepted_at_ms >= self.expires_at_ms.get()
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ApprovalExpired,
                "session budget is outside its validity window",
            ));
        }
        if current.signature_count == 0
            || previous.len() as u64 >= self.limits.max_operations.get()
            || previous
                .iter()
                .try_fold(current.signature_count, |n, p| {
                    n.checked_add(p.signature_count)
                })
                .is_none_or(|n| n > self.limits.max_signatures.get())
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::LimitExceededOperations,
                "shared session operation/signature ceiling exceeded",
            ));
        }
        let number = |s: &DecimalU256| {
            BigUint::from_str(s.as_str()).map_err(|_| invalid("invalid budget quantity"))
        };
        let current_nominal = number(&self.action_nominal_quantity(&current.values)?)?;
        let mut nominal = current_nominal.clone();
        for p in previous {
            nominal += number(&self.action_nominal_quantity(&p.values)?)?;
        }
        if nominal > number(&self.nominal_limits.lifetime)? {
            return Err(ProtocolError::new(
                ProtocolErrorCode::LimitExceededValue,
                "shared nominal lifetime budget exceeded",
            ));
        }
        for w in &self.nominal_limits.rolling_windows {
            let start = current.accepted_at_ms.saturating_sub(w.duration_ms.get());
            let mut total = current_nominal.clone();
            for p in previous.iter().filter(|p| p.accepted_at_ms > start) {
                total += number(&self.action_nominal_quantity(&p.values)?)?;
            }
            if total > number(&w.maximum)? {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::LimitExceededValue,
                    "shared nominal rolling budget exceeded",
                ));
            }
        }
        for cap in &self.limits.value_limits {
            let sum = |cutoff: Option<u64>| -> Result<BigUint, ProtocolError> {
                let mut total = BigUint::from(0u8);
                for p in std::iter::once(current).chain(
                    previous
                        .iter()
                        .filter(|p| cutoff.is_none_or(|c| p.accepted_at_ms > c)),
                ) {
                    for v in p.values.iter().filter(|v| v.asset == cap.asset) {
                        total += number(&v.amount)?;
                    }
                }
                Ok(total)
            };
            if sum(None)? > number(&cap.lifetime)? {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::LimitExceededValue,
                    "shared asset-unit lifetime budget exceeded",
                ));
            }
            for w in &cap.rolling_windows {
                if sum(Some(
                    current.accepted_at_ms.saturating_sub(w.duration_ms.get()),
                ))? > number(&w.maximum)?
                {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::LimitExceededValue,
                        "shared asset-unit rolling budget exceeded",
                    ));
                }
            }
        }
        for w in &self.limits.operation_rate_limits {
            let count = previous
                .iter()
                .filter(|p| {
                    p.accepted_at_ms > current.accepted_at_ms.saturating_sub(w.duration_ms.get())
                })
                .count() as u64;
            if count >= w.maximum.get() {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::SignerRateBackstopDenied,
                    "shared session operation rate exceeded",
                ));
            }
        }
        for w in &self.limits.signature_rate_limits {
            let count = previous
                .iter()
                .filter(|p| {
                    p.accepted_at_ms > current.accepted_at_ms.saturating_sub(w.duration_ms.get())
                })
                .try_fold(current.signature_count, |n, p| {
                    n.checked_add(p.signature_count)
                });
            if count.is_none_or(|n| n > w.maximum.get()) {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::SignerRateBackstopDenied,
                    "shared session signature rate exceeded",
                ));
            }
        }
        Ok(())
    }
}

impl SessionAccounting {
    pub fn canonical_values(
        values: &[SessionAssetAmount],
    ) -> Result<Vec<SessionAssetAmount>, ProtocolError> {
        use num_bigint::BigUint;
        use std::{collections::BTreeMap, str::FromStr};
        let mut totals = BTreeMap::<(String, String), BigUint>::new();
        for v in values {
            *totals
                .entry((v.asset.chain.as_str().to_owned(), v.asset.asset.clone()))
                .or_default() += BigUint::from_str(v.amount.as_str())
                .map_err(|_| invalid("invalid session asset quantity"))?;
        }
        totals
            .into_iter()
            .map(|((chain, asset), n)| {
                Ok(SessionAssetAmount {
                    asset: AssetId {
                        chain: Token::new(chain)?,
                        asset,
                    },
                    amount: DecimalU256::parse(n.to_string())
                        .map_err(|_| invalid("session asset quantity overflow"))?,
                })
            })
            .collect()
    }
}

impl SystemSessionScope {
    pub fn validate_use(&self, use_: &SystemSessionUse) -> Result<(), ProtocolError> {
        use num_bigint::BigUint;
        use std::str::FromStr;
        self.validate()?;
        if !self.actions.contains(&use_.action)
            || !self.chains.contains(&use_.chain)
            || !self.destinations.iter().any(|d| {
                &d.chain == use_.chain.chain()
                    && match use_.chain {
                        SystemSessionChain::Evm { .. } => {
                            d.destination.eq_ignore_ascii_case(&use_.recipient)
                        }
                        SystemSessionChain::Solana { .. } => d.destination == use_.recipient,
                    }
            })
            || match (&use_.action, &use_.token) {
                (SystemSessionAction::NativeTransfer, None) => false,
                (SystemSessionAction::Erc20Transfer, Some(token)) => {
                    !self.tokens.contains(token)
                        || !matches!(use_.chain, SystemSessionChain::Evm { .. })
                }
                _ => true,
            }
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SelectorMismatch,
                "transfer is outside the immutable session scope",
            ));
        }
        let accounting = use_.accounting(None)?;
        for v in accounting.values {
            let cap = self
                .per_action_value_limits
                .iter()
                .find(|c| c.asset == v.asset)
                .ok_or_else(|| invalid("session asset has no per-action limit"))?;
            if BigUint::from_str(v.amount.as_str())
                .map_err(|_| invalid("invalid session quantity"))?
                > BigUint::from_str(cap.maximum.as_str())
                    .map_err(|_| invalid("invalid session ceiling"))?
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::LimitExceededValue,
                    "typed session per-action ceiling exceeded",
                ));
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeySpec, ValueLimit};
    fn n(v: &str) -> DecimalU256 {
        DecimalU256::parse(v).unwrap()
    }
    fn token(s: &str) -> Token {
        Token::new(s).unwrap()
    }
    fn asset(s: &str) -> AssetId {
        AssetId {
            chain: token("polygon"),
            asset: s.into(),
        }
    }
    fn budget() -> SessionBudget {
        SessionBudget {
            wallet_id: token("main"),
            policy_version: DecimalU64::new(1),
            policy_digest: Digest32::from_bytes([1; 32]),
            wallet_revocation_epoch: DecimalU64::new(0),
            member_keys: vec![KeyRef {
                backend: token("local"),
                backend_instance: token("test"),
                locator: "test-key".into(),
                key_spec: KeySpec::Secp256k1,
                public_key_fingerprint: Digest32::from_bytes([2; 32]),
                derivation: None,
            }],
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(10),
                max_signatures: DecimalU64::new(10),
                operation_rate_limits: vec![],
                signature_rate_limits: vec![],
                value_limits: vec![ValueLimit {
                    asset: asset("native"),
                    lifetime: n("1000"),
                    rolling_windows: vec![],
                }],
            },
            nominal_asset_scales: vec![
                SessionAssetScale {
                    asset: asset("usdc"),
                    units_per_nominal_unit: n("1000000"),
                },
                SessionAssetScale {
                    asset: asset("pusd"),
                    units_per_nominal_unit: n("1000000"),
                },
            ],
            nominal_limits: SessionNominalLimits {
                per_action: n("7000000"),
                lifetime: n("10000000"),
                rolling_windows: vec![ValueWindow {
                    maximum: n("10000000"),
                    duration_ms: DecimalU64::new(100),
                }],
            },
            per_action_value_limits: vec![
                SessionValueCeiling {
                    asset: asset("usdc"),
                    maximum: n("7000000"),
                },
                SessionValueCeiling {
                    asset: asset("pusd"),
                    maximum: n("7000000"),
                },
                SessionValueCeiling {
                    asset: asset("native"),
                    maximum: n("100"),
                },
            ],
            not_before_ms: DecimalU64::new(1),
            expires_at_ms: DecimalU64::new(1000),
        }
    }
    fn use_(name: &str, quantity: &str, time: u64) -> SessionRecordedUse {
        SessionRecordedUse {
            accepted_at_ms: time,
            signature_count: 1,
            values: vec![SessionAssetAmount {
                asset: asset(name),
                amount: n(quantity),
            }],
        }
    }
    #[test]
    fn shared_budget_sums_distinct_collateral_assets_and_retains_reserved_uses() {
        let b = budget();
        let first = use_("usdc", "6000000", 10);
        let second = use_("pusd", "5000000", 11);
        b.check_reservation(&[], &first).unwrap();
        assert!(b.check_reservation(&[first], &second).is_err());
    }
    #[test]
    fn unknown_asset_and_per_action_excess_are_never_free() {
        let b = budget();
        assert!(
            b.check_reservation(&[], &use_("shares:42", "1", 10))
                .is_err()
        );
        assert!(
            b.check_reservation(&[], &use_("usdc", "7000001", 10))
                .is_err()
        );
        b.check_reservation(&[], &use_("native", "100", 10))
            .unwrap();
        assert!(
            b.check_reservation(&[], &use_("native", "101", 10))
                .is_err()
        );
    }
    #[test]
    fn group_identity_commits_caps_keys_and_asset_scales() {
        let b = budget();
        let id = b.budget_id().unwrap();
        let mut changed = b.clone();
        changed.nominal_limits.lifetime = n("20000000");
        assert_ne!(id, changed.budget_id().unwrap());
        changed = b.clone();
        changed.member_keys[0].locator = "other-key".into();
        assert_ne!(id, changed.budget_id().unwrap());
        changed = b.clone();
        changed.nominal_asset_scales[0].units_per_nominal_unit = n("1000000000000000000");
        assert_ne!(id, changed.budget_id().unwrap());
    }
    #[test]
    fn conversion_rounds_up_and_duplicate_values_cannot_split_the_cap() {
        let mut b = budget();
        b.nominal_asset_scales[0].units_per_nominal_unit = n("1000000000000000000");
        assert_eq!(
            b.action_nominal_quantity(&[SessionAssetAmount {
                asset: asset("usdc"),
                amount: n("1")
            }])
            .unwrap(),
            n("1")
        );
        let b = budget();
        assert!(
            b.action_nominal_quantity(&[
                SessionAssetAmount {
                    asset: asset("usdc"),
                    amount: n("4000000")
                },
                SessionAssetAmount {
                    asset: asset("usdc"),
                    amount: n("4000000")
                }
            ])
            .is_err()
        );
    }
    #[test]
    fn rolling_limits_age_but_lifetime_caps_do_not_reset() {
        let mut b = budget();
        b.nominal_limits.lifetime = n("20000000");
        let previous = use_("usdc", "6000000", 10);
        let next = use_("pusd", "5000000", 11);
        assert!(
            b.check_reservation(std::slice::from_ref(&previous), &next)
                .is_err()
        );
        let aged = use_("pusd", "5000000", 111);
        b.check_reservation(&[previous], &aged).unwrap();
        assert!(b.check_reservation(&[], &use_("usdc", "1", 1000)).is_err());
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionWindowState {
    pub duration_ms: DecimalU64,
    pub maximum: DecimalU256,
    pub used: DecimalU256,
    pub remaining: DecimalU256,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBudgetState {
    pub budget_id: Digest32,
    pub observed_at_ms: DecimalU64,
    pub operations: DecimalU64,
    pub signatures: DecimalU64,
    pub nominal_used: DecimalU256,
    pub nominal_remaining: DecimalU256,
    pub rolling_windows: Vec<SessionWindowState>,
    pub asset_usage: Vec<SessionAssetAmount>,
    /// Totals include outstanding reservations and ambiguous outcomes.
    pub includes_reserved_and_quarantined: bool,
}
impl SessionBudget {
    pub fn usage_state(
        &self,
        previous: &[SessionRecordedUse],
        now: u64,
    ) -> Result<SessionBudgetState, ProtocolError> {
        use num_bigint::BigUint;
        use std::str::FromStr;
        let n = |v: &DecimalU256| {
            BigUint::from_str(v.as_str()).map_err(|_| invalid("invalid session quantity"))
        };
        let decimal = |v: BigUint| {
            DecimalU256::parse(v.to_string()).map_err(|_| invalid("session usage overflow"))
        };
        let mut total = BigUint::from(0u8);
        let mut signatures = 0u64;
        let mut values = Vec::new();
        for p in previous {
            total += n(&self.action_nominal_quantity(&p.values)?)?;
            signatures = signatures
                .checked_add(p.signature_count)
                .ok_or_else(|| invalid("session signature usage overflow"))?;
            values.extend_from_slice(&p.values);
        }
        let remaining = |maximum: BigUint, used: &BigUint| {
            if maximum > *used {
                maximum - used
            } else {
                BigUint::from(0u8)
            }
        };
        let mut windows = Vec::new();
        for w in &self.nominal_limits.rolling_windows {
            let mut used = BigUint::from(0u8);
            for p in previous
                .iter()
                .filter(|p| p.accepted_at_ms > now.saturating_sub(w.duration_ms.get()))
            {
                used += n(&self.action_nominal_quantity(&p.values)?)?;
            }
            windows.push(SessionWindowState {
                duration_ms: w.duration_ms.clone(),
                maximum: w.maximum.clone(),
                remaining: decimal(remaining(n(&w.maximum)?, &used))?,
                used: decimal(used)?,
            });
        }
        Ok(SessionBudgetState {
            budget_id: self.budget_id()?,
            observed_at_ms: DecimalU64::new(now),
            operations: DecimalU64::new(previous.len() as u64),
            signatures: DecimalU64::new(signatures),
            nominal_remaining: decimal(remaining(n(&self.nominal_limits.lifetime)?, &total))?,
            nominal_used: decimal(total)?,
            rolling_windows: windows,
            asset_usage: SessionAccounting::canonical_values(&values)?,
            includes_reserved_and_quarantined: true,
        })
    }
}

impl SessionBudget {
    pub fn requires_trusted_time(&self) -> bool {
        !self.nominal_limits.rolling_windows.is_empty()
            || !self.limits.operation_rate_limits.is_empty()
            || !self.limits.signature_rate_limits.is_empty()
            || self
                .limits
                .value_limits
                .iter()
                .any(|v| !v.rolling_windows.is_empty())
    }
}

#[cfg(test)]
#[test]
fn native_session_scope_refuses_unpriced_layer_two_fees_and_sol_freshness() {
    let mut scope = SystemSessionScope {
        component_id: Token::new("bloom-machine").unwrap(),
        actions: vec![SystemSessionAction::NativeTransfer],
        chains: vec![SystemSessionChain::Evm {
            chain: Token::new("evm-137").unwrap(),
            chain_id: DecimalU64::new(137),
        }],
        destinations: vec![PolicyDestination {
            chain: Token::new("evm-137").unwrap(),
            destination: "0x1111111111111111111111111111111111111111".into(),
        }],
        tokens: vec![],
        per_action_value_limits: vec![SessionValueCeiling {
            asset: AssetId {
                chain: Token::new("evm-137").unwrap(),
                asset: "native".into(),
            },
            maximum: DecimalU256::parse("100").unwrap(),
        }],
    };
    scope.validate().unwrap();
    for chain_id in [10, 8453] {
        scope.chains = vec![SystemSessionChain::Evm {
            chain: Token::new(format!("evm-{chain_id}")).unwrap(),
            chain_id: DecimalU64::new(chain_id),
        }];
        scope.destinations[0].chain = Token::new(format!("evm-{chain_id}")).unwrap();
        assert!(scope.validate().is_err());
    }
    scope.chains = vec![SystemSessionChain::Solana {
        chain: Token::new("solana").unwrap(),
        genesis_hash: "genesis".into(),
    }];
    assert!(scope.validate().unwrap_err().message.contains("freshness"));
}
