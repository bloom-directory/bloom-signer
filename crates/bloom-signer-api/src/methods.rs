use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};

use crate::{ProtocolError, ProtocolErrorCode};

macro_rules! method_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
        pub enum $name {
            $(
                #[serde(rename = $wire)]
                $variant,
            )+
        }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire),+
                }
            }

            pub fn parse(value: &str) -> Result<Self, ProtocolError> {
                Self::ALL
                    .iter()
                    .copied()
                    .find(|method| method.as_str() == value)
                    .ok_or_else(|| {
                        ProtocolError::new(
                            ProtocolErrorCode::UnknownMethod,
                            format!("unknown method {value}"),
                        )
                    })
            }
        }
    };
}

method_enum!(BrokerSignerMethod {
    SystemHello => "system.hello",
    SignerReadiness => "signer.readiness",
    SignerCapabilities => "signer.capabilities",
    KeyGetPublic => "key.get_public",
    KeyListPublic => "key.list_public",
    KeyDerivationCapabilities => "key.derivation_capabilities",
    KeyDerivePrepare => "key.derive_prepare",
    KeyListDerived => "key.list_derived",
    DerivedAccountList => "wallet.derived_accounts",
    KeyEnrollPrepare => "key.enroll_prepare",
    KeyEnrollStatus => "key.enroll_status",
    CeremonyPrepare => "ceremony.prepare",
    CeremonyComplete => "ceremony.complete",
    CeremonyStatus => "ceremony.status",
    CeremonyCancel => "ceremony.cancel",
    SealedApprovalStatus => "sealed_approval.status",
    SealedApprovalRevoke => "sealed_approval.revoke",
    SealedApprovalRevokeAll => "sealed_approval.revoke_all",
    RevocationState => "revocation.state",
    SignerSign => "signer.sign",
    SignerSignBatch => "signer.sign_batch",
    OperationStatus => "operation.status",
    PolicyRead => "policy.read",
    PolicyCompareAndSwap => "policy.compare_and_swap",
    WalletRegistrationPrepare => "wallet.registration_prepare",
    WalletRegistrationStatus => "wallet.registration_status",
    WalletUnlockPrepare => "wallet.unlock_prepare",
    WalletImportPrepare => "wallet.import_prepare",
    WalletExportPrepare => "wallet.export_prepare",
    WalletDeletePrepare => "wallet.delete_prepare",
    CredentialListPublic => "credential.list_public",
    CredentialAddPrepare => "credential.add_prepare",
    CredentialRemovePrepare => "credential.remove_prepare",
    CredentialReplacePrepare => "credential.replace_prepare",
    RecoveryPrepare => "recovery.prepare",
    CustodyBindOutputRecipient => "custody.bind_output_recipient",
    CustodyComplete => "custody.complete",
    CustodyResult => "custody.result",
    CustodyStatus => "custody.status",
});

impl BrokerSignerMethod {
    /// Whether this method may be served without consuming mutation quota
    /// and while the audit chain is degraded.
    ///
    /// This is the single source of truth. It is an exhaustive match rather
    /// than a name-shape rule for two reasons the previous suffix heuristic
    /// demonstrated: `key.enroll_status` and `wallet.registration_status`
    /// end in `_status`, not `.status`, so a suffix rule silently classified
    /// two reads as mutations; and a new read method (`wallet.derived_accounts`)
    /// was simply absent from the list. Being a match on the enum, adding a
    /// variant now fails to compile until it is classified.
    pub const fn is_read_only(self) -> bool {
        match self {
            Self::SystemHello
            | Self::SignerReadiness
            | Self::SignerCapabilities
            | Self::KeyGetPublic
            | Self::KeyListPublic
            | Self::KeyDerivationCapabilities
            | Self::KeyListDerived
            | Self::DerivedAccountList
            | Self::KeyEnrollStatus
            | Self::CeremonyStatus
            | Self::SealedApprovalStatus
            | Self::RevocationState
            | Self::OperationStatus
            | Self::PolicyRead
            | Self::WalletRegistrationStatus
            | Self::CredentialListPublic
            | Self::CustodyResult
            | Self::CustodyStatus => true,

            Self::KeyDerivePrepare
            | Self::KeyEnrollPrepare
            | Self::CeremonyPrepare
            | Self::CeremonyComplete
            | Self::CeremonyCancel
            | Self::SealedApprovalRevoke
            | Self::SealedApprovalRevokeAll
            | Self::SignerSign
            | Self::SignerSignBatch
            | Self::PolicyCompareAndSwap
            | Self::WalletRegistrationPrepare
            | Self::WalletUnlockPrepare
            | Self::WalletImportPrepare
            | Self::WalletExportPrepare
            | Self::WalletDeletePrepare
            | Self::CredentialAddPrepare
            | Self::CredentialRemovePrepare
            | Self::CredentialReplacePrepare
            | Self::RecoveryPrepare
            | Self::CustodyBindOutputRecipient
            | Self::CustodyComplete => false,
        }
    }
}

method_enum!(ControlMethod {
    Revoke => "control.revoke",
    RevokeAll => "control.revoke_all",
    Status => "control.status",
});

pub type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ProtocolError>> + Send + 'a>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_methods_fail_closed() {
        assert_eq!(
            BrokerSignerMethod::parse("signing.sign").unwrap_err().code,
            ProtocolErrorCode::UnknownMethod
        );
    }
}
