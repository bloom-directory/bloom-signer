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
