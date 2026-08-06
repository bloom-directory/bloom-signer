//! Versioned Broker-to-Signer contract owned by Bloom Signer.
//!
//! This crate contains wire-safe public metadata only. Private keys, decrypted
//! key objects, passkey PRF output, WKEK material, backend credentials, and
//! custody plaintext are deliberately unrepresentable here.

mod approval;
mod ceremony;
mod codec;
mod crypto;
mod error;
mod methods;
mod petal_key;
mod policy;
mod revocation;
mod service;
mod signing;
mod webauthn;

pub use approval::*;
pub use ceremony::*;
pub use codec::*;
pub use crypto::*;
pub use error::*;
pub use methods::*;
pub use petal_key::*;
pub use policy::*;
pub use revocation::*;
pub use service::*;
pub use signing::*;
pub use webauthn::*;

pub use bloom_rpc_wire::{
    AuthenticatedPeer, Base64UrlBytes, BootEpoch, DecimalU64, DecimalU256, Digest32, EnvelopeKind,
    FRAME_MAX_BYTES, HelloChallenge, JSON_MAX_DEPTH, JSON_MAX_LIST_LENGTH, JSON_MAX_STRING_BYTES,
    JournalHeadPolicy, OperationId, ProtocolVersion, ProtocolVersionRange, RPC_ENVELOPE_SCHEMA_V1,
    RequestNonce, SignedEnvelope, SignedJournalHead, Token, TypedRequestMethod, UnsignedEnvelope,
    WireError, WireErrorCode, decode_frame, encode_frame,
};

/// Broker-to-Signer authority contract. Version 1.3 adds the bounded legacy
/// passkey-migration metadata carried by `wallet.import_prepare`.
pub const SIGNER_API_MAJOR: u16 = 1;
pub const SIGNER_API_MINOR_MIN: u16 = 3;
pub const SIGNER_API_MINOR_MAX: u16 = 3;
pub const SIGNER_API_CURRENT: ProtocolVersion =
    ProtocolVersion::new(SIGNER_API_MAJOR, SIGNER_API_MINOR_MAX);
pub const SIGNER_API_RANGE: ProtocolVersionRange =
    ProtocolVersionRange::new(SIGNER_API_MAJOR, SIGNER_API_MINOR_MIN, SIGNER_API_MINOR_MAX);

/// Version policy for the non-authority revocation-control endpoint.
pub const SIGNER_CONTROL_CURRENT: ProtocolVersion = ProtocolVersion::new(1, 1);
pub const SIGNER_CONTROL_RANGE: ProtocolVersionRange = ProtocolVersionRange::new(1, 0, 1);

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn signer_api_range_accepts_the_frozen_current_authority_contract() {
        assert!(SIGNER_API_RANGE.contains(SIGNER_API_CURRENT));
    }

    #[test]
    fn signer_api_range_rejects_incompatible_versions() {
        assert!(!SIGNER_API_RANGE.contains(ProtocolVersion::new(
            SIGNER_API_MAJOR + 1,
            SIGNER_API_MINOR_MIN,
        )));
        assert!(!SIGNER_API_RANGE.contains(ProtocolVersion::new(
            SIGNER_API_MAJOR,
            SIGNER_API_MINOR_MIN - 1,
        )));
    }

    #[test]
    fn signer_control_accepts_1_0_and_current_but_rejects_incompatible_versions() {
        assert!(SIGNER_CONTROL_RANGE.contains(ProtocolVersion::new(1, 0)));
        assert!(SIGNER_CONTROL_RANGE.contains(SIGNER_CONTROL_CURRENT));
        assert!(!SIGNER_CONTROL_RANGE.contains(ProtocolVersion::new(2, 0)));
        assert!(!SIGNER_CONTROL_RANGE.contains(ProtocolVersion::new(1, 2)));
    }
}
