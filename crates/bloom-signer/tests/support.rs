#![allow(dead_code)]
//! Test-only driver for Signer ceremony surfaces.
//!
//! This module is not linked by production Signer artifacts. It
//! produces genuine ES256 WebAuthn bytes and RFC 9180 HPKE envelopes so tests
//! exercise the same public contracts as a browser.

use bloom_signer_api::{
    Base64UrlBytes, DecimalU64, HpkeEnvelope, ProtocolError, ProtocolErrorCode, Token,
    WebAuthnAssertion, WebAuthnAttestation, WebAuthnCredential,
};
use ciborium::value::{Integer, Value};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, setup_sender,
};
use p256::ecdsa::{SigningKey, signature::Signer as _};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest as _, Sha256};

type BloomKem = X25519HkdfSha256;

pub struct VirtualAuthenticator {
    signing_key: SigningKey,
    credential_id: Base64UrlBytes,
    user_handle: Base64UrlBytes,
}

impl VirtualAuthenticator {
    pub fn generate() -> Self {
        let mut credential_id = [0_u8; 32];
        let mut user_handle = [0_u8; 32];
        OsRng.fill_bytes(&mut credential_id);
        OsRng.fill_bytes(&mut user_handle);
        Self {
            signing_key: SigningKey::random(&mut OsRng),
            credential_id: Base64UrlBytes::from_bytes(&credential_id),
            user_handle: Base64UrlBytes::from_bytes(&user_handle),
        }
    }

    pub fn generate_with_user_handle(user_handle: &[u8]) -> Self {
        let mut authenticator = Self::generate();
        authenticator.user_handle = Base64UrlBytes::from_bytes(user_handle);
        authenticator
    }

    pub fn legacy_passkey_json(&self, sign_count: u32) -> serde_json::Value {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        serde_json::json!({
            "cred": {
                "cred_id": self.credential_id,
                "cred": {"type_": "ES256", "key": {"EC_EC2": {
                    "curve": "SECP256R1",
                    "x": Base64UrlBytes::from_bytes(point.x().expect("P-256 x coordinate")),
                    "y": Base64UrlBytes::from_bytes(point.y().expect("P-256 y coordinate"))
                }}},
                "counter": sign_count,
                "transports": null,
                "user_verified": true,
                "backup_eligible": true,
                "backup_state": true,
                "registration_policy": null,
                "extensions": null,
                "attestation": null,
                "attestation_format": null
            }
        })
    }

    pub fn credential(&self, sign_count: u32) -> WebAuthnCredential {
        WebAuthnCredential {
            credential_id: self.credential_id.clone(),
            cose_public_key: Base64UrlBytes::from_bytes(
                &self.cose_public_key().expect("generated key encodes"),
            ),
            user_handle: self.user_handle.clone(),
            rp_id: Token::new("localhost").expect("static RP token"),
            prf_salt: Base64UrlBytes::from_bytes(&Sha256::digest(
                [
                    b"bloom-debug-driver-salt/v1".as_slice(),
                    self.credential_id.decode().as_slice(),
                ]
                .concat(),
            )),
            sign_count: DecimalU64::new(u64::from(sign_count)),
        }
    }

    pub fn assertion(&self, challenge: &[u8], sign_count: u32) -> WebAuthnAssertion {
        let client_data = client_data("webauthn.get", challenge);
        let authenticator_data = authenticator_data(0x05, sign_count);
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        let signature: p256::ecdsa::Signature = self.signing_key.sign(&message);
        WebAuthnAssertion {
            credential_id: self.credential_id.clone(),
            authenticator_data: Base64UrlBytes::from_bytes(&authenticator_data),
            client_data_json: Base64UrlBytes::from_bytes(&client_data),
            signature: Base64UrlBytes::from_bytes(signature.to_der().as_bytes()),
            user_handle: Some(self.user_handle.clone()),
        }
    }

    pub fn attestation(&self, challenge: &[u8]) -> WebAuthnAttestation {
        let mut auth_data = authenticator_data(0x45, 0);
        auth_data.extend_from_slice(&[0_u8; 16]);
        let credential_id = self.credential_id.decode();
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&credential_id);
        auth_data.extend_from_slice(&self.cose_public_key().expect("generated key encodes"));
        let object = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(Vec::new())),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&object, &mut encoded).expect("attestation encodes");
        WebAuthnAttestation {
            credential_id: self.credential_id.clone(),
            client_data_json: Base64UrlBytes::from_bytes(&client_data(
                "webauthn.create",
                challenge,
            )),
            attestation_object: Base64UrlBytes::from_bytes(&encoded),
            transports: vec![Token::new("internal").expect("static transport token")],
        }
    }

    pub fn deterministic_prf(&self) -> [u8; 32] {
        Sha256::digest(
            [
                b"bloom-debug-driver-prf/v1".as_slice(),
                self.credential_id.decode().as_slice(),
            ]
            .concat(),
        )
        .into()
    }

    fn cose_public_key(&self) -> Result<Vec<u8>, ProtocolError> {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        let x = point.x().ok_or_else(driver_error)?;
        let y = point.y().ok_or_else(driver_error)?;
        let value = Value::Map(vec![
            (integer(1), integer(2)),
            (integer(3), integer(-7)),
            (integer(-1), integer(1)),
            (integer(-2), Value::Bytes(x.to_vec())),
            (integer(-3), Value::Bytes(y.to_vec())),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&value, &mut encoded).map_err(|_| driver_error())?;
        Ok(encoded)
    }
}

pub fn seal_hpke(
    recipient_public_key: &Base64UrlBytes,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeEnvelope, ProtocolError> {
    let public_key = <BloomKem as KemTrait>::PublicKey::from_bytes(&recipient_public_key.decode())
        .map_err(|_| driver_error())?;
    let (encapped, mut context) = setup_sender::<ChaCha20Poly1305, HkdfSha256, BloomKem, _>(
        &OpModeS::Base,
        &public_key,
        info,
        &mut OsRng,
    )
    .map_err(|_| driver_error())?;
    let ciphertext = context.seal(plaintext, aad).map_err(|_| driver_error())?;
    Ok(HpkeEnvelope {
        kem_output: Base64UrlBytes::from_bytes(&encapped.to_bytes()),
        ciphertext: Base64UrlBytes::from_bytes(&ciphertext),
    })
}

fn client_data(kind: &str, challenge: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type": kind,
        "challenge": Base64UrlBytes::from_bytes(challenge),
        "origin": "http://localhost:18734",
        "crossOrigin": false
    }))
    .expect("client data serializes")
}

fn authenticator_data(flags: u8, sign_count: u32) -> Vec<u8> {
    let mut data = Sha256::digest(b"localhost").to_vec();
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    data
}

fn integer(value: i128) -> Value {
    Value::Integer(Integer::try_from(value).expect("small COSE integer"))
}

fn driver_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::BackendInvalidRequest,
        "debug driver could not construct standards-compliant proof",
    )
}
