use ciborium::value::{Integer, Value};
use p256::{
    EncodedPoint,
    ecdsa::{Signature, VerifyingKey, signature::Verifier as _},
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::io::Cursor;

use bloom_signer_api::{
    Base64UrlBytes, DecimalU64, ProtocolError, ProtocolErrorCode, Token, WebAuthnAssertion,
    WebAuthnAttestation, WebAuthnCredential,
};

pub const CEREMONY_ORIGIN: &str = "http://localhost:18734";
pub const CEREMONY_RP_ID: &str = "localhost";

fn configured_ceremony_origin() -> String {
    #[cfg(feature = "triad-dev-harness")]
    if let Some(value) = std::env::var_os("BLOOM_TRIAD_DEV_CEREMONY_PORT") {
        let value = value
            .into_string()
            .expect("BLOOM_TRIAD_DEV_CEREMONY_PORT must be UTF-8");
        let port = value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .expect("BLOOM_TRIAD_DEV_CEREMONY_PORT must be an integer from 1 to 65535");
        return format!("http://localhost:{port}");
    }
    CEREMONY_ORIGIN.to_owned()
}

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_ATTESTED_CREDENTIAL: u8 = 0x40;
const FLAG_EXTENSION_DATA: u8 = 0x80;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAssertion {
    pub credential_id: Base64UrlBytes,
    pub user_handle: Option<Base64UrlBytes>,
    pub sign_count: u32,
}

/// Verify a raw ES256 WebAuthn assertion against Signer-owned credential data.
///
/// The caller supplies the exact canonical challenge bytes. Both Broker and
/// Signer invoke this function independently; neither accepts a parsed or
/// "verified" assertion supplied by the other.
pub fn verify_webauthn_assertion(
    assertion: &WebAuthnAssertion,
    credential: &WebAuthnCredential,
    expected_challenge: &[u8],
    require_user_verification: bool,
) -> Result<VerifiedAssertion, ProtocolError> {
    if assertion.credential_id != credential.credential_id {
        return Err(proof_error(
            "credential ID does not match Signer enrollment",
        ));
    }
    verify_client_data(
        &assertion.client_data_json,
        "webauthn.get",
        expected_challenge,
    )?;

    let authenticator_data = assertion.authenticator_data.decode();
    let parsed = parse_authenticator_data(&authenticator_data, require_user_verification)?;
    let rp_hash: [u8; 32] = Sha256::digest(credential.rp_id.as_str().as_bytes()).into();
    if parsed.rp_id_hash != rp_hash {
        return Err(proof_error("authenticator RP ID hash is invalid"));
    }
    let previous = credential.sign_count.get();
    if previous > u32::MAX as u64
        || (parsed.sign_count != 0 && previous != 0 && u64::from(parsed.sign_count) <= previous)
    {
        return Err(proof_error(
            "authenticator signature counter did not advance",
        ));
    }

    let verifying_key = verifying_key_from_cose(&credential.cose_public_key)?;
    let signature = Signature::from_der(&assertion.signature.decode())
        .map_err(|_| proof_error("WebAuthn assertion signature is not canonical ES256 DER"))?;
    let client_hash = Sha256::digest(assertion.client_data_json.decode());
    let mut signed = authenticator_data;
    signed.extend_from_slice(&client_hash);
    verifying_key
        .verify(&signed, &signature)
        .map_err(|_| proof_error("WebAuthn assertion signature is invalid"))?;

    Ok(VerifiedAssertion {
        credential_id: assertion.credential_id.clone(),
        user_handle: assertion.user_handle.clone(),
        sign_count: parsed.sign_count,
    })
}

/// Verify a raw `fmt=none` WebAuthn creation response and extract its ES256 key.
pub fn verify_webauthn_attestation(
    attestation: &WebAuthnAttestation,
    expected_challenge: &[u8],
    expected_user_handle: Base64UrlBytes,
    expected_prf_salt: Base64UrlBytes,
) -> Result<WebAuthnCredential, ProtocolError> {
    verify_client_data(
        &attestation.client_data_json,
        "webauthn.create",
        expected_challenge,
    )?;
    let object: Value =
        ciborium::from_reader(attestation.attestation_object.decode().as_slice())
            .map_err(|_| proof_error("WebAuthn attestation object is malformed CBOR"))?;
    let map = value_map(&object, "attestation object")?;
    let format = text_field(map, "fmt")?;
    if format != "none" {
        return Err(proof_error(
            "only privacy-preserving WebAuthn fmt=none attestation is accepted",
        ));
    }
    let statement = map_field(map, "attStmt")
        .and_then(|value| value.as_map())
        .ok_or_else(|| proof_error("attestation statement is missing"))?;
    if !statement.is_empty() {
        return Err(proof_error("fmt=none attestation statement must be empty"));
    }
    let auth_data = bytes_field(map, "authData")?;
    let parsed = parse_authenticator_data(auth_data, true)?;
    if parsed.flags & FLAG_ATTESTED_CREDENTIAL == 0 {
        return Err(proof_error("attested credential data flag is absent"));
    }
    let rp_hash: [u8; 32] = Sha256::digest(CEREMONY_RP_ID.as_bytes()).into();
    if parsed.rp_id_hash != rp_hash {
        return Err(proof_error("attestation RP ID hash is invalid"));
    }
    if auth_data.len() < 55 {
        return Err(proof_error("attested credential data is truncated"));
    }
    let credential_id_len = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    let credential_end = 55usize
        .checked_add(credential_id_len)
        .filter(|end| *end <= auth_data.len())
        .ok_or_else(|| proof_error("attested credential ID is truncated"))?;
    let credential_id = &auth_data[55..credential_end];
    if credential_id != attestation.credential_id.decode() {
        return Err(proof_error(
            "attested credential ID does not match response ID",
        ));
    }

    let mut cursor = Cursor::new(&auth_data[credential_end..]);
    let cose: Value = ciborium::from_reader(&mut cursor)
        .map_err(|_| proof_error("attested COSE public key is malformed"))?;
    let cose_length = usize::try_from(cursor.position())
        .map_err(|_| proof_error("attested COSE public key length overflow"))?;
    let trailing = &auth_data[credential_end + cose_length..];
    if parsed.flags & FLAG_EXTENSION_DATA == 0 && !trailing.is_empty() {
        return Err(proof_error(
            "attestation has trailing data without the extension flag",
        ));
    }
    validate_cose_value(&cose)?;
    let cose_public_key = canonical_cbor(&cose)?;

    Ok(WebAuthnCredential {
        credential_id: attestation.credential_id.clone(),
        cose_public_key: Base64UrlBytes::from_bytes(&cose_public_key),
        user_handle: expected_user_handle,
        rp_id: Token::new(CEREMONY_RP_ID)?,
        prf_salt: expected_prf_salt,
        sign_count: DecimalU64::new(u64::from(parsed.sign_count)),
    })
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ceremony_type: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

fn verify_client_data(
    encoded: &Base64UrlBytes,
    expected_type: &str,
    expected_challenge: &[u8],
) -> Result<(), ProtocolError> {
    let decoded = encoded.decode();
    let data: ClientData = serde_json::from_slice(&decoded)
        .map_err(|_| proof_error("WebAuthn clientDataJSON is malformed"))?;
    if data.ceremony_type != expected_type
        || data.origin != configured_ceremony_origin()
        || data.cross_origin
        || Base64UrlBytes::parse(data.challenge)? != Base64UrlBytes::from_bytes(expected_challenge)
    {
        return Err(proof_error(
            "WebAuthn type, challenge, origin, or cross-origin binding is invalid",
        ));
    }
    Ok(())
}

struct ParsedAuthenticatorData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
}

fn parse_authenticator_data(
    data: &[u8],
    require_user_verification: bool,
) -> Result<ParsedAuthenticatorData, ProtocolError> {
    if data.len() < 37 {
        return Err(proof_error("authenticator data is truncated"));
    }
    let flags = data[32];
    if flags & FLAG_USER_PRESENT == 0
        || (require_user_verification && flags & FLAG_USER_VERIFIED == 0)
    {
        return Err(proof_error(
            "required WebAuthn user presence or verification flag is absent",
        ));
    }
    Ok(ParsedAuthenticatorData {
        rp_id_hash: data[..32].try_into().expect("length checked"),
        flags,
        sign_count: u32::from_be_bytes(data[33..37].try_into().expect("length checked")),
    })
}

fn verifying_key_from_cose(encoded: &Base64UrlBytes) -> Result<VerifyingKey, ProtocolError> {
    let cose: Value = ciborium::from_reader(encoded.decode().as_slice())
        .map_err(|_| proof_error("credential COSE public key is malformed"))?;
    let (x, y) = validate_cose_value(&cose)?;
    let point = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    VerifyingKey::from_encoded_point(&point)
        .map_err(|_| proof_error("credential ES256 public key is invalid"))
}

fn validate_cose_value(value: &Value) -> Result<(&[u8], &[u8]), ProtocolError> {
    let map = value_map(value, "COSE key")?;
    if integer_field(map, 1)? != 2 || integer_field(map, 3)? != -7 || integer_field(map, -1)? != 1 {
        return Err(proof_error(
            "credential key must be EC2 P-256 with the ES256 algorithm",
        ));
    }
    let x = integer_key_bytes(map, -2)?;
    let y = integer_key_bytes(map, -3)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(proof_error("credential P-256 coordinates must be 32 bytes"));
    }
    Ok((x, y))
}

fn canonical_cbor(value: &Value) -> Result<Vec<u8>, ProtocolError> {
    // RFC 8949 deterministic map order is encoded-key length followed by
    // bytewise lexical order.
    let mut value = value.clone();
    if let Value::Map(entries) = &mut value {
        entries.sort_by_cached_key(|(key, _)| {
            let mut bytes = Vec::new();
            ciborium::into_writer(key, &mut bytes).expect("in-memory CBOR key encodes");
            (bytes.len(), bytes)
        });
    }
    let mut bytes = Vec::new();
    ciborium::into_writer(&value, &mut bytes)
        .map_err(|_| proof_error("credential COSE public key cannot be encoded"))?;
    Ok(bytes)
}

pub(crate) fn es256_cose_public_key(x: &[u8], y: &[u8]) -> Result<Base64UrlBytes, ProtocolError> {
    let value = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())),
        (Value::Integer(3.into()), Value::Integer((-7).into())),
        (Value::Integer((-1).into()), Value::Integer(1.into())),
        (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
        (Value::Integer((-3).into()), Value::Bytes(y.to_vec())),
    ]);
    validate_cose_value(&value)?;
    Ok(Base64UrlBytes::from_bytes(&canonical_cbor(&value)?))
}

fn value_map<'a>(value: &'a Value, name: &str) -> Result<&'a Vec<(Value, Value)>, ProtocolError> {
    value
        .as_map()
        .ok_or_else(|| proof_error(format!("{name} must be a CBOR map")))
}

fn map_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(candidate, _)| candidate.as_text() == Some(key))
        .map(|(_, value)| value)
}

fn text_field<'a>(map: &'a [(Value, Value)], key: &str) -> Result<&'a str, ProtocolError> {
    map_field(map, key)
        .and_then(Value::as_text)
        .ok_or_else(|| proof_error(format!("attestation field {key} is missing or invalid")))
}

fn bytes_field<'a>(map: &'a [(Value, Value)], key: &str) -> Result<&'a [u8], ProtocolError> {
    map_field(map, key)
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
        .ok_or_else(|| proof_error(format!("attestation field {key} is missing or invalid")))
}

fn integer_field(map: &[(Value, Value)], key: i128) -> Result<i128, ProtocolError> {
    map.iter()
        .find(|(candidate, _)| candidate.as_integer().and_then(integer_to_i128) == Some(key))
        .and_then(|(_, value)| value.as_integer())
        .and_then(integer_to_i128)
        .ok_or_else(|| proof_error(format!("COSE integer field {key} is missing")))
}

fn integer_key_bytes(map: &[(Value, Value)], key: i128) -> Result<&[u8], ProtocolError> {
    map.iter()
        .find(|(candidate, _)| candidate.as_integer().and_then(integer_to_i128) == Some(key))
        .and_then(|(_, value)| value.as_bytes())
        .map(Vec::as_slice)
        .ok_or_else(|| proof_error(format!("COSE byte field {key} is missing")))
}

fn integer_to_i128(integer: Integer) -> Option<i128> {
    Some(i128::from(integer))
}

fn proof_error(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::UnauthenticatedPeer, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_data(value: serde_json::Value) -> Base64UrlBytes {
        Base64UrlBytes::from_bytes(&serde_json::to_vec(&value).unwrap())
    }

    #[test]
    fn client_data_tolerates_future_unknown_members() {
        let challenge = b"future-compatible-challenge";
        let encoded = client_data(serde_json::json!({
            "type": "webauthn.get",
            "challenge": Base64UrlBytes::from_bytes(challenge),
            "origin": CEREMONY_ORIGIN,
            "crossOrigin": false,
            "futureBrowserField": {"version": 1}
        }));

        verify_client_data(&encoded, "webauthn.get", challenge).unwrap();
    }

    #[test]
    fn client_data_still_rejects_cross_origin_with_top_origin() {
        let challenge = b"cross-origin-challenge";
        let encoded = client_data(serde_json::json!({
            "type": "webauthn.get",
            "challenge": Base64UrlBytes::from_bytes(challenge),
            "origin": CEREMONY_ORIGIN,
            "crossOrigin": true,
            "topOrigin": "https://example.invalid"
        }));

        let error = verify_client_data(&encoded, "webauthn.get", challenge).unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::UnauthenticatedPeer);
    }

    #[test]
    #[ignore = "requires BLOOM_TRIAD_DEV_CEREMONY_PORT from the focused CI invocation"]
    fn developer_ceremony_origin_is_build_scoped_and_exact() {
        let port = std::env::var("BLOOM_TRIAD_DEV_CEREMONY_PORT")
            .expect("focused CI must select a developer ceremony port");
        let selected = format!("http://localhost:{port}");
        let expected = if cfg!(feature = "triad-dev-harness") {
            selected.as_str()
        } else {
            CEREMONY_ORIGIN
        };
        assert_ne!(
            selected, CEREMONY_ORIGIN,
            "focused CI must select a non-default port"
        );
        assert_eq!(configured_ceremony_origin(), expected);

        let challenge = b"developer-origin-challenge";
        let accepted = client_data(serde_json::json!({
            "type": "webauthn.get",
            "challenge": Base64UrlBytes::from_bytes(challenge),
            "origin": expected,
            "crossOrigin": false
        }));
        verify_client_data(&accepted, "webauthn.get", challenge).unwrap();

        let rejected_origin = if expected == CEREMONY_ORIGIN {
            selected.as_str()
        } else {
            CEREMONY_ORIGIN
        };
        let rejected = client_data(serde_json::json!({
            "type": "webauthn.get",
            "challenge": Base64UrlBytes::from_bytes(challenge),
            "origin": rejected_origin,
            "crossOrigin": false
        }));
        assert!(verify_client_data(&rejected, "webauthn.get", challenge).is_err());
    }
}
