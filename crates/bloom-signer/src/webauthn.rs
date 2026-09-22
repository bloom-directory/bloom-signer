use ciborium::value::{Integer, Value};
use p256::{
    Sec1Point,
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
/// Default ceremony port retained when the Signer config omits
/// `ceremony_port` and no development fallback selects another port.
pub const DEFAULT_CEREMONY_PORT: u16 = 18734;

/// The origin every WebAuthn clientDataJSON must carry.
///
/// Default builds accept only the fixed production origin and ignore
/// `BLOOM_TRIAD_DEV_CEREMONY_PORT` entirely — including values a harness
/// build would reject. A `triad-dev-harness` build honours the variable when
/// it names an explicit localhost port from 1 to 65535; anything else is a
/// configuration error returned to the caller, so a malformed value fails
/// the verification with a diagnosable protocol error instead of a panic.
pub fn configured_ceremony_origin() -> Result<String, ProtocolError> {
    ceremony_origin_for(std::env::var_os("BLOOM_TRIAD_DEV_CEREMONY_PORT").as_deref())
}

/// Serialize a ceremony origin the way browsers do: normally
/// `http://localhost:<port>`; HTTP port 80 serializes as `http://localhost`.
pub fn ceremony_origin_for_port(port: u16) -> String {
    if port == 80 {
        "http://localhost".to_owned()
    } else {
        format!("http://localhost:{port}")
    }
}

/// Resolve the effective ceremony port from the optional `ceremony_port`
/// Signer config field, reading the legacy development fallback only when
/// the file sets no explicit value.
///
/// An explicit file value always wins: a valid explicit port is never
/// rejected because an unused legacy override is malformed, and ordinary
/// builds ignore the legacy variable entirely.
pub fn resolve_ceremony_port(explicit: Option<u16>) -> Result<u16, ProtocolError> {
    resolve_ceremony_port_for_env(
        explicit,
        std::env::var_os("BLOOM_TRIAD_DEV_CEREMONY_PORT").as_deref(),
    )
}

fn resolve_ceremony_port_for_env(
    explicit: Option<u16>,
    _env_value: Option<&std::ffi::OsStr>,
) -> Result<u16, ProtocolError> {
    if let Some(port) = explicit {
        return validate_explicit_ceremony_port(port);
    }
    // The underscore name keeps default builds (which never read the
    // override) warning-free while the harness arm uses the value below.
    #[cfg(feature = "triad-dev-harness")]
    if let Some(value) = _env_value {
        return parse_developer_ceremony_port(value);
    }
    Ok(DEFAULT_CEREMONY_PORT)
}

fn validate_explicit_ceremony_port(port: u16) -> Result<u16, ProtocolError> {
    if port == 0 {
        return Err(ProtocolError::new(
            ProtocolErrorCode::MalformedFrame,
            "ceremony_port must be an integer from 1 to 65535",
        ));
    }
    Ok(port)
}

fn ceremony_origin_for(_env_value: Option<&std::ffi::OsStr>) -> Result<String, ProtocolError> {
    // The underscore name keeps default builds (which never read the
    // override) warning-free while the harness arm uses the value below.
    #[cfg(feature = "triad-dev-harness")]
    if let Some(value) = _env_value {
        let port = parse_developer_ceremony_port(value)?;
        return Ok(format!("http://localhost:{port}"));
    }
    Ok(CEREMONY_ORIGIN.to_owned())
}

#[cfg(feature = "triad-dev-harness")]
fn parse_developer_ceremony_port(value: &std::ffi::OsStr) -> Result<u16, ProtocolError> {
    value
        .to_str()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "BLOOM_TRIAD_DEV_CEREMONY_PORT must be UTF-8 naming an integer from 1 to 65535",
            )
        })
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
    expected_origin: &str,
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
        expected_origin,
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
    expected_origin: &str,
) -> Result<WebAuthnCredential, ProtocolError> {
    verify_client_data(
        &attestation.client_data_json,
        "webauthn.create",
        expected_challenge,
        expected_origin,
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
    expected_origin: &str,
) -> Result<(), ProtocolError> {
    let decoded = encoded.decode();
    let data: ClientData = serde_json::from_slice(&decoded)
        .map_err(|_| proof_error("WebAuthn clientDataJSON is malformed"))?;
    if data.ceremony_type != expected_type
        || data.origin != expected_origin
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
    let point = Sec1Point::from_affine_coordinates(
        x.try_into().expect("validated P-256 coordinate length"),
        y.try_into().expect("validated P-256 coordinate length"),
        false,
    );
    VerifyingKey::from_sec1_point(&point)
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
        let origin = ceremony_origin_for_port(28735);
        let encoded = client_data(serde_json::json!({
            "type": "webauthn.get",
            "challenge": Base64UrlBytes::from_bytes(challenge),
            "origin": origin,
            "crossOrigin": false,
            "futureBrowserField": {"version": 1}
        }));

        verify_client_data(&encoded, "webauthn.get", challenge, &origin).unwrap();
    }

    #[test]
    fn client_data_still_rejects_cross_origin_with_top_origin() {
        let challenge = b"cross-origin-challenge";
        let origin = ceremony_origin_for_port(28735);
        let encoded = client_data(serde_json::json!({
            "type": "webauthn.get",
            "challenge": Base64UrlBytes::from_bytes(challenge),
            "origin": origin,
            "crossOrigin": true,
            "topOrigin": "https://example.invalid"
        }));

        let error = verify_client_data(&encoded, "webauthn.get", challenge, &origin).unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::UnauthenticatedPeer);
    }

    #[test]
    fn ceremony_origin_for_port_serializes_browser_origins() {
        assert_eq!(ceremony_origin_for_port(18734), "http://localhost:18734");
        assert_eq!(ceremony_origin_for_port(28735), "http://localhost:28735");
        assert_eq!(ceremony_origin_for_port(1), "http://localhost:1");
        assert_eq!(ceremony_origin_for_port(65535), "http://localhost:65535");
        // HTTP port 80 is the default port and is omitted from serialization.
        assert_eq!(ceremony_origin_for_port(80), "http://localhost");
        assert_eq!(
            CEREMONY_ORIGIN,
            ceremony_origin_for_port(DEFAULT_CEREMONY_PORT)
        );
    }

    #[test]
    fn explicit_ceremony_port_is_validated_without_env() {
        use std::ffi::OsStr;
        assert_eq!(
            resolve_ceremony_port_for_env(Some(28735), None).unwrap(),
            28735
        );
        assert_eq!(resolve_ceremony_port_for_env(Some(80), None).unwrap(), 80);
        assert_eq!(
            resolve_ceremony_port_for_env(Some(65535), None).unwrap(),
            65535
        );
        let error = resolve_ceremony_port_for_env(Some(0), None).unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::MalformedFrame);
        // An explicit file value wins even when an unused legacy override is
        // malformed; the malformed value must not fail a valid configuration.
        assert_eq!(
            resolve_ceremony_port_for_env(Some(28735), Some(OsStr::new("not-a-port"))).unwrap(),
            28735
        );
    }

    #[test]
    fn missing_ceremony_port_falls_back_to_default_or_legacy_env() {
        use std::ffi::OsStr;
        #[cfg(not(feature = "triad-dev-harness"))]
        {
            // Ordinary builds ignore the legacy variable entirely.
            assert_eq!(
                resolve_ceremony_port_for_env(None, None).unwrap(),
                DEFAULT_CEREMONY_PORT
            );
            assert_eq!(
                resolve_ceremony_port_for_env(None, Some(OsStr::new("28735"))).unwrap(),
                DEFAULT_CEREMONY_PORT
            );
            assert_eq!(
                resolve_ceremony_port_for_env(None, Some(OsStr::new("not-a-port"))).unwrap(),
                DEFAULT_CEREMONY_PORT
            );
        }
        #[cfg(feature = "triad-dev-harness")]
        {
            assert_eq!(
                resolve_ceremony_port_for_env(None, None).unwrap(),
                DEFAULT_CEREMONY_PORT
            );
            assert_eq!(
                resolve_ceremony_port_for_env(None, Some(OsStr::new("28735"))).unwrap(),
                28735
            );
            let error =
                resolve_ceremony_port_for_env(None, Some(OsStr::new("not-a-port"))).unwrap_err();
            assert_eq!(error.code, ProtocolErrorCode::ServiceUnavailable);
        }
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
        assert_eq!(configured_ceremony_origin().unwrap(), expected);

        let challenge = b"developer-origin-challenge";
        let accepted = client_data(serde_json::json!({
            "type": "webauthn.get",
            "challenge": Base64UrlBytes::from_bytes(challenge),
            "origin": expected,
            "crossOrigin": false
        }));
        verify_client_data(&accepted, "webauthn.get", challenge, expected).unwrap();

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
        assert!(verify_client_data(&rejected, "webauthn.get", challenge, expected).is_err());
    }

    /// Invalid developer port configuration must surface as a protocol
    /// error from verification, never a panic; default builds must ignore
    /// the variable entirely, including invalid values.
    #[test]
    fn ceremony_origin_for_is_exact_about_developer_port_values() {
        use std::ffi::OsStr;
        #[cfg(not(feature = "triad-dev-harness"))]
        {
            assert_eq!(ceremony_origin_for(None).unwrap(), CEREMONY_ORIGIN);
            assert_eq!(
                ceremony_origin_for(Some(OsStr::new("28735"))).unwrap(),
                CEREMONY_ORIGIN
            );
            assert_eq!(
                ceremony_origin_for(Some(OsStr::new("0"))).unwrap(),
                CEREMONY_ORIGIN
            );
            assert_eq!(
                ceremony_origin_for(Some(OsStr::new("not-a-port"))).unwrap(),
                CEREMONY_ORIGIN
            );
        }
        #[cfg(feature = "triad-dev-harness")]
        {
            assert_eq!(ceremony_origin_for(None).unwrap(), CEREMONY_ORIGIN);
            assert_eq!(
                ceremony_origin_for(Some(OsStr::new("28735"))).unwrap(),
                "http://localhost:28735"
            );
            assert_eq!(
                ceremony_origin_for(Some(OsStr::new("65535"))).unwrap(),
                "http://localhost:65535"
            );
            for invalid in ["0", "65536", "not-a-port", " 28735", ""] {
                let error = ceremony_origin_for(Some(OsStr::new(invalid))).unwrap_err();
                assert_eq!(
                    error.code,
                    ProtocolErrorCode::ServiceUnavailable,
                    "value {invalid:?} must be rejected, not panic"
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt as _;
                let error =
                    ceremony_origin_for(Some(OsStr::from_bytes(b"\xff\xfeinvalid"))).unwrap_err();
                assert_eq!(error.code, ProtocolErrorCode::ServiceUnavailable);
            }
        }
    }
}
