//! Card-only custody. No wallet state, persisted CVC, or reusable release.
use crate::{
    custody::{EncryptedBlob, decrypt, encrypt},
    hpke::{CUSTODY_INPUT_INFO, CUSTODY_OUTPUT_INFO, HpkeRecipient, seal_to_recipient},
    webauthn::{verify_webauthn_assertion_for_origin, verify_webauthn_attestation_for_origin},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bloom_signer_api::*;
use bloom_signer_backend_api::SecretBytes;
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use parking_lot::Mutex;
use rand::{TryRng, rngs::SysRng};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

fn error(code: ProtocolErrorCode, message: &'static str) -> ProtocolError {
    ProtocolError::new(code, message)
}
fn storage(_: rusqlite::Error) -> ProtocolError {
    error(
        ProtocolErrorCode::ServiceUnavailable,
        "card custody storage failed",
    )
}
fn malformed(_: serde_json::Error) -> ProtocolError {
    error(
        ProtocolErrorCode::MalformedFrame,
        "invalid private card input",
    )
}
fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    SysRng
        .try_fill_bytes(&mut b)
        .expect("OS randomness unavailable");
    b
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct CardDetails {
    pub number: String,
    pub expiry_month: u8,
    pub expiry_year: u16,
    pub name: String,
}
impl CardDetails {
    fn validate(&self, now_ms: u64) -> Result<(), ProtocolError> {
        let digits = self.number.as_bytes();
        let sum: u32 = digits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, b)| {
                let n = u32::from(b.saturating_sub(b'0'));
                if i % 2 == 1 {
                    let v = n * 2;
                    if v > 9 { v - 9 } else { v }
                } else {
                    n
                }
            })
            .sum();
        // Civil month comparison without introducing local timezone behavior.
        let days = (now_ms / 86_400_000) as i64;
        let z = days + 719468;
        let era = z / 146097;
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let mut year = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let month = mp + if mp < 10 { 3 } else { -9 };
        year += i64::from(month <= 2);
        if !(12..=19).contains(&digits.len())
            || !digits.iter().all(u8::is_ascii_digit)
            || digits.iter().all(|b| *b == b'0')
            || sum % 10 != 0
            || !(1..=12).contains(&self.expiry_month)
            || (i64::from(self.expiry_year), i64::from(self.expiry_month)) < (year, month)
            || i64::from(self.expiry_year) > year + 30
            || self.name.is_empty()
            || self.name.len() > 128
            || self.name.chars().any(char::is_control)
        {
            return Err(error(
                ProtocolErrorCode::BackendInvalidRequest,
                "invalid card details",
            ));
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateInput {
    credential_prf: Zeroizing<String>,
    #[serde(default)]
    card: Option<CardDetails>,
    #[serde(default)]
    cvc: Option<Zeroizing<String>>,
}
#[derive(Serialize)]
struct Release<'a> {
    #[serde(flatten)]
    card: &'a CardDetails,
    cvc: &'a str,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Container {
    id: Digest32,
    credential: WebAuthnCredential,
    wrapped_key: EncryptedBlob,
}
struct Pending {
    request: CardPrepareRequest,
    prepared: SignerPreparedCustody,
    recipient: HpkeRecipient,
}
struct State {
    db: Connection,
    pending: HashMap<OperationId, Pending>,
}
pub struct CardCeremonies {
    state: Mutex<State>,
    key: SigningKey,
    key_id: Token,
    origin: String,
}

fn initialize(db: Connection) -> Result<State, ProtocolError> {
    db.execute_batch("PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE;
      CREATE TABLE IF NOT EXISTS container (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS cards (id TEXT PRIMARY KEY, public TEXT NOT NULL, encrypted TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, digest TEXT NOT NULL, state TEXT NOT NULL);
      UPDATE operations SET state='failed' WHERE state='prepared';").map_err(storage)?;
    Ok(State {
        db,
        pending: HashMap::new(),
    })
}
fn container(db: &Connection) -> Result<Option<Container>, ProtocolError> {
    let value: Option<String> = db
        .query_row("SELECT value FROM container WHERE id=1", [], |r| r.get(0))
        .optional()
        .map_err(storage)?;
    value
        .map(|s| serde_json::from_str(&s).map_err(malformed))
        .transpose()
}
fn json<T: Serialize>(value: &T) -> Result<String, ProtocolError> {
    serde_json::to_string(value).map_err(malformed)
}
fn wrap_key(
    prf: &SecretBytes,
    id: &Digest32,
    credential: &Base64UrlBytes,
) -> Result<SecretBytes, ProtocolError> {
    if prf.expose_to_backend().len() != 32 {
        return Err(error(
            ProtocolErrorCode::MalformedFrame,
            "card PRF must contain 32 bytes",
        ));
    }
    let salt = Sha256::digest(serde_jcs::to_vec(&(id, credential)).map_err(malformed)?);
    let mut key = vec![0; 32];
    Hkdf::<Sha256>::new(Some(&salt), prf.expose_to_backend())
        .expand(b"bloom-passkey-card-wrap/v1", &mut key)
        .map_err(|_| {
            error(
                ProtocolErrorCode::ServiceUnavailable,
                "card key derivation failed",
            )
        })?;
    Ok(SecretBytes::new(key))
}
fn card_aad(container_id: &Digest32, card_id: &Token) -> Result<Vec<u8>, ProtocolError> {
    serde_jcs::to_vec(&("bloom-card-record/v1", container_id, card_id)).map_err(malformed)
}
impl CardCeremonies {
    pub fn new(key: SigningKey, key_id: Token, origin: String) -> Result<Self, ProtocolError> {
        Ok(Self {
            state: Mutex::new(initialize(Connection::open_in_memory().map_err(storage)?)?),
            key,
            key_id,
            origin,
        })
    }
    pub fn open_storage(&self, path: &Path) -> Result<(), ProtocolError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| {
                error(
                    ProtocolErrorCode::ServiceUnavailable,
                    "cannot open card custody file",
                )
            })?;
        let meta = file.metadata().map_err(|_| {
            error(
                ProtocolErrorCode::ServiceUnavailable,
                "cannot inspect card custody file",
            )
        })?;
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "unsafe card custody file ownership",
            ));
        }
        let mut state = self.state.lock();
        if !state.pending.is_empty() {
            return Err(error(
                ProtocolErrorCode::OperationIdConflict,
                "cannot replace active card custody",
            ));
        }
        *state = initialize(Connection::open(path).map_err(storage)?)?;
        Ok(())
    }
    pub fn list(&self) -> Result<Vec<CardPublic>, ProtocolError> {
        let state = self.state.lock();
        let mut stmt = state
            .db
            .prepare("SELECT public FROM cards ORDER BY id")
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(storage)?;
        rows.map(|s| serde_json::from_str(&s.map_err(storage)?).map_err(malformed))
            .collect()
    }
    pub fn status(
        &self,
        operation_id: &OperationId,
        now_ms: u64,
    ) -> Result<CardOperationStatus, ProtocolError> {
        let state = self.state.lock();
        if state
            .pending
            .get(operation_id)
            .is_some_and(|p| p.prepared.contribution.expires_at_ms.get() <= now_ms)
        {
            return Ok(CardOperationStatus {
                operation_id: operation_id.clone(),
                state: CardOperationState::Expired,
            });
        }
        let value: Option<String> = state
            .db
            .query_row(
                "SELECT state FROM operations WHERE id=?1",
                [operation_id.as_str()],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?;
        let status = match value.as_deref() {
            Some("prepared") => CardOperationState::Prepared,
            Some("consumed") => CardOperationState::Consumed,
            Some("succeeded") => CardOperationState::Succeeded,
            Some("failed") => CardOperationState::Failed,
            Some("cancelled") => CardOperationState::Cancelled,
            Some("expired") => CardOperationState::Expired,
            None => CardOperationState::Missing,
            _ => {
                return Err(error(
                    ProtocolErrorCode::ServiceUnavailable,
                    "invalid card operation state",
                ));
            }
        };
        Ok(CardOperationStatus {
            operation_id: operation_id.clone(),
            state: status,
        })
    }
    pub fn cancel(
        &self,
        operation_id: &OperationId,
        now_ms: u64,
    ) -> Result<CardOperationStatus, ProtocolError> {
        {
            let mut state = self.state.lock();
            if state
                .db
                .execute(
                    "UPDATE operations SET state='cancelled' WHERE id=?1 AND state='prepared'",
                    [operation_id.as_str()],
                )
                .map_err(storage)?
                != 1
            {
                return Err(error(
                    ProtocolErrorCode::OperationIdConflict,
                    "card operation cannot be cancelled after consumption",
                ));
            }
            state.pending.remove(operation_id);
        }
        self.status(operation_id, now_ms)
    }
    pub fn prepare(
        &self,
        request: CardPrepareRequest,
        now_ms: u64,
    ) -> Result<SignerPreparedCustody, ProtocolError> {
        if request.surface.surface_id.as_str() != "local" {
            return Err(error(
                ProtocolErrorCode::UnauthenticatedPeer,
                "cards require the local ceremony surface",
            ));
        }
        let digest = request.digest()?;
        let mut state = self.state.lock();
        if let Some(pending) = state.pending.get(&request.operation_id) {
            if pending.request.digest()? != digest {
                return Err(error(
                    ProtocolErrorCode::OperationIdConflict,
                    "card operation terms changed",
                ));
            }
            return Ok(pending.prepared.clone());
        }
        let used: bool = state
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1)",
                [request.operation_id.as_str()],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if used {
            return Err(error(
                ProtocolErrorCode::OperationIdConflict,
                "card operation already used",
            ));
        }
        let existing = container(&state.db)?;
        if existing.is_none() && !matches!(request.effect, CardEffect::Add { .. }) {
            return Err(error(
                ProtocolErrorCode::ApprovalNotFound,
                "card container is not enrolled",
            ));
        }
        let present: bool = state
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM cards WHERE id=?1)",
                [request.effect.card_id().as_str()],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if present == matches!(request.effect, CardEffect::Add { .. }) {
            return Err(error(
                ProtocolErrorCode::OperationIdConflict,
                "card record does not match requested operation",
            ));
        }
        let first = existing.is_none();
        let recipient = HpkeRecipient::generate();
        let mut contribution = CustodySignerContribution {
            surface: request.surface.clone(),
            credential_authority_generation: DecimalU64::new(1),
            ceremony_id: Digest32::from_bytes(random()),
            ceremony_kind: request.effect.ceremony_kind(),
            custody_operation_id: request.operation_id.clone(),
            signer_nonce: Digest32::from_bytes(random()),
            review_manifest_digest: digest.clone(),
            wallet_id: None,
            key_ref: None,
            expected_input_class: Token::new("card-input-v1")?,
            required_user_verification: true,
            hpke_recipient_key: recipient.public_key().clone(),
            browser_output_recipient_key: match &request.effect {
                CardEffect::Checkout { recipient_key, .. } => Some(recipient_key.clone()),
                _ => None,
            },
            petal_key_scope: None,
            wallet_seed_profile: None,
            expires_at_ms: DecimalU64::new(now_ms.saturating_add(120_000)),
            signer_key_id: self.key_id.clone(),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        let mut signed = b"bloom-signer-ceremony-contribution/v1".to_vec();
        signed.extend(contribution.unsigned_canonical_bytes()?);
        contribution.signer_signature =
            Base64UrlBytes::from_bytes(&self.key.sign(&signed).to_bytes());
        let phases = if first {
            vec![CeremonyPhase::RegisterCredential, CeremonyPhase::ConfirmPrf]
        } else {
            vec![CeremonyPhase::Approve]
        };
        let challenges = phases
            .into_iter()
            .map(|phase| {
                Ok(CeremonyChallenge {
                    surface: request.surface.clone(),
                    schema: Token::new("bloom.ceremony.challenge.v1")?,
                    ceremony_id: contribution.ceremony_id.clone(),
                    ceremony_kind: contribution.ceremony_kind,
                    operation_id: request.operation_id.clone(),
                    signer_nonce: contribution.signer_nonce.clone(),
                    review_manifest_digest: digest.clone(),
                    signer_contribution_digest: contribution.digest()?,
                    exact_terms_digest: digest.clone(),
                    phase,
                })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        let prepared = SignerPreparedCustody {
            contribution,
            challenges,
            webauthn_options: CeremonyWebAuthnOptions {
                allowed_credentials: existing
                    .as_ref()
                    .map(|c| {
                        vec![CredentialPrfInput {
                            credential_id: c.credential.credential_id.clone(),
                            prf_salt: c.credential.prf_salt.clone(),
                        }]
                    })
                    .unwrap_or_default(),
                registration_user_handle: if first {
                    Some(Base64UrlBytes::from_bytes(&random::<32>()))
                } else {
                    None
                },
                registration_prf_salt: if first {
                    Some(Base64UrlBytes::from_bytes(&random::<32>()))
                } else {
                    None
                },
            },
            verification_credentials: existing.map(|c| vec![c.credential]).unwrap_or_default(),
        };
        state
            .db
            .execute(
                "INSERT INTO operations VALUES (?1,?2,'prepared')",
                params![request.operation_id.as_str(), digest.as_str()],
            )
            .map_err(storage)?;
        state.pending.insert(
            request.operation_id.clone(),
            Pending {
                request,
                prepared: prepared.clone(),
                recipient,
            },
        );
        Ok(prepared)
    }
    pub(crate) fn operation_surface(
        &self,
        operation_id: &OperationId,
    ) -> Result<SurfaceRef, ProtocolError> {
        self.state
            .lock()
            .pending
            .get(operation_id)
            .map(|p| p.request.surface.clone())
            .ok_or_else(|| {
                error(
                    ProtocolErrorCode::OperationIdConflict,
                    "card approval is no longer usable",
                )
            })
    }
    pub fn complete(
        &self,
        complete: CustodyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, ProtocolError> {
        let mut state = self.state.lock();
        let pending = state
            .pending
            .remove(&complete.custody_operation_id)
            .ok_or_else(|| {
                error(
                    ProtocolErrorCode::OperationIdConflict,
                    "card approval is no longer usable",
                )
            })?;
        if pending.prepared.contribution.expires_at_ms.get() <= now_ms {
            state
                .db
                .execute(
                    "UPDATE operations SET state='expired' WHERE id=?1 AND state='prepared'",
                    [complete.custody_operation_id.as_str()],
                )
                .map_err(storage)?;
            return Err(error(
                ProtocolErrorCode::ApprovalExpired,
                "card approval expired",
            ));
        }
        // FULL synchronous commit precedes opening any private input or releasing card data.
        let changed = state
            .db
            .execute(
                "UPDATE operations SET state='consumed' WHERE id=?1 AND state='prepared'",
                [complete.custody_operation_id.as_str()],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(error(
                ProtocolErrorCode::OperationIdConflict,
                "card approval already consumed",
            ));
        }
        self.apply(&mut state, pending, complete, now_ms)
    }
    fn apply(
        &self,
        state: &mut State,
        pending: Pending,
        complete: CustodyCompleteRequest,
        now_ms: u64,
    ) -> Result<CustodyResult, ProtocolError> {
        let contribution = &pending.prepared.contribution;
        let digest = pending.request.digest()?;
        if complete.ceremony_kind != contribution.ceremony_kind
            || complete.ceremony_id != contribution.ceremony_id
            || complete.public_binding_digest != digest
            || now_ms >= contribution.expires_at_ms.get()
        {
            return Err(error(
                ProtocolErrorCode::CeremonyKindMismatch,
                "card approval binding or expiry mismatch",
            ));
        }
        let mut existing = container(&state.db)?;
        let credential = match (&existing, &complete.proof) {
            (
                None,
                WebAuthnCeremonyProof::Registration {
                    attestation,
                    prf_assertion: Some(assertion),
                },
            ) => {
                let mut credential = verify_webauthn_attestation_for_origin(
                    attestation,
                    &pending.prepared.challenges[0].canonical_bytes()?,
                    pending
                        .prepared
                        .webauthn_options
                        .registration_user_handle
                        .clone()
                        .ok_or_else(|| {
                            error(
                                ProtocolErrorCode::MalformedFrame,
                                "missing card enrollment handle",
                            )
                        })?,
                    pending
                        .prepared
                        .webauthn_options
                        .registration_prf_salt
                        .clone()
                        .ok_or_else(|| {
                            error(ProtocolErrorCode::MalformedFrame, "missing card PRF salt")
                        })?,
                    &self.origin,
                    "localhost",
                )?;
                credential.surface = pending.request.surface.clone();
                let verified = verify_webauthn_assertion_for_origin(
                    assertion,
                    &credential,
                    &pending.prepared.challenges[1].canonical_bytes()?,
                    true,
                    &self.origin,
                    "localhost",
                )?;
                credential.sign_count = DecimalU64::new(u64::from(verified.sign_count));
                credential
            }
            (Some(container), WebAuthnCeremonyProof::Assertion { assertion }) => {
                if container.credential.surface != pending.request.surface {
                    return Err(error(
                        ProtocolErrorCode::UnauthenticatedPeer,
                        "card credential surface mismatch",
                    ));
                }
                let mut credential = container.credential.clone();
                let verified = verify_webauthn_assertion_for_origin(
                    assertion,
                    &credential,
                    &pending.prepared.challenges[0].canonical_bytes()?,
                    true,
                    &self.origin,
                    "localhost",
                )?;
                credential.sign_count = DecimalU64::new(u64::from(verified.sign_count));
                credential
            }
            _ => {
                return Err(error(
                    ProtocolErrorCode::CeremonyKindMismatch,
                    "invalid card ceremony proof",
                ));
            }
        };
        let aad = CustodyHpkeAad {
            surface: pending.request.surface.clone(),
            ceremony_id: contribution.ceremony_id.clone(),
            ceremony_kind: contribution.ceremony_kind,
            custody_operation_id: complete.custody_operation_id.clone(),
            signer_nonce: contribution.signer_nonce.clone(),
            signer_contribution_digest: contribution.digest()?,
            wallet_id: None,
            key_ref: None,
            credential_id: Some(credential.credential_id.clone()),
            expected_input_class: contribution.expected_input_class.clone(),
        };
        let secret = pending.recipient.open(
            complete.encrypted_input.as_ref().ok_or_else(|| {
                error(
                    ProtocolErrorCode::MalformedFrame,
                    "missing encrypted card input",
                )
            })?,
            CUSTODY_INPUT_INFO,
            &aad.canonical_bytes()?,
        )?;
        let input: PrivateInput =
            serde_json::from_slice(secret.expose_to_backend()).map_err(malformed)?;
        let prf = SecretBytes::new(
            URL_SAFE_NO_PAD
                .decode(input.credential_prf.as_bytes())
                .map_err(|_| {
                    error(
                        ProtocolErrorCode::MalformedFrame,
                        "invalid card PRF encoding",
                    )
                })?,
        );
        let container_id = existing
            .as_ref()
            .map(|c| c.id.clone())
            .unwrap_or_else(|| Digest32::from_bytes(random()));
        let wrapping = wrap_key(&prf, &container_id, &credential.credential_id)?;
        let key = if let Some(c) = &existing {
            SecretBytes::new(decrypt(
                &wrapping,
                &c.wrapped_key,
                b"bloom-card-container-key/v1",
            )?)
        } else {
            SecretBytes::new(random::<32>().to_vec())
        };
        let mut output = None;
        let tx = state.db.transaction().map_err(storage)?;
        match &pending.request.effect {
            CardEffect::ManualCheckout { .. } => {
                if input.card.is_some() || input.cvc.is_some() {
                    return Err(error(
                        ProtocolErrorCode::MalformedFrame,
                        "manual view cannot accept or release card details",
                    ));
                }
            }
            CardEffect::Add { card_id, label } => {
                if input.cvc.is_some() {
                    return Err(error(
                        ProtocolErrorCode::MalformedFrame,
                        "CVC cannot be stored",
                    ));
                }
                let card = input.card.as_ref().ok_or_else(|| {
                    error(ProtocolErrorCode::MalformedFrame, "card details required")
                })?;
                card.validate(now_ms)?;
                let public = CardPublic {
                    card_id: card_id.clone(),
                    label: label.clone(),
                    brand: if card.number.starts_with('4') {
                        "Visa"
                    } else if card.number.starts_with("34") || card.number.starts_with("37") {
                        "Amex"
                    } else {
                        "Card"
                    }
                    .into(),
                    last4: card.number[card.number.len() - 4..].into(),
                };
                let plaintext = Zeroizing::new(serde_json::to_vec(card).map_err(malformed)?);
                let encrypted = encrypt(&key, &plaintext, &card_aad(&container_id, card_id)?)?;
                tx.execute(
                    "INSERT INTO cards VALUES (?1,?2,?3)",
                    params![card_id.as_str(), json(&public)?, json(&encrypted)?],
                )
                .map_err(storage)?;
            }
            CardEffect::Delete { card_id } => {
                if input.card.is_some() || input.cvc.is_some() {
                    return Err(error(
                        ProtocolErrorCode::MalformedFrame,
                        "unexpected card deletion input",
                    ));
                }
                if tx
                    .execute("DELETE FROM cards WHERE id=?1", [card_id.as_str()])
                    .map_err(storage)?
                    != 1
                {
                    return Err(error(ProtocolErrorCode::ApprovalNotFound, "card not found"));
                }
            }
            CardEffect::Checkout {
                card_id,
                recipient_key,
                ..
            } => {
                if input.card.is_some() {
                    return Err(error(
                        ProtocolErrorCode::MalformedFrame,
                        "checkout cannot replace card details",
                    ));
                }
                let cvc = input
                    .cvc
                    .as_deref()
                    .ok_or_else(|| error(ProtocolErrorCode::MalformedFrame, "CVC required"))?;
                if !(3..=4).contains(&cvc.len()) || !cvc.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(error(ProtocolErrorCode::MalformedFrame, "invalid CVC"));
                }
                let raw: String = tx
                    .query_row(
                        "SELECT encrypted FROM cards WHERE id=?1",
                        [card_id.as_str()],
                        |r| r.get(0),
                    )
                    .map_err(storage)?;
                let blob: EncryptedBlob = serde_json::from_str(&raw).map_err(malformed)?;
                let plaintext =
                    Zeroizing::new(decrypt(&key, &blob, &card_aad(&container_id, card_id)?)?);
                let card: CardDetails = serde_json::from_slice(&plaintext).map_err(malformed)?;
                card.validate(now_ms)?;
                let release = Zeroizing::new(
                    serde_json::to_vec(&Release { card: &card, cvc }).map_err(malformed)?,
                );
                let output_aad = CustodyOutputHpkeAad {
                    surface: pending.request.surface.clone(),
                    ceremony_id: contribution.ceremony_id.clone(),
                    ceremony_kind: contribution.ceremony_kind,
                    custody_operation_id: complete.custody_operation_id.clone(),
                    signer_contribution_digest: contribution.digest()?,
                    public_binding_digest: digest.clone(),
                };
                output = Some(seal_to_recipient(
                    recipient_key,
                    CUSTODY_OUTPUT_INFO,
                    &output_aad.canonical_bytes()?,
                    &release,
                )?);
            }
        }
        let new_container = if let Some(mut container) = existing.take() {
            container.credential = credential;
            container
        } else {
            Container {
                id: container_id,
                credential,
                wrapped_key: encrypt(
                    &wrapping,
                    key.expose_to_backend(),
                    b"bloom-card-container-key/v1",
                )?,
            }
        };
        tx.execute(
            "INSERT OR REPLACE INTO container VALUES (1,?1)",
            [json(&new_container)?],
        )
        .map_err(storage)?;
        tx.execute(
            "UPDATE operations SET state='succeeded' WHERE id=?1",
            [complete.custody_operation_id.as_str()],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        let mut result = CustodyResult {
            surface: Some(pending.request.surface),
            credential_authority_generation: Some(DecimalU64::new(1)),
            ceremony_kind: contribution.ceremony_kind,
            custody_operation_id: complete.custody_operation_id,
            public_status: CeremonyState::Succeeded,
            wallet_id: None,
            public_key_refs: vec![],
            credential_summaries: vec![],
            initial_policy: None,
            receipt_digest: digest,
            encrypted_browser_result: output,
            signer_key_id: self.key_id.clone(),
            signer_signature: Base64UrlBytes::from_bytes(&[]),
        };
        let mut bytes = b"bloom-signer-ceremony-receipt/v1".to_vec();
        bytes.extend(result.unsigned_canonical_bytes()?);
        result.signer_signature = Base64UrlBytes::from_bytes(&self.key.sign(&bytes).to_bytes());
        Ok(result)
    }
}
