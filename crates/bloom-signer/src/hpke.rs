use bloom_signer_backend_api::SecretBytes;
use bloom_triad_protocol::{Base64UrlBytes, HpkeEnvelope, ProtocolError, ProtocolErrorCode};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

type BloomKem = X25519HkdfSha256;
type BloomKdf = HkdfSha256;
type BloomAead = ChaCha20Poly1305;

pub const LOCAL_PRF_INFO: &[u8] = b"bloom-local-prf/v1";
pub const CUSTODY_INPUT_INFO: &[u8] = b"bloom-custody-input/v1";
pub const CUSTODY_OUTPUT_INFO: &[u8] = b"bloom-custody-output/v1";

/// Single-use RFC 9180 X25519 recipient key.
pub struct HpkeRecipient {
    private_key: Zeroizing<Vec<u8>>,
    public_key: Base64UrlBytes,
}

impl HpkeRecipient {
    pub fn generate() -> Self {
        let (private_key, public_key) = BloomKem::gen_keypair(&mut OsRng);
        Self {
            private_key: Zeroizing::new(private_key.to_bytes().to_vec()),
            public_key: Base64UrlBytes::from_bytes(&public_key.to_bytes()),
        }
    }

    pub fn public_key(&self) -> &Base64UrlBytes {
        &self.public_key
    }

    pub fn from_private_key(private_key: SecretBytes) -> Result<Self, ProtocolError> {
        let parsed =
            <BloomKem as KemTrait>::PrivateKey::from_bytes(private_key.expose_to_backend())
                .map_err(|_| hpke_error("HPKE recipient private key is invalid"))?;
        let public_key = BloomKem::sk_to_pk(&parsed);
        Ok(Self {
            private_key: Zeroizing::new(private_key.expose_to_backend().to_vec()),
            public_key: Base64UrlBytes::from_bytes(&public_key.to_bytes()),
        })
    }

    /// Consume the recipient so the private key cannot decrypt a second input.
    pub fn open(
        self,
        envelope: &HpkeEnvelope,
        info: &[u8],
        aad: &[u8],
    ) -> Result<SecretBytes, ProtocolError> {
        envelope.validate()?;
        let private_key =
            <BloomKem as KemTrait>::PrivateKey::from_bytes(self.private_key.as_slice())
                .map_err(|_| hpke_error("HPKE recipient private key is invalid"))?;
        let encapped =
            <BloomKem as KemTrait>::EncappedKey::from_bytes(&envelope.kem_output.decode())
                .map_err(|_| hpke_error("HPKE KEM output is noncanonical"))?;
        let mut context = setup_receiver::<BloomAead, BloomKdf, BloomKem>(
            &OpModeR::Base,
            &private_key,
            &encapped,
            info,
        )
        .map_err(|_| hpke_error("HPKE receiver setup failed"))?;
        let plaintext = context
            .open(&envelope.ciphertext.decode(), aad)
            .map_err(|_| hpke_error("HPKE ciphertext authentication failed"))?;
        Ok(SecretBytes::new(plaintext))
    }
}

/// Browser/debug-driver sender implementation for the fixed Bloom HPKE suite.
///
/// Production Broker deliberately does not depend on this function.
pub fn seal_to_recipient(
    recipient_public_key: &Base64UrlBytes,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeEnvelope, ProtocolError> {
    let public_key = <BloomKem as KemTrait>::PublicKey::from_bytes(&recipient_public_key.decode())
        .map_err(|_| hpke_error("HPKE recipient public key is invalid"))?;
    let (encapped, mut context) = setup_sender::<BloomAead, BloomKdf, BloomKem, _>(
        &OpModeS::Base,
        &public_key,
        info,
        &mut OsRng,
    )
    .map_err(|_| hpke_error("HPKE sender setup failed"))?;
    let ciphertext = context
        .seal(plaintext, aad)
        .map_err(|_| hpke_error("HPKE encryption failed"))?;
    let envelope = HpkeEnvelope {
        kem_output: Base64UrlBytes::from_bytes(&encapped.to_bytes()),
        ciphertext: Base64UrlBytes::from_bytes(&ciphertext),
    };
    envelope.validate()?;
    Ok(envelope)
}

fn hpke_error(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::UnauthenticatedPeer, message)
}
