use serde::{Deserialize, Serialize};

use crate::{Base64UrlBytes, ProtocolError, ProtocolErrorCode};

pub const SINGLE_PAYLOAD_MAX_BYTES: usize = 256 * 1024;
pub const BATCH_CHILD_MAX_BYTES: usize = 64 * 1024;
pub const BATCH_AGGREGATE_MAX_BYTES: usize = 512 * 1024;
pub const BATCH_CHILD_MAX_COUNT: usize = 32;
pub const HPKE_ENVELOPE_MAX_BYTES: usize = 4 * 1024;
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SigningPayloads {
    Single { payload: Base64UrlBytes },
    Batch { children: Vec<Base64UrlBytes> },
}

impl<'de> Deserialize<'de> for SigningPayloads {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Unchecked {
            Single { payload: Base64UrlBytes },
            Batch { children: Vec<Base64UrlBytes> },
        }

        let payloads = match Unchecked::deserialize(deserializer)? {
            Unchecked::Single { payload } => Self::Single { payload },
            Unchecked::Batch { children } => Self::Batch { children },
        };
        payloads.validate().map_err(serde::de::Error::custom)?;
        Ok(payloads)
    }
}

impl SigningPayloads {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Single { payload } => {
                if payload.decode().len() > SINGLE_PAYLOAD_MAX_BYTES {
                    return Err(limit("single decoded payload exceeds 256 KiB"));
                }
            }
            Self::Batch { children } => {
                if children.is_empty() || children.len() > BATCH_CHILD_MAX_COUNT {
                    return Err(limit("batch must contain 1-32 children"));
                }
                let mut aggregate = 0usize;
                for child in children {
                    let length = child.decode().len();
                    if length > BATCH_CHILD_MAX_BYTES {
                        return Err(limit("decoded batch child exceeds 64 KiB"));
                    }
                    aggregate = aggregate
                        .checked_add(length)
                        .ok_or_else(|| limit("decoded batch aggregate overflow"))?;
                }
                if aggregate > BATCH_AGGREGATE_MAX_BYTES {
                    return Err(limit("decoded batch aggregate exceeds 512 KiB"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HpkeEnvelope {
    pub kem_output: Base64UrlBytes,
    pub ciphertext: Base64UrlBytes,
}

impl<'de> Deserialize<'de> for HpkeEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Unchecked {
            kem_output: Base64UrlBytes,
            ciphertext: Base64UrlBytes,
        }

        let unchecked = Unchecked::deserialize(deserializer)?;
        let envelope = Self {
            kem_output: unchecked.kem_output,
            ciphertext: unchecked.ciphertext,
        };
        envelope.validate().map_err(serde::de::Error::custom)?;
        Ok(envelope)
    }
}

impl HpkeEnvelope {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let total = self
            .kem_output
            .decode()
            .len()
            .checked_add(self.ciphertext.decode().len())
            .ok_or_else(|| limit("HPKE envelope length overflow"))?;
        if total > HPKE_ENVELOPE_MAX_BYTES {
            return Err(limit("decoded HPKE envelope exceeds 4 KiB"));
        }
        Ok(())
    }
}

fn limit(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::LimitExceededFrame, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_payload_bound_is_independent() {
        let single = SigningPayloads::Single {
            payload: Base64UrlBytes::from_bytes(&vec![0; SINGLE_PAYLOAD_MAX_BYTES + 1]),
        };
        assert!(single.validate().is_err());

        let child = SigningPayloads::Batch {
            children: vec![Base64UrlBytes::from_bytes(&vec![
                0;
                BATCH_CHILD_MAX_BYTES + 1
            ])],
        };
        assert!(child.validate().is_err());

        let aggregate = SigningPayloads::Batch {
            children: vec![
                Base64UrlBytes::from_bytes(&vec![0; BATCH_CHILD_MAX_BYTES]);
                BATCH_CHILD_MAX_COUNT
            ],
        };
        let error = aggregate.validate().unwrap_err();
        assert!(error.message.contains("aggregate"));

        let count = SigningPayloads::Batch {
            children: vec![Base64UrlBytes::from_bytes(&[]); BATCH_CHILD_MAX_COUNT + 1],
        };
        assert!(count.validate().unwrap_err().message.contains("1-32"));
    }
}
