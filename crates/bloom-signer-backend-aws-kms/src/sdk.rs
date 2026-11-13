use super::{
    AwsKmsInstanceConfig, AwsKmsKeyMetadata, AwsKmsProvider, AwsKmsPublicKey, AwsKmsSignRequest,
    AwsKmsSignResponse, AwsProviderCallContext, AwsProviderError, AwsProviderErrorKind,
    AwsProviderResponse, CredentialSource,
};
#[allow(deprecated)]
use aws_config::{
    BehaviorVersion,
    provider_config::ProviderConfig,
    web_identity_token::{StaticConfiguration, WebIdentityTokenCredentialsProvider},
};
use aws_credential_types::provider::SharedCredentialsProvider;
use aws_sdk_kms::{
    Client,
    config::Region,
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use aws_smithy_runtime_api::client::{orchestrator::HttpResponse, result::SdkError};
use aws_smithy_types::{error::metadata::ProvideErrorMetadata, retry::RetryConfig};
use aws_types::request_id::RequestId;
use bloom_signer_backend_api::BackendFuture;
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Concrete AWS SDK transport. It is constructed only from the closed,
/// explicit credential configuration and disables SDK retries.
pub struct AwsSdkKmsProvider {
    client: Client,
}

#[derive(Clone, Copy)]
enum ProviderOperation {
    ReadOnly,
    Sign,
}

impl AwsSdkKmsProvider {
    pub fn new(config: &AwsKmsInstanceConfig) -> Result<Self, AwsProviderError> {
        config
            .validate()
            .map_err(|_| AwsProviderError::new(AwsProviderErrorKind::InvalidRequest, None))?;
        let region = Region::new(config.region.clone());
        let credentials = explicit_credentials(&config.credential_source, region.clone())?;
        let endpoint = format!("https://kms.{}.amazonaws.com", config.region);
        let sdk_config = aws_sdk_kms::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(region)
            .credentials_provider(credentials)
            .endpoint_url(endpoint)
            .retry_config(RetryConfig::disabled())
            .build();
        Ok(Self {
            client: Client::from_conf(sdk_config),
        })
    }

    async fn describe(
        &self,
        arn: &str,
        context: &AwsProviderCallContext,
    ) -> Result<AwsProviderResponse<AwsKmsKeyMetadata>, AwsProviderError> {
        let output = with_deadline(
            context.deadline_ms.get(),
            ProviderOperation::ReadOnly,
            self.client.describe_key().key_id(arn).send(),
        )
        .await?;
        let request_id = output
            .request_id()
            .map(str::to_owned)
            .ok_or_else(|| AwsProviderError::new(AwsProviderErrorKind::DefinitiveRejected, None))?;
        let metadata = output.key_metadata().ok_or_else(|| {
            AwsProviderError::new(
                AwsProviderErrorKind::DefinitiveRejected,
                Some(request_id.clone()),
            )
        })?;
        let metadata_arn = metadata.arn().ok_or_else(|| {
            AwsProviderError::new(
                AwsProviderErrorKind::DefinitiveRejected,
                Some(request_id.clone()),
            )
        })?;
        let (region, account_id) = arn_region_account(metadata_arn).ok_or_else(|| {
            AwsProviderError::new(
                AwsProviderErrorKind::DefinitiveRejected,
                Some(request_id.clone()),
            )
        })?;
        Ok(AwsProviderResponse {
            value: AwsKmsKeyMetadata {
                arn: metadata_arn.to_owned(),
                account_id,
                region,
                enabled: metadata.enabled(),
                key_usage: metadata
                    .key_usage()
                    .map(|value| value.as_str().to_owned())
                    .unwrap_or_default(),
                key_spec: metadata
                    .key_spec()
                    .map(|value| value.as_str().to_owned())
                    .unwrap_or_default(),
                signing_algorithms: metadata
                    .signing_algorithms()
                    .iter()
                    .map(|value| value.as_str().to_owned())
                    .collect(),
            },
            request_id,
        })
    }

    async fn public_key(
        &self,
        arn: &str,
        context: &AwsProviderCallContext,
    ) -> Result<AwsProviderResponse<AwsKmsPublicKey>, AwsProviderError> {
        let output = with_deadline(
            context.deadline_ms.get(),
            ProviderOperation::ReadOnly,
            self.client.get_public_key().key_id(arn).send(),
        )
        .await?;
        let request_id = output
            .request_id()
            .map(str::to_owned)
            .ok_or_else(|| AwsProviderError::new(AwsProviderErrorKind::DefinitiveRejected, None))?;
        let bytes = output.public_key().ok_or_else(|| {
            AwsProviderError::new(
                AwsProviderErrorKind::DefinitiveRejected,
                Some(request_id.clone()),
            )
        })?;
        Ok(AwsProviderResponse {
            value: AwsKmsPublicKey {
                canonical_spki_der: bytes.as_ref().to_vec(),
                request_id: request_id.clone(),
            },
            request_id,
        })
    }

    async fn sign_digest(
        &self,
        request: AwsKmsSignRequest,
    ) -> Result<AwsKmsSignResponse, AwsProviderError> {
        if request.algorithm != "ECDSA_SHA_256" || !request.message_type_digest {
            return Err(AwsProviderError::new(
                AwsProviderErrorKind::InvalidRequest,
                None,
            ));
        }
        let output = with_deadline(
            request.deadline_ms.get(),
            ProviderOperation::Sign,
            self.client
                .sign()
                .key_id(request.key_arn)
                .message(Blob::new(request.digest))
                .message_type(MessageType::Digest)
                .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                .send(),
        )
        .await?;
        let request_id = output
            .request_id()
            .map(str::to_owned)
            .ok_or_else(|| AwsProviderError::new(AwsProviderErrorKind::DefinitiveRejected, None))?;
        let signature = output.signature().ok_or_else(|| {
            AwsProviderError::new(
                AwsProviderErrorKind::DefinitiveRejected,
                Some(request_id.clone()),
            )
        })?;
        Ok(AwsKmsSignResponse {
            der_signature: signature.as_ref().to_vec(),
            request_id,
        })
    }
}

impl AwsKmsProvider for AwsSdkKmsProvider {
    fn describe_key<'a>(
        &'a self,
        immutable_key_arn: &'a str,
        context: AwsProviderCallContext,
    ) -> BackendFuture<'a, Result<AwsProviderResponse<AwsKmsKeyMetadata>, AwsProviderError>> {
        Box::pin(async move { self.describe(immutable_key_arn, &context).await })
    }

    fn get_public_key<'a>(
        &'a self,
        immutable_key_arn: &'a str,
        context: AwsProviderCallContext,
    ) -> BackendFuture<'a, Result<AwsProviderResponse<AwsKmsPublicKey>, AwsProviderError>> {
        Box::pin(async move { self.public_key(immutable_key_arn, &context).await })
    }

    fn sign<'a>(
        &'a self,
        request: AwsKmsSignRequest,
    ) -> BackendFuture<'a, Result<AwsKmsSignResponse, AwsProviderError>> {
        Box::pin(async move { self.sign_digest(request).await })
    }
}

fn explicit_credentials(
    source: &CredentialSource,
    region: Region,
) -> Result<SharedCredentialsProvider, AwsProviderError> {
    match source {
        CredentialSource::WebIdentity {
            role_arn,
            token_file,
            session_name,
        } => {
            let provider_config = ProviderConfig::without_region()
                .with_region(Some(region))
                .with_retry_config(RetryConfig::disabled());
            let static_configuration = StaticConfiguration {
                web_identity_token_file: PathBuf::from(token_file),
                role_arn: role_arn.clone(),
                session_name: session_name.as_str().to_owned(),
            };
            Ok(SharedCredentialsProvider::new(
                WebIdentityTokenCredentialsProvider::builder()
                    .configure(&provider_config)
                    .static_configuration(static_configuration)
                    .build(),
            ))
        }
    }
}

async fn with_deadline<T, E>(
    deadline_ms: u64,
    operation: ProviderOperation,
    future: impl Future<Output = Result<T, SdkError<E, HttpResponse>>>,
) -> Result<T, AwsProviderError>
where
    E: ProvideErrorMetadata,
{
    let now_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AwsProviderError::new(AwsProviderErrorKind::ProvenNotDispatched, None))?
        .as_millis()
        .try_into()
        .map_err(|_| AwsProviderError::new(AwsProviderErrorKind::ProvenNotDispatched, None))?;
    let remaining = deadline_ms
        .checked_sub(now_ms)
        .ok_or_else(|| AwsProviderError::new(AwsProviderErrorKind::ProvenNotDispatched, None))?;
    match tokio::time::timeout(Duration::from_millis(remaining), future).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(map_sdk_error(error, operation)),
        Err(_) => Err(AwsProviderError::new(
            AwsProviderErrorKind::TimeoutAfterDispatch,
            None,
        )),
    }
}

fn map_sdk_error<E>(
    error: SdkError<E, HttpResponse>,
    operation: ProviderOperation,
) -> AwsProviderError
where
    E: ProvideErrorMetadata,
{
    let request_id = error.meta().request_id().map(str::to_owned);
    let error_code = error.meta().code().map(str::to_owned);
    let kind = match error {
        SdkError::ConstructionFailure(_) => AwsProviderErrorKind::ProvenNotDispatched,
        SdkError::ServiceError(_) => match operation {
            ProviderOperation::ReadOnly => AwsProviderErrorKind::DefinitiveRejected,
            ProviderOperation::Sign
                if error_code
                    .as_deref()
                    .is_some_and(is_definitive_sign_rejection) =>
            {
                AwsProviderErrorKind::DefinitiveRejected
            }
            ProviderOperation::Sign => AwsProviderErrorKind::Unknown,
        },
        SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) | SdkError::ResponseError(_) => {
            AwsProviderErrorKind::Unknown
        }
        _ => AwsProviderErrorKind::Unknown,
    };
    AwsProviderError::new(kind, request_id)
}

fn is_definitive_sign_rejection(code: &str) -> bool {
    matches!(
        code,
        "AccessDeniedException"
            | "DisabledException"
            | "DryRunOperationException"
            | "InvalidArnException"
            | "InvalidGrantTokenException"
            | "InvalidKeyUsageException"
            | "KMSInvalidStateException"
            | "NotFoundException"
            | "ValidationException"
    )
}

fn arn_region_account(arn: &str) -> Option<(String, String)> {
    let mut pieces = arn.split(':');
    if pieces.next()? != "arn" || pieces.next()? != "aws" || pieces.next()? != "kms" {
        return None;
    }
    let region = pieces.next()?.to_owned();
    let account = pieces.next()?.to_owned();
    Some((region, account))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_credential_types::Credentials;
    use aws_smithy_runtime::client::http::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;
    use bloom_signer_api::{DecimalU64, Digest32};

    const ARN: &str = "arn:aws:kms:eu-west-2:123456789012:key/11111111-2222-3333-4444-555555555555";

    #[tokio::test]
    async fn sdk_provider_issues_exact_describe_get_and_digest_sign_requests_once() {
        let replay = StaticReplayClient::new(vec![
            event(
                r#"{"KeyMetadata":{"AWSAccountId":"123456789012","Arn":"arn:aws:kms:eu-west-2:123456789012:key/11111111-2222-3333-4444-555555555555","Enabled":true,"KeyId":"11111111-2222-3333-4444-555555555555","KeyManager":"CUSTOMER","KeySpec":"ECC_SECG_P256K1","KeyUsage":"SIGN_VERIFY","Origin":"AWS_KMS","SigningAlgorithms":["ECDSA_SHA_256"]}}"#,
                "describe-request",
            ),
            event(
                r#"{"KeyId":"11111111-2222-3333-4444-555555555555","KeySpec":"ECC_SECG_P256K1","KeyUsage":"SIGN_VERIFY","PublicKey":"AQID","SigningAlgorithms":["ECDSA_SHA_256"]}"#,
                "public-request",
            ),
            event(
                r#"{"KeyId":"11111111-2222-3333-4444-555555555555","Signature":"MAYCAQECAQE=","SigningAlgorithm":"ECDSA_SHA_256"}"#,
                "sign-request",
            ),
            error_event(
                r#"{"__type":"KMSInternalException","message":"internal"}"#,
                "internal-request",
            ),
        ]);
        let config = aws_sdk_kms::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("eu-west-2"))
            .credentials_provider(Credentials::new(
                "AKID",
                "secret",
                None,
                None,
                "explicit-test",
            ))
            .endpoint_url("https://kms.eu-west-2.amazonaws.com")
            .retry_config(RetryConfig::disabled())
            .http_client(replay.clone())
            .build();
        let provider = AwsSdkKmsProvider {
            client: Client::from_conf(config),
        };
        let context = AwsProviderCallContext {
            deadline_ms: deadline(),
            provider_attempt_id: None,
        };

        let described = provider.describe(ARN, &context).await.unwrap();
        assert_eq!(described.request_id, "describe-request");
        let public = provider.public_key(ARN, &context).await.unwrap();
        assert_eq!(public.value.canonical_spki_der, [1, 2, 3]);
        let signed = provider
            .sign_digest(AwsKmsSignRequest {
                key_arn: ARN.into(),
                digest: [0x33; 32],
                algorithm: "ECDSA_SHA_256".into(),
                message_type_digest: true,
                provider_attempt_id: Digest32::new("22".repeat(32)).unwrap(),
                deadline_ms: deadline(),
            })
            .await
            .unwrap();
        assert_eq!(signed.request_id, "sign-request");
        let ambiguous = provider
            .sign_digest(AwsKmsSignRequest {
                key_arn: ARN.into(),
                digest: [0x44; 32],
                algorithm: "ECDSA_SHA_256".into(),
                message_type_digest: true,
                provider_attempt_id: Digest32::new("55".repeat(32)).unwrap(),
                deadline_ms: deadline(),
            })
            .await
            .unwrap_err();
        assert_eq!(ambiguous.kind, AwsProviderErrorKind::Unknown);
        assert_eq!(ambiguous.request_id.as_deref(), Some("internal-request"));

        let actual = replay.actual_requests().collect::<Vec<_>>();
        assert_eq!(actual.len(), 4);
        let targets = actual
            .iter()
            .map(|request| request.headers().get("x-amz-target").unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            targets,
            [
                "TrentService.DescribeKey",
                "TrentService.GetPublicKey",
                "TrentService.Sign",
                "TrentService.Sign",
            ]
        );
        let sign_body = std::str::from_utf8(actual[2].body().bytes().unwrap()).unwrap();
        assert!(sign_body.contains(r#""MessageType":"DIGEST""#));
        assert!(sign_body.contains(r#""SigningAlgorithm":"ECDSA_SHA_256""#));
        assert!(actual.iter().all(|request| {
            request
                .uri()
                .starts_with("https://kms.eu-west-2.amazonaws.com")
        }));
    }

    fn event(json: &'static str, request_id: &'static str) -> ReplayEvent {
        ReplayEvent::new(
            http::Request::builder()
                .uri("https://kms.eu-west-2.amazonaws.com/")
                .body(SdkBody::empty())
                .unwrap(),
            http::Response::builder()
                .status(200)
                .header("content-type", "application/x-amz-json-1.1")
                .header("x-amzn-requestid", request_id)
                .body(SdkBody::from(json))
                .unwrap(),
        )
    }

    fn error_event(json: &'static str, request_id: &'static str) -> ReplayEvent {
        ReplayEvent::new(
            http::Request::builder()
                .uri("https://kms.eu-west-2.amazonaws.com/")
                .body(SdkBody::empty())
                .unwrap(),
            http::Response::builder()
                .status(500)
                .header("content-type", "application/x-amz-json-1.1")
                .header("x-amzn-requestid", request_id)
                .body(SdkBody::from(json))
                .unwrap(),
        )
    }

    fn deadline() -> DecimalU64 {
        let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap();
        DecimalU64::new(now + 60_000)
    }
}
