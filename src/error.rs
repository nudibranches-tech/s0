//! Gateway-internal error type, mapped to `s3s::S3Error` at the protocol edge, and the
//! re-minting that turns a backend's `S3Error` into the gateway's own before it reaches a
//! client.

use s3s::{S3Error, S3ErrorCode};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("policy engine error: {0}")]
    Pdp(String),

    #[error("bundle error: {0}")]
    Bundle(String),

    #[error("credential store error: {0}")]
    Credentials(String),

    #[error("sts error: {0}")]
    Sts(String),

    #[error("backend proxy error: {0}")]
    Backend(String),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, GatewayError>;

// ── backend error re-minting ────────────────────────────────────────────────────

/// Whether `err` came back from the backend rather than being minted here.
///
/// s3s-aws attaches the SDK error as the `source` of everything it returns, and the
/// gateway's own `s3_error!` refusals never carry one, so the source is the provenance.
pub fn is_backend_error(err: &S3Error) -> bool {
    err.source().is_some()
}

/// Re-mint a backend error as the gateway's own: same code, same HTTP status, a message
/// from [`gateway_message`], and `request_id` in place of the backend's.
///
/// An upstream error body is backend-authored text. AWS names ARNs and account ids in it,
/// Ceph names its tenants, and the request id embeds the zone. Only the code and status
/// cross, because a client branches on those. The original stays the `source`, which is
/// never serialized, so logs keep what the client no longer sees. Headers are not copied.
pub fn remint_backend_error(err: S3Error, request_id: &str) -> S3Error {
    let code = reminted_code(err.code());
    let status = err.status_code();
    let mut out = S3Error::with_message(code.clone(), gateway_message(&code, status));
    if let Some(status) = status {
        out.set_status_code(status);
    }
    out.set_request_id(request_id);
    out.set_source(Box::new(err));
    out
}

/// A backend code the client may see: every code s3s knows, and an unknown one only when
/// it is a plain identifier. The code is backend-authored text too, so anything else
/// (spaces, punctuation, an embedded ARN) becomes `InternalError`; the status survives.
fn reminted_code(code: &S3ErrorCode) -> S3ErrorCode {
    match code {
        S3ErrorCode::Custom(raw) => {
            let raw: &str = raw;
            let plain = raw.len() <= 64
                && raw.starts_with(|c: char| c.is_ascii_alphabetic())
                && raw.chars().all(|c| c.is_ascii_alphanumeric());
            if plain {
                code.clone()
            } else {
                S3ErrorCode::InternalError
            }
        }
        known => known.clone(),
    }
}

/// The gateway's message for a backend error code: a fixed string per code, and one per
/// status class for a code the table does not name. Never derived from the backend's text.
pub fn gateway_message(code: &S3ErrorCode, status: Option<http::StatusCode>) -> &'static str {
    match code.as_str() {
        "AccessDenied" => "Access Denied.",
        "AuthorizationHeaderMalformed" | "InvalidAccessKeyId" | "SignatureDoesNotMatch" => {
            "The storage backend did not accept the gateway's credentials for this request."
        }
        "BadDigest" => "The Content-MD5 or checksum you specified did not match what was received.",
        "BucketNotEmpty" => "The bucket you tried to delete is not empty.",
        "ConditionalRequestConflict" | "OperationAborted" => {
            "A conflicting operation is in progress against this resource. Please try again."
        }
        "EntityTooLarge" => "Your proposed upload exceeds the maximum allowed object size.",
        "EntityTooSmall" => "Your proposed upload is smaller than the minimum allowed object size.",
        "IncompleteBody" => {
            "You did not provide the number of bytes specified by the Content-Length HTTP header."
        }
        "InternalError" => "The storage backend encountered an internal error. Please try again.",
        "InvalidArgument" => "Invalid argument.",
        "InvalidBucketName" => "The specified bucket is not valid.",
        "InvalidDigest" => "The Content-MD5 or checksum you specified is not valid.",
        "InvalidObjectState" => "The operation is not valid for the current state of the object.",
        "InvalidPart" => "One or more of the specified parts could not be found.",
        "InvalidPartOrder" => "The list of parts was not in ascending order.",
        "InvalidRange" => "The requested range is not satisfiable.",
        "InvalidRequest" => "Invalid request.",
        "InvalidStorageClass" => "The storage class you specified is not valid.",
        "InvalidTag" => "The tag provided was not a valid tag.",
        "KeyTooLongError" => "Your key is too long.",
        "MalformedXML" => "The XML you provided was not well-formed or did not validate.",
        "MethodNotAllowed" => "The specified method is not allowed against this resource.",
        "MissingContentLength" => "You must provide the Content-Length HTTP header.",
        "NoSuchBucket" => "The specified bucket does not exist.",
        "NoSuchKey" => "The specified key does not exist.",
        "NoSuchTagSet" => "There is no tag set associated with the object.",
        "NoSuchUpload" => "The specified multipart upload does not exist.",
        "NoSuchVersion" => "The specified version does not exist.",
        "NotImplemented" => "The storage backend does not implement this functionality.",
        "NotModified" => "Not Modified.",
        "PreconditionFailed" => "At least one of the preconditions you specified did not hold.",
        "QuotaExceeded" => "The storage quota for this bucket or tenant has been exceeded.",
        "RequestTimeTooSkewed" => {
            "The difference between the request time and the storage backend's time is too large."
        }
        "RequestTimeout" => "The storage backend timed out waiting for the request.",
        "ServiceUnavailable" => "The storage backend is unavailable. Please try again.",
        "SlowDown" => "Please reduce your request rate.",
        "TooManyParts" => "The upload has more parts than the storage backend allows.",
        "XAmzContentSHA256Mismatch" => {
            "The provided x-amz-content-sha256 header does not match what was computed."
        }
        _ => match status.map(|s| s.as_u16()) {
            Some(400..=499) => "The storage backend refused the request.",
            _ => "The storage backend could not complete the request.",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(code: S3ErrorCode, status: u16, message: &str, request_id: &str) -> S3Error {
        let mut e = S3Error::with_message(code, message.to_string());
        e.set_request_id(request_id);
        e.set_status_code(http::StatusCode::from_u16(status).expect("status"));
        e.set_source(Box::new(std::io::Error::other("sdk service error")));
        e
    }

    const LEAKY: &str = "User: arn:aws:iam::123456789012:user/tenant-owner is not authorized";

    #[test]
    fn a_reminted_error_keeps_code_and_status_and_nothing_else() {
        let cases = [
            (S3ErrorCode::AccessDenied, 403),
            (S3ErrorCode::NoSuchKey, 404),
            (S3ErrorCode::BucketNotEmpty, 409),
            (S3ErrorCode::PreconditionFailed, 412),
            (S3ErrorCode::SlowDown, 503),
            (S3ErrorCode::InternalError, 502),
            // A known code with a status the code alone would not imply: the backend's
            // status is what the client gets.
            (S3ErrorCode::AccessDenied, 400),
            (S3ErrorCode::Custom("QuotaExceeded".into()), 403),
        ];
        for (code, status) in cases {
            let err = remint_backend_error(
                upstream(code.clone(), status, LEAKY, "tx000-upstream-zone"),
                "gw-req-1",
            );
            assert_eq!(*err.code(), code);
            assert_eq!(
                err.status_code().map(|s| s.as_u16()),
                Some(status),
                "{code:?}"
            );
            let message = err.message().expect("a gateway message");
            assert!(
                !message.contains("arn:") && !message.contains("123456789012"),
                "{message}"
            );
            assert_eq!(
                message,
                gateway_message(&code, err.status_code()),
                "the message must come from the table"
            );
            assert_eq!(err.request_id(), Some("gw-req-1"));
            assert!(err.headers().is_none());
            assert!(
                is_backend_error(&err),
                "the original stays the source, for logs"
            );
        }
    }

    #[test]
    fn an_unknown_code_crosses_only_as_a_plain_identifier() {
        for (raw, kept) in [
            ("QuotaExceeded", true),
            ("XMinioAdminBucketQuotaExceeded", true),
            ("arn:aws:iam::123456789012:root", false),
            ("Access Denied", false),
            ("", false),
            ("9Lives", false),
        ] {
            let err = remint_backend_error(
                upstream(S3ErrorCode::Custom(raw.to_string().into()), 403, LEAKY, "r"),
                "gw",
            );
            if kept {
                assert_eq!(err.code().as_str(), raw);
            } else {
                assert_eq!(*err.code(), S3ErrorCode::InternalError, "{raw:?}");
            }
            assert_eq!(err.status_code().map(|s| s.as_u16()), Some(403), "{raw:?}");
        }
        let long = "A".repeat(65);
        let err = remint_backend_error(
            upstream(S3ErrorCode::Custom(long.into()), 400, LEAKY, "r"),
            "gw",
        );
        assert_eq!(*err.code(), S3ErrorCode::InternalError);
    }

    #[test]
    fn a_dispatch_failure_is_reminted_without_inventing_a_status() {
        // No status set, as s3s-aws leaves a connection that never reached the backend:
        // the code-implied 500 still applies, and nothing new is asserted.
        let mut e = S3Error::new(S3ErrorCode::InternalError);
        e.set_source(Box::new(std::io::Error::other("connection refused")));
        let err = remint_backend_error(e, "gw");
        assert_eq!(err.status_code().map(|s| s.as_u16()), Some(500));
        assert_eq!(err.request_id(), Some("gw"));
    }

    #[test]
    fn unnamed_codes_fall_back_per_status_class() {
        let code = S3ErrorCode::Custom("SomethingNew".into());
        assert_eq!(
            gateway_message(&code, Some(http::StatusCode::CONFLICT)),
            "The storage backend refused the request."
        );
        assert_eq!(
            gateway_message(&code, Some(http::StatusCode::BAD_GATEWAY)),
            "The storage backend could not complete the request."
        );
        assert_eq!(
            gateway_message(&code, None),
            "The storage backend could not complete the request."
        );
    }

    #[test]
    fn gateway_minted_errors_are_not_backend_errors() {
        assert!(!is_backend_error(&s3s::s3_error!(
            InvalidArgument,
            "malformed continuation token"
        )));
    }
}
