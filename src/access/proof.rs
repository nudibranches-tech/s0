//! The authorization proof — what makes the gateway fail-closed by *construction*
//! rather than by convention.
//!
//! `OP_TABLE` proves that an enforced op has a hook and a dispatch arm, but not that the
//! hook authorized anything on *this* request: one that returns `Ok(())` down some branch,
//! or is added without wiring an `enforce_*` call, type-checks and forwards. The proof
//! closes that:
//!
//! - only the enforce path can mint one ([`AuthzProof::mint`] is `pub(super)`, so it
//!   is unreachable from `crate::proxy` and from every test outside `crate::access`);
//! - it is minted only on the allow side of a decision that was also audited;
//! - the forward path calls [`require`] before it touches a backend client.
//!
//! A hook that forgets to authorize therefore fails with an internal error rather than
//! reaching the backend.

use std::sync::Arc;

use s3s::{S3Request, S3Result, s3_error};

use super::OperationName;

/// Evidence that the enforce path allowed *this* request.
///
/// Lives in `req.extensions`, which s3s carries from the typed access hook into the `S3`
/// dispatch call unchanged. Presence of the value is the whole signal, so the field and
/// the constructor are private: nothing outside the enforce path may produce one.
#[derive(Debug, Clone)]
pub struct AuthzProof {
    operation: Arc<str>,
}

impl AuthzProof {
    /// Mint a proof for the operation `check` recorded. Visible only inside
    /// `crate::access`.
    pub(super) fn mint(operation: Arc<str>) -> Self {
        AuthzProof { operation }
    }

    /// The operation the enforce path authorized.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }
}

/// Fail closed unless the enforce path authorized this exact request. Called by the
/// forward path before any backend client is resolved.
///
/// A failure here is never a client error — it means an authorized-looking request
/// reached dispatch without a decision, which is a defect in this binary. It is
/// logged at `error!` for exactly that reason.
pub fn require<T>(req: &S3Request<T>) -> S3Result<()> {
    let Some(proof) = req.extensions.get::<AuthzProof>() else {
        tracing::error!("forward refused: no authorization proof — a typed hook did not enforce");
        return Err(s3_error!(
            InternalError,
            "request reached the backend without an authorization decision"
        ));
    };
    // Bind the proof to the operation it was minted for: `s3s`'s `post_object` default
    // re-dispatches a `PostObject` through `put_object`, so "the op that was decided" and
    // "the op being forwarded" are not always the same question.
    let Some(op) = req.extensions.get::<OperationName>() else {
        tracing::error!("forward refused: operation name missing — `check` did not run");
        return Err(s3_error!(
            InternalError,
            "operation name missing from request"
        ));
    };
    if proof.operation() != &*op.0 {
        tracing::error!(
            proved = proof.operation(),
            forwarding = %op.0,
            "forward refused: authorization proof is for a different operation"
        );
        return Err(s3_error!(
            InternalError,
            "authorization proof does not match the forwarded operation"
        ));
    }
    Ok(())
}

/// A backend operation the SFTP front may issue under an [`SftpProof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SftpBackendOp {
    HeadObject,
    GetObject,
    PutObject,
    CreateMultipartUpload,
    UploadPart,
    UploadPartCopy,
    CompleteMultipartUpload,
    AbortMultipartUpload,
    ListObjectsV2,
    DeleteObject,
    CopyObject,
}

/// One licensed backend call: an operation on one key (or, for `ListObjectsV2`, one
/// prefix) of one bucket. A copy names its source too.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SftpLicense {
    pub op: SftpBackendOp,
    pub bucket: String,
    /// The object key, or the list prefix.
    pub key: String,
    /// `(bucket, key)` of a copy's source.
    pub source: Option<(String, String)>,
}

impl SftpLicense {
    pub fn on(op: SftpBackendOp, bucket: &str, key: &str) -> Self {
        SftpLicense {
            op,
            bucket: bucket.to_string(),
            key: key.to_string(),
            source: None,
        }
    }

    pub fn copy(
        op: SftpBackendOp,
        bucket: &str,
        key: &str,
        src_bucket: &str,
        src_key: &str,
    ) -> Self {
        SftpLicense {
            op,
            bucket: bucket.to_string(),
            key: key.to_string(),
            source: Some((src_bucket.to_string(), src_key.to_string())),
        }
    }
}

/// Evidence that the enforce path allowed an SFTP request, and **which backend calls it
/// licenses** (ADR-009 D2). A create-only upload's proof licenses `HeadObject`,
/// `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`,
/// `AbortMultipartUpload` and `PutObject` on one key, and nothing else.
///
/// Minted only by [`crate::access::Enforcer::prove_sftp`], which refuses unless every
/// decision it is handed is an allow. The SFTP backend client calls [`Self::require`]
/// before every backend call; a call the proof does not license is an internal error,
/// exactly as a forward without an [`AuthzProof`] is on the S3 front.
#[derive(Debug, Clone)]
pub struct SftpProof {
    licenses: Vec<SftpLicense>,
}

impl SftpProof {
    pub(super) fn mint(licenses: Vec<SftpLicense>) -> Self {
        SftpProof { licenses }
    }

    /// Fail closed unless this proof licenses exactly `want`.
    pub fn require(&self, want: &SftpLicense) -> Result<(), String> {
        if self.licenses.contains(want) {
            return Ok(());
        }
        tracing::error!(
            ?want,
            "sftp backend call refused: the authorization proof does not license it"
        );
        Err(format!(
            "internal error: {:?} on {}/{} was not licensed by the authorization decision",
            want.op, want.bucket, want.key
        ))
    }

    pub fn licenses(&self) -> &[SftpLicense] {
        &self.licenses
    }
}
