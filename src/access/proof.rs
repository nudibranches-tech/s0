//! The authorization proof — what makes the gateway fail-closed by *construction*
//! rather than by convention.
//!
//! `OP_TABLE` proves that an enforced op has a hook and a dispatch arm. It cannot
//! prove that the hook, on this request, actually authorized anything: a hook that
//! returns `Ok(())` down some branch, or one that is added without wiring an
//! `enforce_*` call, type-checks and forwards. The proof closes that:
//!
//! - only the enforce path can mint one ([`AuthzProof::mint`] is `pub(super)`, so it
//!   is unreachable from `crate::proxy` and from every test outside `crate::access`);
//! - it is minted only on the allow side of a decision that was also audited;
//! - the forward path calls [`require`] before it touches a backend client.
//!
//! So a hook that forgets to authorize cannot reach the backend — it fails with an
//! internal error instead, which is the honest outcome for a gateway bug.

use std::sync::Arc;

use s3s::{S3Request, S3Result, s3_error};

use super::OperationName;

/// Evidence that the enforce path allowed *this* request.
///
/// Lives in `req.extensions`, which s3s carries from the typed access hook into the
/// `S3` dispatch call unchanged (`ops/generated.rs`: the same `s3_req` is passed to
/// both). The field is private and the constructor is module-private on purpose —
/// presence of the value is the whole signal, so nothing outside the enforce path may
/// produce it.
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
    // Bind the proof to the request it was minted for. One request is one operation,
    // so this can only fire if a helper stashed a proof it did not mint here — but
    // `s3s`'s `post_object` default re-dispatches a `PostObject` through
    // `put_object`, so "the op that was decided" and "the op being forwarded" are not
    // the same question, and the cheap check is worth having.
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
