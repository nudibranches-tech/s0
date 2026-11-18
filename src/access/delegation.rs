//! The delegation proof: the mirror image of [`super::proof`] for operations a control
//! backend answers.
//!
//! `check` mints a [`DelegationProof`] when [`super::optable::gate`] says
//! [`super::optable::Gate::Delegated`], and nothing else can ([`DelegationProof::mint`] is
//! `pub(super)`). The delegated hook and the dispatch arm both demand it, and neither this
//! proof nor an [`super::AuthzProof`] opens the other's arm: an enforced arm needs a policy
//! decision, a delegated arm needs `check` to have admitted the operation as delegated.

use std::sync::Arc;

use s3s::{S3Request, S3Result, s3_error};

use super::OperationName;

/// Evidence that `check` admitted *this* request as a delegated operation.
#[derive(Debug, Clone)]
pub struct DelegationProof {
    operation: Arc<str>,
}

impl DelegationProof {
    pub(super) fn mint(operation: Arc<str>) -> Self {
        DelegationProof { operation }
    }

    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }
}

/// Fail closed unless `check` admitted this exact request as delegated. Called by the
/// delegated hook and, before the control client is touched, by the dispatch arm.
pub fn require<T>(req: &S3Request<T>) -> S3Result<()> {
    let Some(proof) = req.extensions.get::<DelegationProof>() else {
        tracing::error!("delegation refused: no delegation proof — `check` did not admit it");
        return Err(s3_error!(
            InternalError,
            "request reached the control backend without a delegation decision"
        ));
    };
    let Some(op) = req.extensions.get::<OperationName>() else {
        tracing::error!("delegation refused: operation name missing — `check` did not run");
        return Err(s3_error!(
            InternalError,
            "operation name missing from request"
        ));
    };
    if proof.operation() != &*op.0 {
        tracing::error!(
            proved = proof.operation(),
            delegating = %op.0,
            "delegation refused: proof is for a different operation"
        );
        return Err(s3_error!(
            InternalError,
            "delegation proof does not match the delegated operation"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use http::{Extensions, HeaderMap, Method};

    use super::*;
    use crate::access::AuthzProof;
    use crate::access::proof;

    fn request(extensions: Extensions) -> S3Request<()> {
        S3Request {
            input: (),
            method: Method::GET,
            uri: "/".parse().expect("uri"),
            headers: HeaderMap::new(),
            extensions,
            credentials: None,
            region: None,
            service: None,
            trailing_headers: None,
        }
    }

    fn with(op: &str, proof_for: &str, delegation: bool) -> S3Request<()> {
        let mut ext = Extensions::new();
        ext.insert(OperationName(op.into()));
        if delegation {
            ext.insert(DelegationProof::mint(proof_for.into()));
        } else {
            ext.insert(AuthzProof::mint(proof_for.into()));
        }
        request(ext)
    }

    #[test]
    fn a_proof_for_the_same_operation_opens_the_delegated_arm() {
        assert!(require(&with("CreateBucket", "CreateBucket", true)).is_ok());
    }

    #[test]
    fn no_proof_and_a_proof_for_another_operation_are_refused() {
        assert!(require(&request(Extensions::new())).is_err());
        assert!(require(&with("CreateBucket", "PutBucketCors", true)).is_err());
        let mut no_name = Extensions::new();
        no_name.insert(DelegationProof::mint("CreateBucket".into()));
        assert!(require(&request(no_name)).is_err());
    }

    #[test]
    fn an_authz_proof_does_not_open_a_delegated_arm() {
        assert!(require(&with("CreateBucket", "CreateBucket", false)).is_err());
    }

    #[test]
    fn a_delegation_proof_does_not_open_an_enforced_arm() {
        let req = with("GetObject", "GetObject", true);
        assert!(proof::require(&req).is_err());
    }
}
