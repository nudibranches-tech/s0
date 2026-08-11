//! The authorization contract: the OPA input superset and the PDP decision.
//! These types are the stable seam between the S3 protocol layer, the policy
//! engines, and the audit sink.

pub mod capture;
mod decision;
mod input;

pub use capture::{CaptureSink, CapturedInput};
pub use decision::{Decision, IMPLEMENTED_OBLIGATIONS, Obligations};
pub use input::{
    AclGrant, Backend, CopySource, OPA_INPUT_FIELDS, OpaInput, Principal, PrincipalAttributes,
    RequestMeta,
};
