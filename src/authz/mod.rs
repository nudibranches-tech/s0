//! The authorization contract: the OPA input superset and the PDP decision.
//! These types are the stable seam between the S3 protocol layer, the policy
//! engines, and the audit sink.

mod decision;
mod input;

pub use decision::{Decision, Obligations};
pub use input::{Backend, CopySource, OpaInput, Principal, PrincipalAttributes, RequestMeta};
