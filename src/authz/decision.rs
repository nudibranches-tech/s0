//! The PDP verdict. Produced identically by the regorus and sidecar engines so
//! the dual-engine parity gate can compare them byte-for-byte.

use serde::{Deserialize, Serialize};

/// One policy decision. Deserialized directly from the rego rule
/// `data.s0.gateway.decision`, so its shape mirrors the rego object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub allow: bool,
    /// Human/audit-facing justification. Always present — deny reasons matter as
    /// much as allow reasons for the regulated audit trail.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub obligations: Obligations,
}

/// Side-effects the PEP must apply to a *permitted* request before forwarding.
/// These only exist because we are on the parsed path; a byte proxy could
/// not honor them.
///
/// `deny_unknown_fields` is a fail-closed rule, not tidiness. The policy module is
/// hot-swapped from the control-plane bundle ([`crate::pdp::embedded::RegorusPdp`]),
/// so a bundle can emit an obligation this binary does not implement — an
/// `excluded_prefixes` narrowing a listing, say. Dropping it silently would turn a
/// *restriction* into an unrestricted forward: the fail-open twin of a policy reading a
/// field no producer emits. Refusing to deserialize instead surfaces as an `Err` out of
/// `Pdp::decide`, which [`crate::access::GatewayAccess::decide`] turns into a denial.
/// So an obligation we do not understand denies the request. Adding a field here is
/// what makes it honored; until then it is enforced by refusal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Obligations {
    /// Narrow an unbounded `ListObjects*` to a single granted prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub narrow_prefix: Option<String>,
    /// Prefix scopes the subject holds on this bucket. When more than one, a
    /// single S3 `prefix` param cannot express them — the PEP fans out or filters.
    /// Empty means "unscoped within what was already allowed".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_prefixes: Vec<String>,
}

impl Decision {
    pub fn deny(reason: impl Into<String>) -> Self {
        Decision {
            allow: false,
            reason: reason.into(),
            obligations: Obligations::default(),
        }
    }

    pub fn allow(reason: impl Into<String>) -> Self {
        Decision {
            allow: true,
            reason: reason.into(),
            obligations: Obligations::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_obligation_is_a_deserialization_error() {
        // The unit-level half of
        // `security_regressions::an_obligation_this_binary_does_not_implement_denies_
        // rather_than_being_ignored`. `Pdp::decide` deserializes the rego object, so a
        // refusal here is an `Err` out of the PDP, which the access layer turns into a
        // denial. Silently dropping the field would instead hand `classify_list` an
        // empty `Obligations` and forward the request.
        let err = serde_json::from_str::<Decision>(
            r#"{"allow":true,"reason":"ok","obligations":{"excluded_prefixes":["p/"]}}"#,
        )
        .expect_err("an obligation this binary cannot honor must not deserialize");
        assert!(format!("{err}").contains("excluded_prefixes"), "{err}");
    }

    #[test]
    fn the_obligations_this_binary_does_implement_still_deserialize() {
        // Positive control: `deny_unknown_fields` must reject the unknown, not the known.
        let d: Decision = serde_json::from_str(
            r#"{"allow":true,"reason":"ok","obligations":{"narrow_prefix":"a/","allowed_prefixes":["a/","b/"]}}"#,
        )
        .expect("known obligations parse");
        assert_eq!(d.obligations.narrow_prefix.as_deref(), Some("a/"));
        assert_eq!(d.obligations.allowed_prefixes, ["a/", "b/"]);
        // And an absent `obligations` is still the empty set, not an error.
        let d: Decision = serde_json::from_str(r#"{"allow":false,"reason":"no"}"#).expect("parse");
        assert_eq!(d.obligations, Obligations::default());
    }
}
