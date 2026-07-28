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
///
/// **That is a control-plane rollout ordering constraint, not an implementation
/// detail.** A policy that emits `visible_buckets` denies *every request it touches* on
/// a binary built before this field existed. The binary must therefore reach every
/// replica before the policy that uses the field is pushed — never the other way round.
/// The same applies to the next field added here.
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
    /// `ListBuckets`: the bucket names this principal may **see**.
    ///
    /// **READ THIS: the empty case is the opposite of [`Self::allowed_prefixes`].**
    /// Empty means *nothing is visible*, not "unrestricted". That asymmetry is
    /// deliberate and it is the whole reason the field exists: every request is
    /// re-signed with the tenant-owner credential, so the backend answers `ListBuckets`
    /// with the entire tenant namespace regardless of what the caller was granted.
    /// A missing or empty obligation therefore has to mean *withhold everything*, or a
    /// policy that forgot to emit one would hand out the tenant's whole bucket list.
    /// [`crate::access::GatewayAccess::list_buckets`] and
    /// `bucket_visibility_defaults_to_nothing_visible` pin it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visible_buckets: Vec<String>,
    /// `ListBuckets`: the **only** unfiltered path, and a rego author has to type it.
    ///
    /// Setting it together with a non-empty [`Self::visible_buckets`] is a deny: the two
    /// say different things about the same response, and guessing which one was meant is
    /// how an allowlist quietly becomes a no-op.
    #[serde(default, skip_serializing_if = "is_false")]
    pub all_buckets_visible: bool,
    /// Obligation names the PEP must implement, or deny.
    ///
    /// Forward compatibility in the safe direction. `deny_unknown_fields` already
    /// refuses an obligation *field* this binary does not know, but it cannot express
    /// "you must apply `visible_buckets`, and if you are too old to know what that means,
    /// refuse". This can: a name outside [`IMPLEMENTED_OBLIGATIONS`] is a denial, so a
    /// policy can make a new restriction mandatory before every replica understands it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub must_understand: Vec<String>,
}

/// `false` is the absent value for a boolean obligation, so it is not serialized —
/// an audit record should carry the obligations that were *imposed*, not a census of
/// every obligation that was not.
#[allow(clippy::trivially_copy_pass_by_ref)] // serde requires the by-reference signature
fn is_false(b: &bool) -> bool {
    !*b
}

/// The obligation names this binary honors — the closed vocabulary
/// [`Obligations::must_understand`] is checked against.
///
/// One entry per field above that carries a *restriction*. `must_understand` itself is
/// not in the set: naming it would be circular, and a binary that did not know the field
/// would already have refused the decision at `deny_unknown_fields`.
pub const IMPLEMENTED_OBLIGATIONS: &[&str] = &[
    "narrow_prefix",
    "allowed_prefixes",
    "visible_buckets",
    "all_buckets_visible",
];

impl Obligations {
    /// The `must_understand` names this binary cannot honor. Empty ⇒ the decision may
    /// be applied; anything else must become a denial at the call site, because an
    /// obligation the PEP silently skips is a restriction that did not happen.
    #[must_use]
    pub fn unimplemented(&self) -> Vec<String> {
        self.must_understand
            .iter()
            .filter(|name| !IMPLEMENTED_OBLIGATIONS.contains(&name.as_str()))
            .cloned()
            .collect()
    }
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

    #[test]
    fn bucket_visibility_defaults_to_nothing_visible() {
        // The asymmetry that makes ListBuckets safe by default, asserted rather than
        // implied. `allowed_prefixes: []` means "unscoped"; `visible_buckets: []` means
        // "nothing". A policy that says nothing about bucket visibility must not be read
        // as permission to return the tenant's whole namespace.
        let d: Decision = serde_json::from_str(r#"{"allow":true,"reason":"ok"}"#).expect("parse");
        assert!(d.obligations.visible_buckets.is_empty());
        assert!(
            !d.obligations.all_buckets_visible,
            "an unfiltered bucket listing must never be the default; a rego author has \
             to type all_buckets_visible"
        );
    }

    #[test]
    fn the_bucket_obligations_deserialize_and_round_trip() {
        let d: Decision = serde_json::from_str(
            r#"{"allow":true,"reason":"ok","obligations":{"visible_buckets":["a","b"],
                "must_understand":["visible_buckets"]}}"#,
        )
        .expect("known obligations parse");
        assert_eq!(d.obligations.visible_buckets, ["a", "b"]);
        assert!(d.obligations.unimplemented().is_empty());

        let d: Decision = serde_json::from_str(
            r#"{"allow":true,"reason":"ok","obligations":{"all_buckets_visible":true}}"#,
        )
        .expect("parse");
        assert!(d.obligations.all_buckets_visible);

        // `false` and the empty vectors are not serialized: the record carries the
        // obligations that were imposed, not the ones that were not.
        let json = serde_json::to_string(&Obligations::default()).expect("serialize");
        assert_eq!(json, "{}");
    }

    #[test]
    fn a_must_understand_name_this_binary_cannot_honor_is_reported() {
        // `deny_unknown_fields` cannot express "apply this, or refuse" — the field it
        // guards may not exist yet on the *newer* side. `must_understand` can, and the
        // call site turns a non-empty answer here into a denial.
        let d: Decision = serde_json::from_str(
            r#"{"allow":true,"reason":"ok","obligations":{"must_understand":["excluded_prefixes"]}}"#,
        )
        .expect("parse");
        assert_eq!(d.obligations.unimplemented(), vec!["excluded_prefixes"]);
        for name in IMPLEMENTED_OBLIGATIONS {
            let d = Obligations {
                must_understand: vec![(*name).to_string()],
                ..Obligations::default()
            };
            assert!(d.unimplemented().is_empty(), "{name}");
        }
    }
}
