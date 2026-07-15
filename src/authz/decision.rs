//! The PDP verdict. Produced identically by the regorus and sidecar engines so
//! the dual-engine parity gate (§4.3.1) can compare them byte-for-byte.

use serde::{Deserialize, Serialize};

/// One policy decision. Deserialized directly from the rego rule
/// `data.hyperfluid.gateway.decision`, so its shape mirrors the rego object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub allow: bool,
    /// Human/audit-facing justification. Always present — deny reasons matter as
    /// much as allow reasons for the regulated audit trail (§6.6).
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub obligations: Obligations,
}

/// Side-effects the PEP must apply to a *permitted* request before forwarding.
/// These only exist because we are on the parsed path (§1.1); a byte proxy could
/// not honor them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Obligations {
    /// Narrow an unbounded `ListObjects*` to a single granted prefix (§5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub narrow_prefix: Option<String>,
    /// Prefix scopes the subject holds on this bucket. When more than one, a
    /// single S3 `prefix` param cannot express them — the PEP fans out or filters
    /// (§5.1). Empty means "unscoped within what was already allowed".
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
