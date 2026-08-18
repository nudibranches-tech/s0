//! Embedded regorus PDP — the in-process fast path: no hop, no serialization to a
//! sidecar.
//!
//! The policy is whatever the control plane pushed in the bundle, falling back to the
//! compiled-in default. A new bundle rebuilds the compiled policy from the current
//! module + data and swaps it atomically: a pushed module replaces the policy in use, a
//! data-only bundle keeps it.

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use regorus::{CompiledPolicy, Engine, Value};

use super::Pdp;
use super::bundle::DECISION_RULE;
use crate::authz::{Decision, OpaInput};
use crate::error::{GatewayError, Result};

pub struct RegorusPdp {
    entrypoint: Arc<str>,
    /// The policy module currently loaded — the pushed module, or the compiled-in
    /// default. Kept so a data-only reload can recompile without losing the policy.
    policy: ArcSwap<String>,
    compiled: ArcSwap<CompiledPolicy>,
}

impl RegorusPdp {
    /// `policy` is the initial rego module — the compiled-in default, or a module read
    /// from the boot bundle. A later [`reload`](RegorusPdp::reload) may replace it.
    pub fn new(policy: &str, initial_data: &serde_json::Value) -> Result<Self> {
        let entrypoint: Arc<str> = Arc::from(DECISION_RULE);
        let compiled = Self::compile(policy, initial_data, &entrypoint)?;
        Ok(RegorusPdp {
            entrypoint,
            policy: ArcSwap::from_pointee(policy.to_string()),
            compiled: ArcSwap::from_pointee(compiled),
        })
    }

    fn compile(
        policy: &str,
        data: &serde_json::Value,
        entrypoint: &Arc<str>,
    ) -> Result<CompiledPolicy> {
        let mut engine = Engine::new();
        // OPA parity: builtins yield `undefined` on error rather than raising, which is
        // what a sidecar OPA does.
        engine.set_strict_builtin_errors(false);
        engine
            .add_policy("gateway/authz.rego".to_string(), policy.to_string())
            .map_err(|e| GatewayError::Pdp(format!("add_policy: {e}")))?;
        let data = Value::from_json_str(&data.to_string())
            .map_err(|e| GatewayError::Bundle(format!("bundle to value: {e}")))?;
        engine
            .add_data(data)
            .map_err(|e| GatewayError::Bundle(format!("add_data: {e}")))?;
        engine
            .compile_with_entrypoint(entrypoint)
            .map_err(|e| GatewayError::Pdp(format!("compile: {e}")))
    }
}

#[async_trait]
impl Pdp for RegorusPdp {
    async fn decide(&self, input: &OpaInput) -> Result<Decision> {
        let compiled = self.compiled.load();
        let input_json = serde_json::to_string(input)?;
        let input_value = Value::from_json_str(&input_json)
            .map_err(|e| GatewayError::Pdp(format!("input to value: {e}")))?;
        let decision_value = compiled
            .eval_with_input(input_value)
            .map_err(|e| GatewayError::Pdp(format!("eval: {e}")))?;
        // Undefined rule ⇒ deny (fail closed).
        if matches!(decision_value, Value::Undefined) {
            return Ok(Decision::deny("regorus: undefined decision"));
        }
        let decision_json = decision_value
            .to_json_str()
            .map_err(|e| GatewayError::Pdp(format!("decision to json: {e}")))?;
        Ok(serde_json::from_str(&decision_json)?)
    }

    /// Rebuild + atomically swap the compiled policy for a new bundle revision. A pushed
    /// `policy` replaces the module in use; `None` keeps the current one (a data-only
    /// change).
    async fn reload(&self, policy: Option<&str>, data: &serde_json::Value) -> Result<()> {
        let current = self.policy.load();
        let effective = policy.unwrap_or(current.as_str());
        let compiled = Self::compile(effective, data, &self.entrypoint)?;
        if let Some(pushed) = policy {
            self.policy.store(Arc::new(pushed.to_string()));
        }
        self.compiled.store(Arc::new(compiled));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{Backend, Principal, PrincipalAttributes, RequestMeta};
    use crate::model::{Action, BackendKind, PrincipalType};

    fn data() -> serde_json::Value {
        serde_json::json!({
            "org_settings": { "freeze_writes": false },
            "tenants": { "acme": {
                "user_attributes": { "alice": { "groups": [], "attributes": [] } },
                "bucket_attributes": {},
                "s3_grants": { "alice": [
                    { "bucket": "b", "actions": ["read_objects"], "prefixes": [""] }
                ] },
                "group_grants": {}
            }}
        })
    }

    fn read_bx() -> OpaInput {
        OpaInput {
            principal: Principal {
                sub: "alice".into(),
                kind: PrincipalType::User,
                attributes: PrincipalAttributes::default(),
            },
            backend: Backend {
                id: "b1".into(),
                kind: BackendKind::RemoteS3,
            },
            tenant: "acme".into(),
            organization_id: "org-acme".into(),
            action: Action::ReadObjects,
            bucket: "b".into(),
            object: Some("x".into()),
            prefix: None,
            copy_source: None,
            delete_keys: None,
            object_tags: None,
            requested_tags: None,
            acl_grants: vec![],
            bypass_governance: false,
            request: RequestMeta::default(),
        }
    }

    const DENY_ALL: &str = "package s3.authz\n\ndecision := {\"allow\": false, \"reason\": \"test deny-all\", \"obligations\": {}}\n";

    #[tokio::test]
    async fn pushed_policy_overrides_default_and_survives_data_reload() {
        // The compiled-in default grants alice read on b/x.
        let pdp = RegorusPdp::new(crate::pdp::GATEWAY_REGO, &data()).unwrap();
        assert!(pdp.decide(&read_bx()).await.unwrap().allow);

        // A pushed deny-all module replaces the default: the same input now denies.
        pdp.reload(Some(DENY_ALL), &data()).await.unwrap();
        assert!(!pdp.decide(&read_bx()).await.unwrap().allow);

        // A data-only reload (policy = None) keeps the pushed module in force.
        pdp.reload(None, &data()).await.unwrap();
        assert!(!pdp.decide(&read_bx()).await.unwrap().allow);
    }
}
