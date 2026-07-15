//! Embedded regorus PDP — the in-process fast path (§4.3.1): µs-scale, no hop, no
//! serialization to a sidecar. Permitted in production only behind the dual-engine
//! parity gate (§4.3.1); until then it is the engine the tests run against.
//!
//! Hot path uses [`regorus::CompiledPolicy`]: compiled once per (policy, bundle
//! revision) and evaluated with `&self` — no lock, no per-request engine clone. On a
//! new bundle we rebuild the compiled policy and swap it atomically.

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use regorus::{CompiledPolicy, Engine, Value};

use super::Pdp;
use super::bundle::DECISION_RULE;
use crate::authz::{Decision, OpaInput};
use crate::error::{GatewayError, Result};

pub struct RegorusPdp {
    /// Policy-loaded, data-less template. Cloned (cheap, Arc-backed) to rebuild the
    /// compiled policy when the bundle changes.
    base: Engine,
    entrypoint: Arc<str>,
    compiled: ArcSwap<CompiledPolicy>,
}

impl RegorusPdp {
    pub fn new(policy: &str, initial_bundle: &serde_json::Value) -> Result<Self> {
        let mut base = Engine::new();
        // OPA parity: builtins yield `undefined` on error rather than raising, matching
        // the sidecar engine so the parity gate can compare byte-for-byte (§4.3.1).
        base.set_strict_builtin_errors(false);
        base.add_policy("gateway/authz.rego".to_string(), policy.to_string())
            .map_err(|e| GatewayError::Pdp(format!("add_policy: {e}")))?;
        let entrypoint: Arc<str> = Arc::from(DECISION_RULE);
        let compiled = Self::compile(&base, &entrypoint, initial_bundle)?;
        Ok(RegorusPdp {
            base,
            entrypoint,
            compiled: ArcSwap::from_pointee(compiled),
        })
    }

    fn compile(
        base: &Engine,
        entrypoint: &Arc<str>,
        bundle: &serde_json::Value,
    ) -> Result<CompiledPolicy> {
        let mut engine = base.clone();
        let data = Value::from_json_str(&bundle.to_string())
            .map_err(|e| GatewayError::Bundle(format!("bundle to value: {e}")))?;
        engine
            .add_data(data)
            .map_err(|e| GatewayError::Bundle(format!("add_data: {e}")))?;
        engine
            .compile_with_entrypoint(entrypoint)
            .map_err(|e| GatewayError::Pdp(format!("compile: {e}")))
    }

    /// Rebuild + atomically swap the compiled policy for a new bundle revision.
    pub fn reload(&self, bundle: &serde_json::Value) -> Result<()> {
        let compiled = Self::compile(&self.base, &self.entrypoint, bundle)?;
        self.compiled.store(Arc::new(compiled));
        Ok(())
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
        // Undefined rule ⇒ deny (fail closed, §6.2).
        if matches!(decision_value, Value::Undefined) {
            return Ok(Decision::deny("regorus: undefined decision"));
        }
        let decision_json = decision_value
            .to_json_str()
            .map_err(|e| GatewayError::Pdp(format!("decision to json: {e}")))?;
        Ok(serde_json::from_str(&decision_json)?)
    }
}
