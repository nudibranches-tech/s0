//! Sidecar OPA PDP (the shipping default, §4.3.1): the same engine every other PEP
//! in the platform runs, on loopback, fed by the bundle. ~0.5–2ms per decision.
//!
//! The embedded regorus engine is a config-swap behind the same [`Pdp`] trait, gated
//! by the dual-engine parity CI check — so this and regorus must agree byte-for-byte.

use async_trait::async_trait;
use serde::Deserialize;

use super::Pdp;
use crate::authz::{Decision, OpaInput};
use crate::error::{GatewayError, Result};

/// Talks to a local OPA over its Data API. The decision path is fixed to the
/// gateway rule; a missing/undefined result fails closed to a deny.
pub struct SidecarPdp {
    client: reqwest::Client,
    decision_url: String,
}

#[derive(Deserialize)]
struct OpaResponse {
    #[serde(default)]
    result: Option<Decision>,
}

impl SidecarPdp {
    /// `base_url` e.g. `http://127.0.0.1:8181`. Path is OPA's convention:
    /// `/v1/data/<package path>/<rule>`.
    pub fn new(base_url: &str, timeout: std::time::Duration) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| GatewayError::Pdp(format!("build opa client: {e}")))?;
        Ok(SidecarPdp {
            client,
            decision_url: format!(
                "{}/v1/data/hyperfluid/gateway/decision",
                base_url.trim_end_matches('/')
            ),
        })
    }
}

#[async_trait]
impl Pdp for SidecarPdp {
    async fn decide(&self, input: &OpaInput) -> Result<Decision> {
        let body = serde_json::json!({ "input": input });
        let resp = self
            .client
            .post(&self.decision_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| GatewayError::Pdp(format!("opa request: {e}")))?;
        if !resp.status().is_success() {
            return Err(GatewayError::Pdp(format!("opa status {}", resp.status())));
        }
        let parsed: OpaResponse = resp
            .json()
            .await
            .map_err(|e| GatewayError::Pdp(format!("opa decode: {e}")))?;
        // Undefined result ⇒ deny (fail closed, §6.2).
        Ok(parsed
            .result
            .unwrap_or_else(|| Decision::deny("opa: undefined decision")))
    }
}
