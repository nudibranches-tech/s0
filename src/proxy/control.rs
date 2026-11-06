//! The control backend client (ADR-011): where the delegable operations go.
//!
//! A dedicated [`Proxy`] over a client of its own, signed with s0's control credential,
//! with retries off and its own timeouts. `s3s_aws::Proxy` drops `req.headers` and
//! `req.extensions` on the way to the SDK, so the caller's identity cannot ride the
//! request; a client-level interceptor reads it from a task-local instead and adds it
//! **before signing**, which puts every `x-s0-*` header inside `SignedHeaders`
//! (ADR-011 D4). The interceptor fails closed: with no caller in scope nothing is sent.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use aws_sdk_s3::config::interceptors::{
    BeforeDeserializationInterceptorContextRef, BeforeTransmitInterceptorContextMut,
};
use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::config::{
    BehaviorVersion, ConfigBag, Credentials, Intercept, Region, RuntimeComponents,
    StalledStreamProtectionConfig,
};
use aws_sdk_s3::error::BoxError;
use aws_sdk_s3::{Client, Config};
use s3s_aws::Proxy;

use crate::access::optable::DelegatedOps;
use crate::config::ControlBackendConfig;
use crate::counters::LabeledCounters;
use crate::error::{GatewayError, Result};
use crate::proxy::ExplicitEmptyBodyLength;

/// `user:<oauth id>` or `sa:<client id>`.
pub const CALLER_SUBJECT_HEADER: &str = "x-s0-caller-subject";
/// The harbor slug of the caller's tenant.
pub const CALLER_TENANT_HEADER: &str = "x-s0-caller-tenant";
/// The organization, taken from the route, never from the credential.
pub const CALLER_ORGANIZATION_HEADER: &str = "x-s0-caller-organization";
/// The backend this s0 serves.
pub const BACKEND_ID_HEADER: &str = "x-s0-backend-id";
/// The decision id of the delegated audit record.
pub const REQUEST_ID_HEADER: &str = "x-s0-request-id";

/// When `check` admitted a delegated request, for the budget of the wait that follows
/// the call.
#[derive(Debug, Clone, Copy)]
pub struct CheckedAt(pub std::time::Instant);

/// The longest a delegated request may take from `check` to its answer: below the 60 s
/// the client waits for a response.
pub const DELEGATED_DEADLINE: Duration = Duration::from_secs(55);

/// The control backend: its client, and the operations it answers.
pub struct ControlBackend {
    config: ControlBackendConfig,
    proxy: Proxy,
    delegated: DelegatedOps,
    placement_wait: Duration,
    binding: Option<(String, String)>,
    requests_total: Arc<LabeledCounters>,
}

impl ControlBackend {
    pub fn from_config(cfg: &ControlBackendConfig) -> Result<Self> {
        let delegated = DelegatedOps::from_names(&cfg.operations)
            .map_err(|e| GatewayError::Config(format!("control_backend: {e}")))?;
        Ok(ControlBackend {
            config: cfg.clone(),
            proxy: build_control_proxy(cfg),
            delegated,
            placement_wait: cfg.placement_wait(),
            binding: None,
            requests_total: Arc::new(LabeledCounters::default()),
        })
    }

    /// Record the (organization, backend) the tenants of `tenants` are bound to, which
    /// the control credential is bound to as well (ADR-011 D2).
    pub fn bound_to(mut self, tenants: &[crate::config::TenantConfig]) -> Self {
        self.binding = tenants
            .first()
            .map(|t| (t.organization_id.clone(), t.backend_id.clone()));
        self
    }

    /// Whether every tenant of `tenants` is bound to the (organization, backend) this
    /// control backend was built for.
    pub fn serves(&self, tenants: &[crate::config::TenantConfig]) -> bool {
        match &self.binding {
            None => true,
            Some((org, backend)) => tenants
                .iter()
                .all(|t| &t.organization_id == org && &t.backend_id == backend),
        }
    }

    /// Whether `other` is the configuration this control backend was built from.
    pub fn is_built_from(&self, other: Option<&ControlBackendConfig>) -> bool {
        other == Some(&self.config)
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }

    pub fn delegated(&self) -> &DelegatedOps {
        &self.delegated
    }

    /// Delegated requests by operation and the class of the status the control backend
    /// answered.
    pub fn requests_total(&self) -> Arc<LabeledCounters> {
        self.requests_total.clone()
    }

    pub fn placement_wait(&self) -> Duration {
        self.placement_wait
    }

    /// The longest a delegated call can be in flight: the call timeout plus the
    /// placement wait.
    pub fn call_budget(&self) -> Duration {
        self.config
            .call_timeout()
            .saturating_add(self.placement_wait)
    }
}

/// Who a delegated call is made for, and what came back. One per request, shared between
/// the dispatcher (which scopes it) and the interceptor (which signs it and records the
/// status the control backend answered).
#[derive(Debug)]
pub struct DelegatedCaller {
    pub subject: String,
    pub tenant: String,
    pub organization_id: String,
    pub backend_id: String,
    pub request_id: String,
    observed_status: OnceLock<u16>,
}

impl DelegatedCaller {
    pub fn new(
        subject: String,
        tenant: String,
        organization_id: String,
        backend_id: String,
        request_id: String,
    ) -> Self {
        DelegatedCaller {
            subject,
            tenant,
            organization_id,
            backend_id,
            request_id,
            observed_status: OnceLock::new(),
        }
    }

    /// The HTTP status the control backend answered, or `None` when no response arrived
    /// (connect failure, timeout, an interceptor refusal).
    pub fn observed_status(&self) -> Option<u16> {
        self.observed_status.get().copied()
    }

    fn headers(&self) -> [(&'static str, &str); 5] {
        [
            (CALLER_SUBJECT_HEADER, &self.subject),
            (CALLER_TENANT_HEADER, &self.tenant),
            (CALLER_ORGANIZATION_HEADER, &self.organization_id),
            (BACKEND_ID_HEADER, &self.backend_id),
            (REQUEST_ID_HEADER, &self.request_id),
        ]
    }
}

tokio::task_local! {
    /// The caller of the delegated call in flight on this task. Set by
    /// [`crate::proxy::GatewayS3`]'s dispatcher around the SDK call, which the
    /// aws-smithy-runtime orchestrator runs inline on the calling task.
    pub static CALLER: Arc<DelegatedCaller>;
}

/// Adds the caller's identity before signing and records the answered status.
#[derive(Debug)]
pub(crate) struct CallerHeaders;

impl Intercept for CallerHeaders {
    fn name(&self) -> &'static str {
        "CallerHeaders"
    }

    fn modify_before_signing(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        CALLER
            .try_with(|caller| {
                let headers = context.request_mut().headers_mut();
                for (name, value) in caller.headers() {
                    headers.try_insert(name, value.to_string())?;
                }
                Ok(())
            })
            .map_err(|_| -> BoxError {
                "no delegated caller in scope; refusing to send an unattributed request".into()
            })?
    }

    fn read_after_transmit(
        &self,
        context: &BeforeDeserializationInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let status = context.response().status().as_u16();
        let _ = CALLER.try_with(|caller| caller.observed_status.set(status));
        Ok(())
    }
}

fn build_control_proxy(cfg: &ControlBackendConfig) -> Proxy {
    let creds = Credentials::new(
        cfg.access_key_id.clone(),
        cfg.secret_access_key.expose().clone(),
        None,
        None,
        "gateway-control",
    );
    let timeouts = TimeoutConfig::builder()
        .connect_timeout(cfg.connect_timeout())
        .operation_timeout(cfg.call_timeout())
        .build();
    let conf: Config = Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .endpoint_url(cfg.endpoint_url.clone())
        .region(Region::new(cfg.region.clone()))
        .credentials_provider(creds)
        .force_path_style(true)
        .retry_config(RetryConfig::disabled())
        .timeout_config(timeouts)
        .stalled_stream_protection(StalledStreamProtectionConfig::disabled())
        .interceptor(CallerHeaders)
        .interceptor(ExplicitEmptyBodyLength)
        .build();
    Proxy::from(Client::from_conf(conf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(n: usize) -> Arc<DelegatedCaller> {
        Arc::new(DelegatedCaller::new(
            format!("user:u{n}"),
            "acme".into(),
            "org-acme".into(),
            "bay-1".into(),
            format!("req-{n}"),
        ))
    }

    #[test]
    fn the_status_is_recorded_once_and_never_overwritten() {
        let c = caller(0);
        assert_eq!(c.observed_status(), None);
        let _ = c.observed_status.set(503);
        let _ = c.observed_status.set(200);
        assert_eq!(c.observed_status(), Some(503));
    }

    #[test]
    fn every_identity_header_is_listed_once() {
        let c = caller(1);
        let names: Vec<_> = c.headers().iter().map(|(n, _)| *n).collect();
        let mut dedup = names.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(names.len(), dedup.len());
        assert!(names.iter().all(|n| n.starts_with("x-s0-")));
    }

    #[tokio::test]
    async fn the_interceptor_refuses_to_send_without_a_caller_in_scope() {
        use s3s::S3;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg: ControlBackendConfig = serde_json::from_value(serde_json::json!({
            "endpoint_url": format!("http://{addr}"),
            "access_key_id": "ctl",
            "secret_access_key": "secret",
            "operations": ["GetBucketCors"],
        }))
        .unwrap();
        let control = ControlBackend::from_config(&cfg).unwrap();
        let req = s3s::S3Request {
            input: s3s::dto::GetBucketCorsInput {
                bucket: "reports".into(),
                ..Default::default()
            },
            method: http::Method::GET,
            uri: "/".parse().unwrap(),
            headers: http::HeaderMap::new(),
            extensions: http::Extensions::new(),
            credentials: None,
            region: None,
            service: None,
            trailing_headers: None,
        };
        assert!(control.proxy().get_bucket_cors(req).await.is_err());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "an unattributed request reached the wire"
        );
    }
}
