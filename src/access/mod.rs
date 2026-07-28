//! The OPA gate — the point of the project. Enforcement lives in the typed
//! per-op hooks (which see the full parsed input), not in `check`:
//!
//! - `check` (pre-deserialization) is the **deny-by-default backstop**: it
//!   denies anonymous, denies any op that [`optable`] does not mark
//!   [`Coverage::Enforced`] (the default per-op hooks fail-OPEN, so an un-covered op
//!   MUST be rejected here), resolves the end-user identity, and stashes it for the
//!   later stages. Each of those refusals emits a **gate** audit record: they are the
//!   whole deny-by-default surface, and a surface with no evidence is not auditable.
//! - The typed hooks (post-deserialization, `&mut`) build the OPA input, call
//!   the PDP, produce exactly one audit record per request, mint the [`AuthzProof`] the
//!   forward path demands, and apply obligations (prefix rewrite) — closing the
//!   CopyObject / multi-delete / form-upload blind spots because they authorize the
//!   *parsed* request. An allowed request's record is *held* rather than emitted, and
//!   settled by the forward path with what the backend leg did
//!   ([`crate::audit::PendingAudit`]); a denied one is emitted immediately, because
//!   there is no forward leg to wait for.
//!
//! A record must never contradict what the client was told. Every refusal is therefore
//! decided *before* the record is written — which is why `classify_list` takes the
//! caller's fan-out capability instead of the caller second-guessing its verdict.
//!
//! Those are two of the three fail-closed layers; the third is [`proof`], which stops
//! a hook that forgets to authorize from reaching the backend at all. They only work
//! together: the table without the proof proves the hook *exists*, not that it *ran*.

pub mod optable;
pub mod proof;

use std::sync::Arc;

use http::Extensions;
use s3s::access::{S3Access, S3AccessContext};
use s3s::dto::*;
use s3s::{S3Request, S3Result, s3_error};

use crate::audit::{
    AuditRecord, BackendOutcome, GateContext, GateStage, GatewayMeta, Outcome, PendingAudit,
};
use crate::auth::SECURITY_TOKEN_HEADER;
use crate::authz::{Backend, CopySource as AuthzCopySource, Decision, OpaInput, RequestMeta};
use crate::gateway::Gateway;
use crate::identity::ResolvedPrincipal;
use crate::model::Action;
use crate::proxy::{RouteSnapshot, fanout};

pub use optable::{Coverage, DangerTier, GateDenial, OP_TABLE, OpSpec, ResourceShape};
pub use proof::AuthzProof;

// PostObject is `Coverage::Denied` in OP_TABLE: `s3s_aws::Proxy` has no `post_object`,
// so a form upload cannot be forwarded. Enforcing it would authorize + audit an
// "Allowed" write that then 501s — a misleading record. The `post_object` hook below is
// retained (it authorizes the parsed form key, blind spot #3); flip the table entry
// once form-upload forwarding lands (PostObject→PutObject conversion).

/// The exact s3s operation name for this request. Only reachable in `check`
/// (`cx.s3_op()`), so `check` stashes it and the typed hooks read it from there
/// rather than each hardcoding its own name.
#[derive(Debug, Clone)]
pub struct OperationName(pub Arc<str>);

/// The op-agnostic view of an in-flight request that the enforce path needs.
///
/// Built once per typed hook from `&mut S3Request<T>`: the s3s generics stop at the
/// hook boundary, while the enforce helpers still reach the live request extensions
/// and the route `check` resolved. Everything the enforce path may need from the
/// request goes here — the alternative is making every helper generic over the op
/// input type.
struct ReqCtx<'a> {
    principal: Arc<ResolvedPrincipal>,
    /// Resolved once in `check`; carries no owner credentials by construction.
    route: Arc<RouteSnapshot>,
    /// Consumed by `AuthzProof` and, in a later stage, by `OpaInput::operation` and
    /// the audit record; the seam exists here because `check` is the only place the
    /// name is available.
    operation: Arc<str>,
    meta: RequestMeta,
    /// The live extensions of the request being enforced — where the authz proof is
    /// stashed, and where later stages stash the response obligations and the
    /// pending-audit handle.
    extensions: &'a mut Extensions,
}

impl<'a> ReqCtx<'a> {
    /// Everything below is stashed by `check`; a missing piece means a hook ran
    /// without the backstop, which is an internal error, never a soft default.
    fn new<T>(req: &'a mut S3Request<T>) -> S3Result<Self> {
        let principal = req
            .extensions
            .get::<Arc<ResolvedPrincipal>>()
            .cloned()
            .ok_or_else(|| s3_error!(InternalError, "resolved principal missing from request"))?;
        let route = req
            .extensions
            .get::<Arc<RouteSnapshot>>()
            .cloned()
            .ok_or_else(|| s3_error!(InternalError, "route snapshot missing from request"))?;
        let operation = req
            .extensions
            .get::<OperationName>()
            .map(|o| o.0.clone())
            .ok_or_else(|| s3_error!(InternalError, "operation name missing from request"))?;
        let meta = request_meta(req);
        Ok(ReqCtx {
            principal,
            route,
            operation,
            meta,
            extensions: &mut req.extensions,
        })
    }

    /// The request-invariant half of the OPA input. A pure projection of the route
    /// snapshot — no routing-table lookup on the hot path, and every sub-decision of
    /// one request is attributed to the same backend and org.
    fn base_input(&self, action: Action, bucket: String) -> OpaInput {
        OpaInput {
            principal: self.principal.to_opa_principal(),
            backend: Backend {
                id: self.route.backend_id.0.clone(),
                kind: self.route.backend_kind,
            },
            tenant: self.route.tenant.clone(),
            organization_id: self.route.organization_id.clone(),
            action,
            bucket,
            object: None,
            prefix: None,
            copy_source: None,
            delete_keys: None,
            object_tags: None,
            request: self.meta.clone(),
        }
    }

    /// Record that this request was authorized. The forward path refuses to touch a
    /// backend without it (`proof::require`), so every allow branch of every enforce
    /// helper must end here — and only an allow branch may.
    fn prove(&mut self) {
        self.extensions
            .insert(AuthzProof::mint(self.operation.clone()));
    }
}

pub struct GatewayAccess {
    gw: Arc<Gateway>,
}

impl GatewayAccess {
    pub fn new(gw: Arc<Gateway>) -> Self {
        GatewayAccess { gw }
    }

    /// Any PDP error fails closed to a deny — never allow on error.
    ///
    /// This is the single funnel: every `Pdp::decide` on the request path goes through
    /// here, so the golden-capture tap below sees 100% of emitted inputs — both halves
    /// of a copy, every key of a multi-delete — without instrumenting a single hook.
    /// If a second call site ever appears, the corpus silently stops being complete;
    /// `tests/golden_capture.rs::decide_is_the_only_pdp_call_site_on_the_request_path`
    /// is the guard.
    async fn decide(&self, cx: &ReqCtx<'_>, input: &OpaInput) -> Decision {
        if let Some(capture) = &self.gw.capture {
            capture.record(&cx.operation, input);
        }
        match self.gw.pdp.decide(input).await {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(%e, "pdp error; failing closed");
                Decision::deny("pdp evaluation error")
            }
        }
    }

    fn record(
        &self,
        input: OpaInput,
        decision: &Decision,
        outcome: Outcome,
        denied_keys: Vec<String>,
    ) -> AuditRecord {
        let meta = GatewayMeta {
            backend_id: input.backend.id.clone(),
            backend_kind: input.backend.kind.as_str().to_string(),
            outcome,
            denied_keys,
            backend: BackendOutcome::NotAttempted,
            backend_status: None,
        };
        AuditRecord::new(
            new_decision_id(),
            now_rfc3339(),
            input,
            decision.clone(),
            meta,
        )
    }

    /// Emit now. For every branch that is **terminal**: the request is refused here and
    /// there is no forward leg to wait for, so waiting would only delay the record.
    fn audit_denied(&self, input: OpaInput, decision: &Decision, denied_keys: Vec<String>) {
        self.gw
            .audit
            .emit(self.record(input, decision, Outcome::Denied, denied_keys));
    }

    /// Hold the record until the forward leg reports back (plan task 18).
    ///
    /// Stashed next to the authorization proof, and for the same reason: both are
    /// "this request was authorized", and the forward path is the single place that
    /// knows what happened next. If nothing ever settles it, `PendingAudit`'s `Drop`
    /// emits it unenriched — the record is deferred, never conditional.
    fn audit_pending(
        &self,
        cx: &mut ReqCtx<'_>,
        input: OpaInput,
        decision: &Decision,
        denied_keys: Vec<String>,
    ) {
        let record = self.record(input, decision, Outcome::Allowed, denied_keys);
        cx.extensions
            .insert(Arc::new(PendingAudit::new(self.gw.audit.clone(), record)));
    }

    /// Record a denial from the pre-policy gate.
    ///
    /// Rate-limited inside the sink: this is the one audit stream an unauthenticated
    /// caller controls the rate of, and letting a scanner fill the queue would make the
    /// gateway drop *decision* records. See `AuditSink::emit_gate_denial`.
    fn audit_gate_denial(
        &self,
        op: &str,
        stage: GateStage,
        access_key_id: Option<&str>,
        tenant: Option<&str>,
        principal_sub: Option<&str>,
        reason: String,
    ) {
        self.gw.audit.emit_gate_denial(AuditRecord::gate_denial(
            new_decision_id(),
            now_rfc3339(),
            GateContext {
                operation: op.to_string(),
                stage,
                access_key_id: access_key_id.map(str::to_string),
                tenant: tenant.map(str::to_string),
                suppressed_since_last: 0,
            },
            reason,
            principal_sub.unwrap_or_default().to_string(),
        ));
    }

    /// The single-object path (get/head/put/delete-one/post-form). One decision, one
    /// audit record.
    async fn enforce_object(
        &self,
        cx: &mut ReqCtx<'_>,
        action: Action,
        bucket: String,
        object: String,
    ) -> S3Result<()> {
        let mut input = cx.base_input(action, bucket);
        input.object = Some(object);
        let decision = self.decide(cx, &input).await;
        let (allow, reason) = (decision.allow, decision.reason.clone());
        if allow {
            self.audit_pending(cx, input, &decision, vec![]);
            cx.prove();
            Ok(())
        } else {
            self.audit_denied(input, &decision, vec![]);
            Err(s3_error!(AccessDenied, "{reason}"))
        }
    }

    /// Copy-style path (CopyObject, UploadPartCopy): authorize BOTH the source read
    /// and the dest write (blind spot #1). One request-level audit record.
    async fn enforce_copy(
        &self,
        cx: &mut ReqCtx<'_>,
        source: &CopySource,
        dest_bucket: String,
        dest_key: String,
    ) -> S3Result<()> {
        let (src_bucket, src_key) = match source {
            CopySource::Bucket { bucket, key, .. } => (bucket.to_string(), key.to_string()),
            _ => {
                return Err(s3_error!(
                    AccessDenied,
                    "unsupported copy source (access-point/outpost)"
                ));
            }
        };
        let mut src_input = cx.base_input(Action::ReadObjects, src_bucket.clone());
        src_input.object = Some(src_key.clone());
        let src_allow = self.decide(cx, &src_input).await.allow;

        let mut dst_input = cx.base_input(Action::WriteObjects, dest_bucket);
        dst_input.object = Some(dest_key);
        dst_input.copy_source = Some(AuthzCopySource {
            bucket: src_bucket,
            key: src_key,
        });
        let dst_allow = self.decide(cx, &dst_input).await.allow;

        let allow = src_allow && dst_allow;
        let decision = if allow {
            Decision::allow("copy allowed (source read + dest write)")
        } else {
            Decision::deny(format!(
                "copy denied (source_read={src_allow}, dest_write={dst_allow})"
            ))
        };
        if allow {
            self.audit_pending(cx, dst_input, &decision, vec![]);
            cx.prove();
            Ok(())
        } else {
            self.audit_denied(dst_input, &decision, vec![]);
            Err(s3_error!(AccessDenied, "copy denied by policy"))
        }
    }

    /// List-style path (ListObjects*, ListMultipartUploads): decide, classify the
    /// obligation, and audit. The caller applies the verdict to the request
    /// (rewrite prefix, stash a fan-out obligation, or deny).
    ///
    /// `fanout` says whether **this** request can be fanned out, and it is an argument
    /// rather than a caller-side check because of what used to happen when it was not:
    /// the caller refused the fan-out *after* this function had already audited
    /// `Outcome::Allowed` and minted a proof, so the decision log said allowed and the
    /// client got a 403. A record that contradicts what happened is worse than no
    /// record. Every refusal is now a `Deny` verdict here, before anything is written.
    async fn enforce_list(
        &self,
        cx: &mut ReqCtx<'_>,
        bucket: String,
        prefix: Option<String>,
        fanout: Fanout,
    ) -> ListVerdict {
        let mut input = cx.base_input(Action::ListObjects, bucket);
        input.prefix = prefix;
        let decision = self.decide(cx, &input).await;
        let verdict = classify_list(&decision, self.gw.limits().max_list_fanout, fanout);
        match &verdict {
            ListVerdict::Deny(reason) => {
                let d = Decision::deny(reason.clone());
                self.audit_denied(input, &d, vec![]);
            }
            _ => {
                self.audit_pending(cx, input, &decision, vec![]);
                cx.prove();
            }
        }
        verdict
    }
}

#[async_trait::async_trait]
impl S3Access for GatewayAccess {
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
        // Every branch below emits an audit record as well as a log line. It used to
        // emit only the log line, which meant the decision log held zero evidence of
        // the entire deny-by-default surface — all 84 gate-denied ops, every anonymous
        // request, and every credential that resolved to nothing — so "was this
        // gateway probed?" was unanswerable from the audit trail. The access-key id is
        // a semi-public identifier and is recorded; the secret never is.
        //
        // These records are rate-limited in the sink (`emit_gate_denial`): an
        // unauthenticated caller can produce them at line rate, and an audit queue full
        // of scanner noise would evict the decision records of real access. Suppression
        // is counted and reported, never silent.
        let op = cx.s3_op().name().to_string();
        let access_key = match cx.credentials() {
            Some(c) => c.access_key.clone(),
            None => {
                tracing::debug!(%op, "gate deny: anonymous request");
                self.audit_gate_denial(
                    &op,
                    GateStage::Anonymous,
                    None,
                    None,
                    None,
                    "unsigned request".into(),
                );
                return Err(s3_error!(AccessDenied, "Signature is required"));
            }
        };
        // Deny-by-default backstop: an op the table does not mark `Enforced` fails
        // OPEN at its typed hook (s3s defaults every one of them to `Ok(())`), so it
        // MUST be rejected here. `gate_op` also refuses the two structurally
        // unauthorizable ops ahead of, and independently of, their coverage.
        if let Err(denial) = optable::gate_op(&op) {
            tracing::warn!(%op, %access_key, reason = denial.as_str(), "gate deny: operation refused");
            self.audit_gate_denial(
                &op,
                GateStage::OperationNotEnforced,
                Some(&access_key),
                None,
                None,
                denial.as_str().to_string(),
            );
            return Err(s3_error!(AccessDenied, "{}: {op}", denial.as_str()));
        }
        // The STS session token rides in the header for signed requests and in the
        // query string for presigned URLs — presigned links flow through the
        // same OPA gate, so accept both.
        let token = session_token(cx.headers(), cx.uri());
        let principal = match self.gw.identity.resolve(&access_key, token.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(%op, %access_key, error = %e, "gate deny: identity rejected");
                // The credential-forgery signal: an expired or forged session token, or
                // an access key this gateway does not know. Nothing downstream of here
                // ever sees the request, so this record is the only evidence it existed.
                self.audit_gate_denial(
                    &op,
                    GateStage::IdentityRejected,
                    Some(&access_key),
                    None,
                    None,
                    format!("identity rejected: {e}"),
                );
                return Err(s3_error!(AccessDenied, "identity rejected: {e}"));
            }
        };
        // The route is resolved exactly ONCE, here, and every later stage reads that
        // snapshot: a hook, its audit record and the forward can never disagree about
        // which backend and org a request belonged to, even across a routing swap.
        let Some(route) = self.gw.registry.route_snapshot(&principal.tenant) else {
            tracing::warn!(%op, sub = %principal.sub, tenant = %principal.tenant, "gate deny: tenant not routable");
            // The one gate stage with a resolved principal. The organization is still
            // unknown — it comes from the route that does not exist — so the record
            // carries the tenant the principal claimed and no org label at all.
            self.audit_gate_denial(
                &op,
                GateStage::TenantNotRoutable,
                Some(&access_key),
                Some(&principal.tenant),
                Some(&principal.sub),
                format!("tenant {} is not routable", principal.tenant),
            );
            return Err(s3_error!(
                AccessDenied,
                "tenant {} is not routable",
                principal.tenant
            ));
        };
        let ext = cx.extensions_mut();
        ext.insert(Arc::new(principal));
        ext.insert(Arc::new(route));
        ext.insert(OperationName(Arc::from(op.as_str())));
        Ok(())
    }

    async fn get_object(&self, req: &mut S3Request<GetObjectInput>) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object(&mut cx, Action::ReadObjects, bucket, key)
            .await
    }

    async fn head_object(&self, req: &mut S3Request<HeadObjectInput>) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object(&mut cx, Action::ReadObjects, bucket, key)
            .await
    }

    async fn put_object(&self, req: &mut S3Request<PutObjectInput>) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object(&mut cx, Action::WriteObjects, bucket, key)
            .await
    }

    async fn post_object(&self, req: &mut S3Request<PostObjectInput>) -> S3Result<()> {
        // Blind spot #3: the form-upload key is in the parsed body — authorize it.
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object(&mut cx, Action::WriteObjects, bucket, key)
            .await
    }

    async fn delete_object(&self, req: &mut S3Request<DeleteObjectInput>) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object(&mut cx, Action::DeleteObjects, bucket, key)
            .await
    }

    async fn delete_objects(&self, req: &mut S3Request<DeleteObjectsInput>) -> S3Result<()> {
        // Blind spot #2: multi-delete keys live in the XML body — authorize EACH key,
        // then filter the forwarded request to only the allowed keys.
        // Read once: two loads could straddle a config apply and report a cap the
        // request was not actually measured against.
        let max_delete_keys = self.gw.limits().max_delete_keys;
        if req.input.delete.objects.len() > max_delete_keys {
            return Err(s3_error!(
                InvalidRequest,
                "delete request exceeds {max_delete_keys} keys"
            ));
        }
        let bucket = req.input.bucket.clone();
        let all_keys: Vec<String> = req
            .input
            .delete
            .objects
            .iter()
            .map(|o| o.key.clone())
            .collect();
        let mut cx = ReqCtx::new(req)?;

        let mut allowed: Vec<String> = Vec::new();
        let mut denied: Vec<String> = Vec::new();
        for key in &all_keys {
            let mut input = cx.base_input(Action::DeleteObjects, bucket.clone());
            input.object = Some(key.clone());
            if self.decide(&cx, &input).await.allow {
                allowed.push(key.clone());
            } else {
                denied.push(key.clone());
            }
        }

        let mut record_input = cx.base_input(Action::DeleteObjects, bucket);
        record_input.delete_keys = Some(all_keys);
        if allowed.is_empty() {
            let decision = Decision::deny("all delete keys denied");
            self.audit_denied(record_input, &decision, denied);
            return Err(s3_error!(AccessDenied, "all delete keys denied by policy"));
        }
        let decision = Decision::allow(format!(
            "{} allowed, {} denied",
            allowed.len(),
            denied.len()
        ));
        self.audit_pending(&mut cx, record_input, &decision, denied);
        cx.prove();
        // Per-key filtering: forward only authorized keys.
        req.input
            .delete
            .objects
            .retain(|o| allowed.contains(&o.key));
        Ok(())
    }

    async fn copy_object(&self, req: &mut S3Request<CopyObjectInput>) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let source = req.input.copy_source.clone();
        let mut cx = ReqCtx::new(req)?;
        self.enforce_copy(&mut cx, &source, bucket, key).await
    }

    async fn list_objects_v2(&self, req: &mut S3Request<ListObjectsV2Input>) -> S3Result<()> {
        let (bucket, prefix) = (req.input.bucket.clone(), req.input.prefix.clone());
        // Fan-out re-paginates raw keys; delimiter (folder) listing across multiple
        // prefixes is a follow-up (ADR-004). Decided *before* the enforce call so the
        // refusal is the audited verdict rather than an unrecorded override of one.
        let fanout_support = if req.input.delimiter.is_some() {
            Fanout::Unsupported(NO_FANOUT_WITH_DELIMITER)
        } else {
            Fanout::Supported
        };
        // Scoped: the verdict is applied to `req` below, so the context's borrow of
        // the request must end first.
        let verdict = {
            let mut cx = ReqCtx::new(req)?;
            self.enforce_list(&mut cx, bucket, prefix, fanout_support)
                .await
        };
        match verdict {
            ListVerdict::Deny(reason) => Err(s3_error!(AccessDenied, "{reason}")),
            ListVerdict::AllowAsIs => Ok(()),
            ListVerdict::Narrow(np) => {
                req.input.prefix = Some(np);
                Ok(())
            }
            ListVerdict::FanOut(prefixes) => {
                req.extensions
                    .insert(Arc::new(fanout::ListFanout { prefixes }));
                Ok(())
            }
        }
    }

    async fn list_objects(&self, req: &mut S3Request<ListObjectsInput>) -> S3Result<()> {
        let (bucket, prefix) = (req.input.bucket.clone(), req.input.prefix.clone());
        let verdict = {
            let mut cx = ReqCtx::new(req)?;
            self.enforce_list(
                &mut cx,
                bucket,
                prefix,
                Fanout::Unsupported(NO_FANOUT_ON_THIS_OP),
            )
            .await
        };
        list_verdict_single(verdict, &mut req.input.prefix)
    }

    // ── Multipart upload lifecycle (write on the key), plus its copy + list ops ──

    async fn create_multipart_upload(
        &self,
        req: &mut S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object(&mut cx, Action::WriteObjects, bucket, key)
            .await
    }

    async fn upload_part(&self, req: &mut S3Request<UploadPartInput>) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object(&mut cx, Action::WriteObjects, bucket, key)
            .await
    }

    async fn complete_multipart_upload(
        &self,
        req: &mut S3Request<CompleteMultipartUploadInput>,
    ) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object(&mut cx, Action::WriteObjects, bucket, key)
            .await
    }

    async fn abort_multipart_upload(
        &self,
        req: &mut S3Request<AbortMultipartUploadInput>,
    ) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object(&mut cx, Action::WriteObjects, bucket, key)
            .await
    }

    async fn list_parts(&self, req: &mut S3Request<ListPartsInput>) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object(&mut cx, Action::ReadObjects, bucket, key)
            .await
    }

    async fn upload_part_copy(&self, req: &mut S3Request<UploadPartCopyInput>) -> S3Result<()> {
        // Blind spot: authorize the copy source read + the dest part write.
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let source = req.input.copy_source.clone();
        let mut cx = ReqCtx::new(req)?;
        self.enforce_copy(&mut cx, &source, bucket, key).await
    }

    async fn list_multipart_uploads(
        &self,
        req: &mut S3Request<ListMultipartUploadsInput>,
    ) -> S3Result<()> {
        let (bucket, prefix) = (req.input.bucket.clone(), req.input.prefix.clone());
        let verdict = {
            let mut cx = ReqCtx::new(req)?;
            self.enforce_list(
                &mut cx,
                bucket,
                prefix,
                Fanout::Unsupported(NO_FANOUT_ON_THIS_OP),
            )
            .await
        };
        list_verdict_single(verdict, &mut req.input.prefix)
    }
}

/// What to do with a list request after the PDP decision.
enum ListVerdict {
    Deny(String),
    /// Allowed as requested (whole-bucket or already-in-scope prefix).
    AllowAsIs,
    /// Rewrite the request prefix to this single granted prefix.
    Narrow(String),
    /// Allowed across several granted prefixes — the dispatcher fans out (ADR-004).
    FanOut(Vec<String>),
}

/// Whether a multi-prefix fan-out can actually be executed for this request.
///
/// Only `ListObjectsV2` without a delimiter has a fan-out dispatch arm
/// (`proxy::fan_out_list_v2`, ADR-004). Everything else must refuse a multi-prefix
/// grant, and the refusal has to be part of the *verdict* so it is audited as the
/// denial it is.
#[derive(Debug, Clone, Copy)]
enum Fanout {
    Supported,
    /// Carries the client-facing reason, which becomes the deny reason and the 403
    /// message — one string, so the record and the response cannot disagree.
    Unsupported(&'static str),
}

const NO_FANOUT_ON_THIS_OP: &str =
    "multi-prefix listing is not supported for this operation; list a single prefix";
const NO_FANOUT_WITH_DELIMITER: &str =
    "delimiter listing across multiple granted prefixes is unsupported; list a single prefix";

/// Classify the PDP obligation into a list verdict. Multi-prefix within the fan-out
/// bound becomes `FanOut`; above the bound, or on an op that cannot fan out, it fails
/// closed.
fn classify_list(decision: &Decision, max_fanout: usize, fanout: Fanout) -> ListVerdict {
    if !decision.allow {
        return ListVerdict::Deny(decision.reason.clone());
    }
    // Defense in depth: the shipped rego sets at most one obligation.
    if decision.obligations.narrow_prefix.is_some()
        && !decision.obligations.allowed_prefixes.is_empty()
    {
        return ListVerdict::Deny("ambiguous list obligation (narrow + allowed prefixes)".into());
    }
    if let Some(np) = &decision.obligations.narrow_prefix {
        return ListVerdict::Narrow(np.clone());
    }
    let allowed = &decision.obligations.allowed_prefixes;
    if !allowed.is_empty() {
        // Refuse here, not at the caller: the caller refuses *after* `enforce_list` has
        // audited and minted a proof, which is what made the decision log disagree with
        // the HTTP status.
        if let Fanout::Unsupported(why) = fanout {
            return ListVerdict::Deny(why.to_string());
        }
        if allowed.len() > max_fanout {
            return ListVerdict::Deny(format!(
                "list spans {} granted prefixes, exceeding the fan-out bound {max_fanout}; narrow your prefix",
                allowed.len()
            ));
        }
        let mut prefixes = allowed.clone();
        prefixes.sort();
        prefixes.dedup();
        return ListVerdict::FanOut(prefixes);
    }
    ListVerdict::AllowAsIs
}

/// Apply a list verdict for ops without fan-out dispatch (v1 list, multipart list).
fn list_verdict_single(verdict: ListVerdict, prefix: &mut Option<String>) -> S3Result<()> {
    match verdict {
        ListVerdict::Deny(reason) => Err(s3_error!(AccessDenied, "{reason}")),
        ListVerdict::AllowAsIs => Ok(()),
        ListVerdict::Narrow(np) => {
            *prefix = Some(np);
            Ok(())
        }
        // Unreachable: these call sites pass `Fanout::Unsupported`, under which
        // `classify_list` returns `Deny` instead. Kept as a compile-checked backstop —
        // if a future edit makes it reachable, the request fails rather than being
        // forwarded unbounded, and the loud code says the invariant broke rather than
        // implying the client did something wrong.
        ListVerdict::FanOut(_) => Err(s3_error!(
            InternalError,
            "fan-out verdict reached an operation with no fan-out dispatch"
        )),
    }
}

fn request_meta<T>(req: &S3Request<T>) -> RequestMeta {
    RequestMeta {
        method: req.method.to_string(),
        params: req.uri.query().map(redact_query),
        headers_subset: Default::default(),
    }
}

/// Redact credential-bearing presign params so an audit record never stores a
/// replayable URL or bearer token. Param names are kept; only the values are dropped.
fn redact_query(q: &str) -> String {
    const REDACT: [&str; 3] = [
        "x-amz-signature",
        "x-amz-security-token",
        "x-amz-credential",
    ];
    q.split('&')
        .map(|p| {
            let name = p.split('=').next().unwrap_or(p);
            if REDACT.contains(&name.to_ascii_lowercase().as_str()) {
                format!("{name}=REDACTED")
            } else {
                p.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// The STS session token from the `X-Amz-Security-Token` header (signed requests) or
/// query param (presigned URLs). Our session tokens are URL-safe JWTs, but we
/// percent-decode defensively.
fn session_token(headers: &http::HeaderMap, uri: &http::Uri) -> Option<String> {
    if let Some(v) = headers
        .get(SECURITY_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        return Some(v.to_string());
    }
    let query = uri.query()?;
    query.split('&').find_map(|pair| {
        pair.strip_prefix("X-Amz-Security-Token=")
            .map(percent_decode)
    })
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn new_decision_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::Obligations;

    fn allow_with(obl: Obligations) -> Decision {
        Decision {
            allow: true,
            reason: "ok".into(),
            obligations: obl,
        }
    }

    #[test]
    fn the_gate_admits_the_blind_spot_ops() {
        for op in [
            "CopyObject",
            "DeleteObjects",
            "ListObjectsV2",
            "CreateMultipartUpload",
            "UploadPartCopy",
            "CompleteMultipartUpload",
        ] {
            assert!(optable::gate_op(op).is_ok(), "{op} must pass the gate");
        }
        // Ops we do not (or cannot yet) forward must be refused — they would fail-open
        // at their default typed hook, so check() must reject them. PostObject is
        // excluded on purpose: s3s_aws::Proxy has no post_object.
        for op in [
            "PutBucketAcl",
            "DeleteBucket",
            "GetBucketPolicy",
            "PostObject",
        ] {
            assert_eq!(
                optable::gate_op(op),
                Err(GateDenial::NotEnforced),
                "{op} must be denied by default"
            );
        }
    }

    #[test]
    fn list_denied_passes_through_reason() {
        let d = Decision::deny("nope");
        assert!(matches!(
            classify_list(&d, 16, Fanout::Supported),
            ListVerdict::Deny(_)
        ));
    }

    #[test]
    fn list_single_prefix_narrows() {
        let d = allow_with(Obligations {
            narrow_prefix: Some("2024/".into()),
            allowed_prefixes: vec![],
        });
        assert!(
            matches!(classify_list(&d, 16, Fanout::Supported), ListVerdict::Narrow(np) if np == "2024/")
        );
        // A narrowing needs no fan-out dispatch, so it must survive on an op that
        // cannot fan out — otherwise this fix would have turned every v1 list by a
        // prefix-scoped subject into a denial.
        assert!(
            matches!(classify_list(&d, 16, Fanout::Unsupported(NO_FANOUT_ON_THIS_OP)), ListVerdict::Narrow(np) if np == "2024/")
        );
    }

    #[test]
    fn list_multi_prefix_within_bound_fans_out_sorted() {
        let d = allow_with(Obligations {
            narrow_prefix: None,
            allowed_prefixes: vec!["2025/".into(), "2024/".into()],
        });
        assert!(matches!(
            classify_list(&d, 16, Fanout::Supported),
            ListVerdict::FanOut(p) if p == vec!["2024/".to_string(), "2025/".to_string()]
        ));
    }

    #[test]
    fn list_multi_prefix_over_bound_fails_closed() {
        let d = allow_with(Obligations {
            narrow_prefix: None,
            allowed_prefixes: vec!["a/".into(), "b/".into(), "c/".into()],
        });
        assert!(matches!(
            classify_list(&d, 2, Fanout::Supported),
            ListVerdict::Deny(_)
        ));
    }

    #[test]
    fn list_unrestricted_is_allow_as_is() {
        let d = allow_with(Obligations::default());
        assert!(matches!(
            classify_list(&d, 16, Fanout::Supported),
            ListVerdict::AllowAsIs
        ));
    }

    #[test]
    fn a_fanout_an_operation_cannot_execute_is_a_deny_verdict_not_a_caller_override() {
        // Defect 4. `enforce_list` audits from the verdict, so a refusal that lives at
        // the *caller* is a refusal the audit record never sees: it logged
        // `Outcome::Allowed`, minted a proof, and the client got a 403. Both refusal
        // sites — a v1/multipart list, and a v2 list carrying a delimiter — must show
        // up here as `Deny`, carrying the message the client is about to be given.
        let d = allow_with(Obligations {
            narrow_prefix: None,
            allowed_prefixes: vec!["2024/".into(), "2025/".into()],
        });
        for why in [NO_FANOUT_ON_THIS_OP, NO_FANOUT_WITH_DELIMITER] {
            match classify_list(&d, 16, Fanout::Unsupported(why)) {
                ListVerdict::Deny(reason) => assert_eq!(reason, why),
                other => panic!(
                    "a fan-out that cannot be executed must be a Deny verdict, got {}",
                    match other {
                        ListVerdict::FanOut(_) => "FanOut",
                        ListVerdict::AllowAsIs => "AllowAsIs",
                        ListVerdict::Narrow(_) => "Narrow",
                        ListVerdict::Deny(_) => unreachable!(),
                    }
                ),
            }
        }
        // Positive control: the same obligation on the one op that *can* fan out is
        // still a fan-out, so the denial above is about dispatch, not about
        // multi-prefix grants being broken.
        assert!(matches!(
            classify_list(&d, 16, Fanout::Supported),
            ListVerdict::FanOut(_)
        ));
    }

    #[test]
    fn session_token_from_header_and_presigned_query() {
        let uri: http::Uri = "/b/k".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(SECURITY_TOKEN_HEADER, "hdr-token".parse().unwrap());
        assert_eq!(session_token(&headers, &uri).as_deref(), Some("hdr-token"));

        // Presigned URL: token in the query, percent-encoded.
        let empty = http::HeaderMap::new();
        let uri: http::Uri =
            "/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Security-Token=ab%2Fcd&X-Amz-Signature=x"
                .parse()
                .unwrap();
        assert_eq!(session_token(&empty, &uri).as_deref(), Some("ab/cd"));

        // Neither.
        let uri: http::Uri = "/b/k?X-Amz-Signature=x".parse().unwrap();
        assert_eq!(session_token(&empty, &uri), None);
    }

    #[test]
    fn redact_query_drops_credential_values() {
        let q = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA%2F..&X-Amz-Security-Token=jwt&X-Amz-Signature=abcd";
        let r = redact_query(q);
        assert!(r.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(r.contains("X-Amz-Signature=REDACTED"));
        assert!(r.contains("X-Amz-Security-Token=REDACTED"));
        assert!(r.contains("X-Amz-Credential=REDACTED"));
        assert!(!r.contains("jwt") && !r.contains("abcd"));
    }
}
