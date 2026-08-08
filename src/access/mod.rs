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
//!
//! ## Riders
//!
//! "Authorizes the parsed request" was, until M4, a claim about `(bucket, key)` only. The
//! rest of the parsed request — the canned ACL, the five `x-amz-grant-*` headers, an
//! inline `x-amz-tagging`, `x-amz-bypass-governance-retention` — rode through unread, so
//! a `PutObject` with `x-amz-acl: public-read` was allowed on the strength of the key and
//! made the object world-readable. [`headers`] and [`tagging`] close that, and the
//! enforcement has two distinct shapes, on purpose:
//!
//! - **screened in code** ([`GatewayAccess::screen_riders`]) — **any** ACL that confers
//!   anything on anyone (public or named), an unrecognized canned ACL, a governance
//!   bypass, a reserved tag key. No grant may authorize these, so no PDP question is
//!   asked and no bundle can reach them.
//! - **decomposed into its own verb** ([`GatewayAccess::authorize_riders`]) — an inline
//!   tag set takes a `write_object_tags` decision on the same object. Still one audit
//!   record for the request, the way a copy's two halves are one record.
//!
//! The answer is a **denial, never a silent strip**; see [`headers`] for the argument and
//! ADR-008 for the decision.
//!
//! ACL decomposition was the second bullet until 2026-08-08: a conferring ACL took its
//! own `write_object_acl` decision. That verb was removed with the rest of the
//! control-plane vocabulary, so conferring ACLs joined the first bullet — refused in
//! code, on every write path, with a real `Deny` record. See [`headers`].

pub mod headers;
pub mod optable;
pub mod proof;
pub mod tagging;

use std::collections::BTreeMap;
use std::sync::Arc;

use http::Extensions;
use s3s::access::{S3Access, S3AccessContext};
use s3s::dto::*;
use s3s::{S3Error, S3Request, S3Result, s3_error};

use crate::access::headers::RequestRiders;
use crate::access::tagging::ReservedTagKeys;
use crate::audit::{
    AuditRecord, BackendOutcome, GateContext, GateStage, GatewayMeta, Outcome, PendingAudit,
};
use crate::auth::SECURITY_TOKEN_HEADER;
use crate::authz::{Backend, CopySource as AuthzCopySource, Decision, OpaInput, RequestMeta};
use crate::gateway::Gateway;
use crate::identity::ResolvedPrincipal;
use crate::model::Action;
use crate::proxy::RouteSnapshot;
use crate::proxy::obligations::{BucketVisibility, ResponseObligations};

pub use optable::{Coverage, DangerTier, GateDenial, OP_TABLE, OpSpec, ResourceShape};
pub use proof::AuthzProof;

/// The ACL fields of an object-shaped s3s input, as [`headers::AclFields`].
///
/// A macro rather than a trait because the four input types share these fields by
/// coincidence of the S3 API, not by any relationship s3s expresses — and a macro that
/// names every field explicitly is what makes "the hook forgot one" a compile error at
/// the call site rather than a silent `None`.
macro_rules! object_acl_fields {
    ($i:expr) => {
        crate::access::headers::AclFields {
            canned: $i.acl.as_ref().map(|a| a.as_str()),
            full_control: $i.grant_full_control.as_deref(),
            read: $i.grant_read.as_deref(),
            // Object ACLs have no WRITE permission — only bucket ACLs do.
            write: None,
            read_acp: $i.grant_read_acp.as_deref(),
            write_acp: $i.grant_write_acp.as_deref(),
        }
    };
}

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
            requested_tags: None,
            acl_grants: vec![],
            bypass_governance: false,
            request: self.meta.clone(),
        }
    }

    /// The base input for an object-shaped decision, with the request's riders attached.
    ///
    /// One place rather than four, because the failure mode of the old code was precisely
    /// that each write hook built its own input and none of them carried the ACL.
    fn write_input(
        &self,
        action: Action,
        bucket: String,
        object: String,
        riders: &RequestRiders,
    ) -> OpaInput {
        let mut input = self.base_input(action, bucket);
        input.object = Some(object);
        input.acl_grants = riders.acl.clone();
        input.requested_tags = riders.tags.clone();
        input.bypass_governance = riders.bypass_governance;
        input
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

    /// Ask the PDP about one prepared input, then act on the answer: hold the record
    /// and mint the proof on allow, emit the record and refuse on deny.
    ///
    /// Every single-decision hook funnels through here, so "audited exactly once, and a
    /// proof exists only on the allow side" is one branch to read rather than one per
    /// op — which is what makes adding an op the ~15-line diff it should be.
    async fn enforce(&self, cx: &mut ReqCtx<'_>, input: OpaInput) -> S3Result<()> {
        let decision = self.decide(cx, &input).await;
        // An obligation the policy declared mandatory and this binary cannot apply is a
        // denial, not a warning. `deny_unknown_fields` on `Obligations` covers the case
        // where the *field* is unknown; this covers the case where the field is known,
        // the value parsed, and the op has no way to honor it — a restriction that
        // silently did not happen is the fail-open shape this project exists to avoid.
        //
        // Gated on `allow` so a request the policy refused outright is recorded with the
        // policy's own reason: it was already denied, and reporting the obligation
        // instead would put a misleading cause on the record.
        if decision.allow
            && let Some(reason) = unimplemented_obligations(&decision)
        {
            let decision = Decision::deny(reason.clone());
            self.audit_denied(input, &decision, vec![]);
            return Err(s3_error!(AccessDenied, "{reason}"));
        }
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

    /// A refusal the **gateway** decided rather than the PDP: a semantic cap, a body it
    /// will not forward, a bucket name outside the caller's tenant.
    ///
    /// It writes an audit record and answers `AccessDenied`, and both halves are the
    /// point (accepted review defect B-1). The obvious spelling —
    /// `return Err(s3_error!(InvalidRequest, "…"))` before the enforce call — returns
    /// ahead of every audit site, so an over-cap request left **no** evidence at all and
    /// reached the client as a 400: a refusal on authorization grounds reported as a
    /// client formatting mistake, invisible to the decision log. A cap is a resource
    /// bound whose violation is a real Deny sub-decision on the op's own verb.
    ///
    /// The reason is prefixed so the record says **which layer** refused: the rego's own
    /// reasons all read `deny: …`/`allow: …`, and a record that merely said
    /// "over the 10-tag cap" would look like a policy verdict for a question no policy
    /// was asked. A structured `verdict_source` on the record would be better than a
    /// string convention and belongs with the next audit-shape change.
    fn refuse(&self, input: OpaInput, reason: String) -> S3Error {
        self.deny(input, format!("deny (gateway): {reason}"))
    }

    /// Record a refusal against `input` and answer 403, with the reason verbatim.
    ///
    /// The un-prefixed sibling of [`Self::refuse`], for a denial the **policy** produced
    /// even though no single `enforce` call did: a composite verdict over several
    /// sub-decisions (a copy's two halves; a write plus the `write_object_tags` its
    /// inline `x-amz-tagging` requires). Prefixing those with `deny (gateway):` would
    /// claim the gateway made a call the PDP actually made.
    fn deny(&self, input: OpaInput, reason: String) -> S3Error {
        let decision = Decision::deny(reason.clone());
        self.audit_denied(input, &decision, vec![]);
        s3_error!(AccessDenied, "{reason}")
    }

    /// The reserved-key list currently published by the control plane.
    ///
    /// Read from the live bundle on each tag write rather than cached: the bundle is the
    /// revocation channel, and a list held in a long-lived field would keep enforcing a
    /// reservation the control plane has since changed. Tag writes are rare enough that
    /// a JSON lookup per write is not a hot path.
    fn reserved_tag_keys(&self) -> ReservedTagKeys {
        ReservedTagKeys::from_bundle(&self.gw.bundles.current().data)
    }

    /// Refuse — **in code, ahead of and independent of any policy** — the riders no grant
    /// may authorize.
    ///
    /// Three refusals, in this order:
    ///
    /// 1. **`x-amz-bypass-governance-retention`.** Object-lock governance mode exists so
    ///    that a retained object cannot be destroyed; the bypass header is the documented
    ///    way to destroy it anyway. AWS gates it on its own IAM action
    ///    (`s3:BypassGovernanceRetention`) and the gateway's grant vocabulary has **no
    ///    equivalent** — so there is no grant that could express "may defeat WORM", and
    ///    inventing one here would be a cross-repo contract change made unilaterally by
    ///    a PEP. Until the vocabulary gains a verb, the honest answer is that this
    ///    gateway does not broker retention overrides. The attempt is still put on the
    ///    record (`input.bypass_governance`), which is the point: in a regulated
    ///    deployment "who tried to bypass retention" is a question the audit trail must
    ///    be able to answer.
    /// 2. **Any conferring ACL** — public *or* named. See [`headers`]. Public exposure
    ///    was always refused here because a wildcard grant conferred `write_object_acl`
    ///    and the default access model seeds one for every Owner. Since 2026-08-08 the
    ///    named case is refused too, for a different and simpler reason: the verb is
    ///    gone, because an object ACL grants access hyperfluid never projected and
    ///    therefore cannot show or revoke. Both refusals come back as
    ///    [`headers::AclDisposition::refusal`], so a tier added to that enum later is
    ///    screened by this line without it changing.
    /// 3. **A reserved tag key**, including the shipped default in which *every* key is
    ///    reserved because the control plane has published no list. See [`tagging`].
    fn screen_riders(&self, riders: &RequestRiders) -> Result<(), String> {
        if riders.bypass_governance {
            return Err(
                "the request carries x-amz-bypass-governance-retention, which would \
                 override object-lock retention; no verb in this gateway's grant \
                 vocabulary expresses that authority, so it is refused in code rather \
                 than left to a policy that has no way to say yes"
                    .to_string(),
            );
        }
        if let Some(why) = headers::classify(&riders.acl).refusal() {
            return Err(why.to_string());
        }
        if let Some(tags) = &riders.tags {
            self.reserved_tag_keys().check(tags)?;
        }
        Ok(())
    }

    /// Authorize the riders as **separate verbs on the same object**, after the gateway's
    /// own screening and before the write itself is recorded.
    ///
    /// This is the modelling decision at the centre of the retrofit. An inline
    /// `x-amz-tagging` is a `PutObjectTagging` wearing a `PutObject`'s clothes, and it
    /// must go through `write_object_tags` precisely because a tag can satisfy an ABAC
    /// condition — which is also why `write_object_tags` was *not* merged into
    /// `write_objects` when the vocabulary shrank.
    ///
    /// The ACL used to be decomposed the same way, onto `write_object_acl`. It is now
    /// screened in [`Self::screen_riders`] instead: there is no verb left to decompose
    /// onto, and "no grant matches" would have been a misleading reason for a request no
    /// grant could ever match.
    ///
    /// `Some(reason)` ⇒ refuse. Returns rather than denying inline so the caller records
    /// **one** audit entry against the primary input, the way `enforce_copy` does: a
    /// request produces one record, whatever it decomposed into.
    async fn authorize_riders(
        &self,
        cx: &mut ReqCtx<'_>,
        input: &OpaInput,
        riders: &RequestRiders,
    ) -> Option<String> {
        if riders.tags.is_some() {
            let mut tag_input = input.clone();
            tag_input.action = Action::WriteObjectTags;
            if !self.decide(cx, &tag_input).await.allow {
                return Some(
                    "deny: the request carries an inline tag set (x-amz-tagging), which \
                     requires write_object_tags on this object; no grant matches"
                        .to_string(),
                );
            }
        }
        None
    }

    /// The write path for an object op that can carry riders: screen them, authorize them
    /// as their own verbs, then decide the write itself.
    ///
    /// The fast path is unchanged — a request with no ACL, no inline tags and no bypass
    /// header costs exactly one decision, as it did before the retrofit.
    async fn enforce_object_write(
        &self,
        cx: &mut ReqCtx<'_>,
        action: Action,
        bucket: String,
        object: String,
        riders: Result<RequestRiders, String>,
    ) -> S3Result<()> {
        // The riders are parsed from `&req.input` *before* the `ReqCtx` takes its mutable
        // borrow, so a malformed one arrives here as an `Err` rather than as an early
        // return the audit path never saw (defect B-1: a refusal with no record is not a
        // refusal anyone can review).
        let riders = match riders {
            Ok(r) => r,
            Err(why) => {
                let mut input = cx.base_input(action, bucket);
                input.object = Some(object);
                return Err(self.refuse(input, why));
            }
        };
        let input = cx.write_input(action, bucket, object, &riders);
        if let Err(why) = self.screen_riders(&riders) {
            return Err(self.refuse(input, why));
        }
        if let Some(why) = self.authorize_riders(cx, &input, &riders).await {
            return Err(self.deny(input, why));
        }
        self.enforce(cx, input).await
    }

    /// The single-object path (get/head/put/delete-one/post-form/tagging). One
    /// decision, one audit record.
    async fn enforce_object(
        &self,
        cx: &mut ReqCtx<'_>,
        action: Action,
        bucket: String,
        object: String,
    ) -> S3Result<()> {
        let mut input = cx.base_input(action, bucket);
        input.object = Some(object);
        self.enforce(cx, input).await
    }

    /// The keyless bucket path (head/location/create/delete). There is no object and no
    /// prefix, so the decision is exactly "this verb, on this bucket, for this
    /// principal" — and grant prefixes cannot narrow it, which is why these verbs are
    /// separate from the object ones rather than a keyless fall-through of them.
    async fn enforce_bucket(
        &self,
        cx: &mut ReqCtx<'_>,
        action: Action,
        bucket: String,
    ) -> S3Result<()> {
        debug_assert!(action.is_bucket_scoped());
        let input = cx.base_input(action, bucket);
        self.enforce(cx, input).await
    }

    /// The account-scoped enumeration path (`ListBuckets`), and the first decision in
    /// this gateway whose verdict is applied to a **response**.
    ///
    /// It answers with a [`BucketVisibility`] rather than a `S3Result<()>` because a
    /// refusal here is not a 403 — see [`GatewayAccess::list_buckets`] for why. Three
    /// things are settled before it returns, in this order, and every one of them writes
    /// exactly one audit record:
    ///
    /// 1. the PDP denied ⇒ nothing is visible, recorded as the denial it is;
    /// 2. the PDP allowed but the obligation cannot be applied (ambiguous, or a
    ///    `must_understand` this binary does not implement) ⇒ nothing is visible,
    ///    recorded as a gateway-side deny naming the obligation. The classification
    ///    happens **before** the audit call on purpose (plan defect B-3): the previous
    ///    shape errored out of obligation handling ahead of every audit site, so a
    ///    refused `ListBuckets` left no record at all;
    /// 3. the PDP allowed with a usable obligation ⇒ that visibility, the record is
    ///    held for the forward leg, and the proof is minted.
    async fn enforce_bucket_listing(&self, cx: &mut ReqCtx<'_>) -> BucketVisibility {
        // `bucket: ""` is the account scope. The rego MUST gate every bucket-scoped rule
        // on `input.bucket != ""`, or a `"bucket": "*"` grant matches the empty string
        // and the per-bucket denylist is keyed on a bucket nobody named (plan defect
        // B-2). `policy/gateway/authz.rego` does; `the_wildcard_grant_does_not_match_the
        // _account_scope` in the corpus is the guard.
        //
        // `Action::Read` in the ACCOUNT shape. It is the same verb `HeadBucket` uses in
        // the bucket shape, and the empty bucket is the only thing that tells the two
        // apart — which is why every rego rule reading it carries a shape gate.
        let input = cx.base_input(Action::Read, String::new());
        let decision = self.decide(cx, &input).await;
        match classify_bucket_listing(&decision) {
            BucketListing::Withhold(reason) => {
                let denial = Decision::deny(reason);
                self.audit_denied(input, &denial, vec![]);
                BucketVisibility::Nothing
            }
            BucketListing::Show(visibility) => {
                self.audit_pending(cx, input, &decision, vec![]);
                cx.prove();
                visibility
            }
        }
    }

    /// Copy-style path (CopyObject, UploadPartCopy): authorize BOTH the source read
    /// and the dest write (blind spot #1). One request-level audit record.
    ///
    /// `riders` are the destination's: a `CopyObject` carrying `x-amz-acl` sets the ACL of
    /// the *new* object, and one carrying `x-amz-tagging` with
    /// `x-amz-tagging-directive: REPLACE` sets its tags. They are screened and authorized
    /// exactly as they are on a plain write — the copy path had the same hole and it was
    /// the more dangerous of the two, because the destination bucket need not be the
    /// source's.
    async fn enforce_copy(
        &self,
        cx: &mut ReqCtx<'_>,
        source: &CopySource,
        dest_bucket: String,
        dest_key: String,
        riders: RequestRiders,
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
        let mut dst_input = cx.write_input(Action::WriteObjects, dest_bucket, dest_key, &riders);
        dst_input.copy_source = Some(AuthzCopySource {
            bucket: src_bucket.clone(),
            key: src_key.clone(),
        });
        // Screened before either half is asked about: a public ACL on the destination is
        // refused whatever the answers would have been, and refusing early keeps the
        // record's reason the one the client is given.
        if let Err(why) = self.screen_riders(&riders) {
            return Err(self.refuse(dst_input, why));
        }

        let mut src_input = cx.base_input(Action::ReadObjects, src_bucket);
        src_input.object = Some(src_key);
        let src_allow = self.decide(cx, &src_input).await.allow;

        let dst_allow = self.decide(cx, &dst_input).await.allow;

        if src_allow
            && dst_allow
            && let Some(why) = self.authorize_riders(cx, &dst_input, &riders).await
        {
            return Err(self.deny(dst_input, why));
        }

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
        // the entire deny-by-default surface — all 76 gate-denied ops, every anonymous
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

    /// Write an object — and, if the request says so, decide who may read it.
    ///
    /// Until the M4 retrofit this hook read `bucket` and `key` and nothing else, so
    /// `x-amz-acl: public-read` reached RGW unexamined and the object became
    /// world-readable behind an audit record that said "allowed write". See
    /// [`headers`] for the classification and for why the answer is a denial rather than
    /// a silent strip.
    async fn put_object(&self, req: &mut S3Request<PutObjectInput>) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let max_tags = self.gw.limits().max_tag_count;
        let riders = RequestRiders::parse(
            object_acl_fields!(req.input),
            req.input.tagging.as_deref(),
            false,
            max_tags,
        );
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object_write(&mut cx, Action::WriteObjects, bucket, key, riders)
            .await
    }

    /// Browser form upload. Blind spot #3: the key is in the parsed multipart body, not
    /// in the path, so only a hook that reads the *parsed* request can authorize it.
    ///
    /// This is the one op that breaks the "check sees no body" invariant, and not by
    /// choice: s3s aggregates the whole file into memory during route resolution, ahead
    /// of `check` and of everything here (`s3s-0.14.1/src/ops/mod.rs:539-551`). So an
    /// unauthenticated caller can make this process allocate up to
    /// `limits.post_object_max_file_size` before a single authorization step runs; that
    /// default is lowered to 64 MiB for exactly this reason. Nothing in this hook can
    /// move that bound — by the time it runs, the allocation already happened.
    ///
    /// Its `acl` and `tagging` arrive as **form fields**, not headers, which is the other
    /// reason the strip escape hatch is not implemented: they are covered by the signed
    /// POST policy document, so rewriting the form after signature verification would
    /// forward a body that no longer matches the policy the caller signed — an opaque 403
    /// from RGW instead of an honest one from here.
    async fn post_object(&self, req: &mut S3Request<PostObjectInput>) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let max_tags = self.gw.limits().max_tag_count;
        let riders = RequestRiders::parse(
            object_acl_fields!(req.input),
            req.input.tagging.as_deref(),
            false,
            max_tags,
        );
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object_write(&mut cx, Action::WriteObjects, bucket, key, riders)
            .await
    }

    /// Delete one object — refusing outright to defeat its retention.
    ///
    /// `x-amz-bypass-governance-retention` used to ride through unread, which on a bucket
    /// with object lock in governance mode meant a `delete_objects` grant silently
    /// included "and may destroy retained records". See [`Self::screen_riders`].
    async fn delete_object(&self, req: &mut S3Request<DeleteObjectInput>) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let riders = Ok(RequestRiders {
            bypass_governance: req.input.bypass_governance_retention.unwrap_or(false),
            ..RequestRiders::default()
        });
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object_write(&mut cx, Action::DeleteObjects, bucket, key, riders)
            .await
    }

    async fn delete_objects(&self, req: &mut S3Request<DeleteObjectsInput>) -> S3Result<()> {
        // Blind spot #2: multi-delete keys live in the XML body — authorize EACH key,
        // then filter the forwarded request to only the allowed keys.
        // Read once: two loads could straddle a config apply and report a cap the
        // request was not actually measured against.
        let max_delete_keys = self.gw.limits().max_delete_keys;
        let bucket = req.input.bucket.clone();
        let bypass_governance = req.input.bypass_governance_retention.unwrap_or(false);
        let key_count = req.input.delete.objects.len();
        let all_keys: Vec<String> = req
            .input
            .delete
            .objects
            .iter()
            .map(|o| o.key.clone())
            .collect();
        let mut cx = ReqCtx::new(req)?;
        // Defect B-1, on the cap that predates it: this used to `return Err(s3_error!(
        // InvalidRequest, …))` above, ahead of `ReqCtx` and therefore ahead of every
        // audit site — so an over-cap multi-delete left no record at all. It refuses
        // like every other cap now. `delete_keys` is deliberately NOT recorded here:
        // the request is over the bound precisely because it carries too many, and an
        // audit record is not the place to copy an unbounded list.
        if key_count > max_delete_keys {
            let input = cx.base_input(Action::DeleteObjects, bucket);
            return Err(self.refuse(
                input,
                format!(
                    "delete request carries {key_count} keys, over the {max_delete_keys}-key cap"
                ),
            ));
        }
        // The bypass header covers the WHOLE batch, so it is screened once, before any
        // key is decided — and it refuses the whole request rather than being applied to
        // the keys that happened to be allowed. A partially-honored WORM bypass is not a
        // thing this gateway should be able to produce.
        if bypass_governance {
            let mut input = cx.base_input(Action::DeleteObjects, bucket);
            input.bypass_governance = true;
            let why = self
                .screen_riders(&RequestRiders {
                    bypass_governance: true,
                    ..RequestRiders::default()
                })
                .expect_err("a bypass rider is always refused");
            return Err(self.refuse(input, why));
        }

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
        let max_tags = self.gw.limits().max_tag_count;
        // `x-amz-tagging` only takes effect under `x-amz-tagging-directive: REPLACE`;
        // under the default `COPY` the destination inherits the *source object's* tags,
        // which the gateway does not read (that is `object_tags`, ADR-003's gated
        // on-demand fetch, still unwired). So: a REPLACE directive is a tag write and is
        // authorized as one — including a REPLACE with no header, which installs the
        // empty set. A header sent under a COPY directive is authorized too rather than
        // ignored, because the caller asked for it and the gateway does not silently
        // decide a request meant less than it said. What rides through unauthorized is
        // the inherited set under COPY, and that is on the op's blind-spot list.
        let replace = req
            .input
            .tagging_directive
            .as_ref()
            .map(TaggingDirective::as_str)
            == Some(TaggingDirective::REPLACE);
        let tagging = match (replace, req.input.tagging.as_deref()) {
            (true, Some(t)) => Some(t),
            (true, None) => Some(""),
            (false, t) => t,
        };
        let riders = RequestRiders::parse(object_acl_fields!(req.input), tagging, false, max_tags);
        let mut cx = ReqCtx::new(req)?;
        let riders = match riders {
            Ok(r) => r,
            Err(why) => {
                let mut input = cx.base_input(Action::WriteObjects, bucket);
                input.object = Some(key);
                return Err(self.refuse(input, why));
            }
        };
        self.enforce_copy(&mut cx, &source, bucket, key, riders)
            .await
    }

    async fn list_objects_v2(&self, req: &mut S3Request<ListObjectsV2Input>) -> S3Result<()> {
        // Same s3s comma-list defect as `get_object_attributes`; see `split_comma_list`.
        if let Some(opt) = req.input.optional_object_attributes.as_mut() {
            split_comma_list(opt);
        }
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
                ResponseObligations::fanout(prefixes).install(&mut req.extensions);
                Ok(())
            }
        }
    }

    async fn list_objects(&self, req: &mut S3Request<ListObjectsInput>) -> S3Result<()> {
        // Same s3s comma-list defect as `get_object_attributes`; see `split_comma_list`.
        if let Some(opt) = req.input.optional_object_attributes.as_mut() {
            split_comma_list(opt);
        }
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

    /// Begin a multipart upload. The ACL and tag set are fixed **here**, at creation, not
    /// at `CompleteMultipartUpload` — so this is the only hook in the multipart lifecycle
    /// where they can be authorized, and it was the one that did not look.
    async fn create_multipart_upload(
        &self,
        req: &mut S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let max_tags = self.gw.limits().max_tag_count;
        let riders = RequestRiders::parse(
            object_acl_fields!(req.input),
            req.input.tagging.as_deref(),
            false,
            max_tags,
        );
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object_write(&mut cx, Action::WriteObjects, bucket, key, riders)
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
        // No riders: `UploadPartCopy` carries no ACL, tag or retention fields — the part's
        // destination object was created (and its ACL fixed) by `CreateMultipartUpload`.
        self.enforce_copy(&mut cx, &source, bucket, key, RequestRiders::default())
            .await
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

    /// Enumerate the caller's buckets — the first operation whose *response* the gateway
    /// filters, and the only hook here that does not answer a refusal with a 403.
    ///
    /// ### Why the answer is never `AccessDenied`
    ///
    /// A `ListBuckets` response discloses names, and the empty response discloses
    /// nothing. So the two ways of ending up with nothing to show —
    ///
    /// - the principal may not enumerate at all, and
    /// - the principal may enumerate and holds no bucket grants
    ///
    /// — must be **indistinguishable**, or the status code is an oracle that answers
    /// "does this credential hold `list_buckets` in this tenant?" for anyone who asks.
    /// Both therefore return `200` with an empty `<Buckets/>`, through the same branch,
    /// and neither contacts the backend — so they cost the same wall-clock time as well
    /// as carrying the same bytes. The distinction is preserved exactly where it belongs:
    /// in the audit record, which says `Denied` for the first and `Allowed` for the
    /// second.
    ///
    /// This is not a weakening of deny-by-default. The *default*, with no obligation at
    /// all, is [`BucketVisibility::Nothing`] — the empty listing — and a bucket becomes
    /// visible only by being named in an obligation a policy emitted. What changed is the
    /// shape of the refusal, not its strictness.
    ///
    /// ### Why the hook returns `Ok(())` on a denial
    ///
    /// Because the empty response has to be produced *somewhere*, and an `S3Access` hook
    /// cannot produce a response — only a verdict. The dispatcher does it, from the
    /// obligation installed here. What keeps that from being a hole:
    /// `GatewayS3::list_buckets` refuses outright if no visibility obligation is present
    /// (so a hook that never ran cannot forward), and the `Nothing` branch it takes here
    /// contacts no backend and reads no data — it constructs an empty listing and returns.
    /// No [`AuthzProof`] is minted on this path, and none is needed, because nothing is
    /// fetched.
    async fn list_buckets(&self, req: &mut S3Request<ListBucketsInput>) -> S3Result<()> {
        let visibility = {
            let mut cx = ReqCtx::new(req)?;
            self.enforce_bucket_listing(&mut cx).await
        };
        ResponseObligations::buckets(visibility).install(&mut req.extensions);
        Ok(())
    }

    // ── bucket existence (M4 tier 1: client compatibility) ──────────────────────
    //
    // What is NOT here, since 2026-08-08, and deliberately: `create_bucket`,
    // `delete_bucket`, `{get,put}_bucket_policy` and `{get,put}_bucket_cors`. They were
    // enforced hooks from M4 until the settlement made the gateway data-plane only, and
    // they were REMOVED rather than stubbed — a stub would have been a hook that returns
    // `Ok(())`, which is the s3s fail-OPEN default wearing a comment. With no hook and no
    // dispatch arm, `OP_TABLE` marks each `Coverage::Denied`, `check` refuses it before
    // deserialization, and even a bug in `check` lands on s3s's `NotImplemented`.
    // `tests/gate_invariants.rs::denied_ops_have_no_dispatch_arm` holds that.
    //
    // Bucket existence, policy, CORS and quota are properties of the MANAGED resource —
    // the `HFBucket` CR — and they are changed through the console and the operator, so
    // that no bucket exists without a CR behind it. See `optable::NON_GATEWAY_VERBS`.

    async fn head_bucket(&self, req: &mut S3Request<HeadBucketInput>) -> S3Result<()> {
        let bucket = req.input.bucket.clone();
        let mut cx = ReqCtx::new(req)?;
        self.enforce_bucket(&mut cx, Action::Read, bucket).await
    }

    async fn get_bucket_location(
        &self,
        req: &mut S3Request<GetBucketLocationInput>,
    ) -> S3Result<()> {
        // The existence verb, not a configuration one: every SDK probes this on connect,
        // so charging it to anything else would make ordinary use require a grant nobody
        // would know to give. Same verb, and same answer, as HeadBucket and ListBuckets.
        let bucket = req.input.bucket.clone();
        let mut cx = ReqCtx::new(req)?;
        self.enforce_bucket(&mut cx, Action::Read, bucket).await
    }

    // ── object tagging and attributes (M4 tier 3) ───────────────────────────────

    /// `read_objects`, same verb as `GetObject` — merged 2026-08-08.
    ///
    /// Reading an object's tags is strictly less than reading the object itself: anyone
    /// who can `GetObject` can read the bytes the tags describe. A separate
    /// `read_object_tags` verb therefore bought no containment and cost a grant an
    /// administrator had to know to give, which in practice meant tag reads 403'd for
    /// principals who could already download the object.
    ///
    /// The WRITE direction is **not** merged, and the asymmetry is the whole point: a
    /// tag can satisfy an ABAC condition, so writing one can elevate. See
    /// [`Action::WriteObjectTags`].
    async fn get_object_tagging(&self, req: &mut S3Request<GetObjectTaggingInput>) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object(&mut cx, Action::ReadObjects, bucket, key)
            .await
    }

    /// Install a tag set.
    ///
    /// The tags ride to the PDP as `requested_tags` — the **proposed** set, never the
    /// object's current one — because a tag write is an ABAC input: a principal that can
    /// set the key its own grant conditions read can elevate itself. Deciding against the
    /// current set would authorize the state the object is leaving, not the one it is
    /// entering.
    ///
    /// That is necessary and not sufficient, so the reserved-key guard runs here too and
    /// runs *first*: see [`tagging`] for why an absent `reserved_tag_keys` list refuses
    /// every tag write rather than reserving nothing.
    async fn put_object_tagging(&self, req: &mut S3Request<PutObjectTaggingInput>) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let tag_set = req.input.tagging.tag_set.clone();
        let max_tags = self.gw.limits().max_tag_count;
        let mut cx = ReqCtx::new(req)?;
        let refused = |cx: &ReqCtx<'_>, tags: Option<&BTreeMap<String, String>>| {
            let mut input = cx.base_input(Action::WriteObjectTags, bucket.clone());
            input.object = Some(key.clone());
            input.requested_tags = tags.cloned();
            input
        };
        let tags = match parse_tag_set(&tag_set, max_tags) {
            Ok(t) => t,
            Err(why) => return Err(self.refuse(refused(&cx, None), why)),
        };
        if let Err(why) = self.reserved_tag_keys().check(&tags) {
            return Err(self.refuse(refused(&cx, Some(&tags)), why));
        }
        let input = refused(&cx, Some(&tags));
        self.enforce(&mut cx, input).await
    }

    /// Clear an object's tag set.
    ///
    /// No `requested_tags`: the request names no tags, it removes whatever is there.
    /// Reading the current set first would be an on-demand backend fetch, which is
    /// ADR-003's gated `object_tags` path and is deliberately not wired.
    ///
    /// It is still a **tag write**, so it is refused while tagging is inert. That is not
    /// pedantry: removing a tag changes the ABAC facts about an object just as setting one
    /// does, and a deployment whose control plane has not yet said which keys a policy may
    /// depend on cannot tell which removals matter.
    async fn delete_object_tagging(
        &self,
        req: &mut S3Request<DeleteObjectTaggingInput>,
    ) -> S3Result<()> {
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        if let Some(why) = self.reserved_tag_keys().inert_reason() {
            let mut input = cx.base_input(Action::WriteObjectTags, bucket);
            input.object = Some(key);
            return Err(self.refuse(input, why));
        }
        self.enforce_object(&mut cx, Action::WriteObjectTags, bucket, key)
            .await
    }

    /// `read_objects`, same verb as `GetObject`: it answers questions about the object
    /// a reader could answer by reading it. The one thing it adds is `ObjectParts` —
    /// the multipart structure — which any read-granted principal now sees. Recorded as
    /// a blind spot; not solved here.
    async fn get_object_attributes(
        &self,
        req: &mut S3Request<GetObjectAttributesInput>,
    ) -> S3Result<()> {
        split_comma_list(&mut req.input.object_attributes);
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        let mut cx = ReqCtx::new(req)?;
        self.enforce_object(&mut cx, Action::ReadObjects, bucket, key)
            .await
    }
}

/// Re-split a header list s3s parsed as one element per *repeated header* back into one
/// element per comma-separated value.
///
/// Found by driving `boto3` through the gateway at a real backend, not by a unit test —
/// which is the point of the client-compatibility matrix. AWS clients send a
/// `list`-shaped header as a single header with comma-separated values
/// (`x-amz-object-attributes: ETag,ObjectSize`), but `s3s`'s `parse_list_header`
/// (`http/de.rs:118-132`) iterates `headers.get_all(name)` and never splits on the comma,
/// so it produces the one-element list `["ETag,ObjectSize"]`. The forward then re-encodes
/// that element through the AWS SDK, which **quotes any element containing a comma** — so
/// the backend receives `x-amz-object-attributes: "ETag,ObjectSize"` and answers
/// `400 InvalidArgument`. Verified end to end: one attribute works through the gateway,
/// two do not, and both work when the same client talks to the backend directly.
///
/// The rewrite is a canonicalization, not an authorization decision: the requested
/// attribute list is not separately authorized (recorded as a blind spot on
/// `GetObjectAttributes`), and splitting can only make the forwarded value *more* faithful
/// to what the caller signed. It happens in the hook rather than the dispatch arm so the
/// canonicalize-before-forward invariant still holds — the value the PDP saw, the value on
/// the audit record and the value forwarded are the same one.
fn split_comma_list<T: HeaderListItem>(values: &mut Vec<T>) {
    if !values.iter().any(|v| v.as_str().contains(',')) {
        return;
    }
    *values = values
        .iter()
        .flat_map(|v| {
            v.as_str()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .map(T::from_string)
        .collect();
}

/// The s3s enum-newtypes that appear in a `list`-shaped header. Neither implements
/// `AsRef<str>`, so this is the smallest common surface [`split_comma_list`] needs.
trait HeaderListItem {
    fn as_str(&self) -> &str;
    fn from_string(s: String) -> Self;
}

macro_rules! header_list_item {
    ($t:ty) => {
        impl HeaderListItem for $t {
            fn as_str(&self) -> &str {
                <$t>::as_str(self)
            }
            fn from_string(s: String) -> Self {
                Self::from(s)
            }
        }
    };
}

header_list_item!(ObjectAttributes);
header_list_item!(OptionalObjectAttributes);

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
    if let Some(reason) = unimplemented_obligations(decision) {
        return ListVerdict::Deny(reason);
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

/// What to do with a `ListBuckets` after the PDP decision.
enum BucketListing {
    /// Show nothing, and record `reason` as the denial. The client cannot tell this
    /// from an allowed listing with an empty visible set — deliberately.
    Withhold(String),
    /// Forward, and filter the response to this visibility.
    Show(BucketVisibility),
}

/// Turn a decision into a bucket-visibility verdict.
///
/// Every branch that is not an explicit, unambiguous grant of visibility ends in
/// [`BucketListing::Withhold`]. In particular an **absent** obligation does — that is
/// the asymmetry documented on [`crate::authz::Obligations::visible_buckets`], and it is
/// what makes a policy that forgot to say anything about bucket visibility safe rather
/// than catastrophic.
fn classify_bucket_listing(decision: &Decision) -> BucketListing {
    if !decision.allow {
        return BucketListing::Withhold(decision.reason.clone());
    }
    if let Some(reason) = unimplemented_obligations(decision) {
        return BucketListing::Withhold(reason);
    }
    let obligations = &decision.obligations;
    if obligations.all_buckets_visible && !obligations.visible_buckets.is_empty() {
        // Two obligations describing the same response, disagreeing. Picking either one
        // is a guess about which the author meant, and the wrong guess publishes the
        // tenant's namespace.
        return BucketListing::Withhold(
            "deny (gateway): ambiguous bucket-visibility obligation — all_buckets_visible \
             was set together with a visible_buckets list"
                .to_string(),
        );
    }
    if obligations.all_buckets_visible {
        return BucketListing::Show(BucketVisibility::All);
    }
    // `only` collapses the empty set to `Nothing`, so "allowed, nothing granted" and
    // "allowed, these buckets granted" are the same code path with different data.
    BucketListing::Show(BucketVisibility::only(
        obligations.visible_buckets.iter().cloned().collect(),
    ))
}

/// The deny reason for a decision carrying a `must_understand` this binary cannot
/// honor, or `None` when every named obligation is implemented.
fn unimplemented_obligations(decision: &Decision) -> Option<String> {
    let missing = decision.obligations.unimplemented();
    if missing.is_empty() {
        return None;
    }
    Some(format!(
        "deny (gateway): the policy requires obligation(s) {} which this gateway does \
         not implement; upgrade the gateway before pushing a policy that depends on them",
        missing.join(", ")
    ))
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

/// The tag set a `PutObjectTagging` asks to install, as the map the PDP sees.
///
/// Two refusals, both of them about the PDP and the backend seeing the same thing:
///
/// - **the cap** (`limits.max_tag_count`, AWS's own limit is 10);
/// - **duplicate keys.** A `TagSet` is a list, so it can carry one key twice. Folding
///   it into a map silently keeps one of them, and the backend keeps whichever *it*
///   prefers — a parser differential in which the policy authorizes a tag set the object
///   never receives. A tag with no key is refused for the same reason.
fn parse_tag_set(tag_set: &[Tag], max_tags: usize) -> Result<BTreeMap<String, String>, String> {
    if tag_set.len() > max_tags {
        return Err(format!(
            "tag set carries {} tags, over the {max_tags}-tag cap",
            tag_set.len()
        ));
    }
    let mut tags = BTreeMap::new();
    for tag in tag_set {
        let Some(key) = tag.key.clone() else {
            return Err("tag set carries a tag with no key".to_string());
        };
        if tags
            .insert(key.clone(), tag.value.clone().unwrap_or_default())
            .is_some()
        {
            return Err(format!(
                "tag set carries the key {key:?} twice; the gateway will not authorize a \
                 tag set it cannot resolve the same way the backend will"
            ));
        }
    }
    Ok(tags)
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
        // The form upload is now one of them: its key lives in the parsed multipart
        // body, so only a typed hook can authorize it, and its s3s trait default
        // *forwards* rather than refusing.
        assert!(optable::gate_op("PostObject").is_ok());
        // ListBuckets is now one of them: it is the only op whose response the gateway
        // rewrites, so its hook is what installs the visibility obligation the
        // dispatcher applies.
        assert!(optable::gate_op("ListBuckets").is_ok());
        // Ops with no hook must be refused — they would fail-open at their default
        // typed hook, so check() must reject them.
        for op in [
            "PutBucketAcl",
            "PutObjectAcl",
            "ListObjectVersions",
            "RestoreObject",
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
            ..Obligations::default()
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
            allowed_prefixes: vec!["2025/".into(), "2024/".into()],
            ..Obligations::default()
        });
        assert!(matches!(
            classify_list(&d, 16, Fanout::Supported),
            ListVerdict::FanOut(p) if p == vec!["2024/".to_string(), "2025/".to_string()]
        ));
    }

    #[test]
    fn list_multi_prefix_over_bound_fails_closed() {
        let d = allow_with(Obligations {
            allowed_prefixes: vec!["a/".into(), "b/".into(), "c/".into()],
            ..Obligations::default()
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
            allowed_prefixes: vec!["2024/".into(), "2025/".into()],
            ..Obligations::default()
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

    // ── ListBuckets: the response-obligation classifier ─────────────────────────

    fn withheld(d: &Decision) -> String {
        match classify_bucket_listing(d) {
            BucketListing::Withhold(reason) => reason,
            BucketListing::Show(v) => {
                panic!("expected the listing to be withheld, got {v:?}")
            }
        }
    }

    fn shown(d: &Decision) -> BucketVisibility {
        match classify_bucket_listing(d) {
            BucketListing::Show(v) => v,
            BucketListing::Withhold(reason) => {
                panic!("expected a listing, got a refusal: {reason}")
            }
        }
    }

    #[test]
    fn an_allow_with_no_visibility_obligation_shows_nothing() {
        // THE default that makes this safe. Every request is re-signed with the
        // tenant-owner credential, so the backend answers ListBuckets with the whole
        // tenant namespace; a policy that allowed the enumeration and said nothing about
        // visibility must therefore yield an empty listing, never an unfiltered one.
        assert_eq!(
            shown(&allow_with(Obligations::default())),
            BucketVisibility::Nothing
        );
    }

    #[test]
    fn a_named_visible_set_becomes_an_exact_filter() {
        let vis = shown(&allow_with(Obligations {
            visible_buckets: vec!["reports".into(), "logs".into()],
            ..Obligations::default()
        }));
        assert!(vis.admits("reports") && vis.admits("logs"));
        assert!(!vis.admits("secrets"));
        assert!(
            !vis.admits("reports-archive"),
            "visible_buckets is a set of names, not a set of prefixes"
        );
    }

    #[test]
    fn only_an_explicit_all_buckets_visible_forwards_the_listing_unfiltered() {
        assert_eq!(
            shown(&allow_with(Obligations {
                all_buckets_visible: true,
                ..Obligations::default()
            })),
            BucketVisibility::All
        );
    }

    #[test]
    fn an_ambiguous_visibility_obligation_shows_nothing() {
        // Two obligations describing one response and disagreeing. Resolving it either
        // way is a guess, and one of the guesses publishes the tenant's namespace.
        let reason = withheld(&allow_with(Obligations {
            all_buckets_visible: true,
            visible_buckets: vec!["reports".into()],
            ..Obligations::default()
        }));
        assert!(reason.contains("ambiguous"), "{reason}");
    }

    #[test]
    fn a_denied_enumeration_and_an_empty_grant_set_are_the_same_answer() {
        // Requirement: the caller must not be able to tell "you may not enumerate" from
        // "you may, and you hold nothing". Both are Nothing, so both produce the same
        // empty listing through the same branch at the same cost. What separates them is
        // the audit record, which is where the distinction belongs.
        let denied = Decision::deny("no grant matches action/scope");
        assert!(matches!(
            classify_bucket_listing(&denied),
            BucketListing::Withhold(_)
        ));
        assert_eq!(
            shown(&allow_with(Obligations::default())),
            BucketVisibility::Nothing
        );
    }

    #[test]
    fn a_must_understand_this_binary_cannot_honor_denies_every_shape() {
        // The rollout ordering guard, on all three verdict paths: a policy may declare an
        // obligation mandatory, and a gateway too old to apply it must refuse rather than
        // skip it. Pushing such a policy before the binary is a self-inflicted outage,
        // which is exactly why it must be loud.
        let d = allow_with(Obligations {
            visible_buckets: vec!["reports".into()],
            must_understand: vec!["excluded_prefixes".into()],
            ..Obligations::default()
        });
        assert!(withheld(&d).contains("excluded_prefixes"));
        assert!(matches!(
            classify_list(&d, 16, Fanout::Supported),
            ListVerdict::Deny(reason) if reason.contains("excluded_prefixes")
        ));
        assert!(unimplemented_obligations(&d).is_some());

        // Positive control: a name this binary does implement is not a refusal.
        let ok = allow_with(Obligations {
            all_buckets_visible: true,
            must_understand: vec!["all_buckets_visible".into()],
            ..Obligations::default()
        });
        assert_eq!(shown(&ok), BucketVisibility::All);
        assert!(unimplemented_obligations(&ok).is_none());
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
