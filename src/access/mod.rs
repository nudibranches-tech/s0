//! The OPA gate (§4.3) — the point of the project. Enforcement lives in the typed
//! per-op hooks (which see the full parsed input), not in `check`:
//!
//! - `check` (pre-deserialization) is the **deny-by-default backstop** (§6.2): it
//!   denies anonymous, denies any op not on the implemented allowlist (the 99 typed
//!   hooks fail-OPEN, so an un-listed op MUST be rejected here), resolves the
//!   end-user identity, and stashes it for the later stages.
//! - The typed hooks (post-deserialization, `&mut`) build the OPA input (§5), call
//!   the PDP, emit exactly one audit record per request (§6.6), and apply obligations
//!   (prefix rewrite) — closing the CopyObject / multi-delete / form-upload blind
//!   spots because they authorize the *parsed* request.

use std::sync::Arc;

use s3s::access::{S3Access, S3AccessContext};
use s3s::dto::*;
use s3s::{S3Request, S3Result, s3_error};

use crate::audit::{AuditRecord, GatewayMeta, Outcome};
use crate::auth::SECURITY_TOKEN_HEADER;
use crate::authz::{Backend, CopySource as AuthzCopySource, Decision, OpaInput, RequestMeta};
use crate::gateway::Gateway;
use crate::identity::ResolvedPrincipal;
use crate::model::{Action, BackendId, BackendKind};
use crate::proxy::fanout;

/// The ops the gateway implements a typed hook for. `check` denies everything else
/// (deny-by-default backstop — adding an op here and implementing its hook are one
/// change, §6.2).
const ALLOWED_OPS: &[&str] = &[
    "GetObject",
    "HeadObject",
    "PutObject",
    "DeleteObject",
    "DeleteObjects",
    "CopyObject",
    "ListObjectsV2",
    "ListObjects",
    "CreateMultipartUpload",
    "UploadPart",
    "UploadPartCopy",
    "CompleteMultipartUpload",
    "AbortMultipartUpload",
    "ListParts",
    "ListMultipartUploads",
];
// PostObject is intentionally NOT allow-listed: `s3s_aws::Proxy` has no `post_object`,
// so a form upload cannot be forwarded. Allow-listing it would authorize + audit an
// "Allowed" write that then 501s — a misleading record. The `post_object` hook below is
// retained (it authorizes the parsed form key, blind spot #3); re-add to the allowlist
// once form-upload forwarding lands (PostObject→PutObject conversion).

pub struct GatewayAccess {
    gw: Arc<Gateway>,
}

impl GatewayAccess {
    pub fn new(gw: Arc<Gateway>) -> Self {
        GatewayAccess { gw }
    }

    fn principal<T>(&self, req: &S3Request<T>) -> S3Result<Arc<ResolvedPrincipal>> {
        req.extensions
            .get::<Arc<ResolvedPrincipal>>()
            .cloned()
            .ok_or_else(|| s3_error!(InternalError, "resolved principal missing from request"))
    }

    fn base_input(&self, p: &ResolvedPrincipal, action: Action, bucket: String) -> OpaInput {
        let (id, kind) = self
            .gw
            .registry
            .backend_of(&p.tenant)
            .unwrap_or((BackendId(String::new()), BackendKind::Ceph));
        // Org is the gateway's AUTHORITATIVE tenant->org binding, never the
        // credential's self-declared org — audit attribution must not be drift-able
        // (§6.6). Post-`check` the tenant is routable, so this is always resolved; an
        // unresolved org yields an empty label the console drops fail-closed (§3.6).
        let organization_id = self
            .gw
            .registry
            .organization_of(&p.tenant)
            .map(str::to_string)
            .unwrap_or_default();
        OpaInput {
            principal: p.to_opa_principal(),
            backend: Backend { id: id.0, kind },
            tenant: p.tenant.clone(),
            organization_id,
            action,
            bucket,
            object: None,
            prefix: None,
            copy_source: None,
            delete_keys: None,
            object_tags: None,
            request: RequestMeta::default(),
        }
    }

    /// Any PDP error fails closed to a deny (§6.2) — never allow on error.
    async fn decide(&self, input: &OpaInput) -> Decision {
        match self.gw.pdp.decide(input).await {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(%e, "pdp error; failing closed");
                Decision::deny("pdp evaluation error")
            }
        }
    }

    fn audit(
        &self,
        input: OpaInput,
        decision: &Decision,
        outcome: Outcome,
        denied_keys: Vec<String>,
    ) {
        let meta = GatewayMeta {
            backend_id: input.backend.id.clone(),
            backend_kind: input.backend.kind.as_str().to_string(),
            outcome,
            denied_keys,
            backend_status: None,
        };
        let record = AuditRecord::new(
            new_decision_id(),
            now_rfc3339(),
            input,
            decision.clone(),
            meta,
        );
        self.gw.audit.emit(record);
    }

    /// The single-object path (get/head/put/delete-one/post-form). One decision, one
    /// audit record.
    async fn enforce_object(
        &self,
        principal: &ResolvedPrincipal,
        action: Action,
        bucket: String,
        object: String,
        request: RequestMeta,
    ) -> S3Result<()> {
        let mut input = self.base_input(principal, action, bucket);
        input.object = Some(object);
        input.request = request;
        let decision = self.decide(&input).await;
        let (allow, reason) = (decision.allow, decision.reason.clone());
        let outcome = outcome_of(allow);
        self.audit(input, &decision, outcome, vec![]);
        if allow {
            Ok(())
        } else {
            Err(s3_error!(AccessDenied, "{reason}"))
        }
    }

    /// Copy-style path (CopyObject, UploadPartCopy): authorize BOTH the source read
    /// and the dest write (blind spot #1). One request-level audit record.
    async fn enforce_copy(
        &self,
        principal: &ResolvedPrincipal,
        source: &CopySource,
        dest_bucket: String,
        dest_key: String,
        request: RequestMeta,
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
        let mut src_input = self.base_input(principal, Action::ReadObjects, src_bucket.clone());
        src_input.object = Some(src_key.clone());
        let src_allow = self.decide(&src_input).await.allow;

        let mut dst_input = self.base_input(principal, Action::WriteObjects, dest_bucket);
        dst_input.object = Some(dest_key);
        dst_input.copy_source = Some(AuthzCopySource {
            bucket: src_bucket,
            key: src_key,
        });
        dst_input.request = request;
        let dst_allow = self.decide(&dst_input).await.allow;

        let allow = src_allow && dst_allow;
        let decision = if allow {
            Decision::allow("copy allowed (source read + dest write)")
        } else {
            Decision::deny(format!(
                "copy denied (source_read={src_allow}, dest_write={dst_allow})"
            ))
        };
        self.audit(dst_input, &decision, outcome_of(allow), vec![]);
        if allow {
            Ok(())
        } else {
            Err(s3_error!(AccessDenied, "copy denied by policy"))
        }
    }

    /// List-style path (ListObjects*, ListMultipartUploads): decide, classify the
    /// obligation (§5.1), and audit. The caller applies the verdict to the request
    /// (rewrite prefix, stash a fan-out obligation, or deny).
    async fn enforce_list(
        &self,
        principal: &ResolvedPrincipal,
        bucket: String,
        prefix: Option<String>,
        request: RequestMeta,
    ) -> ListVerdict {
        let mut input = self.base_input(principal, Action::ListObjects, bucket);
        input.prefix = prefix;
        input.request = request;
        let decision = self.decide(&input).await;
        let verdict = classify_list(&decision, self.gw.limits.max_list_fanout);
        match &verdict {
            ListVerdict::Deny(reason) => {
                let d = Decision::deny(reason.clone());
                self.audit(input, &d, Outcome::Denied, vec![]);
            }
            _ => self.audit(input, &decision, Outcome::Allowed, vec![]),
        }
        verdict
    }
}

#[async_trait::async_trait]
impl S3Access for GatewayAccess {
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
        // Gate rejections are logged for ops visibility of denied access *attempts*
        // (the access-key id is a semi-public identifier, never the secret). They are
        // not emitted as decision-log records — those are per parsed object op (§6.6);
        // a dedicated gate-rejection audit event is a documented follow-up.
        let op = cx.s3_op().name().to_string();
        let access_key = match cx.credentials() {
            Some(c) => c.access_key.clone(),
            None => {
                tracing::debug!(%op, "gate deny: anonymous request");
                return Err(s3_error!(AccessDenied, "Signature is required"));
            }
        };
        // Deny-by-default backstop: un-listed ops fail-open at their typed hook, so
        // they MUST be rejected here (§6.2).
        if !ALLOWED_OPS.contains(&op.as_str()) {
            tracing::warn!(%op, %access_key, "gate deny: operation not permitted");
            return Err(s3_error!(
                AccessDenied,
                "operation {op} is not permitted by the gateway"
            ));
        }
        // The STS session token rides in the header for signed requests and in the
        // query string for presigned URLs (§4.2) — presigned links flow through the
        // same OPA gate, so accept both.
        let token = session_token(cx.headers(), cx.uri());
        let principal = match self.gw.identity.resolve(&access_key, token.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(%op, %access_key, error = %e, "gate deny: identity rejected");
                return Err(s3_error!(AccessDenied, "identity rejected: {e}"));
            }
        };
        if self.gw.registry.backend_of(&principal.tenant).is_none() {
            tracing::warn!(%op, sub = %principal.sub, tenant = %principal.tenant, "gate deny: tenant not routable");
            return Err(s3_error!(
                AccessDenied,
                "tenant {} is not routable",
                principal.tenant
            ));
        }
        cx.extensions_mut().insert(Arc::new(principal));
        Ok(())
    }

    async fn get_object(&self, req: &mut S3Request<GetObjectInput>) -> S3Result<()> {
        let p = self.principal(req)?;
        let meta = request_meta(req);
        self.enforce_object(
            &p,
            Action::ReadObjects,
            req.input.bucket.clone(),
            req.input.key.clone(),
            meta,
        )
        .await
    }

    async fn head_object(&self, req: &mut S3Request<HeadObjectInput>) -> S3Result<()> {
        let p = self.principal(req)?;
        let meta = request_meta(req);
        self.enforce_object(
            &p,
            Action::ReadObjects,
            req.input.bucket.clone(),
            req.input.key.clone(),
            meta,
        )
        .await
    }

    async fn put_object(&self, req: &mut S3Request<PutObjectInput>) -> S3Result<()> {
        let p = self.principal(req)?;
        let meta = request_meta(req);
        self.enforce_object(
            &p,
            Action::WriteObjects,
            req.input.bucket.clone(),
            req.input.key.clone(),
            meta,
        )
        .await
    }

    async fn post_object(&self, req: &mut S3Request<PostObjectInput>) -> S3Result<()> {
        // Blind spot #3: the form-upload key is in the parsed body — authorize it.
        let p = self.principal(req)?;
        let meta = request_meta(req);
        self.enforce_object(
            &p,
            Action::WriteObjects,
            req.input.bucket.clone(),
            req.input.key.clone(),
            meta,
        )
        .await
    }

    async fn delete_object(&self, req: &mut S3Request<DeleteObjectInput>) -> S3Result<()> {
        let p = self.principal(req)?;
        let meta = request_meta(req);
        self.enforce_object(
            &p,
            Action::DeleteObjects,
            req.input.bucket.clone(),
            req.input.key.clone(),
            meta,
        )
        .await
    }

    async fn delete_objects(&self, req: &mut S3Request<DeleteObjectsInput>) -> S3Result<()> {
        // Blind spot #2: multi-delete keys live in the XML body — authorize EACH key,
        // then filter the forwarded request to only the allowed keys (§5).
        let p = self.principal(req)?;
        if req.input.delete.objects.len() > self.gw.limits.max_delete_keys {
            return Err(s3_error!(
                InvalidRequest,
                "delete request exceeds {} keys",
                self.gw.limits.max_delete_keys
            ));
        }
        let bucket = req.input.bucket.clone();
        let mut allowed: Vec<String> = Vec::new();
        let mut denied: Vec<String> = Vec::new();
        for oid in &req.input.delete.objects {
            let mut input = self.base_input(&p, Action::DeleteObjects, bucket.clone());
            input.object = Some(oid.key.clone());
            if self.decide(&input).await.allow {
                allowed.push(oid.key.clone());
            } else {
                denied.push(oid.key.clone());
            }
        }

        let all_keys: Vec<String> = req
            .input
            .delete
            .objects
            .iter()
            .map(|o| o.key.clone())
            .collect();
        let mut record_input = self.base_input(&p, Action::DeleteObjects, bucket);
        record_input.delete_keys = Some(all_keys);
        record_input.request = request_meta(req);
        let decision = if allowed.is_empty() {
            Decision::deny("all delete keys denied")
        } else {
            Decision::allow(format!(
                "{} allowed, {} denied",
                allowed.len(),
                denied.len()
            ))
        };
        let outcome = outcome_of(!allowed.is_empty());
        self.audit(record_input, &decision, outcome, denied.clone());

        if allowed.is_empty() {
            return Err(s3_error!(AccessDenied, "all delete keys denied by policy"));
        }
        // Per-key filtering: forward only authorized keys.
        req.input
            .delete
            .objects
            .retain(|o| allowed.contains(&o.key));
        Ok(())
    }

    async fn copy_object(&self, req: &mut S3Request<CopyObjectInput>) -> S3Result<()> {
        let p = self.principal(req)?;
        let meta = request_meta(req);
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        self.enforce_copy(&p, &req.input.copy_source, bucket, key, meta)
            .await
    }

    async fn list_objects_v2(&self, req: &mut S3Request<ListObjectsV2Input>) -> S3Result<()> {
        let p = self.principal(req)?;
        let bucket = req.input.bucket.clone();
        let meta = request_meta(req);
        let prefix = req.input.prefix.clone();
        match self.enforce_list(&p, bucket, prefix, meta).await {
            ListVerdict::Deny(reason) => Err(s3_error!(AccessDenied, "{reason}")),
            ListVerdict::AllowAsIs => Ok(()),
            ListVerdict::Narrow(np) => {
                req.input.prefix = Some(np);
                Ok(())
            }
            ListVerdict::FanOut(prefixes) => {
                // Fan-out re-paginates raw keys; delimiter (folder) listing across
                // multiple prefixes is a follow-up (ADR-004).
                if req.input.delimiter.is_some() {
                    return Err(s3_error!(
                        AccessDenied,
                        "delimiter listing across multiple granted prefixes is unsupported; list a single prefix"
                    ));
                }
                req.extensions
                    .insert(Arc::new(fanout::ListFanout { prefixes }));
                Ok(())
            }
        }
    }

    async fn list_objects(&self, req: &mut S3Request<ListObjectsInput>) -> S3Result<()> {
        let p = self.principal(req)?;
        let bucket = req.input.bucket.clone();
        let meta = request_meta(req);
        let prefix = req.input.prefix.clone();
        let verdict = self.enforce_list(&p, bucket, prefix, meta).await;
        list_verdict_single(verdict, &mut req.input.prefix)
    }

    // ── Multipart upload lifecycle (write on the key), plus its copy + list ops ──

    async fn create_multipart_upload(
        &self,
        req: &mut S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<()> {
        let p = self.principal(req)?;
        let meta = request_meta(req);
        self.enforce_object(
            &p,
            Action::WriteObjects,
            req.input.bucket.clone(),
            req.input.key.clone(),
            meta,
        )
        .await
    }

    async fn upload_part(&self, req: &mut S3Request<UploadPartInput>) -> S3Result<()> {
        let p = self.principal(req)?;
        let meta = request_meta(req);
        self.enforce_object(
            &p,
            Action::WriteObjects,
            req.input.bucket.clone(),
            req.input.key.clone(),
            meta,
        )
        .await
    }

    async fn complete_multipart_upload(
        &self,
        req: &mut S3Request<CompleteMultipartUploadInput>,
    ) -> S3Result<()> {
        let p = self.principal(req)?;
        let meta = request_meta(req);
        self.enforce_object(
            &p,
            Action::WriteObjects,
            req.input.bucket.clone(),
            req.input.key.clone(),
            meta,
        )
        .await
    }

    async fn abort_multipart_upload(
        &self,
        req: &mut S3Request<AbortMultipartUploadInput>,
    ) -> S3Result<()> {
        let p = self.principal(req)?;
        let meta = request_meta(req);
        self.enforce_object(
            &p,
            Action::WriteObjects,
            req.input.bucket.clone(),
            req.input.key.clone(),
            meta,
        )
        .await
    }

    async fn list_parts(&self, req: &mut S3Request<ListPartsInput>) -> S3Result<()> {
        let p = self.principal(req)?;
        let meta = request_meta(req);
        self.enforce_object(
            &p,
            Action::ReadObjects,
            req.input.bucket.clone(),
            req.input.key.clone(),
            meta,
        )
        .await
    }

    async fn upload_part_copy(&self, req: &mut S3Request<UploadPartCopyInput>) -> S3Result<()> {
        // Blind spot: authorize the copy source read + the dest part write.
        let p = self.principal(req)?;
        let meta = request_meta(req);
        let (bucket, key) = (req.input.bucket.clone(), req.input.key.clone());
        self.enforce_copy(&p, &req.input.copy_source, bucket, key, meta)
            .await
    }

    async fn list_multipart_uploads(
        &self,
        req: &mut S3Request<ListMultipartUploadsInput>,
    ) -> S3Result<()> {
        let p = self.principal(req)?;
        let bucket = req.input.bucket.clone();
        let meta = request_meta(req);
        let prefix = req.input.prefix.clone();
        let verdict = self.enforce_list(&p, bucket, prefix, meta).await;
        list_verdict_single(verdict, &mut req.input.prefix)
    }
}

/// What to do with a list request after the PDP decision.
enum ListVerdict {
    Deny(String),
    /// Allowed as requested (whole-bucket or already-in-scope prefix).
    AllowAsIs,
    /// Rewrite the request prefix to this single granted prefix (§5.1).
    Narrow(String),
    /// Allowed across several granted prefixes — the dispatcher fans out (ADR-004).
    FanOut(Vec<String>),
}

/// Classify the PDP obligation into a list verdict. Multi-prefix within the fan-out
/// bound becomes `FanOut`; above the bound it fails closed.
fn classify_list(decision: &Decision, max_fanout: usize) -> ListVerdict {
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

/// Apply a list verdict for ops without fan-out dispatch (v1 list, multipart list):
/// a multi-prefix `FanOut` fails closed here.
fn list_verdict_single(verdict: ListVerdict, prefix: &mut Option<String>) -> S3Result<()> {
    match verdict {
        ListVerdict::Deny(reason) => Err(s3_error!(AccessDenied, "{reason}")),
        ListVerdict::AllowAsIs => Ok(()),
        ListVerdict::Narrow(np) => {
            *prefix = Some(np);
            Ok(())
        }
        ListVerdict::FanOut(_) => Err(s3_error!(
            AccessDenied,
            "multi-prefix listing is not supported for this operation; list a single prefix"
        )),
    }
}

fn outcome_of(allow: bool) -> Outcome {
    if allow {
        Outcome::Allowed
    } else {
        Outcome::Denied
    }
}

fn request_meta<T>(req: &S3Request<T>) -> RequestMeta {
    RequestMeta {
        method: req.method.to_string(),
        params: req.uri.query().map(str::to_string),
        headers_subset: Default::default(),
    }
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
    fn allowlist_covers_the_blind_spot_ops() {
        for op in [
            "CopyObject",
            "DeleteObjects",
            "ListObjectsV2",
            "CreateMultipartUpload",
            "UploadPartCopy",
            "CompleteMultipartUpload",
        ] {
            assert!(ALLOWED_OPS.contains(&op), "{op} must be on the allowlist");
        }
        // Ops we do not (or cannot yet) forward must NOT be allow-listed — they would
        // fail-open at their default typed hook, so check() must reject them (§6.2).
        // PostObject is excluded on purpose: s3s_aws::Proxy has no post_object.
        for op in [
            "PutBucketAcl",
            "DeleteBucket",
            "GetBucketPolicy",
            "PostObject",
        ] {
            assert!(!ALLOWED_OPS.contains(&op), "{op} must be denied by default");
        }
    }

    #[test]
    fn list_denied_passes_through_reason() {
        let d = Decision::deny("nope");
        assert!(matches!(classify_list(&d, 16), ListVerdict::Deny(_)));
    }

    #[test]
    fn list_single_prefix_narrows() {
        let d = allow_with(Obligations {
            narrow_prefix: Some("2024/".into()),
            allowed_prefixes: vec![],
        });
        assert!(matches!(classify_list(&d, 16), ListVerdict::Narrow(np) if np == "2024/"));
    }

    #[test]
    fn list_multi_prefix_within_bound_fans_out_sorted() {
        let d = allow_with(Obligations {
            narrow_prefix: None,
            allowed_prefixes: vec!["2025/".into(), "2024/".into()],
        });
        assert!(matches!(
            classify_list(&d, 16),
            ListVerdict::FanOut(p) if p == vec!["2024/".to_string(), "2025/".to_string()]
        ));
    }

    #[test]
    fn list_multi_prefix_over_bound_fails_closed() {
        let d = allow_with(Obligations {
            narrow_prefix: None,
            allowed_prefixes: vec!["a/".into(), "b/".into(), "c/".into()],
        });
        assert!(matches!(classify_list(&d, 2), ListVerdict::Deny(_)));
    }

    #[test]
    fn list_unrestricted_is_allow_as_is() {
        let d = allow_with(Obligations::default());
        assert!(matches!(classify_list(&d, 16), ListVerdict::AllowAsIs));
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
}
