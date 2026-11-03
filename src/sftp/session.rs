//! One SFTP session: request dispatch over the closed operation table (ADR-009 D2, D7,
//! D10, D11).
//!
//! Every request that touches storage takes at least one decision through the shared
//! [`crate::access::Enforcer`] — the same PDP, cache and obligations as S3 — and **all
//! decisions of one request are taken before its first backend call**. The backend is then
//! reached only under an [`SftpProof`] that names the calls those decisions license.
//!
//! Before every operation the session's credential is re-checked against the current
//! bundle (memoized per revision, so a steady-state check is one string compare). A failed
//! re-check denies the operation, aborts any open transfer and ends the session.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;

use super::account::{Authenticated, Credential};
use super::backend::{BackendError, SftpBackend};
use super::codec::{
    self, Attrs, NameEntry, Request, Response, SSH_FXF_APPEND, SSH_FXF_CREAT, SSH_FXF_EXCL,
    SSH_FXF_READ, SSH_FXF_TRUNC, SSH_FXF_WRITE, StatusCode,
};
use super::paths::{Mapped, PathError, realpath};
use super::transfer::{Commit, Download, Upload, UploadLimits, WriteError};
use super::{SessionCounters, Shared};
use crate::access::{Enforcer, SftpBackendOp as Op, SftpLicense, SftpProof};
use crate::audit::{BackendOutcome, Outcome, PendingAudit, SessionBlock, TransferBlock};
use crate::authz::{
    Backend, CopySource, Decision, OpaInput, Principal, PrincipalAttributes, Protocol, RequestMeta,
};
use crate::config::ConditionalCreate;
use crate::model::Action;
use crate::proxy::RouteSnapshot;

/// File and directory modes reported in attributes. They describe nothing about
/// authorization (D10).
const FILE_MODE: u32 = 0o100_640;
const DIR_MODE: u32 = 0o040_750;

/// Largest DATA payload one READ returns. Advertised through `limits@openssh.com`.
pub const MAX_READ: u32 = 255 * 1024;

/// Entries per NAME reply in a listing.
const READDIR_BATCH: usize = 128;

/// Upper bound on a listing assembled from several granted prefixes (D7 narrowing).
const MAX_MATERIALIZED_ENTRIES: usize = 100_000;

/// Above this a rename copies in parts; `CopyObject` is limited to 5 GiB.
const COPY_PART: u64 = 1024 * 1024 * 1024;

/// What the connection loop does after a request.
pub enum Next {
    Reply(Response),
    /// Reply, then close the channel: a framing error.
    ReplyAndClose(Response),
    /// Close without a reply: the credential was revoked.
    Close(&'static str),
}

/// The fixed identity of an authenticated connection.
pub struct SessionIdentity {
    pub session_id: String,
    pub client_ip: IpAddr,
    pub login: String,
    pub credential: Credential,
}

struct Decided {
    input: OpaInput,
    decision: Decision,
}

enum Handle {
    Dir(DirHandle),
    Read(ReadHandle),
    /// Boxed: an upload's state is much larger than a listing's or a download's.
    Write(Box<WriteHandle>),
}

struct DirHandle {
    prefix: String,
    inputs: Vec<OpaInput>,
    decided_rev: String,
    listing: Listing,
    sent_dots: bool,
    omitted: u64,
    audit: Arc<PendingAudit>,
    proof: SftpProof,
}

enum Listing {
    /// One delimiter listing of `prefix`, paged lazily.
    Paged {
        continuation: Option<String>,
        done: bool,
    },
    /// Assembled from several granted prefixes, merged and sorted.
    Materialized(VecDeque<NameEntry>),
}

struct ReadHandle {
    dl: Download,
    inputs: Vec<OpaInput>,
    decided_rev: String,
    audit: Arc<PendingAudit>,
}

struct WriteHandle {
    up: Upload,
    inputs: Vec<OpaInput>,
    decided_rev: String,
    audit: Arc<PendingAudit>,
    flags: Vec<String>,
}

pub struct SftpSession {
    shared: Arc<Shared>,
    id: SessionIdentity,
    current: Authenticated,
    checked_rev: String,
    handles: HashMap<u32, Handle>,
    next_handle: u32,
    counters: Arc<SessionCounters>,
    initialized: bool,
}

fn status(id: u32, code: StatusCode, msg: impl Into<String>) -> Next {
    Next::Reply(Response::status(id, code, msg))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn file_attrs(size: u64, mtime: u32) -> Attrs {
    Attrs {
        size: Some(size),
        permissions: Some(FILE_MODE),
        atime_mtime: Some((mtime, mtime)),
        ..Attrs::default()
    }
}

fn dir_attrs() -> Attrs {
    Attrs {
        permissions: Some(DIR_MODE),
        ..Attrs::default()
    }
}

/// `ls -l` form, owner and group `-` (D10).
fn longname(name: &str, attrs: &Attrs) -> Vec<u8> {
    let is_dir = attrs.permissions == Some(DIR_MODE);
    let mode = if is_dir { "drwxr-x---" } else { "-rw-r-----" };
    let size = attrs.size.unwrap_or(0);
    let mtime = attrs.atime_mtime.map_or(0, |(_, m)| m);
    let when = chrono::DateTime::from_timestamp(i64::from(mtime), 0)
        .map(|t| t.format("%b %e %H:%M").to_string())
        .unwrap_or_else(|| "Jan  1 00:00".into());
    format!("{mode}    1 -        -        {size:>10} {when} {name}").into_bytes()
}

fn entry(name: &str, attrs: Attrs) -> NameEntry {
    NameEntry {
        filename: name.as_bytes().to_vec(),
        longname: longname(name, &attrs),
        attrs,
    }
}

fn flag_names(pflags: u32) -> Vec<String> {
    [
        (SSH_FXF_READ, "READ"),
        (SSH_FXF_WRITE, "WRITE"),
        (SSH_FXF_APPEND, "APPEND"),
        (SSH_FXF_CREAT, "CREAT"),
        (SSH_FXF_TRUNC, "TRUNC"),
        (SSH_FXF_EXCL, "EXCL"),
    ]
    .iter()
    .filter(|(f, _)| pflags & f != 0)
    .map(|(_, n)| (*n).to_string())
    .collect()
}

/// A path error as the SFTP status D6 prescribes: `NO_SUCH_FILE` for a request naming an
/// existing entry, `FAILURE` ("invalid file name") for one that would create one.
fn path_error(id: u32, e: PathError, creating: bool) -> Next {
    let code = if creating || e == PathError::DotDot {
        StatusCode::Failure
    } else {
        StatusCode::NoSuchFile
    };
    status(id, code, e.message())
}

impl SftpSession {
    pub fn new(
        shared: Arc<Shared>,
        id: SessionIdentity,
        current: Authenticated,
        revision: String,
        counters: Arc<SessionCounters>,
    ) -> Self {
        SftpSession {
            shared,
            id,
            current,
            checked_rev: revision,
            handles: HashMap::new(),
            next_handle: 1,
            counters,
            initialized: false,
        }
    }

    fn enforcer(&self) -> &Enforcer {
        &self.shared.enforcer
    }

    /// Re-run the credential check if the bundle revision moved since it last passed.
    pub fn reauth(&mut self) -> Result<(), String> {
        let bundle = self.shared.gw.bundles.current();
        if bundle.revision == self.checked_rev {
            return Ok(());
        }
        let dir = self.shared.directory.get(&bundle);
        let auth = dir.authenticate(
            &self.id.login,
            &self.id.credential,
            self.id.client_ip,
            now_unix(),
        )?;
        if auth.account.tenant != self.current.account.tenant
            || auth.account.subject_key != self.current.account.subject_key
            || auth.account.home != self.current.account.home
        {
            // The account now reaches a different subject or home. An open session must
            // not silently follow it there.
            return Err("the account's subject or home changed".into());
        }
        self.current = auth;
        self.checked_rev = bundle.revision.clone();
        Ok(())
    }

    fn route(&self) -> Option<RouteSnapshot> {
        self.shared
            .gw
            .registry
            .route_snapshot(&self.current.account.tenant)
    }

    fn input(&self, route: &RouteSnapshot, op: &str, action: Action, bucket: &str) -> OpaInput {
        OpaInput {
            principal: Principal {
                sub: self.current.account.sub.clone(),
                kind: self.current.account.principal_type,
                attributes: PrincipalAttributes {
                    groups: self.current.groups.clone(),
                    extra: serde_json::Map::new(),
                },
            },
            backend: Backend {
                id: route.backend_id.0.clone(),
                kind: route.backend_kind,
            },
            tenant: route.tenant.clone(),
            organization_id: route.organization_id.clone(),
            action,
            bucket: bucket.to_string(),
            object: None,
            prefix: None,
            copy_source: None,
            delete_keys: None,
            object_tags: None,
            requested_tags: None,
            acl_grants: vec![],
            bypass_governance: false,
            request: RequestMeta {
                protocol: Protocol::Sftp,
                method: op.to_string(),
                params: None,
                headers_subset: Default::default(),
            },
        }
    }

    fn object_input(&self, route: &RouteSnapshot, op: &str, action: Action, key: &str) -> OpaInput {
        let mut i = self.input(route, op, action, &self.current.account.home.bucket);
        i.object = Some(key.to_string());
        i
    }

    fn list_input(&self, route: &RouteSnapshot, op: &str, prefix: &str) -> OpaInput {
        let mut i = self.input(
            route,
            op,
            Action::ListObjects,
            &self.current.account.home.bucket,
        );
        i.prefix = Some(prefix.to_string());
        i
    }

    fn block(&self, op: &str, flags: Vec<String>) -> SessionBlock {
        SessionBlock {
            protocol: "sftp".into(),
            session_id: self.id.session_id.clone(),
            client_ip: self.id.client_ip.to_string(),
            login: self.id.login.clone(),
            auth: self.current.auth.clone(),
            sftp_op: op.to_string(),
            open_flags: flags,
            transfer: None,
            omitted_entries: None,
        }
    }

    fn emit_denied(&self, input: OpaInput, decision: &Decision, block: SessionBlock) {
        let mut rec = self
            .enforcer()
            .record(input, decision, Outcome::Denied, vec![]);
        rec.gateway.session = Some(block);
        self.enforcer().emit(rec);
    }

    fn pending(
        &self,
        input: OpaInput,
        decision: &Decision,
        block: SessionBlock,
    ) -> Arc<PendingAudit> {
        let mut rec = self
            .enforcer()
            .record(input, decision, Outcome::Allowed, vec![]);
        rec.gateway.session = Some(block);
        self.enforcer().pending_record(rec)
    }

    /// Ask every question of one request, before any backend call. On a denial the
    /// request is recorded once, against the first denied input, and refused.
    ///
    /// `labels` name each half for the aggregate reason ("rename source read: …").
    async fn authorize(
        &mut self,
        op: &str,
        inputs: Vec<OpaInput>,
        labels: &[&str],
        flags: Vec<String>,
        id: u32,
    ) -> Result<Vec<Decided>, Next> {
        let mut out = Vec::with_capacity(inputs.len());
        for (n, input) in inputs.into_iter().enumerate() {
            let mut decision = self.enforcer().decide(op, &input).await;
            if decision.allow
                && let Some(reason) = Enforcer::unimplemented_obligations(&decision)
            {
                decision = Decision::deny(reason);
            }
            if !decision.allow {
                let reason = match labels.get(n) {
                    Some(l) if labels.len() > 1 => format!("{l}: {}", decision.reason),
                    _ => decision.reason.clone(),
                };
                let denial = Decision::deny(reason.clone());
                // The record carries the primary input (a rename's destination, with its
                // copy source), so one request produces one record.
                let primary = out
                    .first()
                    .map(|d: &Decided| d.input.clone())
                    .filter(|_| labels.len() > 1)
                    .unwrap_or(input);
                self.emit_denied(primary, &denial, self.block(op, flags));
                self.counters.denied.fetch_add(1, Ordering::Relaxed);
                return Err(status(id, StatusCode::PermissionDenied, reason));
            }
            out.push(Decided { input, decision });
        }
        Ok(out)
    }

    fn prove(&self, decided: &[Decided], licenses: Vec<SftpLicense>) -> Option<SftpProof> {
        let ds: Vec<&Decision> = decided.iter().map(|d| &d.decision).collect();
        self.enforcer().prove_sftp(&ds, licenses)
    }

    fn backend(&self, route: RouteSnapshot) -> SftpBackend {
        SftpBackend::new(self.shared.gw.registry.clone(), Arc::new(route))
    }

    fn mode_for(&self, route: &RouteSnapshot) -> ConditionalCreate {
        self.shared
            .conditional_create
            .get(&route.backend_id.0)
            .copied()
            .unwrap_or_default()
    }

    fn map(&self, raw: &[u8]) -> Result<Mapped, PathError> {
        self.current.account.home.map(raw)
    }

    fn alloc_handle(&mut self, h: Handle) -> Vec<u8> {
        let n = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1).max(1);
        self.handles.insert(n, h);
        n.to_be_bytes().to_vec()
    }

    fn handle_id(raw: &[u8]) -> Option<u32> {
        <[u8; 4]>::try_from(raw).ok().map(u32::from_be_bytes)
    }

    pub fn write_handles(&self) -> usize {
        self.handles
            .values()
            .filter(|h| matches!(h, Handle::Write(_)))
            .count()
    }

    /// Dispatch one request. The closed table: every v3 packet type and every extended
    /// request has exactly one arm, and anything else is `SSH_FX_OP_UNSUPPORTED`.
    pub async fn handle(&mut self, req: Request) -> Next {
        self.counters.operations.fetch_add(1, Ordering::Relaxed);
        if let Request::Init { version } = req {
            if self.initialized {
                return Next::Close("INIT sent twice");
            }
            if version < codec::SFTP_VERSION {
                return Next::Close("client SFTP version below 3");
            }
            self.initialized = true;
            return Next::Reply(Response::Version {
                extensions: vec![
                    ("limits@openssh.com", "1"),
                    ("posix-rename@openssh.com", "1"),
                ],
            });
        }
        if req.id().is_none() {
            return Next::Close("request without id");
        }
        if !self.initialized {
            return Next::Close("SSH_FXP_INIT must be the first packet");
        }
        if let Err(reason) = self.reauth() {
            tracing::warn!(session = %self.id.session_id, %reason, "sftp credential re-check failed; closing the session");
            return Next::Close("credential_revoked");
        }
        let op = req.name();
        match req {
            Request::Init { .. } => unreachable!("handled above"),
            Request::Realpath { id, path } => match realpath(&path) {
                Ok(p) => Next::Reply(Response::Name {
                    id,
                    entries: vec![NameEntry {
                        filename: p.clone().into_bytes(),
                        longname: p.into_bytes(),
                        attrs: Attrs::default(),
                    }],
                }),
                Err(e) => path_error(id, e, false),
            },
            Request::Stat { id, path } | Request::Lstat { id, path } => {
                self.stat(op, id, &path).await
            }
            Request::Fstat { id, handle } => self.fstat(id, &handle),
            Request::Opendir { id, path } => self.opendir(op, id, &path).await,
            Request::Readdir { id, handle } => self.readdir(op, id, &handle).await,
            Request::Open {
                id,
                path,
                pflags,
                attrs: _,
            } => self.open(op, id, &path, pflags).await,
            Request::Read {
                id,
                handle,
                offset,
                len,
            } => self.read(op, id, &handle, offset, len).await,
            Request::Write {
                id,
                handle,
                offset,
                data,
            } => self.write(op, id, &handle, offset, data).await,
            Request::Close { id, handle } => self.close(op, id, &handle).await,
            Request::Remove { id, path } => self.remove(op, id, &path).await,
            Request::Mkdir { id, path, attrs: _ } => self.mkdir(op, id, &path).await,
            Request::Rmdir { id, path } => self.rmdir(op, id, &path).await,
            Request::Rename { id, old, new } => self.rename(op, id, &old, &new, false).await,
            Request::PosixRename { id, old, new } => self.rename(op, id, &old, &new, true).await,
            Request::Setstat { id, attrs, .. } => {
                if attrs.is_empty() {
                    status(id, StatusCode::Ok, "")
                } else {
                    status(
                        id,
                        StatusCode::OpUnsupported,
                        "an object store cannot honour attribute changes",
                    )
                }
            }
            Request::Fsetstat { id, handle, attrs } => {
                if Self::handle_id(&handle).is_none_or(|h| !self.handles.contains_key(&h)) {
                    return status(id, StatusCode::Failure, "invalid handle");
                }
                if attrs.is_empty() {
                    status(id, StatusCode::Ok, "")
                } else {
                    status(
                        id,
                        StatusCode::OpUnsupported,
                        "an object store cannot honour attribute changes",
                    )
                }
            }
            Request::Symlink { id, .. } | Request::Readlink { id, .. } => {
                status(id, StatusCode::OpUnsupported, "no links in an object store")
            }
            Request::Limits { id } => {
                let l = self.shared.gw.limits();
                Next::Reply(Response::ExtendedReply {
                    id,
                    data: codec::limits_reply(
                        l.sftp.max_sftp_packet_len as u64,
                        u64::from(MAX_READ),
                        (l.sftp.max_sftp_packet_len - 1024) as u64,
                        l.sftp.max_write_handles as u64 + 64,
                    ),
                })
            }
            Request::Extended { id, .. } => {
                status(id, StatusCode::OpUnsupported, "unsupported extension")
            }
            Request::Unknown { id, .. } => status(
                id.unwrap_or(0),
                StatusCode::OpUnsupported,
                "unsupported request",
            ),
        }
    }

    // ── STAT ────────────────────────────────────────────────────────────────────

    async fn stat(&mut self, op: &str, id: u32, path: &[u8]) -> Next {
        let m = match self.map(path) {
            Ok(m) => m,
            Err(e) => return path_error(id, e, false),
        };
        if m.is_root {
            // Reveals only the account's own configuration: no decision.
            return Next::Reply(Response::Attrs {
                id,
                attrs: dir_attrs(),
            });
        }
        let Some(route) = self.route() else {
            return status(id, StatusCode::PermissionDenied, "tenant not routable");
        };
        let input = self.list_input(&route, op, &m.key);
        let decided = match self.authorize(op, vec![input], &[], vec![], id).await {
            Ok(d) => d,
            Err(n) => return n,
        };
        let ob = decided[0].decision.obligations.clone();
        let granted: Vec<String> = ob
            .narrow_prefix
            .iter()
            .cloned()
            .chain(ob.allowed_prefixes.iter().cloned())
            .collect();
        let audit = self.pending(
            decided[0].input.clone(),
            &decided[0].decision,
            self.block(op, vec![]),
        );
        if !granted.is_empty() {
            // The target is a directory iff some granted prefix lies under it. No backend
            // call: the key itself is outside every grant.
            let dir = format!("{}/", m.key);
            audit.settle(BackendOutcome::NotAttempted, None);
            return if granted.iter().any(|q| q.starts_with(&dir)) {
                Next::Reply(Response::Attrs {
                    id,
                    attrs: dir_attrs(),
                })
            } else {
                status(id, StatusCode::NoSuchFile, "no such file")
            };
        }
        let bucket = self.current.account.home.bucket.clone();
        let dir = m.dir_prefix();
        let Some(proof) = self.prove(
            &decided,
            vec![
                SftpLicense::on(Op::HeadObject, &bucket, &m.key),
                SftpLicense::on(Op::ListObjectsV2, &bucket, &dir),
            ],
        ) else {
            return status(id, StatusCode::Failure, "internal error: no proof");
        };
        let backend = self.backend(route);
        // A file `x` and a directory `x/` can coexist; STAT resolves to the file.
        match backend.head(&proof, &bucket, &m.key).await {
            Ok(Some(meta)) => {
                audit.settle(BackendOutcome::SucceededStatusUnknown, None);
                return Next::Reply(Response::Attrs {
                    id,
                    attrs: file_attrs(meta.size, meta.mtime),
                });
            }
            Ok(None) => {}
            Err(e) => {
                audit.settle(BackendOutcome::Failed, e.status());
                return status(id, StatusCode::Failure, format!("{e}"));
            }
        }
        match backend
            .list(&proof, &bucket, &dir, false, None, Some(1))
            .await
        {
            Ok(page) => {
                audit.settle(BackendOutcome::SucceededStatusUnknown, None);
                if page.objects.is_empty() && page.prefixes.is_empty() {
                    status(id, StatusCode::NoSuchFile, "no such file")
                } else {
                    Next::Reply(Response::Attrs {
                        id,
                        attrs: dir_attrs(),
                    })
                }
            }
            Err(e) => {
                audit.settle(BackendOutcome::Failed, e.status());
                status(id, StatusCode::Failure, format!("{e}"))
            }
        }
    }

    fn fstat(&self, id: u32, handle: &[u8]) -> Next {
        let h = Self::handle_id(handle).and_then(|h| self.handles.get(&h));
        match h {
            None => status(id, StatusCode::Failure, "invalid handle"),
            Some(Handle::Dir(_)) => Next::Reply(Response::Attrs {
                id,
                attrs: dir_attrs(),
            }),
            Some(Handle::Read(r)) => Next::Reply(Response::Attrs {
                id,
                attrs: file_attrs(r.dl.size, 0),
            }),
            Some(Handle::Write(w)) => Next::Reply(Response::Attrs {
                id,
                attrs: file_attrs(w.up.bytes(), 0),
            }),
        }
    }

    // ── OPENDIR / READDIR ───────────────────────────────────────────────────────

    async fn opendir(&mut self, op: &str, id: u32, path: &[u8]) -> Next {
        let m = match self.map(path) {
            Ok(m) => m,
            Err(e) => return path_error(id, e, false),
        };
        let Some(route) = self.route() else {
            return status(id, StatusCode::PermissionDenied, "tenant not routable");
        };
        let prefix = m.dir_prefix();
        let input = self.list_input(&route, op, &prefix);
        let decided = match self
            .authorize(op, vec![input.clone()], &[], vec![], id)
            .await
        {
            Ok(d) => d,
            Err(n) => return n,
        };
        let ob = &decided[0].decision.obligations;
        if ob.narrow_prefix.is_some() && !ob.allowed_prefixes.is_empty() {
            let d = Decision::deny("ambiguous list obligation (narrow + allowed prefixes)");
            self.emit_denied(input, &d, self.block(op, vec![]));
            return status(id, StatusCode::PermissionDenied, d.reason);
        }
        let mut granted: Vec<String> = ob
            .narrow_prefix
            .iter()
            .cloned()
            .chain(ob.allowed_prefixes.iter().cloned())
            .collect();
        granted.sort();
        granted.dedup();
        let max_fanout = self.shared.gw.limits().max_list_fanout;
        if granted.len() > max_fanout {
            let d = Decision::deny(format!(
                "list spans {} granted prefixes, exceeding the fan-out bound {max_fanout}",
                granted.len()
            ));
            self.emit_denied(input, &d, self.block(op, vec![]));
            return status(id, StatusCode::PermissionDenied, d.reason);
        }
        let bucket = self.current.account.home.bucket.clone();
        let mut licenses = vec![SftpLicense::on(Op::ListObjectsV2, &bucket, &prefix)];
        for q in &granted {
            licenses.push(SftpLicense::on(Op::ListObjectsV2, &bucket, q));
        }
        let Some(proof) = self.prove(&decided, licenses) else {
            return status(id, StatusCode::Failure, "internal error: no proof");
        };
        let audit = self.pending(
            decided[0].input.clone(),
            &decided[0].decision,
            self.block(op, vec![]),
        );
        let mut handle = DirHandle {
            prefix: prefix.clone(),
            inputs: vec![input],
            decided_rev: self.checked_rev.clone(),
            listing: Listing::Paged {
                continuation: None,
                done: false,
            },
            sent_dots: false,
            omitted: 0,
            audit,
            proof,
        };
        if !granted.is_empty() {
            match self.materialize(&route, &handle, &granted).await {
                Ok((entries, omitted)) => {
                    handle.listing = Listing::Materialized(entries);
                    handle.omitted = omitted;
                }
                Err(e) => {
                    handle.audit.settle(BackendOutcome::Failed, e.status());
                    return status(id, StatusCode::Failure, format!("{e}"));
                }
            }
        }
        let h = self.alloc_handle(Handle::Dir(handle));
        Next::Reply(Response::Handle { id, handle: h })
    }

    /// The D7 narrowing of a listing of directory prefix `P` onto granted prefixes `Q`.
    async fn materialize(
        &self,
        route: &RouteSnapshot,
        h: &DirHandle,
        granted: &[String],
    ) -> Result<(VecDeque<NameEntry>, u64), BackendError> {
        let backend = self.backend(route.clone());
        let home = &self.current.account.home;
        let p = &h.prefix;
        let mut names: std::collections::BTreeMap<String, Attrs> = Default::default();
        let mut omitted = 0u64;
        for q in granted {
            let Some(rest) = q.strip_prefix(p.as_str()) else {
                continue;
            };
            if let Some((first, _)) = rest.split_once('/') {
                // The first component is a directory entry with no backend call.
                if super::paths::listing_name_ok(first) {
                    names.entry(first.to_string()).or_insert_with(dir_attrs);
                } else {
                    omitted += 1;
                }
                continue;
            }
            let mut cont = None;
            loop {
                let page = backend
                    .list(&h.proof, &home.bucket, q, true, cont.take(), None)
                    .await?;
                for (key, meta) in &page.objects {
                    if key == p {
                        continue;
                    }
                    match home.child_name(p, key) {
                        Some(n) => {
                            names
                                .entry(n.to_string())
                                .or_insert_with(|| file_attrs(meta.size, meta.mtime));
                        }
                        None => omitted += 1,
                    }
                }
                for cp in &page.prefixes {
                    match home.child_name(p, cp) {
                        Some(n) => {
                            names.entry(n.to_string()).or_insert_with(dir_attrs);
                        }
                        None => omitted += 1,
                    }
                }
                if names.len() > MAX_MATERIALIZED_ENTRIES {
                    return Err(BackendError::Other {
                        status: None,
                        message: "listing too large to assemble across granted prefixes".into(),
                    });
                }
                match page.next {
                    Some(n) => cont = Some(n),
                    None => break,
                }
            }
        }
        Ok((
            names.into_iter().map(|(n, a)| entry(&n, a)).collect(),
            omitted,
        ))
    }

    async fn readdir(&mut self, op: &str, id: u32, handle: &[u8]) -> Next {
        let Some(hid) = Self::handle_id(handle) else {
            return status(id, StatusCode::Failure, "invalid handle");
        };
        let Some(Handle::Dir(mut h)) = self.handles.remove(&hid) else {
            return status(id, StatusCode::Failure, "invalid handle");
        };
        // Re-decided on a revision change.
        if h.decided_rev != self.checked_rev {
            match self.authorize(op, h.inputs.clone(), &[], vec![], id).await {
                Ok(_) => h.decided_rev = self.checked_rev.clone(),
                Err(n) => {
                    h.audit.settle(BackendOutcome::NotAttempted, None);
                    return n;
                }
            }
        }
        let mut out = Vec::new();
        if !h.sent_dots {
            out.push(entry(".", dir_attrs()));
            out.push(entry("..", dir_attrs()));
            h.sent_dots = true;
        }
        let route = self.route();
        let result = match &mut h.listing {
            Listing::Materialized(q) => {
                while out.len() < READDIR_BATCH {
                    match q.pop_front() {
                        Some(e) => out.push(e),
                        None => break,
                    }
                }
                Ok(())
            }
            Listing::Paged { continuation, done } => {
                let dots = out.len();
                let mut result = Ok(());
                // A page whose every entry is filtered out must not read as EOF: keep
                // paging until something is returned or the listing is exhausted.
                while !*done && out.len() == dots {
                    let step = match &route {
                        None => Err(BackendError::Other {
                            status: None,
                            message: "tenant not routable".into(),
                        }),
                        Some(route) => {
                            let home = self.current.account.home.clone();
                            let backend = self.backend(route.clone());
                            match backend
                                .list(
                                    &h.proof,
                                    &home.bucket,
                                    &h.prefix,
                                    true,
                                    continuation.take(),
                                    Some(READDIR_BATCH as i32),
                                )
                                .await
                            {
                                Ok(page) => {
                                    for (key, meta) in &page.objects {
                                        // The marker of the listed directory itself is not an entry.
                                        if key == &h.prefix {
                                            continue;
                                        }
                                        match home.child_name(&h.prefix, key) {
                                            Some(n) => out
                                                .push(entry(n, file_attrs(meta.size, meta.mtime))),
                                            None => h.omitted += 1,
                                        }
                                    }
                                    for cp in &page.prefixes {
                                        match home.child_name(&h.prefix, cp) {
                                            Some(n) => out.push(entry(n, dir_attrs())),
                                            None => h.omitted += 1,
                                        }
                                    }
                                    match page.next {
                                        Some(n) => *continuation = Some(n),
                                        None => *done = true,
                                    }
                                    Ok(())
                                }
                                Err(e) => Err(e),
                            }
                        }
                    };
                    if step.is_err() {
                        result = step;
                        break;
                    }
                }
                result
            }
        };
        if let Err(e) = result {
            let st = e.status();
            self.handles.insert(hid, Handle::Dir(h));
            if let Some(Handle::Dir(h)) = self.handles.get(&hid) {
                h.audit.settle(BackendOutcome::Failed, st);
            }
            return status(id, StatusCode::Failure, format!("{e}"));
        }
        self.handles.insert(hid, Handle::Dir(h));
        if out.is_empty() {
            return status(id, StatusCode::Eof, "");
        }
        Next::Reply(Response::Name { id, entries: out })
    }

    // ── OPEN ────────────────────────────────────────────────────────────────────

    async fn open(&mut self, op: &str, id: u32, path: &[u8], pflags: u32) -> Next {
        let read = pflags & SSH_FXF_READ != 0;
        let write = pflags & SSH_FXF_WRITE != 0;
        let creat = pflags & SSH_FXF_CREAT != 0;
        let trunc = pflags & SSH_FXF_TRUNC != 0;
        let excl = pflags & SSH_FXF_EXCL != 0;
        if pflags & SSH_FXF_APPEND != 0 || (read && write) {
            return status(
                id,
                StatusCode::OpUnsupported,
                "append, resume and read-write opens are not supported",
            );
        }
        if read && !write {
            if creat || trunc || excl {
                return status(id, StatusCode::OpUnsupported, "unsupported open flags");
            }
            return self.open_read(op, id, path, pflags).await;
        }
        if !write {
            return status(id, StatusCode::OpUnsupported, "unsupported open flags");
        }
        if !creat && !trunc {
            return status(
                id,
                StatusCode::OpUnsupported,
                "in-place modification is not supported",
            );
        }
        self.open_write(op, id, path, pflags).await
    }

    async fn open_read(&mut self, op: &str, id: u32, path: &[u8], pflags: u32) -> Next {
        let m = match self.map(path) {
            Ok(m) => m,
            Err(e) => return path_error(id, e, false),
        };
        if m.is_root {
            return status(id, StatusCode::Failure, "is a directory");
        }
        let Some(route) = self.route() else {
            return status(id, StatusCode::PermissionDenied, "tenant not routable");
        };
        let flags = flag_names(pflags);
        let input = self.object_input(&route, op, Action::ReadObjects, &m.key);
        let decided = match self
            .authorize(op, vec![input.clone()], &[], flags.clone(), id)
            .await
        {
            Ok(d) => d,
            Err(n) => return n,
        };
        let bucket = self.current.account.home.bucket.clone();
        let Some(proof) = self.prove(
            &decided,
            vec![SftpLicense::on(Op::GetObject, &bucket, &m.key)],
        ) else {
            return status(id, StatusCode::Failure, "internal error: no proof");
        };
        let audit = self.pending(input.clone(), &decided[0].decision, self.block(op, flags));
        match Download::open(self.backend(route), proof, bucket, m.key.clone()).await {
            Ok(Some(dl)) => {
                let h = self.alloc_handle(Handle::Read(ReadHandle {
                    dl,
                    inputs: vec![input],
                    decided_rev: self.checked_rev.clone(),
                    audit,
                }));
                Next::Reply(Response::Handle { id, handle: h })
            }
            Ok(None) => {
                audit.settle(BackendOutcome::Failed, Some(404));
                status(id, StatusCode::NoSuchFile, "no such file")
            }
            Err(e) => {
                audit.settle(BackendOutcome::Failed, e.status());
                status(id, StatusCode::Failure, format!("{e}"))
            }
        }
    }

    /// The D8 table.
    async fn open_write(&mut self, op: &str, id: u32, path: &[u8], pflags: u32) -> Next {
        let creat = pflags & SSH_FXF_CREAT != 0;
        let trunc = pflags & SSH_FXF_TRUNC != 0;
        let excl = pflags & SSH_FXF_EXCL != 0;
        let flags = flag_names(pflags);
        let m = match self.map(path) {
            Ok(m) => m,
            Err(e) => return path_error(id, e, creat),
        };
        if m.is_root || m.key.ends_with('/') {
            return status(id, StatusCode::Failure, "is a directory");
        }
        let limits = self.shared.gw.limits().sftp.clone();
        if self.write_handles() >= limits.max_write_handles {
            return status(id, StatusCode::Failure, "too many open write handles");
        }
        let Some(route) = self.route() else {
            return status(id, StatusCode::PermissionDenied, "tenant not routable");
        };
        let bucket = self.current.account.home.bucket.clone();
        let key = m.key.clone();
        let licenses = |b: &str, k: &str| {
            vec![
                SftpLicense::on(Op::HeadObject, b, k),
                SftpLicense::on(Op::PutObject, b, k),
                SftpLicense::on(Op::CreateMultipartUpload, b, k),
                SftpLicense::on(Op::UploadPart, b, k),
                SftpLicense::on(Op::CompleteMultipartUpload, b, k),
                SftpLicense::on(Op::AbortMultipartUpload, b, k),
            ]
        };
        // The first question: create (WRITE|CREAT…) or overwrite (WRITE|TRUNC without CREAT).
        let first_action = if creat {
            Action::CreateObjects
        } else {
            Action::WriteObjects
        };
        let first = self.object_input(&route, op, first_action, &key);
        let decided = match self
            .authorize(op, vec![first.clone()], &[], flags.clone(), id)
            .await
        {
            Ok(d) => d,
            Err(n) => return n,
        };
        // A HEAD under the write decision returns no content; only existence matters.
        let Some(head_proof) = self.prove(
            &decided,
            vec![SftpLicense::on(Op::HeadObject, &bucket, &key)],
        ) else {
            return status(id, StatusCode::Failure, "internal error: no proof");
        };
        let backend = self.backend(route.clone());
        let exists = match backend.head(&head_proof, &bucket, &key).await {
            Ok(m) => m.is_some(),
            Err(e) => {
                let rec = self.pending(first, &decided[0].decision, self.block(op, flags));
                rec.settle(BackendOutcome::Failed, e.status());
                return status(id, StatusCode::Failure, format!("{e}"));
            }
        };
        let (record_input, record_decision, create_only) = match (creat, trunc, excl, exists) {
            (false, _, _, false) => {
                let rec = self.pending(first, &decided[0].decision, self.block(op, flags));
                rec.settle(BackendOutcome::SucceededStatusUnknown, None);
                return status(id, StatusCode::NoSuchFile, "no such file");
            }
            (true, _, _, false) => (first, decided[0].decision.clone(), true),
            (true, _, true, true) => {
                let rec = self.pending(first, &decided[0].decision, self.block(op, flags));
                rec.settle_with(BackendOutcome::SucceededStatusUnknown, None, |r| {
                    if let Some(s) = r.gateway.session.as_mut() {
                        s.transfer = Some(TransferBlock {
                            bytes: 0,
                            parts: 0,
                            commit: Commit::Rejected.as_str().into(),
                            reason: Some("file exists".into()),
                        });
                    }
                });
                return status(id, StatusCode::Failure, "file exists");
            }
            (true, false, false, true) => {
                let rec = self.pending(first, &decided[0].decision, self.block(op, flags));
                rec.settle(BackendOutcome::SucceededStatusUnknown, None);
                return status(
                    id,
                    StatusCode::OpUnsupported,
                    "in-place modification is not supported",
                );
            }
            (true, true, false, true) => {
                // Exists: overwriting needs write_objects. Refused before any byte.
                let w = self.object_input(&route, op, Action::WriteObjects, &key);
                let mut d = self.enforcer().decide(op, &w).await;
                if d.allow
                    && let Some(r) = Enforcer::unimplemented_obligations(&d)
                {
                    d = Decision::deny(r);
                }
                if !d.allow {
                    let reason = format!("file exists and overwrite is not granted ({})", d.reason);
                    self.emit_denied(w, &Decision::deny(reason.clone()), self.block(op, flags));
                    return status(id, StatusCode::PermissionDenied, reason);
                }
                (w, d, false)
            }
            (false, _, _, true) => (first, decided[0].decision.clone(), false),
        };
        // The proof for the whole transfer, from the decision that licenses it.
        let Some(proof) = self
            .enforcer()
            .prove_sftp(&[&record_decision], licenses(&bucket, &key))
        else {
            return status(id, StatusCode::Failure, "internal error: no proof");
        };
        let mode = self.mode_for(&route);
        let inflight = if create_only {
            match self
                .shared
                .inflight
                .claim(&route.backend_id.0, &bucket, &key)
            {
                Some(g) => Some(g),
                None => {
                    let rec = self.pending(record_input, &record_decision, self.block(op, flags));
                    rec.settle(BackendOutcome::NotAttempted, None);
                    return status(id, StatusCode::Failure, "upload in progress");
                }
            }
        } else {
            None
        };
        let Some(memory) = self
            .shared
            .memory
            .reserve(
                limits.transfer_reservation(),
                std::time::Duration::from_secs(10),
            )
            .await
        else {
            let rec = self.pending(record_input, &record_decision, self.block(op, flags));
            rec.settle(BackendOutcome::NotAttempted, None);
            return status(id, StatusCode::Failure, "server busy");
        };
        let audit = self.pending(
            record_input.clone(),
            &record_decision,
            self.block(op, flags.clone()),
        );
        let up = Upload::new(
            backend,
            proof,
            bucket,
            key,
            create_only,
            mode,
            UploadLimits {
                part_size: limits.part_size,
                max_inflight_parts: limits.max_inflight_parts,
                reorder_window: limits.reorder_window,
                max_file_size: limits.max_file_size,
            },
            memory,
            inflight,
        );
        self.shared
            .metrics
            .transfers_started
            .fetch_add(1, Ordering::Relaxed);
        let h = self.alloc_handle(Handle::Write(Box::new(WriteHandle {
            up,
            inputs: vec![record_input],
            decided_rev: self.checked_rev.clone(),
            audit,
            flags,
        })));
        Next::Reply(Response::Handle { id, handle: h })
    }

    // ── READ / WRITE / CLOSE ────────────────────────────────────────────────────

    async fn read(&mut self, op: &str, id: u32, handle: &[u8], offset: u64, len: u32) -> Next {
        let Some(hid) = Self::handle_id(handle) else {
            return status(id, StatusCode::Failure, "invalid handle");
        };
        let Some(Handle::Read(mut h)) = self.handles.remove(&hid) else {
            return status(id, StatusCode::Failure, "invalid handle");
        };
        if h.decided_rev != self.checked_rev {
            match self.authorize(op, h.inputs.clone(), &[], vec![], id).await {
                Ok(_) => h.decided_rev = self.checked_rev.clone(),
                Err(n) => {
                    let bytes = h.dl.bytes_sent;
                    h.audit
                        .settle_with(BackendOutcome::SucceededStatusUnknown, None, |r| {
                            if let Some(s) = r.gateway.session.as_mut() {
                                s.transfer = Some(TransferBlock {
                                    bytes,
                                    parts: 0,
                                    commit: "denied".into(),
                                    reason: Some(format!(
                                        "denied mid-transfer at byte offset {offset}"
                                    )),
                                });
                            }
                        });
                    return n;
                }
            }
        }
        let r = h.dl.read(offset, len.min(MAX_READ)).await;
        let next = match r {
            Ok(Some(data)) => {
                self.counters
                    .bytes_out
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                Next::Reply(Response::Data { id, data })
            }
            Ok(None) => status(id, StatusCode::Eof, ""),
            Err(e) => status(id, StatusCode::Failure, format!("{e}")),
        };
        self.handles.insert(hid, Handle::Read(h));
        next
    }

    async fn write(&mut self, op: &str, id: u32, handle: &[u8], offset: u64, data: Bytes) -> Next {
        let Some(hid) = Self::handle_id(handle) else {
            return status(id, StatusCode::Failure, "invalid handle");
        };
        let Some(Handle::Write(mut h)) = self.handles.remove(&hid) else {
            return status(id, StatusCode::Failure, "invalid handle");
        };
        let len = data.len() as u64;
        if h.decided_rev != self.checked_rev {
            match self
                .authorize(op, h.inputs.clone(), &[], h.flags.clone(), id)
                .await
            {
                Ok(_) => h.decided_rev = self.checked_rev.clone(),
                Err(n) => {
                    h.up.abort().await;
                    Self::settle_transfer(
                        &h,
                        Commit::Denied,
                        Some(format!("denied mid-transfer at byte offset {offset}")),
                    );
                    self.shared
                        .metrics
                        .transfers_aborted
                        .fetch_add(1, Ordering::Relaxed);
                    return n;
                }
            }
        }
        match h.up.write(offset, data).await {
            Ok(()) => {
                self.counters.bytes_in.fetch_add(len, Ordering::Relaxed);
                self.handles.insert(hid, Handle::Write(h));
                status(id, StatusCode::Ok, "")
            }
            Err(WriteError::Unsupported(why)) => {
                // Refused, but the transfer stays open: the client may still CLOSE and
                // be told about the gap there.
                self.handles.insert(hid, Handle::Write(h));
                status(id, StatusCode::OpUnsupported, why)
            }
            Err(WriteError::Failure(why)) => {
                h.up.abort().await;
                Self::settle_transfer(&h, Commit::Aborted, Some(why.clone()));
                self.shared
                    .metrics
                    .transfers_aborted
                    .fetch_add(1, Ordering::Relaxed);
                status(id, StatusCode::Failure, why)
            }
        }
    }

    fn settle_transfer(h: &WriteHandle, commit: Commit, reason: Option<String>) {
        let (bytes, parts) = (h.up.bytes(), h.up.parts());
        let outcome = match commit {
            Commit::Committed => BackendOutcome::SucceededStatusUnknown,
            Commit::Denied => BackendOutcome::NotAttempted,
            _ => BackendOutcome::Failed,
        };
        h.audit.settle_with(outcome, None, |r| {
            if commit == Commit::Denied {
                r.result = Decision::deny(reason.clone().unwrap_or_default());
                r.gateway.outcome = Outcome::Denied;
            }
            if let Some(s) = r.gateway.session.as_mut() {
                s.transfer = Some(TransferBlock {
                    bytes,
                    parts,
                    commit: commit.as_str().into(),
                    reason,
                });
            }
        });
    }

    async fn close(&mut self, op: &str, id: u32, handle: &[u8]) -> Next {
        let Some(hid) = Self::handle_id(handle) else {
            return status(id, StatusCode::Failure, "invalid handle");
        };
        let Some(h) = self.handles.remove(&hid) else {
            return status(id, StatusCode::Failure, "invalid handle");
        };
        match h {
            Handle::Dir(d) => {
                let omitted = d.omitted;
                d.audit
                    .settle_with(BackendOutcome::SucceededStatusUnknown, None, |r| {
                        if let Some(s) = r.gateway.session.as_mut() {
                            s.omitted_entries = Some(omitted);
                        }
                    });
                status(id, StatusCode::Ok, "")
            }
            Handle::Read(r) => {
                let bytes = r.dl.bytes_sent;
                r.audit
                    .settle_with(BackendOutcome::SucceededStatusUnknown, None, |rec| {
                        if let Some(s) = rec.gateway.session.as_mut() {
                            s.transfer = Some(TransferBlock {
                                bytes,
                                parts: 0,
                                commit: "read".into(),
                                reason: None,
                            });
                        }
                    });
                status(id, StatusCode::Ok, "")
            }
            Handle::Write(mut w) => {
                // Final re-authorization against the current bundle (D14 step 4).
                match self
                    .authorize(op, w.inputs.clone(), &[], w.flags.clone(), id)
                    .await
                {
                    Ok(_) => {}
                    Err(n) => {
                        w.up.abort().await;
                        Self::settle_transfer(&w, Commit::Denied, Some("denied at close".into()));
                        self.shared
                            .metrics
                            .transfers_aborted
                            .fetch_add(1, Ordering::Relaxed);
                        return n;
                    }
                }
                match w.up.commit(self.shared.commit_gate.as_ref()).await {
                    Ok(()) => {
                        Self::settle_transfer(&w, Commit::Committed, None);
                        self.shared
                            .metrics
                            .transfers_committed
                            .fetch_add(1, Ordering::Relaxed);
                        status(id, StatusCode::Ok, "")
                    }
                    Err((commit, e)) => {
                        let why = match e {
                            WriteError::Failure(w) => w,
                            WriteError::Unsupported(w) => w.to_string(),
                        };
                        Self::settle_transfer(&w, commit, Some(why.clone()));
                        self.shared
                            .metrics
                            .transfers_aborted
                            .fetch_add(1, Ordering::Relaxed);
                        status(id, StatusCode::Failure, why)
                    }
                }
            }
        }
    }

    /// Abort every open transfer: disconnect without CLOSE, idle timeout, revocation,
    /// shutdown. Never commits.
    pub async fn abort_all(&mut self, reason: &str) {
        let ids: Vec<u32> = self.handles.keys().copied().collect();
        for hid in ids {
            if let Some(h) = self.handles.remove(&hid) {
                match h {
                    Handle::Write(mut w) => {
                        w.up.abort().await;
                        Self::settle_transfer(&w, Commit::Aborted, Some(reason.to_string()));
                        self.shared
                            .metrics
                            .transfers_aborted
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Handle::Read(r) => r.audit.settle(BackendOutcome::SucceededStatusUnknown, None),
                    Handle::Dir(d) => d.audit.settle(BackendOutcome::SucceededStatusUnknown, None),
                }
            }
        }
    }

    /// Abort write transfers idle for longer than `idle`.
    pub async fn sweep_idle_transfers(&mut self, idle: std::time::Duration) {
        let stale: Vec<u32> = self
            .handles
            .iter()
            .filter_map(|(k, h)| match h {
                Handle::Write(w) if w.up.last_write.elapsed() > idle => Some(*k),
                _ => None,
            })
            .collect();
        for hid in stale {
            if let Some(Handle::Write(mut w)) = self.handles.remove(&hid) {
                w.up.abort().await;
                Self::settle_transfer(&w, Commit::Aborted, Some("transfer idle timeout".into()));
                self.shared
                    .metrics
                    .transfers_aborted
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    // ── REMOVE / MKDIR / RMDIR / RENAME ─────────────────────────────────────────

    async fn remove(&mut self, op: &str, id: u32, path: &[u8]) -> Next {
        let m = match self.map(path) {
            Ok(m) => m,
            Err(e) => return path_error(id, e, false),
        };
        if m.is_root {
            return status(id, StatusCode::Failure, "is a directory");
        }
        let Some(route) = self.route() else {
            return status(id, StatusCode::PermissionDenied, "tenant not routable");
        };
        let input = self.object_input(&route, op, Action::DeleteObjects, &m.key);
        let decided = match self
            .authorize(op, vec![input.clone()], &[], vec![], id)
            .await
        {
            Ok(d) => d,
            Err(n) => return n,
        };
        let bucket = self.current.account.home.bucket.clone();
        let Some(proof) = self.prove(
            &decided,
            vec![
                SftpLicense::on(Op::HeadObject, &bucket, &m.key),
                SftpLicense::on(Op::DeleteObject, &bucket, &m.key),
            ],
        ) else {
            return status(id, StatusCode::Failure, "internal error: no proof");
        };
        let audit = self.pending(input, &decided[0].decision, self.block(op, vec![]));
        let backend = self.backend(route);
        match backend.head(&proof, &bucket, &m.key).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                audit.settle(BackendOutcome::Failed, Some(404));
                return status(id, StatusCode::NoSuchFile, "no such file");
            }
            Err(e) => {
                audit.settle(BackendOutcome::Failed, e.status());
                return status(id, StatusCode::Failure, format!("{e}"));
            }
        }
        match backend.delete(&proof, &bucket, &m.key).await {
            Ok(()) => {
                audit.settle(BackendOutcome::SucceededStatusUnknown, None);
                status(id, StatusCode::Ok, "")
            }
            Err(e) => {
                audit.settle(BackendOutcome::Failed, e.status());
                status(id, StatusCode::Failure, format!("{e}"))
            }
        }
    }

    async fn mkdir(&mut self, op: &str, id: u32, path: &[u8]) -> Next {
        let m = match self.map(path) {
            Ok(m) => m,
            Err(e) => return path_error(id, e, true),
        };
        if m.is_root {
            return status(id, StatusCode::Failure, "file exists");
        }
        let Some(route) = self.route() else {
            return status(id, StatusCode::PermissionDenied, "tenant not routable");
        };
        let marker = m.dir_prefix();
        let input = self.object_input(&route, op, Action::CreateObjects, &marker);
        let decided = match self
            .authorize(op, vec![input.clone()], &[], vec![], id)
            .await
        {
            Ok(d) => d,
            Err(n) => return n,
        };
        let bucket = self.current.account.home.bucket.clone();
        let Some(proof) = self.prove(
            &decided,
            vec![
                SftpLicense::on(Op::HeadObject, &bucket, &marker),
                SftpLicense::on(Op::PutObject, &bucket, &marker),
            ],
        ) else {
            return status(id, StatusCode::Failure, "internal error: no proof");
        };
        let audit = self.pending(input, &decided[0].decision, self.block(op, vec![]));
        let backend = self.backend(route.clone());
        let native = self.mode_for(&route) == ConditionalCreate::Native;
        if !native {
            match backend.head(&proof, &bucket, &marker).await {
                Ok(None) => {}
                Ok(Some(_)) => {
                    audit.settle(BackendOutcome::SucceededStatusUnknown, None);
                    return status(id, StatusCode::Failure, "file exists");
                }
                Err(e) => {
                    audit.settle(BackendOutcome::Failed, e.status());
                    return status(id, StatusCode::Failure, format!("{e}"));
                }
            }
        }
        match backend
            .put(&proof, &bucket, &marker, Bytes::new(), native)
            .await
        {
            Ok(()) => {
                audit.settle(BackendOutcome::SucceededStatusUnknown, None);
                status(id, StatusCode::Ok, "")
            }
            Err(BackendError::PreconditionFailed) => {
                audit.settle(BackendOutcome::Failed, Some(412));
                status(id, StatusCode::Failure, "file exists")
            }
            Err(e) => {
                audit.settle(BackendOutcome::Failed, e.status());
                status(id, StatusCode::Failure, format!("{e}"))
            }
        }
    }

    async fn rmdir(&mut self, op: &str, id: u32, path: &[u8]) -> Next {
        let m = match self.map(path) {
            Ok(m) => m,
            Err(e) => return path_error(id, e, false),
        };
        if m.is_root {
            return status(id, StatusCode::Failure, "cannot remove the home directory");
        }
        let Some(route) = self.route() else {
            return status(id, StatusCode::PermissionDenied, "tenant not routable");
        };
        let marker = m.dir_prefix();
        // Emptiness is a fact about the prefix, and every bit returned must be authorized.
        let del = self.object_input(&route, op, Action::DeleteObjects, &marker);
        let list = self.list_input(&route, op, &marker);
        let decided = match self
            .authorize(
                op,
                vec![del.clone(), list],
                &["rmdir marker delete", "rmdir emptiness list"],
                vec![],
                id,
            )
            .await
        {
            Ok(d) => d,
            Err(n) => return n,
        };
        if decided[1].decision.obligations.narrow_prefix.is_some()
            || !decided[1].decision.obligations.allowed_prefixes.is_empty()
        {
            let d = Decision::deny("rmdir needs list_objects on the whole directory");
            self.emit_denied(del, &d, self.block(op, vec![]));
            return status(id, StatusCode::PermissionDenied, d.reason);
        }
        let bucket = self.current.account.home.bucket.clone();
        let Some(proof) = self.prove(
            &decided,
            vec![
                SftpLicense::on(Op::ListObjectsV2, &bucket, &marker),
                SftpLicense::on(Op::DeleteObject, &bucket, &marker),
            ],
        ) else {
            return status(id, StatusCode::Failure, "internal error: no proof");
        };
        let audit = self.pending(del, &decided[0].decision, self.block(op, vec![]));
        let backend = self.backend(route);
        let page = match backend
            .list(&proof, &bucket, &marker, false, None, Some(2))
            .await
        {
            Ok(p) => p,
            Err(e) => {
                audit.settle(BackendOutcome::Failed, e.status());
                return status(id, StatusCode::Failure, format!("{e}"));
            }
        };
        let has_marker = page.objects.iter().any(|(k, _)| k == &marker);
        let others = page.objects.iter().any(|(k, _)| k != &marker) || !page.prefixes.is_empty();
        if others {
            audit.settle(BackendOutcome::SucceededStatusUnknown, None);
            return status(id, StatusCode::Failure, "directory not empty");
        }
        if !has_marker {
            audit.settle(BackendOutcome::SucceededStatusUnknown, None);
            return status(id, StatusCode::NoSuchFile, "no such directory");
        }
        match backend.delete(&proof, &bucket, &marker).await {
            Ok(()) => {
                audit.settle(BackendOutcome::SucceededStatusUnknown, None);
                status(id, StatusCode::Ok, "")
            }
            Err(e) => {
                audit.settle(BackendOutcome::Failed, e.status());
                status(id, StatusCode::Failure, format!("{e}"))
            }
        }
    }

    /// RENAME (create-only target) and `posix-rename@openssh.com` (overwrite target): a
    /// server-side copy then a delete. Not atomic; if the delete fails both keys remain
    /// and the status says so.
    async fn rename(&mut self, op: &str, id: u32, old: &[u8], new: &[u8], overwrite: bool) -> Next {
        let a = match self.map(old) {
            Ok(m) => m,
            Err(e) => return path_error(id, e, false),
        };
        let b = match self.map(new) {
            Ok(m) => m,
            Err(e) => return path_error(id, e, true),
        };
        if a.is_root || b.is_root {
            return status(id, StatusCode::Failure, "cannot rename the home directory");
        }
        if a.key == b.key {
            return status(id, StatusCode::Ok, "");
        }
        let Some(route) = self.route() else {
            return status(id, StatusCode::PermissionDenied, "tenant not routable");
        };
        let bucket = self.current.account.home.bucket.clone();
        let read = self.object_input(&route, op, Action::ReadObjects, &a.key);
        let mut write = self.object_input(
            &route,
            op,
            if overwrite {
                Action::WriteObjects
            } else {
                Action::CreateObjects
            },
            &b.key,
        );
        write.copy_source = Some(CopySource {
            bucket: bucket.clone(),
            key: a.key.clone(),
        });
        let del = self.object_input(&route, op, Action::DeleteObjects, &a.key);
        // The record carries the destination, with the source as `copy_source`, exactly
        // as `CopyObject` does. Order matters for that: write first.
        let decided = match self
            .authorize(
                op,
                vec![write.clone(), read, del],
                &[
                    "rename target write",
                    "rename source read",
                    "rename source delete",
                ],
                vec![],
                id,
            )
            .await
        {
            Ok(d) => d,
            Err(n) => return n,
        };
        let proof = self.prove(
            &decided,
            vec![
                SftpLicense::on(Op::HeadObject, &bucket, &a.key),
                SftpLicense::on(Op::HeadObject, &bucket, &b.key),
                SftpLicense::copy(Op::CopyObject, &bucket, &b.key, &bucket, &a.key),
                SftpLicense::on(Op::CreateMultipartUpload, &bucket, &b.key),
                SftpLicense::copy(Op::UploadPartCopy, &bucket, &b.key, &bucket, &a.key),
                SftpLicense::on(Op::CompleteMultipartUpload, &bucket, &b.key),
                SftpLicense::on(Op::AbortMultipartUpload, &bucket, &b.key),
                SftpLicense::on(Op::PutObject, &bucket, &b.key),
                SftpLicense::on(Op::DeleteObject, &bucket, &a.key),
            ],
        );
        let Some(proof) = proof else {
            return status(id, StatusCode::Failure, "internal error: no proof");
        };
        let audit = self.pending(
            write,
            &Decision::allow("rename allowed (source read + target write + source delete)"),
            self.block(op, vec![]),
        );
        let backend = self.backend(route.clone());
        let size = match backend.head(&proof, &bucket, &a.key).await {
            Ok(Some(m)) => m.size,
            Ok(None) => {
                audit.settle(BackendOutcome::Failed, Some(404));
                // Directories are prefixes; renaming one is not supported in v1.
                return status(
                    id,
                    StatusCode::NoSuchFile,
                    "no such file (directory renames are not supported)",
                );
            }
            Err(e) => {
                audit.settle(BackendOutcome::Failed, e.status());
                return status(id, StatusCode::Failure, format!("{e}"));
            }
        };
        let native = self.mode_for(&route) == ConditionalCreate::Native;
        let conditional = !overwrite && native;
        if !overwrite {
            // Early, byte-free refusal; `native` closes the race at the commit.
            match backend.head(&proof, &bucket, &b.key).await {
                Ok(None) => {}
                Ok(Some(_)) => {
                    audit.settle(BackendOutcome::SucceededStatusUnknown, None);
                    return status(id, StatusCode::Failure, "file exists");
                }
                Err(e) => {
                    audit.settle(BackendOutcome::Failed, e.status());
                    return status(id, StatusCode::Failure, format!("{e}"));
                }
            }
        }
        let copied = if overwrite && size <= 5 * 1024 * 1024 * 1024 {
            backend.copy(&proof, &bucket, &b.key, &a.key).await
        } else if size == 0 {
            backend
                .put(&proof, &bucket, &b.key, Bytes::new(), conditional)
                .await
        } else {
            self.multipart_copy(&backend, &proof, &bucket, &a.key, &b.key, size, conditional)
                .await
        };
        match copied {
            Ok(()) => {}
            Err(BackendError::PreconditionFailed) => {
                audit.settle(BackendOutcome::Failed, Some(412));
                return status(id, StatusCode::Failure, "file exists");
            }
            Err(e) => {
                audit.settle(BackendOutcome::Failed, e.status());
                return status(id, StatusCode::Failure, format!("{e}"));
            }
        }
        match backend.delete(&proof, &bucket, &a.key).await {
            Ok(()) => {
                audit.settle(BackendOutcome::SucceededStatusUnknown, None);
                status(id, StatusCode::Ok, "")
            }
            Err(e) => {
                audit.settle_with(BackendOutcome::Failed, e.status(), |r| {
                    r.result.reason = format!(
                        "{}; the copy succeeded but deleting the source failed: both keys now exist",
                        r.result.reason
                    );
                });
                status(
                    id,
                    StatusCode::Failure,
                    "copied to the new name, but removing the old name failed: both names now exist",
                )
            }
        }
    }

    /// `CreateMultipartUpload` + `UploadPartCopy`×n + (conditional)
    /// `CompleteMultipartUpload`, because `CopyObject` has no destination condition in
    /// s3s 0.14.1 (E4). Aborted on any error.
    #[allow(clippy::too_many_arguments)]
    async fn multipart_copy(
        &self,
        backend: &SftpBackend,
        proof: &SftpProof,
        bucket: &str,
        src: &str,
        dst: &str,
        size: u64,
        conditional: bool,
    ) -> Result<(), BackendError> {
        let upload = backend.create_multipart(proof, bucket, dst).await?;
        let mut parts = Vec::new();
        let mut start = 0u64;
        let mut n = 1i32;
        let result = async {
            while start < size {
                let end = (start + COPY_PART).min(size) - 1;
                let etag = backend
                    .upload_part_copy(proof, bucket, dst, &upload, n, bucket, src, (start, end))
                    .await?;
                parts.push((n, etag));
                start = end + 1;
                n += 1;
            }
            backend
                .complete_multipart(proof, bucket, dst, &upload, parts, conditional)
                .await
        }
        .await;
        if result.is_err() {
            let _ = backend.abort_multipart(proof, bucket, dst, &upload).await;
        }
        result
    }
}
