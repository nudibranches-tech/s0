//! The SFTP front: a second protocol on the gateway core (ADR-009).
//!
//! The client holds an SSH key and nothing else — no S3 power at all. The stat an upload
//! needs is issued **by s0**, with the tenant backend credential, after an authorization
//! decision for the SFTP operation; s0 sees the open flags and enforces create-only in
//! policy (`create_objects`); and there is one audit trail and one policy for both
//! protocols.
//!
//! - [`transport`] — russh, the algorithm floor, every `Handler` method overridden.
//! - [`preauth`]   — PROXY v2 and the strict-KEX requirement, before russh sees a byte.
//! - [`account`]   — bundle-driven authentication (`data.sftp`).
//! - [`codec`]     — the SFTP v3 wire format, pure and fuzzable.
//! - [`paths`]     — the virtual root.
//! - [`session`]   — request dispatch and authorization.
//! - [`transfer`]  — the upload and download state machines.
//! - [`backend`]   — proof-checked backend calls.
//! - [`limits`]    — caps, bans, rate limits, the memory budget.

pub mod account;
pub mod backend;
pub mod codec;
pub mod limits;
pub mod paths;
pub mod preauth;
pub mod session;
pub mod transfer;
pub mod transport;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub use account::{AuthInfo, CertInfo};

use crate::access::Enforcer;
use crate::audit::{AuditRecord, SessionEvent, SessionEventKind};
use crate::authz::Decision;
use crate::config::SftpConfig;
use crate::error::{GatewayError, Result};
use crate::gateway::Gateway;
use account::{Authenticated, Credential, DirectoryCache};
use limits::{
    BanPolicy, BanTable, Cidr, ConnectionTracker, MemoryBudget, PreauthRate, SubjectGuard,
    SubjectSessions,
};
use preauth::{KillSwitch, ProxyHeader, StrictKexGuard};
use session::{Next, SessionIdentity, SftpSession};
use transfer::{AlwaysCommit, CommitGate, InflightKeys};

/// Counters the admin listener publishes.
#[derive(Default)]
pub struct SftpMetrics {
    pub connections_accepted: AtomicU64,
    pub connections_active: AtomicU64,
    pub preauth_rejected: AtomicU64,
    pub auth_failed: AtomicU64,
    pub auth_credential_mismatch: AtomicU64,
    pub auth_succeeded: AtomicU64,
    pub banned: AtomicU64,
    pub transfers_started: AtomicU64,
    pub transfers_committed: AtomicU64,
    pub transfers_aborted: AtomicU64,
}

impl SftpMetrics {
    /// `(name, type, help, value)` for `/metrics`.
    pub fn series(&self) -> Vec<(&'static str, &'static str, &'static str, u64)> {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        vec![
            (
                "s0_sftp_connections_accepted_total",
                "counter",
                "TCP connections accepted by the SFTP listener.",
                g(&self.connections_accepted),
            ),
            (
                "s0_sftp_connections_active",
                "gauge",
                "Open SFTP connections.",
                g(&self.connections_active),
            ),
            (
                "s0_sftp_preauth_rejected_total",
                "counter",
                "Connections refused before authentication (caps, rate, ban, CIDR denylist, PROXY header, non-strict KEX).",
                g(&self.preauth_rejected),
            ),
            (
                "s0_sftp_auth_failed_total",
                "counter",
                "Failed SFTP authentications.",
                g(&self.auth_failed),
            ),
            (
                "s0_sftp_auth_credential_mismatch_total",
                "counter",
                "Failed SFTP authentications where the credential did not match (the subset of s0_sftp_auth_failed_total that can count toward a ban).",
                g(&self.auth_credential_mismatch),
            ),
            (
                "s0_sftp_auth_succeeded_total",
                "counter",
                "Successful SFTP authentications.",
                g(&self.auth_succeeded),
            ),
            (
                "s0_sftp_banned_total",
                "counter",
                "Addresses banned for repeated authentication failures (per replica).",
                g(&self.banned),
            ),
            (
                "s0_sftp_transfers_started_total",
                "counter",
                "Upload transfers opened.",
                g(&self.transfers_started),
            ),
            (
                "s0_sftp_transfers_committed_total",
                "counter",
                "Upload transfers committed.",
                g(&self.transfers_committed),
            ),
            (
                "s0_sftp_transfers_aborted_total",
                "counter",
                "Upload transfers aborted or rejected (never committed).",
                g(&self.transfers_aborted),
            ),
        ]
    }
}

/// Per-session counters for the disconnect record.
#[derive(Default)]
pub struct SessionCounters {
    pub operations: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub denied: AtomicU64,
}

/// State shared by every connection of the front.
pub struct Shared {
    pub gw: Arc<Gateway>,
    pub enforcer: Enforcer,
    pub directory: DirectoryCache,
    pub inflight: Arc<InflightKeys>,
    pub memory: MemoryBudget,
    pub connections: Arc<ConnectionTracker>,
    pub subjects: Arc<SubjectSessions>,
    pub bans: BanTable,
    pub preauth: PreauthRate,
    pub metrics: Arc<SftpMetrics>,
    pub commit_gate: Arc<dyn CommitGate>,
    pub trusted_proxies: Vec<Cidr>,
    pub drain: Duration,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl Shared {
    fn ban_policy(&self) -> BanPolicy {
        let l = &self.gw.limits().sftp;
        BanPolicy {
            threshold: l.auth_failure_ban_threshold,
            window: Duration::from_secs(l.auth_failure_window_secs),
            ban: Duration::from_secs(l.auth_failure_ban_secs),
            capacity: l.ban_table_size,
        }
    }

    /// Count a finished connection's authentication failures toward the ban — only if it
    /// never authenticated.
    ///
    /// Counting at the end rather than as each attempt fails is what keeps ordinary
    /// clients unbanned: every offered key is answered uniformly (no probe oracle), so an
    /// agent holding several keys signs with the wrong ones before the right one. Those
    /// rejections are audited, but a connection that then logs in is a legitimate client,
    /// and counting them would ban a NAT'd partner after a few routine connections.
    fn settle_auth_failures(&self, conn: &ConnState) {
        if conn.is_authenticated() {
            return;
        }
        let failures = conn.auth_failures.load(Ordering::Relaxed);
        let now = Instant::now();
        let policy = self.ban_policy();
        for _ in 0..failures {
            if self.bans.record_failure(conn.client_ip, now, policy) {
                self.emit_event(
                    conn,
                    SessionEventKind::Banned,
                    None,
                    None,
                    false,
                    "deny (gateway): too many authentication failures; address banned".into(),
                );
                self.metrics.banned.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    /// Emit an `sftp/session` record (ADR-009 D13).
    ///
    /// `authed` carries the account and tenant of an authenticated session, which is the
    /// only case that earns an org label; everything else is unattributed.
    pub fn emit_event(
        &self,
        conn: &ConnState,
        kind: SessionEventKind,
        login: Option<&str>,
        authed: Option<(&Authenticated, &str)>,
        allow: bool,
        reason: String,
    ) {
        self.emit_event_inner(conn, kind, login, authed, allow, reason, None);
    }

    /// An `auth_failed` record, saying whether the credential did not match (see
    /// [`SessionEvent::credential_mismatch`]).
    pub fn emit_auth_failed(
        &self,
        conn: &ConnState,
        login: &str,
        reason: String,
        credential_mismatch: bool,
    ) {
        self.emit_event_inner(
            conn,
            SessionEventKind::AuthFailed,
            Some(login),
            None,
            false,
            reason,
            Some(credential_mismatch),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_event_inner(
        &self,
        conn: &ConnState,
        kind: SessionEventKind,
        login: Option<&str>,
        authed: Option<(&Authenticated, &str)>,
        allow: bool,
        reason: String,
        credential_mismatch: Option<bool>,
    ) {
        let org = authed.and_then(|(_, tenant)| {
            self.gw
                .registry
                .route_snapshot(tenant)
                .map(|r| r.organization_id)
        });
        let counters = matches!(kind, SessionEventKind::Disconnected).then_some(&conn.counters);
        let event = SessionEvent {
            event: kind,
            protocol: "sftp".into(),
            session_id: conn.session_id.clone(),
            client_ip: conn.client_ip.to_string(),
            login: login.map(str::to_string),
            auth: authed.map(|(a, _)| a.auth.clone()),
            tenant: authed.map(|(_, t)| t.to_string()),
            duration_secs: counters.map(|_| conn.started.elapsed().as_secs()),
            operations: counters.map(|c| c.operations.load(Ordering::Relaxed)),
            bytes_in: counters.map(|c| c.bytes_in.load(Ordering::Relaxed)),
            bytes_out: counters.map(|c| c.bytes_out.load(Ordering::Relaxed)),
            credential_mismatch,
            suppressed_since_last: 0,
        };
        let result = Decision {
            allow,
            reason,
            obligations: Default::default(),
        };
        let requested_by = authed
            .map(|(a, _)| a.account.sub.clone())
            .unwrap_or_default();
        let record = AuditRecord::session_event(
            crate::access::enforcer::new_decision_id(),
            crate::access::enforcer::now_rfc3339(),
            event,
            result,
            requested_by,
            org.as_deref(),
            self.gw.audit.labels(),
        );
        self.gw.audit.emit_session_event(record);
    }

    fn preauth_reject(&self, conn: &ConnState, reason: &str) {
        self.metrics
            .preauth_rejected
            .fetch_add(1, Ordering::Relaxed);
        self.emit_event(
            conn,
            SessionEventKind::PreauthRejected,
            None,
            None,
            false,
            format!("deny (gateway): {reason}"),
        );
    }
}

/// One connection's state, shared between the SSH handler and the connection task.
pub struct ConnState {
    pub session_id: String,
    pub client_ip: IpAddr,
    pub started: Instant,
    pub counters: Arc<SessionCounters>,
    authenticated: AtomicBool,
    /// Authentication failures on this connection, counted toward the ban when the
    /// connection ends unauthenticated ([`Shared::settle_auth_failures`]).
    auth_failures: AtomicU32,
    auth: Mutex<Option<AuthSlot>>,
    close_reason: Mutex<Option<&'static str>>,
    /// The SFTP subsystem task, awaited before the `disconnected` record so that record
    /// comes after the transfers it ended were aborted, and carries their reason.
    sftp_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Signalled once a disconnect has been handed to the SSH session (the SFTP teardown,
    /// the handshake watcher). That only queues it: russh's task may be stuck writing to
    /// a client that stopped reading, so the connection task gives it [`DISCONNECT_GRACE`]
    /// to end, then fires `kill_switch`.
    teardown: tokio::sync::Notify,
    /// Fails every read and write on the connection's socket (`StrictKexGuard`), so a
    /// russh task stuck writing to a client that stopped reading ends, and drops it.
    kill_switch: KillSwitch,
}

struct AuthSlot {
    login: String,
    credential: Credential,
    auth: Authenticated,
    revision: String,
    _subject: SubjectGuard,
}

impl ConnState {
    fn new(client_ip: IpAddr) -> Self {
        ConnState {
            session_id: uuid::Uuid::new_v4().to_string(),
            client_ip,
            started: Instant::now(),
            counters: Arc::new(SessionCounters::default()),
            authenticated: AtomicBool::new(false),
            auth_failures: AtomicU32::new(0),
            auth: Mutex::new(None),
            close_reason: Mutex::new(None),
            sftp_task: Mutex::new(None),
            teardown: tokio::sync::Notify::new(),
            kill_switch: KillSwitch::default(),
        }
    }

    /// Note one authentication failure; see [`Shared::settle_auth_failures`].
    pub fn note_auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Forget this connection's failures so far: the client has just presented a
    /// credential that matched, so the mismatches before it (an agent's other keys) are a
    /// legitimate client's, even if the gateway then refuses to admit it.
    pub fn forgive_auth_failures(&self) {
        self.auth_failures.store(0, Ordering::Relaxed);
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated.load(Ordering::Acquire)
    }

    pub fn set_authenticated(
        &self,
        login: &str,
        credential: Credential,
        auth: Authenticated,
        revision: String,
        subject: SubjectGuard,
    ) {
        *self.auth.lock().unwrap_or_else(|e| e.into_inner()) = Some(AuthSlot {
            login: login.to_string(),
            credential,
            auth,
            revision,
            _subject: subject,
        });
        self.authenticated.store(true, Ordering::Release);
    }

    /// `(login, account, tenant)` of the authenticated session.
    pub fn auth_snapshot(&self) -> Option<(String, Authenticated, String)> {
        self.auth
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|s| {
                (
                    s.login.clone(),
                    s.auth.clone(),
                    s.auth.account.tenant.clone(),
                )
            })
    }

    /// Record the SFTP subsystem task (one per connection).
    pub fn set_sftp_task(&self, task: tokio::task::JoinHandle<()>) {
        *self.sftp_task.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
    }

    fn sftp_started(&self) -> bool {
        self.sftp_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    fn set_close_reason(&self, r: &'static str) {
        let mut g = self.close_reason.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            *g = Some(r);
        }
    }
}

/// The SFTP front, built from an enabled `sftp` section.
pub struct SftpFront {
    shared: Arc<Shared>,
    config: Arc<russh::server::Config>,
    listen: SocketAddr,
    host_keys: Vec<(String, String)>,
}

impl SftpFront {
    pub fn build(gw: Arc<Gateway>, cfg: &SftpConfig) -> Result<Self> {
        let keys = transport::load_host_keys(&cfg.host_keys)?;
        let limits = gw.limits().sftp.clone();
        for k in &keys {
            tracing::info!(algorithm = %k.algorithm, fingerprint = %k.fingerprint, "sftp host key loaded; publish this fingerprint to partners for pinning");
        }
        let host_keys = keys
            .iter()
            .map(|k| (k.algorithm.clone(), k.fingerprint.clone()))
            .collect();
        let config = Arc::new(transport::server_config(&keys, &limits));
        let trusted_proxies = cfg
            .proxy_protocol
            .as_ref()
            .map(|p| {
                p.trusted_cidrs
                    .iter()
                    .map(|c| Cidr::parse(c).map_err(GatewayError::Config))
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let shared = Arc::new(Shared {
            enforcer: Enforcer::new(gw.clone()),
            directory: DirectoryCache::default(),
            inflight: Arc::new(InflightKeys::default()),
            memory: MemoryBudget::new(limits.max_transfer_memory),
            connections: Arc::new(ConnectionTracker::default()),
            subjects: Arc::new(SubjectSessions::default()),
            bans: BanTable::default(),
            preauth: PreauthRate::default(),
            metrics: Arc::new(SftpMetrics::default()),
            commit_gate: Arc::new(AlwaysCommit),
            trusted_proxies,
            drain: Duration::from_secs(cfg.drain_secs),
            shutdown,
            gw,
        });
        Ok(SftpFront {
            shared,
            config,
            listen: cfg.listen,
            host_keys,
        })
    }

    pub fn host_key_fingerprints(&self) -> Vec<(String, String)> {
        self.host_keys.clone()
    }

    pub fn metrics(&self) -> Arc<SftpMetrics> {
        self.shared.metrics.clone()
    }

    /// Accept until `shutdown` resolves, then stop accepting, give open sessions the
    /// drain budget, and return once they have ended (aborting every open transfer).
    pub async fn serve(self, shutdown: impl std::future::Future<Output = ()>) -> Result<()> {
        let listener = TcpListener::bind(self.listen).await.map_err(|e| {
            GatewayError::Config(format!("bind sftp listener {}: {e}", self.listen))
        })?;
        self.serve_on(listener, shutdown).await
    }

    /// [`Self::serve`] on an already-bound listener (tests bind port 0).
    pub async fn serve_on(
        self,
        listener: TcpListener,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<()> {
        tracing::info!(listen = ?listener.local_addr().ok(), "sftp front listening");
        let mut tasks = tokio::task::JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::warn!(%e, "sftp accept failed");
                            continue;
                        }
                    };
                    let shared = self.shared.clone();
                    let config = self.config.clone();
                    tasks.spawn(handle_connection(shared, config, stream, peer));
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        drop(listener);
        tracing::info!(
            drain_secs = self.shared.drain.as_secs(),
            "sftp listener closed; draining sessions"
        );
        let _ = self.shared.shutdown.send(true);
        // Longer than a connection's own wait for its session teardown (`drain + 5s` in
        // `handle_connection`), so a slow abort still ends in its `disconnected` record
        // rather than being cut off here.
        let deadline = self.shared.drain + Duration::from_secs(8);
        if tokio::time::timeout(deadline, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tracing::error!("sftp sessions outlived the drain budget; aborting them");
            tasks.abort_all();
        }
        Ok(())
    }
}

async fn handle_connection(
    shared: Arc<Shared>,
    config: Arc<russh::server::Config>,
    mut stream: TcpStream,
    peer: SocketAddr,
) {
    shared
        .metrics
        .connections_accepted
        .fetch_add(1, Ordering::Relaxed);
    let limits = shared.gw.limits().sftp.clone();
    // One deadline from accept to authentication, covering the PROXY header, the version
    // exchange and KEX (which `StrictKexGuard` holds back until the client's KEXINIT, so
    // russh's own wait for the version line never starts its clock) and authentication.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(limits.handshake_timeout_secs);
    let _ = stream.set_nodelay(true);

    // The client address: the peer, or what a trusted load balancer's PROXY v2 header
    // says. A trusted peer that does not send one is disconnected; an untrusted peer that
    // sends one is caught by the strict-KEX guard below.
    let client_ip = if limits::any_contains(&shared.trusted_proxies, peer.ip()) {
        match tokio::time::timeout_at(deadline, preauth::read_proxy_v2(&mut stream)).await {
            Ok(Ok(ProxyHeader::Local)) => return,
            Ok(Ok(ProxyHeader::Proxied { source })) => source.ip(),
            Ok(Err(e)) => {
                let conn = ConnState::new(peer.ip());
                shared.preauth_reject(&conn, &format!("PROXY header: {e}"));
                return;
            }
            Err(_) => {
                let conn = ConnState::new(peer.ip());
                shared.preauth_reject(&conn, "PROXY header timeout");
                return;
            }
        }
    } else {
        peer.ip()
    };
    let conn = Arc::new(ConnState::new(client_ip));
    let now = Instant::now();
    {
        let dir = shared.directory.get(&shared.gw.bundles.current());
        if dir.is_source_denied(client_ip) {
            shared.preauth_reject(&conn, "source address on the bundle denylist");
            return;
        }
    }
    if shared.bans.is_banned(client_ip, now) {
        shared.preauth_reject(&conn, "address banned for repeated authentication failures");
        return;
    }
    if !shared.preauth.allow(
        client_ip,
        now,
        limits.preauth_rate_per_ip_per_min,
        limits.preauth_burst_per_ip,
        limits.ban_table_size,
    ) {
        shared.preauth_reject(&conn, "pre-authentication rate limit");
        return;
    }
    let _guard = match shared.connections.admit(
        client_ip,
        limits.max_connections,
        limits.max_connections_per_ip,
    ) {
        Ok(g) => g,
        Err(why) => {
            shared.preauth_reject(&conn, why);
            return;
        }
    };
    shared
        .metrics
        .connections_active
        .fetch_add(1, Ordering::Relaxed);
    let refusal: Arc<OnceLock<&'static str>> = Arc::new(OnceLock::new());
    let guarded = StrictKexGuard::new(stream)
        .with_refusal_slot(refusal.clone())
        .with_kill_switch(conn.kill_switch.clone());
    let handler = transport::SshHandler::new(shared.clone(), conn.clone());
    let started = tokio::time::timeout_at(
        deadline,
        russh::server::run_stream(config, guarded, handler),
    )
    .await;
    let result = match started {
        Err(_) => {
            conn.set_close_reason("handshake timeout");
            Err("handshake timeout before the SSH session started".to_string())
        }
        Ok(Err(e)) => Err(e.to_string()),
        Ok(Ok(running)) => {
            let handle = running.handle();
            let watcher_conn = conn.clone();
            let subsystem_wait = Duration::from_secs(limits.handshake_timeout_secs);
            // Ends a connection that has not authenticated by the deadline, or that has
            // authenticated but not started the SFTP subsystem one handshake timeout
            // later: neither has an SFTP teardown to end it.
            let watcher = tokio::spawn(async move {
                tokio::time::sleep_until(deadline).await;
                let reason = if !watcher_conn.is_authenticated() {
                    watcher_conn.set_close_reason("handshake timeout");
                    "authentication timeout"
                } else {
                    tokio::time::sleep(subsystem_wait).await;
                    if watcher_conn.sftp_started() {
                        return;
                    }
                    watcher_conn.set_close_reason("no sftp subsystem");
                    "sftp subsystem not requested"
                };
                request_disconnect(&watcher_conn, &handle, None, reason).await;
            });
            // The session ends when the client goes, or after a disconnect was requested.
            // That disconnect is only queued: a russh task stuck writing to a client that
            // stopped reading never takes it. Dropping `running` would only detach that
            // task, with the socket open and no longer counted; firing the kill switch
            // fails its write so it ends. Wait for it, so the connection stays counted
            // until it does.
            let mut running = running;
            let r = tokio::select! {
                r = &mut running => r.map_err(|e| e.to_string()),
                _ = conn.teardown.notified() => {
                    match tokio::time::timeout(DISCONNECT_GRACE, &mut running).await {
                        Ok(r) => r.map_err(|e| e.to_string()),
                        Err(_) => {
                            conn.kill_switch.fire();
                            if tokio::time::timeout(KILL_GRACE, &mut running).await.is_err() {
                                // Keep waiting: russh's task still holds the socket, so the
                                // connection stays counted until it ends. Drain aborts this
                                // task if it never does.
                                tracing::warn!(session = %conn.session_id, "sftp connection task did not end after the kill switch; still waiting");
                                let _ = (&mut running).await;
                            }
                            Err("connection dropped: the client stopped reading".to_string())
                        }
                    }
                }
            };
            watcher.abort();
            r
        }
    };
    shared
        .metrics
        .connections_active
        .fetch_sub(1, Ordering::Relaxed);
    shared.settle_auth_failures(&conn);
    if let Some(why) = refusal.get() {
        shared.preauth_reject(&conn, why);
        return;
    }
    // Let the SFTP session finish first: it aborts open transfers and records why it
    // ended. Bounded, so a wedged backend call cannot hold the record back forever.
    let task = conn
        .sftp_task
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if let Some(task) = task
        && tokio::time::timeout(shared.drain + Duration::from_secs(5), task)
            .await
            .is_err()
    {
        conn.set_close_reason("session teardown timeout");
    }
    match conn.auth_snapshot() {
        Some((login, auth, tenant)) => {
            let reason = conn
                .close_reason
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .unwrap_or(if result.is_ok() {
                    "client close"
                } else {
                    "connection lost"
                });
            shared.emit_event(
                &conn,
                SessionEventKind::Disconnected,
                Some(&login),
                Some((&auth, &tenant)),
                true,
                format!("disconnect: {reason}"),
            );
        }
        None => {
            if let Err(e) = result {
                tracing::debug!(client_ip = %client_ip, error = %e, "sftp connection ended before authentication");
            }
        }
    }
}

/// One frame from the reader task.
enum Frame {
    Packet(Bytes),
    TooLarge,
}

/// Drive the SFTP subsystem on an accepted session channel.
pub(crate) async fn run_sftp(
    shared: Arc<Shared>,
    conn: Arc<ConnState>,
    channel: russh::Channel<russh::server::Msg>,
    handle: russh::server::Handle,
) {
    let channel_id = channel.id();
    let Some((login, credential, auth, revision)) = ({
        let g = conn.auth.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().map(|s| {
            (
                s.login.clone(),
                s.credential.clone(),
                s.auth.clone(),
                s.revision.clone(),
            )
        })
    }) else {
        let _ = handle.close(channel_id).await;
        return;
    };
    let stream = channel.into_stream();
    let (mut rd, wr) = tokio::io::split(stream);
    let max_packet = shared.gw.limits().sftp.max_sftp_packet_len;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Frame>(4);
    // The reader is the only place bytes leave the channel. The bounded hand-off means a
    // session busy flushing a part stops reading, and SSH flow control stops the client.
    let reader = tokio::spawn(async move {
        loop {
            let mut len = [0u8; 4];
            if rd.read_exact(&mut len).await.is_err() {
                return;
            }
            let n = u32::from_be_bytes(len) as usize;
            // Checked against the bound BEFORE any allocation.
            if n == 0 || n > max_packet {
                let _ = tx.send(Frame::TooLarge).await;
                return;
            }
            let mut body = vec![0u8; n];
            if rd.read_exact(&mut body).await.is_err() {
                return;
            }
            if tx.send(Frame::Packet(Bytes::from(body))).await.is_err() {
                return;
            }
        }
    });

    let mut sess = SftpSession::new(
        shared.clone(),
        SessionIdentity {
            session_id: conn.session_id.clone(),
            client_ip: conn.client_ip,
            login,
            credential,
        },
        auth,
        revision,
        conn.counters.clone(),
    );
    let mut bundle_rx = shared.gw.bundles.subscribe();
    let mut shutdown_rx = shared.shutdown.subscribe();
    // `subscribe` marks the current value seen: a session that reaches this point after
    // the drain began (it was still authenticating) would otherwise never drain.
    if *shutdown_rx.borrow() {
        shutdown_rx.mark_changed();
    }
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut last_request = Instant::now();
    let mut draining: Option<Instant> = None;
    // The reply in flight. Writing it (and pacing after it) is a future the loop polls
    // beside the revocation sweep, the drain and the idle checks, never awaited inline:
    // a client that stops reopening its SSH window would otherwise freeze all of them
    // and pin the session's reservations. While a reply is in flight no request is read,
    // so the client is still flow-controlled; a reply stuck past `idle_timeout_secs`
    // ends the session as idle (no request is read meanwhile).
    let mut writer: Option<(ReplyWriter, Pacer)> = Some((wr, Pacer::new()));
    let mut sending: Option<Sending> = None;
    let reason: &'static str = loop {
        tokio::select! {
            sent = async {
                match sending.as_mut() {
                    Some(f) => f.await,
                    None => std::future::pending().await,
                }
            }, if sending.is_some() => {
                sending = None;
                let Sent { wr, pacer, ok, close } = sent;
                writer = Some((wr, pacer));
                if !ok {
                    break "client close";
                }
                if let Some(why) = close {
                    break why;
                }
            }
            frame = rx.recv(), if sending.is_none() => {
                let body = match frame {
                    None => break "client close",
                    Some(Frame::TooLarge) => break "protocol error: packet length out of bounds",
                    Some(Frame::Packet(b)) => b,
                };
                let next = match codec::parse(body) {
                    Ok(req) => sess.handle(req).await,
                    Err(e) => match e.id {
                        Some(id) => Next::ReplyAndClose(codec::Response::status(id, codec::StatusCode::BadMessage, e.reason)),
                        None => Next::Close("protocol error: malformed packet"),
                    },
                };
                // A long request (a commit, a large rename) is not idle time.
                last_request = Instant::now();
                let (reply, close) = match next {
                    Next::Reply(r) => (Some(r), None),
                    Next::ReplyAndClose(r) => (Some(r), Some("protocol error: malformed packet")),
                    Next::Close(why) => (None, Some(why)),
                };
                let Some(r) = reply else {
                    break close.unwrap_or("protocol error");
                };
                let Some((mut wr, mut pacer)) = writer.take() else {
                    break "internal error: no writer";
                };
                let (shared, conn) = (shared.clone(), conn.clone());
                sending = Some(Box::pin(async move {
                    let ok = wr.write_all(&r.encode()).await.is_ok();
                    if ok && close.is_none() {
                        pacer.pace(&shared, &conn).await;
                    }
                    Sent { wr, pacer, ok, close }
                }));
            }
            changed = bundle_rx.changed() => {
                if changed.is_err() {
                    continue;
                }
                // The sweep: an idle session with a revoked key is closed within one poll
                // interval, not left open until its next request.
                if let Err(why) = sess.reauth() {
                    tracing::warn!(session = %conn.session_id, %why, "sftp credential revoked by a bundle swap");
                    break "credential_revoked";
                }
            }
            _ = shutdown_rx.changed() => {
                draining = Some(Instant::now() + shared.drain);
                if sess.write_handles() == 0 {
                    break "shutdown";
                }
            }
            _ = tick.tick() => {
                let l = shared.gw.limits().sftp.clone();
                if last_request.elapsed() > Duration::from_secs(l.idle_timeout_secs) {
                    break "idle";
                }
                sess.sweep_idle_transfers(Duration::from_secs(l.transfer_idle_timeout_secs)).await;
                if let Some(deadline) = draining
                    && (sess.write_handles() == 0 || Instant::now() >= deadline)
                {
                    break "shutdown";
                }
            }
        }
    };
    sess.abort_all(reason).await;
    reader.abort();
    conn.set_close_reason(reason);
    // A reply already in flight (say, the OK of a CLOSE that just committed, when the
    // drain or a revocation ends the session) still goes out. Bounded: on a stalled client
    // it is dropped with its half of the stream.
    if let Some(f) = sending.take()
        && let Ok(Sent { wr, pacer, .. }) = tokio::time::timeout(Duration::from_secs(1), f).await
    {
        writer = Some((wr, pacer));
    }
    if let Some((mut wr, _)) = writer {
        let _ = tokio::time::timeout(Duration::from_secs(1), wr.shutdown()).await;
    }
    request_disconnect(&conn, &handle, Some(channel_id), reason).await;
}

/// Hand a disconnect (after closing `channel`, if any) to the SSH session, then signal
/// the connection task, which ends the connection if russh's task does not.
///
/// Bounded: on a connection the client has stalled, the SSH session cannot take these
/// messages, and the caller must not wait on it. If they cannot even be queued, russh's
/// task is certainly stuck, so the kill switch fires at once rather than after
/// [`DISCONNECT_GRACE`].
async fn request_disconnect(
    conn: &ConnState,
    handle: &russh::server::Handle,
    channel: Option<russh::ChannelId>,
    reason: &str,
) {
    let sent = tokio::time::timeout(TEARDOWN_SEND, async {
        if let Some(channel) = channel {
            let _ = handle.close(channel).await;
        }
        handle
            .disconnect(russh::Disconnect::ByApplication, reason.into(), "en".into())
            .await
    })
    .await;
    if !matches!(sent, Ok(Ok(()))) {
        conn.kill_switch.fire();
    }
    conn.teardown.notify_one();
}

/// How long [`request_disconnect`] waits to hand the channel close and the disconnect to
/// the SSH session before dropping the connection.
const TEARDOWN_SEND: Duration = Duration::from_secs(2);

/// How long the connection task waits, once a disconnect was queued, for russh's task to
/// send it and end before firing the kill switch. A responsive session ends well within
/// it; one that does not is stuck writing to a client that stopped reading.
const DISCONNECT_GRACE: Duration = Duration::from_secs(5);

/// How long the connection task waits for russh's task to end once the kill switch fired
/// before logging a warning. It ends at its next poll; past this the task is somehow not
/// being polled, and the connection task keeps waiting (still counted) rather than
/// releasing the slot of a socket that is still open.
const KILL_GRACE: Duration = Duration::from_secs(5);

/// The write half of the SFTP channel.
type ReplyWriter = tokio::io::WriteHalf<russh::ChannelStream<russh::server::Msg>>;

/// A reply being written (then paced), owning the writer until it is done.
type Sending = std::pin::Pin<Box<dyn std::future::Future<Output = Sent> + Send>>;

/// A finished [`Sending`]: the writer handed back, and whether the write succeeded.
struct Sent {
    wr: ReplyWriter,
    pacer: Pacer,
    ok: bool,
    close: Option<&'static str>,
}

/// Per-session bandwidth cap, per direction (ADR-009 D12). Unlimited by default.
///
/// The budget accrues from a baseline that is moved forward whenever the session is more
/// than [`Pacer::MAX_CREDIT`] under its rate, so an idle or slow stretch cannot bank an
/// unbounded burst to spend later at full speed.
struct Pacer {
    base: Instant,
    base_moved: u64,
}

impl Pacer {
    const MAX_CREDIT: Duration = Duration::from_secs(1);

    fn new() -> Self {
        Pacer {
            base: Instant::now(),
            base_moved: 0,
        }
    }

    async fn pace(&mut self, shared: &Shared, conn: &ConnState) {
        let rate = shared.gw.limits().sftp.bandwidth_bytes_per_sec;
        if rate == 0 {
            return;
        }
        let moved = conn
            .counters
            .bytes_in
            .load(Ordering::Relaxed)
            .max(conn.counters.bytes_out.load(Ordering::Relaxed));
        if let Some(wait) = self.delay(moved, rate, Instant::now()) {
            tokio::time::sleep(wait).await;
        }
    }

    /// How long to hold the session at `now`, having moved `moved` bytes in total at
    /// `rate` bytes per second; `None` when it is within its budget.
    fn delay(&mut self, moved: u64, rate: u64, now: Instant) -> Option<Duration> {
        let due =
            Duration::from_secs_f64(moved.saturating_sub(self.base_moved) as f64 / rate as f64);
        let elapsed = now.saturating_duration_since(self.base);
        if due > elapsed {
            return Some(due - elapsed);
        }
        if elapsed - due > Self::MAX_CREDIT {
            self.base = now.checked_sub(Self::MAX_CREDIT).unwrap_or(now);
            self.base_moved = moved;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_stretch_banks_at_most_one_second_of_credit() {
        let rate = 1_000_000;
        let t0 = Instant::now();
        let mut p = Pacer {
            base: t0,
            base_moved: 0,
        };
        // An hour of near-idle requests: a few bytes a minute, never held.
        let mut moved = 0;
        for minute in 1..=60 {
            moved += 100;
            let now = t0 + Duration::from_secs(60 * minute);
            assert_eq!(p.delay(moved, rate, now), None);
        }
        // Then 3.6 GB at once: only one second of it is free, the rest is paced.
        let now = t0 + Duration::from_secs(3600);
        let wait = p.delay(moved + 3_600_000_000, rate, now).expect("held");
        assert!(
            wait >= Duration::from_secs(3598) && wait <= Duration::from_secs(3600),
            "{wait:?}"
        );
    }

    #[test]
    fn a_session_at_its_rate_is_held_to_it() {
        let t0 = Instant::now();
        let mut p = Pacer {
            base: t0,
            base_moved: 0,
        };
        assert_eq!(
            p.delay(2_000, 1_000, t0 + Duration::from_secs(1)),
            Some(Duration::from_secs(1))
        );
        assert_eq!(p.delay(2_000, 1_000, t0 + Duration::from_secs(2)), None);
    }
}
