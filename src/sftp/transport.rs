//! The SSH transport: russh, pinned, with a code-constant algorithm floor (ADR-009 D3).
//!
//! **Every `Handler` method is overridden.** russh's defaults answer `exec`, `shell`,
//! `env`, `pty-req` and `subsystem` with `Ok(())` **without replying** (E5), the same
//! fail-open shape as the s3s hooks. Rust cannot reject a default method left in place, so
//! `tests/sftp_transport.rs` holds the list of `Handler` methods in the pinned russh
//! against the `fn` names in this file's `impl Handler`.
//!
//! The algorithm lists are `const`s, not configuration: tightening them ships with a
//! release, and nothing an operator sets can loosen them.

use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use russh::keys::{Algorithm, Certificate, EcdsaCurve, HashAlg, PrivateKey, PublicKey};
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Preferred};

use super::account::{Credential, Refusal, client_key_allowed};
use super::{ConnState, Shared};
use crate::audit::SessionEventKind;
use crate::error::GatewayError;

type GwResult<T> = crate::error::Result<T>;

/// KEX, in preference order. The strict-KEX and ext-info markers ride along; strict KEX is
/// additionally **required** of the client by `preauth::StrictKexGuard`.
pub const KEX: &[russh::kex::Name] = &[
    russh::kex::MLKEM768X25519_SHA256,
    russh::kex::CURVE25519,
    russh::kex::CURVE25519_PRE_RFC_8731,
    russh::kex::ECDH_SHA2_NISTP256,
    russh::kex::ECDH_SHA2_NISTP384,
    russh::kex::ECDH_SHA2_NISTP521,
    russh::kex::EXTENSION_SUPPORT_AS_SERVER,
    russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

/// AEAD only: no CBC, no CTR.
pub const CIPHERS: &[russh::cipher::Name] = &[
    russh::cipher::CHACHA20_POLY1305,
    russh::cipher::AES_256_GCM,
    russh::cipher::AES_128_GCM,
];

/// Unused under AEAD; listed only because negotiation requires a list. No SHA-1.
pub const MACS: &[russh::mac::Name] = &[russh::mac::HMAC_SHA512_ETM, russh::mac::HMAC_SHA256_ETM];

/// zlib is attack surface (decompression amplification) for no gain on already-compressed
/// partner files.
pub const COMPRESSION: &[russh::compression::Name] = &[russh::compression::NONE];

/// Host-key algorithms: ed25519 required, ECDSA P-256 optional. No RSA (E8).
pub const HOST_KEY_ALGORITHMS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
];

/// The `Preferred` built from the constants above.
pub fn preferred() -> Preferred {
    Preferred {
        kex: Cow::Borrowed(KEX),
        key: Cow::Borrowed(HOST_KEY_ALGORITHMS),
        host_key_certificates: Cow::Borrowed(&[]),
        cipher: Cow::Borrowed(CIPHERS),
        mac: Cow::Borrowed(MACS),
        compression: Cow::Borrowed(COMPRESSION),
    }
}

/// One loaded host key and its published fingerprint.
pub struct HostKey {
    pub key: PrivateKey,
    pub algorithm: String,
    pub fingerprint: String,
}

/// Load the mounted host keys. A missing, unreadable, world-readable, encrypted, RSA,
/// unsupported or duplicate key refuses startup, and so does a set with no ed25519 key.
/// There is no silent generation: a pod that regenerates its host key teaches every
/// partner to accept key changes, which is the MITM pinning exists to stop.
pub fn load_host_keys(paths: &[impl AsRef<Path>]) -> GwResult<Vec<HostKey>> {
    let mut out: Vec<HostKey> = Vec::new();
    for p in paths {
        let p = p.as_ref();
        let err = |m: String| GatewayError::Config(format!("sftp host key {}: {m}", p.display()));
        let meta = std::fs::metadata(p).map_err(|e| err(format!("unreadable: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o004 != 0 {
                return Err(err("is world-readable".into()));
            }
        }
        #[cfg(not(unix))]
        let _ = meta;
        let pem = std::fs::read_to_string(p).map_err(|e| err(format!("unreadable: {e}")))?;
        let key = PrivateKey::from_openssh(&pem)
            .map_err(|e| err(format!("not an OpenSSH private key: {e}")))?;
        if key.is_encrypted() {
            return Err(err(
                "is encrypted; mount it decrypted from the secret store".into(),
            ));
        }
        let algorithm = key.algorithm();
        if !HOST_KEY_ALGORITHMS.contains(&algorithm) {
            return Err(err(format!(
                "algorithm {} is not accepted (ed25519, or ECDSA P-256); RSA host keys are refused",
                algorithm.as_str()
            )));
        }
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        if out.iter().any(|k| k.fingerprint == fingerprint) {
            return Err(err("duplicates another host key".into()));
        }
        out.push(HostKey {
            algorithm: algorithm.as_str().to_string(),
            fingerprint,
            key,
        });
    }
    if !out
        .iter()
        .any(|k| k.algorithm == Algorithm::Ed25519.as_str())
    {
        return Err(GatewayError::Config(
            "frontends.sftp.host_keys must include an ed25519 key".into(),
        ));
    }
    Ok(out)
}

/// The russh server config: publickey only, the constant algorithm floor, the configured
/// attempt cap and constant-time rejection.
pub fn server_config(
    keys: &[HostKey],
    limits: &crate::config::SftpLimits,
) -> russh::server::Config {
    russh::server::Config {
        server_id: russh::SshId::Standard(Cow::Borrowed("SSH-2.0-s0")),
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(1)),
        keys: keys.iter().map(|k| k.key.clone()).collect(),
        max_auth_attempts: limits.max_auth_attempts,
        inactivity_timeout: Some(std::time::Duration::from_secs(
            limits.idle_timeout_secs + 60,
        )),
        preferred: preferred(),
        nodelay: true,
        ..Default::default()
    }
}

/// Errors that end a connection from inside the handler.
#[derive(Debug)]
pub enum HandlerError {
    Ssh(russh::Error),
    Refused(&'static str),
}

impl From<russh::Error> for HandlerError {
    fn from(e: russh::Error) -> Self {
        HandlerError::Ssh(e)
    }
}

impl std::fmt::Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandlerError::Ssh(e) => write!(f, "{e}"),
            HandlerError::Refused(r) => f.write_str(r),
        }
    }
}

/// Per-connection SSH handler.
pub struct SshHandler {
    shared: Arc<Shared>,
    conn: Arc<ConnState>,
    /// The one `session` channel, until its `subsystem sftp` request starts the session.
    pending: Option<Channel<Msg>>,
    session_channel: Option<ChannelId>,
    sftp_started: bool,
    probes: usize,
}

fn reject_publickey_only() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(MethodSet::from(&[MethodKind::PublicKey][..])),
        partial_success: false,
    }
}

impl SshHandler {
    pub fn new(shared: Arc<Shared>, conn: Arc<ConnState>) -> Self {
        SshHandler {
            shared,
            conn,
            pending: None,
            session_channel: None,
            sftp_started: false,
            probes: 0,
        }
    }

    /// A failed authentication: audited (no org label), and noted on the connection. It
    /// counts toward the ban only if the connection ends without authenticating
    /// (`Shared::settle_auth_failures`), so a wrong key offered before the right one
    /// does not count against a client that then logs in.
    fn fail(&mut self, login: &str, reason: String) -> Result<Auth, HandlerError> {
        self.reject(login, reason, true)
    }

    /// A refusal that is not the client's fault (a bundle the gateway refuses): audited
    /// like a failure, but never counted toward the ban. Counting it would ban an address
    /// for presenting a correct credential — every partner behind the same NAT with it.
    fn refuse(&mut self, login: &str, reason: String) -> Result<Auth, HandlerError> {
        self.reject(login, reason, false)
    }

    /// A credential that matched, refused admission (an unresolvable membership, a tenant
    /// that cannot be routed, the subject's session cap): not counted, and the
    /// connection's earlier mismatches are forgiven, so an agent that signed with its
    /// other keys first is not banned for retrying while the subject is at its cap.
    fn refuse_matched(&mut self, login: &str, reason: String) -> Result<Auth, HandlerError> {
        self.conn.forgive_auth_failures();
        self.refuse(login, reason)
    }

    fn reject(&mut self, login: &str, reason: String, counted: bool) -> Result<Auth, HandlerError> {
        tracing::info!(session = %self.conn.session_id, client_ip = %self.conn.client_ip, %login, %reason, counted, "sftp authentication failed");
        self.shared
            .metrics
            .auth_failed
            .fetch_add(1, Ordering::Relaxed);
        self.shared.emit_auth_failed(
            &self.conn,
            login,
            format!("deny (gateway): {reason}"),
            counted,
        );
        if counted {
            self.shared
                .metrics
                .auth_credential_mismatch
                .fetch_add(1, Ordering::Relaxed);
            self.conn.note_auth_failure();
        }
        Ok(reject_publickey_only())
    }

    fn check(&mut self, login: &str, credential: Credential) -> Result<Auth, HandlerError> {
        let bundle = self.shared.gw.bundles.current();
        let dir = self.shared.directory.get(&bundle);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let auth = match dir.authenticate_classified(login, &credential, self.conn.client_ip, now) {
            Ok(a) => a,
            Err(Refusal::Credential(r)) => return self.fail(login, r),
            Err(Refusal::Gateway(r)) => return self.refuse(login, r),
            Err(Refusal::Admission(r)) => return self.refuse_matched(login, r),
        };
        if self
            .shared
            .gw
            .registry
            .route_snapshot(&auth.account.tenant)
            .is_none()
        {
            return self.refuse_matched(
                login,
                format!("tenant {} is not routable", auth.account.tenant),
            );
        }
        let max = self.shared.gw.limits().sftp.max_sessions_per_subject;
        let subject = format!("{}/{}", auth.account.tenant, auth.account.subject_key);
        let Some(guard) = self.shared.subjects.admit(&subject, max) else {
            return self.refuse_matched(
                login,
                "too many concurrent sessions for this subject".into(),
            );
        };
        self.conn
            .set_authenticated(login, credential, auth, bundle.revision.clone(), guard);
        Ok(Auth::Accept)
    }
}

impl russh::server::Handler for SshHandler {
    type Error = HandlerError;

    /// Answered with the method list; russh counts it as an attempt.
    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(reject_publickey_only())
    }

    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        self.fail(user, "password authentication is not offered".into())
    }

    /// Counted toward `max_key_probes`, and answered **uniformly**: an offered key is
    /// always allowed to proceed to the signature, and the decision is taken only after
    /// the signature verifies. A probe therefore confirms nothing — not even for an
    /// authorized (login, key) pair — which is stricter than D3 requires and removes the
    /// probe as an account oracle. The cost is a signature verification per offered key.
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.probes += 1;
        let max = self.shared.gw.limits().sftp.max_key_probes;
        if self.probes > max {
            let _ = self.fail(user, format!("more than {max} public keys offered"));
            return Err(HandlerError::Refused("key probe limit"));
        }
        if !client_key_allowed(public_key.key_data()) {
            return self.fail(
                user,
                format!(
                    "client key type {} is not accepted (ed25519 and ECDSA only; RSA is refused, E6)",
                    public_key.algorithm().as_str()
                ),
            );
        }
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.check(
            user,
            Credential::PublicKey {
                key: public_key.key_data().clone(),
            },
        )
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        self.check(
            user,
            Credential::Certificate {
                cert: Box::new(certificate.clone()),
            },
        )
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        _response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        self.fail(
            user,
            "keyboard-interactive authentication is not offered".into(),
        )
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        self.shared
            .metrics
            .auth_succeeded
            .fetch_add(1, Ordering::Relaxed);
        let (login, auth, tenant) = match self.conn.auth_snapshot() {
            Some(a) => a,
            None => return Err(HandlerError::Refused("authentication state missing")),
        };
        let reason = format!("allow (gateway): {}", auth.auth.method);
        self.shared.emit_event(
            &self.conn,
            SessionEventKind::AuthSucceeded,
            Some(&login),
            Some((&auth, &tenant)),
            true,
            reason,
        );
        Ok(())
    }

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(None)
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Exactly one `session` channel per connection.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.session_channel.is_some() || !self.conn.is_authenticated() {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        self.session_channel = Some(channel.id());
        self.pending = Some(channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    /// The server never opens a channel, so there is nothing to confirm.
    async fn channel_open_confirmation(
        &mut self,
        _id: ChannelId,
        _max_packet_size: u32,
        _window_size: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Err(HandlerError::Refused(
            "unexpected channel open confirmation",
        ))
    }

    /// Data reaches the SFTP session through the channel stream, not through here.
    async fn data(
        &mut self,
        _channel: ChannelId,
        _data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn extended_data(
        &mut self,
        _channel: ChannelId,
        _code: u32,
        _data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn window_adjusted(
        &mut self,
        _channel: ChannelId,
        _new_size: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn adjust_window(&mut self, _channel: ChannelId, current: u32) -> u32 {
        current
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        refuse_request(channel, session)
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        refuse_request(channel, session)
    }

    /// Refused, but the channel stays open — the one channel request that does not end
    /// the session.
    ///
    /// Stock OpenSSH sends `env` on the session channel *before* `subsystem sftp`
    /// whenever its config has `SendEnv` (the Debian, Ubuntu and macOS defaults carry
    /// `SendEnv LANG LC_*`). Closing the channel here would lock every such partner out.
    /// No variable is set — there is no process to set it in — and the refusal is
    /// explicit (`SSH_MSG_CHANNEL_FAILURE`, sent when the client asked for a reply), so
    /// nothing relies on a russh default (E5). Deviation from ADR-009 D3, which closes the
    /// channel on every non-`sftp` request.
    async fn env_request(
        &mut self,
        channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        refuse_request(channel, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        refuse_request(channel, session)
    }

    /// Exactly `sftp`, exactly once, on the one session channel.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" || self.sftp_started || self.session_channel != Some(channel) {
            return refuse_request(channel, session);
        }
        let Some(ch) = self.pending.take() else {
            return refuse_request(channel, session);
        };
        self.sftp_started = true;
        session.channel_success(channel)?;
        let shared = self.shared.clone();
        let conn = self.conn.clone();
        let handle = session.handle();
        let task = tokio::spawn(super::run_sftp(shared, conn.clone(), ch, handle));
        conn.set_sftp_task(task);
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        refuse_request(channel, session)
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        session.close(channel)?;
        Ok(false)
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        _signal: russh::Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        refuse_request(channel, session)
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        _address: &str,
        _port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn cancel_streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// No DH group exchange is offered (`KEX` above), so there is no group to look up.
    async fn lookup_dh_gex_group(
        &mut self,
        _gex_params: &russh::client::GexParams,
    ) -> Result<Option<russh::kex::dh::groups::DhGroup>, Self::Error> {
        Ok(None)
    }
}

/// An explicit `SSH_MSG_CHANNEL_FAILURE`, then close the channel. Nothing relies on a
/// russh default.
fn refuse_request(channel: ChannelId, session: &mut Session) -> Result<(), HandlerError> {
    session.channel_failure(channel)?;
    session.close(channel)?;
    Ok(())
}
