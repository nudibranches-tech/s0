//! `POST /internal/v1/derived-keys`, driven over a real socket.
//!
//! The control plane asks s0 for a long-lived key instead of deriving one itself, so the
//! one property worth proving is that **the credential it is handed is one the data plane
//! honours** — not that it matches a golden vector, which drifts silently.
//!
//! So every test here mints over HTTP through the production `internal::route`, then
//! signs a real SigV4 request with what came back, against the **same** gateway process,
//! and asserts on the authorization outcome. No re-derivation, no fixture in between: if
//! the encoding, the ring, the epoch or the tenant table were wrong, the request fails.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::sigv4::RawRequest;
use s0::config::{GatewayConfig, InternalApiConfig};
use s0::gateway::Gateway;
use s0::internal::{DERIVED_KEY_PATH, InternalApi, SHARED_SECRET_HEADER};
use s0::pdp::{Bundle, content_revision};
use s0::secret::Secret;

const SECRET: &str = "platform-shared-secret-value";
const DERIVED_KEY_HEX: &str = "abababababababababababababababababababababababababababababababab";

/// A background compaction identity — the kind of long-lived consumer this endpoint is
/// for.
const SUBJECT: &str = "trino-background";
const ORG: &str = "org-acme";

/// The same fixture shape as `derived_keys_e2e`: one grant, one prefix, and the epoch
/// floor the whole revocation story hangs off. `include_epoch` off is a real state — a
/// tenant the projection has not yet published a floor for.
fn bundle(key_epoch: u32, include_epoch: bool) -> serde_json::Value {
    let mut tenant = serde_json::json!({
        "user_attributes": { SUBJECT: { "groups": [], "attributes": [] } },
        "bucket_attributes": { "reports": { "denylist": {} } },
        "s3_grants": { SUBJECT: [
            { "bucket": "reports", "actions": ["read_objects", "list_objects"],
              "prefixes": ["2024/"] },
            { "bucket": "reports", "actions": ["read"], "prefixes": [] }
        ] },
        "group_grants": {}
    });
    if include_epoch {
        tenant["s3_key_epoch"] = key_epoch.into();
    }
    serde_json::json!({
        "org_settings": { "freeze_writes": false, "reserved_tag_keys": ["acme/*"] },
        "tenants": { "acme": tenant }
    })
}

struct Harness {
    s3_base: String,
    internal_base: String,
    gw: Arc<Gateway>,
    _audit: s0::audit::AuditHandle,
    _dir: std::path::PathBuf,
}

impl Harness {
    /// A whole gateway from a config file, plus the internal API on a second socket
    /// holding the gateway's **own** derived-key half — the wiring `main.rs` performs.
    async fn boot(tag: &str, key_epoch: u32, derived: bool) -> Harness {
        let dir = common::scratch(tag);
        let bundle_path = dir.join("bundle.json");
        std::fs::write(&bundle_path, bundle(key_epoch, true).to_string()).expect("bundle");

        let mut cfg = serde_json::json!({
            "listen": "127.0.0.1:0",
            "sts": { "master_key_hex": "00".repeat(32), "signing_key_hex": "11".repeat(32) },
            "pdp": { "mode": "embedded" },
            "audit": { "sink_url": "http://127.0.0.1:59999/none",
                       "spill_path": dir.join("audit.ndjson") },
            "backends": [ { "id": "bay-1", "kind": "ceph", "endpoint_url": "http://127.0.0.1:1" } ],
            "tenants": [
                { "tenant": "acme", "organization_id": ORG, "backend_id": "bay-1",
                  "owner_access_key": "OWNER", "owner_secret_key": "OWNERSECRET" },
                { "tenant": "globex", "organization_id": "org-globex", "backend_id": "bay-1",
                  "owner_access_key": "OWNER2", "owner_secret_key": "OWNERSECRET2" }
            ],
            "bundle_path": bundle_path,
        });
        if derived {
            cfg["derived_keys"] = serde_json::json!({ "master_key_hex": DERIVED_KEY_HEX });
        }
        let cfg = GatewayConfig::from_json(&cfg.to_string()).expect("config must load");
        let (gw, audit) = Gateway::build(&cfg).expect("gateway must build");

        let s3_base = serve(|addr| {
            let serving = gw.clone();
            tokio::spawn(async move {
                let _ =
                    s0::server::serve_with_shutdown(serving, addr, std::future::pending::<()>())
                        .await;
            });
        })
        .await;

        let api = Arc::new(
            InternalApi::new(
                &InternalApiConfig {
                    listen: "127.0.0.1:0".parse().expect("addr"),
                    shared_secret: Some(Secret::from(SECRET)),
                    max_session_ttl_secs: 3600,
                },
                gw.identity.sts(),
                gw.registry.clone(),
            )
            .with_derived_keys(gw.identity.derived()),
        );
        let internal_base = serve(|addr| {
            tokio::spawn(async move {
                let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
                let _ = s0::internal::serve_on(api, listener, std::future::pending::<()>()).await;
            });
        })
        .await;

        Harness {
            s3_base,
            internal_base,
            gw,
            _audit: audit,
            _dir: dir,
        }
    }

    /// One bundle poll: a new revision into the store both the credential layer and the
    /// mint read. Nothing restarts.
    fn publish(&self, key_epoch: u32, include_epoch: bool) {
        let doc = bundle(key_epoch, include_epoch);
        self.gw
            .bundles
            .store(Bundle::new(content_revision(&doc.to_string()), doc));
    }

    /// `POST /internal/v1/derived-keys`, authenticated, as the control plane makes it.
    async fn mint(&self, tenant: &str, org: &str, sub: &str) -> (u16, serde_json::Value) {
        self.mint_at(tenant, org, sub, None).await
    }

    async fn mint_at(
        &self,
        tenant: &str,
        org: &str,
        sub: &str,
        key_epoch: Option<u32>,
    ) -> (u16, serde_json::Value) {
        let mut body = serde_json::json!({
            "sub": sub,
            "principal_type": "service_account",
            "tenant": tenant,
            "organization_id": org,
        });
        if let Some(e) = key_epoch {
            body["key_epoch"] = e.into();
        }
        self.post(body).await
    }

    async fn post(&self, body: serde_json::Value) -> (u16, serde_json::Value) {
        let resp = reqwest::Client::new()
            .post(format!("{}{DERIVED_KEY_PATH}", self.internal_base))
            .header(SHARED_SECRET_HEADER, SECRET)
            .json(&body)
            .send()
            .await
            .expect("request");
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        (
            status,
            serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text)),
        )
    }

    /// `GET reports/<key>` signed with the two fields the mint returned, and nothing
    /// else — no session token, exactly as a consumer's SDK would send it.
    async fn get(&self, key: &str, minted: &serde_json::Value) -> (u16, String) {
        let host = self.s3_base.trim_start_matches("http://").to_string();
        let req = RawRequest::new("GET", format!("/reports/{key}"));
        let signed = req.sign(
            &host,
            minted["access_key_id"].as_str().expect("access_key_id"),
            minted["secret_access_key"]
                .as_str()
                .expect("secret_access_key"),
        );
        let mut builder = reqwest::Client::new().get(req.url(&self.s3_base));
        for (k, v) in signed {
            builder = builder.header(k, v);
        }
        let resp = builder.send().await.expect("request");
        let status = resp.status().as_u16();
        (status, resp.text().await.unwrap_or_default())
    }
}

/// Bind, hand the address to the server, wait until it answers.
async fn serve(spawn: impl FnOnce(SocketAddr)) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener);
    spawn(addr);
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    format!("http://{addr}")
}

/// An allowed request reaches the forward and dies at the closed backend port.
fn assert_allowed(status: u16, body: &str, what: &str) {
    assert!(
        status >= 500,
        "{what}: expected ALLOW and a failure at the closed backend, got {status} {body}"
    );
}

fn assert_denied_by_policy(status: u16, body: &str, what: &str) {
    assert_eq!(status, 403, "{what}: {body}");
    assert!(body.contains("AccessDenied"), "{what}: got {body}");
}

fn assert_credential_not_honoured(status: u16, body: &str, what: &str) {
    assert_eq!(status, 403, "{what}: {body}");
    assert!(body.contains("InvalidAccessKeyId"), "{what}: got {body}");
}

/// **The headline, and the reason minting lives in s0.** One authenticated call returns
/// two fields that an ordinary SigV4 client uses to read a real object — authorized per
/// prefix against grants the credential does not carry, and refused one prefix over. No
/// golden vector, no second encoder.
#[tokio::test]
async fn a_key_minted_over_the_internal_api_is_honoured_by_the_data_plane() {
    let hx = Harness::boot("mint-honoured", 1, true).await;

    let (status, minted) = hx.mint("acme", ORG, SUBJECT).await;
    assert_eq!(status, 200, "mint: {minted}");
    assert_eq!(minted["key_epoch"], 1, "stamped with the published floor");
    assert_eq!(minted["kid"], "k0");
    assert!(
        minted["access_key_id"]
            .as_str()
            .expect("access_key_id")
            .starts_with("HFSA"),
        "the derived namespace: {minted}"
    );

    let (status, body) = hx.get("2024/q1.parquet", &minted).await;
    assert_allowed(status, &body, "inside the grant");

    let (status, body) = hx.get("2023/q1.parquet", &minted).await;
    assert_denied_by_policy(status, &body, "one prefix over");
}

/// **The epoch is read, not accepted.** The mint stamps whatever floor the bundle in
/// force publishes, so a key cannot be minted below the floor (revoked on arrival) or
/// above it (unrevocable). Raising the floor afterwards revokes it, through the same
/// bundle swap every other revocation here uses.
#[tokio::test]
async fn the_minted_epoch_tracks_the_bundle_and_a_raised_floor_revokes_the_key() {
    let hx = Harness::boot("mint-epoch", 1, true).await;

    let (_, first) = hx.mint("acme", ORG, SUBJECT).await;
    assert_eq!(first["key_epoch"], 1);

    hx.publish(5, true);
    let (status, second) = hx.mint("acme", ORG, SUBJECT).await;
    assert_eq!(status, 200, "{second}");
    assert_eq!(
        second["key_epoch"], 5,
        "the mint follows the bundle rather than a number the caller supplied"
    );

    // The first key is now below the floor; the second is at it.
    let (status, body) = hx.get("2024/q1.parquet", &first).await;
    assert_credential_not_honoured(status, &body, "a key below the raised floor");
    let (status, body) = hx.get("2024/q1.parquet", &second).await;
    assert_allowed(status, &body, "a key reissued at the new floor");
}

/// **Rotation without a gap**, which is the whole reason `key_epoch` is a request field.
///
/// A derived key is a pure function of its inputs, so re-minting a principal at the same
/// epoch returns the *same* two strings — the epoch is the serial number. Rotation mints
/// one above the floor, runs both keys, and only then revokes, so the consumer is never
/// without a working credential.
#[tokio::test]
async fn a_rotation_can_run_two_keys_before_the_old_one_is_cut() {
    let hx = Harness::boot("mint-rotate", 1, true).await;

    let (_, old) = hx.mint("acme", ORG, SUBJECT).await;
    let (status, same) = hx.mint("acme", ORG, SUBJECT).await;
    assert_eq!(status, 200, "{same}");
    assert_eq!(
        old["access_key_id"], same["access_key_id"],
        "the same principal at the same epoch is the same key, not a second one"
    );

    // Mint the successor one epoch up. Both work: the floor is still 1.
    let (status, new) = hx.mint_at("acme", ORG, SUBJECT, Some(2)).await;
    assert_eq!(status, 200, "{new}");
    assert_ne!(new["access_key_id"], old["access_key_id"]);
    let (status, body) = hx.get("2024/q1.parquet", &old).await;
    assert_allowed(status, &body, "the outgoing key during the overlap");
    let (status, body) = hx.get("2024/q1.parquet", &new).await;
    assert_allowed(status, &body, "the incoming key during the overlap");

    // Cut the old one by raising the floor past it. The new key is unaffected.
    hx.publish(2, true);
    let (status, body) = hx.get("2024/q1.parquet", &old).await;
    assert_credential_not_honoured(status, &body, "the outgoing key after the cut");
    let (status, body) = hx.get("2024/q1.parquet", &new).await;
    assert_allowed(status, &body, "the incoming key after the cut");

    // And an epoch the floor has already passed is refused rather than clamped up: a
    // caller asking for it is working from state that has moved.
    let (status, body) = hx.mint_at("acme", ORG, SUBJECT, Some(1)).await;
    assert_eq!(status, 409, "{body}");
}

/// **A tenant that has not opted in gets no key at all**, rather than a key that silently
/// fails on first use. Absence denies at the mint for the same reason it denies at
/// admission, and 409 says so: the tenant exists, the feature does not.
#[tokio::test]
async fn a_tenant_with_no_published_epoch_is_refused_at_the_mint() {
    let hx = Harness::boot("mint-no-epoch", 1, true).await;
    hx.publish(1, false);

    let (status, body) = hx.mint("acme", ORG, SUBJECT).await;
    assert_eq!(status, 409, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("s3_key_epoch"),
        "the refusal must name the field the platform has to publish: {body}"
    );
}

/// The same cross-checks the session mint applies, for the same reason: attribution comes
/// from the gateway's routing table, so a credential minted against a tenant it does not
/// route, or against an organization it binds elsewhere, would be evaluated against facts
/// nobody asserted.
#[tokio::test]
async fn the_asserted_tenant_and_organization_are_checked_against_this_gateways_table() {
    let hx = Harness::boot("mint-assertions", 1, true).await;

    let (status, body) = hx.mint("not-a-tenant", ORG, SUBJECT).await;
    assert_eq!(status, 400, "unroutable tenant: {body}");

    let (status, body) = hx.mint("acme", "org-globex", SUBJECT).await;
    assert_eq!(status, 400, "organization mismatch: {body}");

    let (status, body) = hx.mint("acme", ORG, "   ").await;
    assert_eq!(status, 400, "empty subject: {body}");
}

/// Off is off, and it is **409, not 404**: the route exists on every build, so a caller
/// that gets this back knows to look at the gateway's config rather than at its own URL —
/// the difference between "wrong version deployed" and "feature not switched on".
#[tokio::test]
async fn a_gateway_with_no_ring_refuses_rather_than_pretending_the_route_is_absent() {
    let hx = Harness::boot("mint-off", 1, false).await;

    let (status, body) = hx.mint("acme", ORG, SUBJECT).await;
    assert_eq!(status, 409, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("derived_keys"),
        "the refusal must name the config section: {body}"
    );
}

/// Unauthenticated is unauthenticated, on this path as on the session path — checked
/// before the method, the path match, or any read of the body.
#[tokio::test]
async fn the_mint_is_behind_the_same_shared_secret() {
    let hx = Harness::boot("mint-auth", 1, true).await;

    let resp = reqwest::Client::new()
        .post(format!("{}{DERIVED_KEY_PATH}", hx.internal_base))
        .json(
            &serde_json::json!({ "sub": SUBJECT, "principal_type": "service_account",
                                   "tenant": "acme", "organization_id": ORG }),
        )
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status().as_u16(), 401);
}

/// The request has **nowhere to put a scope, a duration or a group**, and a caller that
/// tries is refused rather than silently having the field dropped — dropping a field the
/// caller believed it had applied is permanent for a credential that never expires.
#[tokio::test]
async fn an_unknown_field_is_refused_rather_than_dropped() {
    let hx = Harness::boot("mint-unknown", 1, true).await;

    for extra in [
        "duration_seconds",
        "groups",
        "prefixes",
        "scope",
        "organization",
    ] {
        let mut body = serde_json::json!({ "sub": SUBJECT, "principal_type": "service_account",
                                           "tenant": "acme", "organization_id": ORG });
        body[extra] = serde_json::json!(1);
        let (status, response) = hx.post(body).await;
        assert_eq!(status, 400, "`{extra}` must be refused: {response}");
    }
}
