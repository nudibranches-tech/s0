//! Derived long-lived per-principal keys, end to end.
//!
//! The unit tests in `src/auth/derived.rs` and `src/auth/mod.rs` prove the derivation and
//! the admission rules. This file proves the thing that actually matters to the five
//! consumers F18 has to migrate: **an off-the-shelf S3 client, holding two static fields
//! and nothing else, signs a real SigV4 request over TCP and the gateway authorizes it
//! against the bundle's grants** — and stops doing so one bundle poll after the key is
//! revoked.
//!
//! Everything here goes through `Gateway::build`, the one production assembly path, over
//! a real config file and a real bundle file. Nothing is hand-wired: if the config schema,
//! the ring loading, the bundle plumbing or the `S3Auth` dispatch were wrong, these tests
//! could not pass.
//!
//! The backend endpoint is a **closed port**, deliberately. An *allowed* request therefore
//! fails at the forward with a `500`-class error, which is the unambiguous signal that the
//! decision was allow and the request really left the policy engine — exactly the role the
//! `404 NoSuchKey` plays in the cluster measurements in the migration notes. A denial never
//! gets that far and answers `403`, and an unknown or forged credential is refused by s3s
//! before the gate with `InvalidAccessKeyId`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::sigv4::RawRequest;
use s0::auth::derived::{DerivedKeyAuthority, DerivedKeyCredential, DerivedPrincipal};
use s0::config::GatewayConfig;
use s0::gateway::Gateway;
use s0::model::PrincipalType;
use s0::pdp::{Bundle, content_revision};

/// The master key the gateway is configured with, in the two spellings the test needs.
const DERIVED_KEY_HEX: &str = "abababababababababababababababababababababababababababababababab";

/// The subject F18 migrates first: Trino's background compaction identity. Held as a
/// service account, granted one prefix of one bucket — where today it holds the
/// tenant-owner key and reaches every bucket in the tenant.
const SUBJECT: &str = "trino-background";

/// The bundle the gateway decides against.
///
/// `s3_key_epoch` is the field this whole feature's revocation hangs off, and it is here
/// rather than in a helper so that the two states a test moves between — floor 1 and
/// floor 2 — are visible side by side.
fn bundle(key_epoch: u32) -> serde_json::Value {
    serde_json::json!({
        "org_settings": { "freeze_writes": false, "reserved_tag_keys": ["hyperfluid/*"] },
        "tenants": { "acme": {
            // The gateway's compiled-in default module keys on the RAW sub (the pushed
            // platform module keys `sa:<client id>`); this fixture uses the default, so
            // the raw spelling is correct here.
            "user_attributes": { SUBJECT: { "groups": [], "attributes": [] } },
            "bucket_attributes": { "reports": { "denylist": {} } },
            "s3_grants": { SUBJECT: [
                { "bucket": "reports", "actions": ["read_objects", "list_objects"],
                  "prefixes": ["2024/"] },
                { "bucket": "reports", "actions": ["read"], "prefixes": [] }
            ] },
            "group_grants": {},
            // ── F17: the revocation floor ──────────────────────────────────────────
            "s3_key_epoch": key_epoch
        }}
    })
}

fn config_json(dir: &std::path::Path, bundle_path: &std::path::Path, derived: bool) -> String {
    let mut cfg = serde_json::json!({
        "listen": "127.0.0.1:0",
        "sts": { "master_key_hex": "00".repeat(32), "signing_key_hex": "11".repeat(32) },
        "pdp": { "mode": "embedded" },
        "audit": { "sink_url": "http://127.0.0.1:59999/none",
                   "spill_path": dir.join("audit.ndjson") },
        "backends": [ { "id": "bay-1", "kind": "ceph", "endpoint_url": "http://127.0.0.1:1" } ],
        "tenants": [
            { "tenant": "acme", "organization_id": "org-acme", "backend_id": "bay-1",
              "owner_access_key": "OWNER", "owner_secret_key": "OWNERSECRET" }
        ],
        "static_credentials": [
            { "access_key_id": common::ACCESS_KEY, "secret_access_key": common::SECRET_KEY,
              "principal_sub": SUBJECT, "tenant": "acme", "organization_id": "org-acme" }
        ],
        "bundle_path": bundle_path,
    });
    if derived {
        cfg["derived_keys"] = serde_json::json!({ "master_key_hex": DERIVED_KEY_HEX });
    }
    cfg.to_string()
}

struct Harness {
    base: String,
    gw: Arc<Gateway>,
    _audit: s0::audit::AuditHandle,
    _dir: std::path::PathBuf,
}

impl Harness {
    /// The whole gateway, from a config file, exactly as the binary builds it.
    async fn boot(tag: &str, key_epoch: u32, derived: bool) -> Harness {
        let dir = common::scratch(tag);
        let bundle_path = dir.join("bundle.json");
        std::fs::write(&bundle_path, bundle(key_epoch).to_string()).expect("bundle");
        let cfg = GatewayConfig::from_json(&config_json(&dir, &bundle_path, derived))
            .expect("config must load");
        let (gw, audit) = Gateway::build(&cfg).expect("gateway must build");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);
        let serving = gw.clone();
        tokio::spawn(async move {
            let _ =
                s0::server::serve_with_shutdown(serving, addr, std::future::pending::<()>()).await;
        });
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Harness {
            base: format!("http://{addr}"),
            gw,
            _audit: audit,
            _dir: dir,
        }
    }

    /// One bundle poll, as `bundle_refresh` performs it: a new revision installed into
    /// the same store the credential layer reads. Nothing else changes — no restart, no
    /// config edit, no credential store to rewrite.
    fn publish(&self, key_epoch: u32) {
        let raw = bundle(key_epoch).to_string();
        self.gw
            .bundles
            .store(Bundle::new(content_revision(&raw), bundle(key_epoch)));
    }

    /// `GET reports/<key>`, signed for real, over TCP.
    async fn get(&self, key: &str, access_key: &str, secret: &str) -> (u16, String) {
        self.get_with_token(key, access_key, secret, None).await
    }

    /// The same, carrying an STS session token — the third credential class, so its
    /// behaviour can be compared on a gateway that has derived keys switched on.
    async fn get_with_token(
        &self,
        key: &str,
        access_key: &str,
        secret: &str,
        token: Option<&str>,
    ) -> (u16, String) {
        let host = self.base.trim_start_matches("http://").to_string();
        // `sign` supplies `host`, `x-amz-date` and `x-amz-content-sha256` itself, and
        // returns every header that goes on the wire.
        let mut req = RawRequest::new("GET", format!("/reports/{key}"));
        if let Some(t) = token {
            req = req.header("x-amz-security-token", t);
        }
        let signed = req.sign(&host, access_key, secret);
        let client = reqwest::Client::new();
        let mut builder = client.get(req.url(&self.base));
        for (k, v) in signed {
            builder = builder.header(k, v);
        }
        let resp = builder.send().await.expect("request");
        let status = resp.status().as_u16();
        (status, resp.text().await.unwrap_or_default())
    }
}

/// The credential a consumer would be handed, minted through the same helper the
/// platform half (F17b) will call.
fn mint(epoch: u32, tenant: &str) -> DerivedKeyCredential {
    let authority =
        DerivedKeyAuthority::new(hex::decode(DERIVED_KEY_HEX).unwrap()).expect("authority");
    authority
        .mint(&DerivedPrincipal {
            tenant: tenant.into(),
            sub: SUBJECT.into(),
            principal_type: PrincipalType::ServiceAccount,
            key_epoch: epoch,
        })
        .expect("mint")
}

/// An allowed request reaches the forward and dies at the closed backend port. A denial
/// never gets there.
fn assert_reached_the_backend(status: u16, body: &str, what: &str) {
    assert!(
        status >= 500,
        "{what}: expected the request to be ALLOWED and to fail at the closed backend, \
         got {status} {body}"
    );
}

fn assert_denied_by_policy(status: u16, body: &str, what: &str) {
    assert_eq!(status, 403, "{what}: {body}");
    assert!(
        body.contains("AccessDenied"),
        "{what}: expected an authorization denial, got {body}"
    );
}

fn assert_credential_not_honoured(status: u16, body: &str, what: &str) {
    assert_eq!(status, 403, "{what}: {body}");
    assert!(
        body.contains("InvalidAccessKeyId"),
        "{what}: expected the credential to be refused before the gate, got {body}"
    );
}

/// **The headline.** Two static fields, an ordinary SigV4 client, and the gateway
/// authorizes per prefix against grants the credential does not carry.
#[tokio::test]
async fn a_derived_key_signs_a_real_request_and_is_authorized_by_the_bundle() {
    let hx = Harness::boot("derived-allow", 1, true).await;
    let creds = mint(1, "acme");

    let (status, body) = hx
        .get(
            "2024/q1.csv",
            &creds.access_key_id,
            &creds.secret_access_key,
        )
        .await;
    assert_reached_the_backend(status, &body, "a granted prefix");

    // …and the grant is what bounds it, not the credential: the same key, one prefix
    // over, is denied. That is the whole point of F17 — the tenant-owner key this
    // replaces reaches every bucket in the tenant.
    let (status, body) = hx
        .get(
            "2023/q1.csv",
            &creds.access_key_id,
            &creds.secret_access_key,
        )
        .await;
    assert_denied_by_policy(status, &body, "a prefix outside the grant");
}

/// A forged id must be **indistinguishable from an unknown key**: same status, same AWS
/// error code, no signal that the forgery was structurally close.
#[tokio::test]
async fn a_forged_key_is_refused_exactly_like_one_that_never_existed() {
    let hx = Harness::boot("derived-forged", 1, true).await;
    let creds = mint(1, "acme");
    let (head, mac) = creds.access_key_id.rsplit_once('.').unwrap();
    let forged = format!(
        "{head}.{}{}",
        if mac.starts_with('A') { 'B' } else { 'A' },
        &mac[1..]
    );

    // A forged MAC, and a credential from a completely different key ring — a real mint
    // against key material this gateway does not have.
    let other_ring = DerivedKeyAuthority::new(vec![0xEE; 32]).unwrap();
    let alien = other_ring
        .mint(&DerivedPrincipal {
            tenant: "acme".into(),
            sub: SUBJECT.into(),
            principal_type: PrincipalType::ServiceAccount,
            key_epoch: 1,
        })
        .unwrap();

    for (what, key, secret) in [
        (
            "a flipped MAC",
            forged.clone(),
            creds.secret_access_key.clone(),
        ),
        (
            "a key minted under material this gateway does not hold",
            alien.access_key_id.clone(),
            alien.secret_access_key.clone(),
        ),
        (
            "a key naming a tenant this gateway does not route",
            {
                let c = mint(1, "some-other-tenant");
                c.access_key_id
            },
            mint(1, "some-other-tenant").secret_access_key,
        ),
        (
            "a shape that was never minted at all",
            "HFSAk0.AQEAAAABBGFjbWV4.AAAAAAAAAAAAAAAAAAAAAA".to_string(),
            "whatever".to_string(),
        ),
    ] {
        let (status, body) = hx.get("2024/q1.csv", &key, &secret).await;
        assert_credential_not_honoured(status, &body, what);
    }

    // Positive control on the same gateway, so the four refusals above are not the
    // gateway refusing everything.
    let (status, body) = hx
        .get(
            "2024/q1.csv",
            &creds.access_key_id,
            &creds.secret_access_key,
        )
        .await;
    assert_reached_the_backend(status, &body, "the genuine key");
}

/// **Revocation, over the wire, through a real bundle swap.**
///
/// This is the property that makes a credential nobody can delete safe to hand out.
#[tokio::test]
async fn a_revoked_key_stops_working_within_one_bundle_refresh() {
    let hx = Harness::boot("derived-revoke", 1, true).await;
    let creds = mint(1, "acme");

    let (status, body) = hx
        .get(
            "2024/q1.csv",
            &creds.access_key_id,
            &creds.secret_access_key,
        )
        .await;
    assert_reached_the_backend(status, &body, "before revocation");

    // One poll. The operator raised the tenant's key epoch; nothing else happened.
    hx.publish(2);

    let (status, body) = hx
        .get(
            "2024/q1.csv",
            &creds.access_key_id,
            &creds.secret_access_key,
        )
        .await;
    assert_credential_not_honoured(status, &body, "after revocation");

    // A reissued key at the new epoch works immediately, which is what makes this a
    // revocation rather than a switch that turns the feature off.
    let reissued = mint(2, "acme");
    let (status, body) = hx
        .get(
            "2024/q1.csv",
            &reissued.access_key_id,
            &reissued.secret_access_key,
        )
        .await;
    assert_reached_the_backend(status, &body, "the reissued key");

    // And a bundle that publishes NO epoch at all denies rather than admits: the
    // fail-closed direction, over the wire.
    let mut no_epoch = bundle(2);
    no_epoch["tenants"]["acme"]
        .as_object_mut()
        .unwrap()
        .remove("s3_key_epoch");
    hx.gw.bundles.store(Bundle::new("rev-no-epoch", no_epoch));
    let (status, body) = hx
        .get(
            "2024/q1.csv",
            &reissued.access_key_id,
            &reissued.secret_access_key,
        )
        .await;
    assert_credential_not_honoured(status, &body, "a bundle with no epoch published");
}

/// **The multi-replica property (F8), as two processes rather than as an argument.**
///
/// A key minted against one gateway is presented to a second one that has never seen it,
/// shares no store with it, and was built from config alone — which is also what a pod
/// restart looks like from the client's side.
#[tokio::test]
async fn a_key_minted_against_one_gateway_works_against_a_second_instance() {
    let creds = mint(1, "acme");
    let pod_a = Harness::boot("derived-pod-a", 1, true).await;
    let (status, body) = pod_a
        .get(
            "2024/q1.csv",
            &creds.access_key_id,
            &creds.secret_access_key,
        )
        .await;
    assert_reached_the_backend(status, &body, "pod A");
    drop(pod_a);

    let pod_b = Harness::boot("derived-pod-b", 1, true).await;
    let (status, body) = pod_b
        .get(
            "2024/q1.csv",
            &creds.access_key_id,
            &creds.secret_access_key,
        )
        .await;
    assert_reached_the_backend(
        status,
        &body,
        "pod B — a derived key did not survive a restart, so the secret is not derived",
    );
}

/// **An STS session is untouched by the new class**, on a gateway that has it switched
/// on: minted under the config's own key ring, presented with its session token, and
/// authorized against the same grants — allow inside the prefix, deny outside it.
///
/// `tests/web_identity_e2e.rs` and `tests/internal_session.rs` cover the STS door itself
/// and run unchanged; what they do not cover is the STS path *coexisting* with derived
/// keys, which is the only thing this stage could have broken.
#[tokio::test]
async fn an_sts_session_still_works_on_a_gateway_with_derived_keys_switched_on() {
    use s0::auth::sts::{SessionClaims, StsAuthority};

    let hx = Harness::boot("derived-sts", 1, true).await;
    // The same key material the config gives the gateway.
    let sts = StsAuthority::new(vec![0u8; 32], vec![0x11u8; 32]).unwrap();
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let session = sts
        .mint(
            "sid-e2e",
            SessionClaims {
                sub: SUBJECT.into(),
                principal_type: PrincipalType::ServiceAccount,
                groups: vec![],
                tenant: "acme".into(),
                org: "org-acme".into(),
                sid: "sid-e2e".into(),
                exp,
            },
        )
        .expect("mint");

    let (status, body) = hx
        .get_with_token(
            "2024/q1.csv",
            &session.access_key_id,
            &session.secret_access_key,
            Some(&session.session_token),
        )
        .await;
    assert_reached_the_backend(status, &body, "an STS session inside its grant");

    let (status, body) = hx
        .get_with_token(
            "2023/q1.csv",
            &session.access_key_id,
            &session.secret_access_key,
            Some(&session.session_token),
        )
        .await;
    assert_denied_by_policy(status, &body, "an STS session outside its grant");

    // The STS namespace is still answered by the STS authority alone: a session key
    // with no token is refused, exactly as before.
    let (status, body) = hx
        .get(
            "2024/q1.csv",
            &session.access_key_id,
            &session.secret_access_key,
        )
        .await;
    assert_denied_by_policy(status, &body, "an STS key presented with no session token");
}

/// **The additive guarantee, over the wire.** A static credential behaves identically on
/// a gateway with derived keys switched on and on one with the section absent — and on
/// the latter, the derived namespace answers nothing at all.
#[tokio::test]
async fn static_credentials_are_unaffected_and_the_namespace_is_reserved_when_switched_off() {
    let creds = mint(1, "acme");
    for (tag, derived) in [("derived-on", true), ("derived-off", false)] {
        let hx = Harness::boot(tag, 1, derived).await;

        // The static credential: allowed inside its grant, denied outside it, in both
        // configurations.
        let (status, body) = hx
            .get("2024/q1.csv", common::ACCESS_KEY, common::SECRET_KEY)
            .await;
        assert_reached_the_backend(status, &body, &format!("{tag}: static, granted prefix"));
        let (status, body) = hx
            .get("2023/q1.csv", common::ACCESS_KEY, common::SECRET_KEY)
            .await;
        assert_denied_by_policy(status, &body, &format!("{tag}: static, outside the grant"));

        // The derived key: honoured only where the feature is on. With it off the
        // namespace is reserved and answered by nothing — never by the static store.
        let (status, body) = hx
            .get(
                "2024/q1.csv",
                &creds.access_key_id,
                &creds.secret_access_key,
            )
            .await;
        if derived {
            assert_reached_the_backend(status, &body, "derived key with the feature on");
        } else {
            assert_credential_not_honoured(status, &body, "derived key with the feature off");
        }
    }
}
