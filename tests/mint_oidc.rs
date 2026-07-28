//! End-to-end OIDC verification for the STS mint (the badge desk), with a real
//! RS256 keypair: sign a token with the private key, verify it through the production
//! `StandardVerifier` path (signature + issuer/audience/expiry + claim extraction).
//! No Keycloak needed — the keypair stands in for the IdP's signing key.
//!
//! Plus the JWKS refresh loop, against a real (counting) HTTP endpoint.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use s0::config::StsMintConfig;
use s0::mint::{OidcVerifier, StandardVerifier};

const PRIVATE_PEM: &str = include_str!("testdata/oidc_test_rsa.pem");
const PUBLIC_PEM: &str = include_str!("testdata/oidc_test_rsa_pub.pem");

const ISSUER: &str = "https://kc.example/realms/acme";
const AUDIENCE: &str = "s0";

fn verifier() -> StandardVerifier {
    let cfg = StsMintConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        jwks_uri: None,
        public_key_pem: Some(PUBLIC_PEM.to_string()),
        sub_claim: "sub".into(),
        groups_claim: "groups".into(),
        tenant_claim: "harbor".into(),
        org_claim: "org".into(),
        jwks_timeout_secs: 5,
        jwks_refresh_secs: 300,
    };
    StandardVerifier::from_config(&cfg).expect("verifier")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sign(claims: serde_json::Value) -> String {
    encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn verifies_a_real_rs256_token_and_extracts_identity() {
    let token = sign(serde_json::json!({
        "iss": ISSUER, "aud": AUDIENCE, "exp": now() + 3600,
        "sub": "oidc-sub-alice", "harbor": "acme", "org": "org-acme",
        "groups": ["analysts", "radiology"]
    }));
    let id = verifier().verify(&token).await.expect("verify");
    assert_eq!(id.sub, "oidc-sub-alice");
    assert_eq!(id.tenant, "acme");
    assert_eq!(id.org, "org-acme");
    assert_eq!(
        id.groups,
        vec!["analysts".to_string(), "radiology".to_string()]
    );
}

#[tokio::test]
async fn rejects_wrong_audience() {
    let token = sign(serde_json::json!({
        "iss": ISSUER, "aud": "some-other-service", "exp": now() + 3600,
        "sub": "alice", "harbor": "acme", "org": "org-acme"
    }));
    assert!(verifier().verify(&token).await.is_err());
}

#[tokio::test]
async fn rejects_token_missing_audience() {
    // A token that simply omits `aud` must be rejected, not accepted.
    let token = sign(serde_json::json!({
        "iss": ISSUER, "exp": now() + 3600,
        "sub": "alice", "harbor": "acme", "org": "org-acme"
    }));
    assert!(verifier().verify(&token).await.is_err());
}

#[tokio::test]
async fn rejects_token_missing_issuer() {
    let token = sign(serde_json::json!({
        "aud": AUDIENCE, "exp": now() + 3600,
        "sub": "alice", "harbor": "acme", "org": "org-acme"
    }));
    assert!(verifier().verify(&token).await.is_err());
}

#[tokio::test]
async fn rejects_expired_token() {
    let token = sign(serde_json::json!({
        "iss": ISSUER, "aud": AUDIENCE, "exp": 1_000_000_000u64,
        "sub": "alice", "harbor": "acme", "org": "org-acme"
    }));
    assert!(verifier().verify(&token).await.is_err());
}

#[tokio::test]
async fn rejects_token_signed_by_a_different_key() {
    // A token signed with an HS256 secret must not verify against the RS256 public key.
    let token = encode(
        &Header::new(Algorithm::HS256),
        &serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "exp": now() + 3600,
            "sub": "mallory", "harbor": "acme", "org": "org-acme"
        }),
        &EncodingKey::from_secret(b"attacker-secret"),
    )
    .unwrap();
    assert!(verifier().verify(&token).await.is_err());
}

/// A JWKS endpoint that counts how many times it was fetched.
async fn counting_jwks_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicU64>) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    let hits = Arc::new(AtomicU64::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let served = served.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |_req| {
                    let served = served.clone();
                    async move {
                        served.fetch_add(1, Ordering::Relaxed);
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            http_body_util::Full::new(bytes::Bytes::from_static(br#"{"keys":[]}"#)),
                        ))
                    }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await;
            });
        }
    });
    (format!("http://{addr}/certs"), hits)
}

#[tokio::test]
async fn jwks_is_refreshed_in_the_background_not_only_on_a_kid_miss() {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    let (uri, hits) = counting_jwks_server().await;
    let cfg = StsMintConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        jwks_uri: Some(uri),
        public_key_pem: None,
        sub_claim: "sub".into(),
        groups_claim: "groups".into(),
        tenant_claim: "harbor".into(),
        org_claim: "org".into(),
        jwks_timeout_secs: 5,
        jwks_refresh_secs: 0, // overridden below; 0 must mean "no background task"
    };
    // A zero interval leaves the miss-driven path alone and spawns nothing.
    let off = Arc::new(StandardVerifier::from_config(&cfg).unwrap());
    assert!(off.spawn_jwks_refresh().is_none());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        hits.load(Ordering::Relaxed),
        0,
        "nothing should poll the IdP when the background refresh is off"
    );

    // With an interval, the cache is warmed at startup and kept warm — WITHOUT any
    // mint traffic. Refresh-on-kid-miss alone would show zero fetches here, and would
    // instead make the first request after a key rotation pay (and possibly fail) the
    // fetch, on every replica at once.
    let verifier = Arc::new(
        StandardVerifier::from_config(&StsMintConfig {
            jwks_refresh_secs: 1,
            ..cfg
        })
        .unwrap(),
    );
    let task = verifier.spawn_jwks_refresh().expect("background refresh");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        hits.load(Ordering::Relaxed) >= 1,
        "the key set must be warm before the first request, not one interval later"
    );
    task.abort();
}
