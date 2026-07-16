//! End-to-end OIDC verification for the STS mint (the badge desk), with a real
//! RS256 keypair: sign a token with the private key, verify it through the production
//! `StandardVerifier` path (signature + issuer/audience/expiry + claim extraction).
//! No Keycloak needed — the keypair stands in for the IdP's signing key.

use std::time::{SystemTime, UNIX_EPOCH};

use hyperfluid_s3_gateway::config::StsMintConfig;
use hyperfluid_s3_gateway::mint::{OidcVerifier, StandardVerifier};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

const PRIVATE_PEM: &str = include_str!("testdata/oidc_test_rsa.pem");
const PUBLIC_PEM: &str = include_str!("testdata/oidc_test_rsa_pub.pem");

const ISSUER: &str = "https://kc.example/realms/acme";
const AUDIENCE: &str = "hyperfluid-gateway";

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
