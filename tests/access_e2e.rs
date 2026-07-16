//! End-to-end enforcement through the real `S3Access` typed hooks: principal →
//! OPA input (§5) → regorus decision → obligation/mutation. Exercises the object
//! read/deny path, per-key multi-delete filtering (blind spot #2), and single-prefix
//! list rewrite (§5.1) against the shipped rego — no live backend needed (the hooks
//! only read the routing table, they never open a backend connection).

use std::sync::Arc;

use http::{Extensions, HeaderMap, Method};
use hyperfluid_s3_gateway::access::GatewayAccess;
use hyperfluid_s3_gateway::audit::{self, AuditConfig};
use hyperfluid_s3_gateway::auth::sts::StsAuthority;
use hyperfluid_s3_gateway::auth::{Identity, StaticCredentialStore};
use hyperfluid_s3_gateway::config::GatewayConfig;
use hyperfluid_s3_gateway::gateway::Gateway;
use hyperfluid_s3_gateway::identity::ResolvedPrincipal;
use hyperfluid_s3_gateway::model::PrincipalType;
use hyperfluid_s3_gateway::pdp::{Bundle, BundleStore, CachingPdp, GATEWAY_REGO, Pdp, RegorusPdp};
use hyperfluid_s3_gateway::proxy::BackendRegistry;
use s3s::S3Request;
use s3s::access::S3Access;
use s3s::dto::{
    CreateMultipartUploadInput, Delete, DeleteObjectsInput, GetObjectInput,
    ListMultipartUploadsInput, ListObjectsV2Input, ObjectIdentifier,
};

fn bundle() -> serde_json::Value {
    serde_json::json!({
        "org_settings": { "freeze_writes": false },
        "tenants": { "acme": {
            "user_attributes": {
                "alice": { "groups": [], "attributes": [] },
                "multi": { "groups": [], "attributes": [] }
            },
            "bucket_attributes": { "reports": { "denylist": {} } },
            "s3_grants": {
                "alice": [
                    { "bucket": "reports",
                      "actions": ["read_objects", "list_objects", "write_objects", "delete_objects"],
                      "prefixes": ["2024/"] }
                ],
                "multi": [
                    { "bucket": "reports", "actions": ["list_objects"], "prefixes": ["2024/", "2025/"] }
                ]
            },
            "group_grants": {}
        }}
    })
}

fn config_json() -> String {
    let spill = std::env::temp_dir().join("gw-e2e-audit.ndjson");
    serde_json::json!({
        "listen": "127.0.0.1:0",
        "sts": { "master_key_hex": "00".repeat(32), "signing_key_hex": "11".repeat(32) },
        "pdp": { "mode": "embedded" },
        "audit": { "sink_url": "http://127.0.0.1:59999/none", "spill_path": spill },
        "backends": [
            { "id": "bay-1", "kind": "ceph", "endpoint_url": "http://127.0.0.1:7480" }
        ],
        "tenants": [
            { "tenant": "acme", "organization_id": "org-acme", "backend_id": "bay-1",
              "owner_access_key": "OWNER", "owner_secret_key": "OWNERSECRET" }
        ],
        "bundle_path": "/dev/null"
    })
    .to_string()
}

async fn test_gateway() -> Arc<Gateway> {
    let cfg = GatewayConfig::from_json(&config_json()).expect("config");
    let data = bundle();
    let bundles = Arc::new(BundleStore::new(Bundle::new("rev-1", data.clone())));
    let regorus = RegorusPdp::new(GATEWAY_REGO, &data).expect("regorus");
    let pdp: Arc<dyn Pdp> = Arc::new(CachingPdp::new(
        Arc::new(regorus) as Arc<dyn Pdp>,
        bundles.clone(),
        1000,
    ));
    let identity = Arc::new(Identity::new(
        Arc::new(StsAuthority::new(vec![0u8; 32], vec![1u8; 32]).unwrap()),
        Arc::new(StaticCredentialStore::new()),
    ));
    let registry = Arc::new(BackendRegistry::from_config(&cfg).unwrap());
    let (audit, _audit_handle) = audit::spawn(AuditConfig {
        sink_url: cfg.audit.sink_url.clone(),
        spill_path: cfg.audit.spill_path.clone(),
        ..AuditConfig::default()
    });
    Arc::new(Gateway {
        identity,
        pdp,
        audit,
        registry,
        limits: cfg.limits.clone(),
        bundles,
    })
}

fn alice() -> ResolvedPrincipal {
    ResolvedPrincipal {
        sub: "alice".into(),
        principal_type: PrincipalType::User,
        groups: vec![],
        tenant: "acme".into(),
        organization_id: "org-acme".into(),
    }
}

fn multi() -> ResolvedPrincipal {
    ResolvedPrincipal {
        sub: "multi".into(),
        principal_type: PrincipalType::User,
        groups: vec![],
        tenant: "acme".into(),
        organization_id: "org-acme".into(),
    }
}

fn request<T>(input: T, method: Method) -> S3Request<T> {
    request_as(alice(), input, method)
}

fn request_as<T>(principal: ResolvedPrincipal, input: T, method: Method) -> S3Request<T> {
    let mut extensions = Extensions::new();
    extensions.insert(Arc::new(principal));
    S3Request {
        input,
        method,
        uri: "/".parse().unwrap(),
        headers: HeaderMap::new(),
        extensions,
        credentials: None,
        region: None,
        service: None,
        trailing_headers: None,
    }
}

#[tokio::test]
async fn get_object_within_grant_is_allowed() {
    let access = GatewayAccess::new(test_gateway().await);
    let mut req = request(
        GetObjectInput {
            bucket: "reports".into(),
            key: "2024/q1.csv".into(),
            ..Default::default()
        },
        Method::GET,
    );
    assert!(access.get_object(&mut req).await.is_ok());
}

#[tokio::test]
async fn get_object_outside_grant_is_denied() {
    let access = GatewayAccess::new(test_gateway().await);
    let mut req = request(
        GetObjectInput {
            bucket: "reports".into(),
            key: "2023/old.csv".into(),
            ..Default::default()
        },
        Method::GET,
    );
    assert!(access.get_object(&mut req).await.is_err());
}

#[tokio::test]
async fn multi_delete_filters_to_authorized_keys() {
    let access = GatewayAccess::new(test_gateway().await);
    let oid = |key: &str| ObjectIdentifier {
        e_tag: None,
        key: key.into(),
        last_modified_time: None,
        size: None,
        version_id: None,
    };
    let mut req = request(
        DeleteObjectsInput {
            bucket: "reports".into(),
            bypass_governance_retention: None,
            checksum_algorithm: None,
            delete: Delete {
                objects: vec![oid("2024/a.csv"), oid("2023/b.csv")],
                ..Default::default()
            },
            expected_bucket_owner: None,
            mfa: None,
            request_payer: None,
        },
        Method::POST,
    );
    // At least one key allowed => Ok, and the denied key is stripped from the forward.
    assert!(access.delete_objects(&mut req).await.is_ok());
    let kept: Vec<&str> = req
        .input
        .delete
        .objects
        .iter()
        .map(|o| o.key.as_str())
        .collect();
    assert_eq!(kept, vec!["2024/a.csv"]);
}

#[tokio::test]
async fn unbounded_list_is_narrowed_to_grant_prefix() {
    let access = GatewayAccess::new(test_gateway().await);
    let mut req = request(
        ListObjectsV2Input {
            bucket: "reports".into(),
            prefix: None,
            ..Default::default()
        },
        Method::GET,
    );
    assert!(access.list_objects_v2(&mut req).await.is_ok());
    assert_eq!(req.input.prefix.as_deref(), Some("2024/"));
}

#[tokio::test]
async fn create_multipart_upload_within_grant_is_allowed() {
    let access = GatewayAccess::new(test_gateway().await);
    let mut req = request(
        CreateMultipartUploadInput {
            bucket: "reports".into(),
            key: "2024/big.bin".into(),
            ..Default::default()
        },
        Method::POST,
    );
    assert!(access.create_multipart_upload(&mut req).await.is_ok());
}

#[tokio::test]
async fn create_multipart_upload_outside_prefix_is_denied() {
    let access = GatewayAccess::new(test_gateway().await);
    let mut req = request(
        CreateMultipartUploadInput {
            bucket: "reports".into(),
            key: "2023/big.bin".into(),
            ..Default::default()
        },
        Method::POST,
    );
    assert!(access.create_multipart_upload(&mut req).await.is_err());
}

#[tokio::test]
async fn list_multipart_uploads_is_narrowed_to_grant_prefix() {
    let access = GatewayAccess::new(test_gateway().await);
    let mut req = request(
        ListMultipartUploadsInput {
            bucket: "reports".into(),
            prefix: None,
            ..Default::default()
        },
        Method::GET,
    );
    assert!(access.list_multipart_uploads(&mut req).await.is_ok());
    assert_eq!(req.input.prefix.as_deref(), Some("2024/"));
}

#[tokio::test]
async fn multi_prefix_list_allows_and_stashes_fanout() {
    use hyperfluid_s3_gateway::proxy::fanout::ListFanout;
    let access = GatewayAccess::new(test_gateway().await);
    // `multi` holds list grants on two prefixes; an unbounded list is now allowed with
    // a fan-out obligation (previously it fail-closed).
    let mut req = request_as(
        multi(),
        ListObjectsV2Input {
            bucket: "reports".into(),
            prefix: None,
            ..Default::default()
        },
        Method::GET,
    );
    assert!(access.list_objects_v2(&mut req).await.is_ok());
    let fo = req
        .extensions
        .get::<Arc<ListFanout>>()
        .expect("fan-out obligation stashed");
    assert_eq!(fo.prefixes, vec!["2024/".to_string(), "2025/".to_string()]);
}
