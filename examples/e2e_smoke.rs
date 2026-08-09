//! End-to-end smoke: drive the running gateway with a real aws-sdk-s3 client and
//! assert allow / deny / narrow, decided by the sidecar OPA over the projected bundle,
//! against a real MinIO backend. Run by `e2e/run.sh`.

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::{Client, Config};

fn client(endpoint: &str, ak: &str, sk: &str) -> Client {
    let conf = Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .force_path_style(true)
        .credentials_provider(Credentials::new(ak, sk, None, None, "e2e"))
        .build();
    Client::from_conf(conf)
}

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

#[tokio::main]
async fn main() {
    let minio = env("MINIO_URL", "http://127.0.0.1:9000");
    let gw = env("GATEWAY_URL", "http://127.0.0.1:8014");
    let admin = client(
        &minio,
        &env("MINIO_AK", "minioadmin"),
        &env("MINIO_SK", "minioadmin"),
    );
    let alice = client(
        &gw,
        &env("ALICE_AK", "alice-akid"),
        &env("ALICE_SK", "alice-secret-key"),
    );

    let mut failures = 0u32;
    let mut check = |name: &str, ok: bool| {
        println!("{}  {name}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            failures += 1;
        }
    };

    // Setup: bucket create is not a gateway op, so provision it on MinIO directly.
    let _ = admin.create_bucket().bucket("data").send().await;

    // Write under the granted prefix -> allow.
    let r = alice
        .put_object()
        .bucket("data")
        .key("2024/report.txt")
        .body(ByteStream::from_static(b"hello"))
        .send()
        .await;
    check("put within grant (2024/) allowed", r.is_ok());

    // Read it back -> allow, body matches.
    let got = match alice
        .get_object()
        .bucket("data")
        .key("2024/report.txt")
        .send()
        .await
    {
        Ok(o) => o
            .body
            .collect()
            .await
            .map(|b| b.into_bytes().to_vec())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    check("get within grant allowed + body matches", got == b"hello");

    // Write outside the granted prefix -> deny.
    let r = alice
        .put_object()
        .bucket("data")
        .key("2025/secret.txt")
        .body(ByteStream::from_static(b"nope"))
        .send()
        .await;
    check("put outside grant (2025/) denied", r.is_err());

    // Unbounded list -> DENIED since 2026-08-09. alice holds only `2024/`, and a list
    // that names no prefix is refused rather than silently rewritten into it (AWS
    // parity; a filtered listing with no signal that it is filtered reads as the whole
    // bucket). Asserted through the real sidecar OPA, so this is the shipped module's
    // answer and not the embedded engine's.
    let r = alice.list_objects_v2().bucket("data").send().await;
    check("unbounded list denied", r.is_err());

    // …and the over-broad-but-overlapping list is still narrowed to the grant, which is
    // the positive control: the deny above is about the ABSENT prefix, not about
    // listing being broken.
    let keys: Vec<String> = match alice
        .list_objects_v2()
        .bucket("data")
        .prefix("20")
        .send()
        .await
    {
        Ok(o) => o
            .contents()
            .iter()
            .filter_map(|x| x.key().map(String::from))
            .collect(),
        Err(_) => Vec::new(),
    };
    check(
        "over-broad list narrowed to 2024/",
        keys == vec!["2024/report.txt".to_string()],
    );

    // Delete -> alice holds no delete_objects grant -> deny.
    let r = alice
        .delete_object()
        .bucket("data")
        .key("2024/report.txt")
        .send()
        .await;
    check("delete denied (no delete_objects grant)", r.is_err());

    if failures == 0 {
        println!("\nALL PASS");
    } else {
        eprintln!("\n{failures} FAILED");
        std::process::exit(1);
    }
}
