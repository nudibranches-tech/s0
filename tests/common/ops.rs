//! The enforced operations, with a real typed input for each.
//!
//! Shared because three files need exactly the same list and getting it out of step is
//! the failure mode: `gate_invariants.rs` probes every entry for a hook, a dispatch arm
//! and a minted proof, and `golden_capture.rs` requires each to contribute at least one
//! captured input. Every walk of the list cross-checks itself against
//! `optable::enforced_ops()`, so flipping an operation to `Enforced` without adding it
//! here fails the suite rather than quietly losing coverage.

use s0::access::optable::enforced_ops;
use s3s::dto::*;

pub fn copy_source() -> CopySource {
    CopySource::Bucket {
        bucket: "reports".into(),
        key: "2024/src.csv".into(),
        version_id: None,
    }
}

/// `CopyObjectInput` and `UploadPartCopyInput` are the two enforced inputs with no
/// `Default` — they carry a required `CopySource` — so they go through the builder.
pub fn copy_object_input() -> CopyObjectInput {
    let mut b = CopyObjectInput::builder();
    b.set_bucket("reports".into());
    b.set_key("2024/dst.csv".into());
    b.set_copy_source(copy_source());
    b.build().expect("copy object input")
}

pub fn upload_part_copy_input() -> UploadPartCopyInput {
    let mut b = UploadPartCopyInput::builder();
    b.set_bucket("reports".into());
    b.set_key("2024/dst.csv".into());
    b.set_copy_source(copy_source());
    b.set_part_number(1);
    b.set_upload_id("upload-1".into());
    b.build().expect("upload part copy input")
}

pub fn delete_objects_input() -> DeleteObjectsInput {
    DeleteObjectsInput {
        bucket: "reports".into(),
        bypass_governance_retention: None,
        checksum_algorithm: None,
        delete: Delete {
            objects: vec![ObjectIdentifier {
                key: "2024/x".into(),
                e_tag: None,
                last_modified_time: None,
                size: None,
                version_id: None,
            }],
            ..Default::default()
        },
        expected_bucket_owner: None,
        mfa: None,
        request_payer: None,
    }
}

/// A syntactically real bucket policy that does **not** lock the gateway out.
///
/// It has to be real: the `PutBucketPolicy` hook parses the document and refuses one it
/// cannot read, so `Policy::default()` (the empty string) would exercise the refusal
/// path rather than the allow path in every probe that uses it.
pub const BENIGN_BUCKET_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Sid":"TeamRead","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::acme:user/alice"},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::reports/2024/*"]}]}"#;

/// A policy whose `Deny` names every principal — which necessarily includes the
/// tenant-owner credential the gateway itself re-signs with. The self-lockout shape.
pub const SELF_LOCKOUT_BUCKET_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Sid":"DenyAll","Effect":"Deny","Principal":"*","Action":["s3:*"],"Resource":["arn:aws:s3:::reports/*"]}]}"#;

pub fn put_bucket_policy_input() -> PutBucketPolicyInput {
    PutBucketPolicyInput {
        bucket: "reports".into(),
        policy: BENIGN_BUCKET_POLICY.into(),
        ..Default::default()
    }
}

/// `PutBucketCorsInput` and `PutObjectTaggingInput` carry a required body and so have
/// no `Default`.
pub fn put_bucket_cors_input() -> PutBucketCorsInput {
    PutBucketCorsInput {
        bucket: "reports".into(),
        cors_configuration: CORSConfiguration {
            cors_rules: vec![CORSRule {
                allowed_headers: None,
                allowed_methods: vec!["GET".into()],
                allowed_origins: vec!["https://console.example".into()],
                expose_headers: None,
                id: Some("console".into()),
                max_age_seconds: Some(300),
            }],
        },
        checksum_algorithm: None,
        content_md5: None,
        expected_bucket_owner: None,
    }
}

pub fn put_object_tagging_input() -> PutObjectTaggingInput {
    PutObjectTaggingInput {
        bucket: "reports".into(),
        key: "2024/x".into(),
        tagging: Tagging {
            tag_set: vec![Tag {
                key: Some("tier".into()),
                value: Some("internal".into()),
            }],
        },
        checksum_algorithm: None,
        content_md5: None,
        expected_bucket_owner: None,
        request_payer: None,
        version_id: None,
    }
}

/// Fail unless the operations a probe actually walked are exactly `OP_TABLE`'s
/// enforced set.
pub fn assert_matches_enforced_set(mut seen: Vec<&str>) {
    let mut expected = enforced_ops();
    seen.sort_unstable();
    expected.sort_unstable();
    assert_eq!(
        seen, expected,
        "the probe list in each_enforced_op! and OP_TABLE's Enforced set disagree"
    );
}

/// Apply `$probe!(s3s_method, "OpName", input)` to each enforced operation.
///
/// Types and helpers are fully qualified so the macro does not depend on what the
/// invoking file happens to have imported.
#[macro_export]
macro_rules! each_enforced_op {
    ($probe:ident) => {{
        $probe!(
            abort_multipart_upload,
            "AbortMultipartUpload",
            s3s::dto::AbortMultipartUploadInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                upload_id: "upload-1".into(),
                ..Default::default()
            }
        );
        $probe!(
            complete_multipart_upload,
            "CompleteMultipartUpload",
            s3s::dto::CompleteMultipartUploadInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                upload_id: "upload-1".into(),
                ..Default::default()
            }
        );
        $probe!(
            copy_object,
            "CopyObject",
            $crate::common::ops::copy_object_input()
        );
        $probe!(
            create_bucket,
            "CreateBucket",
            s3s::dto::CreateBucketInput {
                bucket: "reports".into(),
                ..Default::default()
            }
        );
        $probe!(
            create_multipart_upload,
            "CreateMultipartUpload",
            s3s::dto::CreateMultipartUploadInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                ..Default::default()
            }
        );
        $probe!(
            delete_bucket,
            "DeleteBucket",
            s3s::dto::DeleteBucketInput {
                bucket: "reports".into(),
                ..Default::default()
            }
        );
        $probe!(
            delete_object,
            "DeleteObject",
            s3s::dto::DeleteObjectInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                ..Default::default()
            }
        );
        $probe!(
            delete_object_tagging,
            "DeleteObjectTagging",
            s3s::dto::DeleteObjectTaggingInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                ..Default::default()
            }
        );
        $probe!(
            delete_objects,
            "DeleteObjects",
            $crate::common::ops::delete_objects_input()
        );
        $probe!(
            get_bucket_cors,
            "GetBucketCors",
            s3s::dto::GetBucketCorsInput {
                bucket: "reports".into(),
                ..Default::default()
            }
        );
        $probe!(
            get_bucket_location,
            "GetBucketLocation",
            s3s::dto::GetBucketLocationInput {
                bucket: "reports".into(),
                ..Default::default()
            }
        );
        $probe!(
            get_bucket_policy,
            "GetBucketPolicy",
            s3s::dto::GetBucketPolicyInput {
                bucket: "reports".into(),
                ..Default::default()
            }
        );
        $probe!(
            get_object,
            "GetObject",
            s3s::dto::GetObjectInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                ..Default::default()
            }
        );
        $probe!(
            get_object_attributes,
            "GetObjectAttributes",
            s3s::dto::GetObjectAttributesInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                object_attributes: vec![s3s::dto::ObjectAttributes::from_static(
                    s3s::dto::ObjectAttributes::OBJECT_SIZE
                )],
                ..Default::default()
            }
        );
        $probe!(
            get_object_tagging,
            "GetObjectTagging",
            s3s::dto::GetObjectTaggingInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                ..Default::default()
            }
        );
        $probe!(
            head_bucket,
            "HeadBucket",
            s3s::dto::HeadBucketInput {
                bucket: "reports".into(),
                ..Default::default()
            }
        );
        $probe!(
            head_object,
            "HeadObject",
            s3s::dto::HeadObjectInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                ..Default::default()
            }
        );
        $probe!(
            list_buckets,
            "ListBuckets",
            s3s::dto::ListBucketsInput::default()
        );
        $probe!(
            list_multipart_uploads,
            "ListMultipartUploads",
            s3s::dto::ListMultipartUploadsInput {
                bucket: "reports".into(),
                prefix: Some("2024/".into()),
                ..Default::default()
            }
        );
        $probe!(
            list_objects,
            "ListObjects",
            s3s::dto::ListObjectsInput {
                bucket: "reports".into(),
                prefix: Some("2024/".into()),
                ..Default::default()
            }
        );
        $probe!(
            list_objects_v2,
            "ListObjectsV2",
            s3s::dto::ListObjectsV2Input {
                bucket: "reports".into(),
                prefix: Some("2024/".into()),
                ..Default::default()
            }
        );
        $probe!(
            list_parts,
            "ListParts",
            s3s::dto::ListPartsInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                upload_id: "upload-1".into(),
                ..Default::default()
            }
        );
        $probe!(
            post_object,
            "PostObject",
            s3s::dto::PostObjectInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                ..Default::default()
            }
        );
        $probe!(
            put_bucket_cors,
            "PutBucketCors",
            $crate::common::ops::put_bucket_cors_input()
        );
        $probe!(
            put_bucket_policy,
            "PutBucketPolicy",
            $crate::common::ops::put_bucket_policy_input()
        );
        $probe!(
            put_object,
            "PutObject",
            s3s::dto::PutObjectInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                ..Default::default()
            }
        );
        $probe!(
            put_object_tagging,
            "PutObjectTagging",
            $crate::common::ops::put_object_tagging_input()
        );
        $probe!(
            upload_part,
            "UploadPart",
            s3s::dto::UploadPartInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                upload_id: "upload-1".into(),
                part_number: 1,
                ..Default::default()
            }
        );
        $probe!(
            upload_part_copy,
            "UploadPartCopy",
            $crate::common::ops::upload_part_copy_input()
        );
    }};
}
