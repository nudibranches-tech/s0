All data extracted. Below is the reference.

---

# s3s 0.14.1 DTO reference — authz input + prefix-rewrite

## `use` paths

All types are re-exported flat from the `s3s::dto` module (`src/dto/mod.rs`):
```rust
// mod.rs
pub use self::generated::*;      // line 19 — all *Input structs, ObjectIdentifier, Delete, type aliases
mod copy_source;                 // line 27
pub use self::copy_source::*;    // line 28 — CopySource, ParseCopySourceError
pub type List<T> = Vec<T>;       // line 51
```
```rust
use s3s::dto::{
    DeleteObjectsInput, Delete, ObjectIdentifier, ObjectIdentifierList,
    CopyObjectInput, CopySource, ParseCopySourceError,
    ListObjectsV2Input, ListObjectsInput,
    GetObjectInput, PutObjectInput, HeadObjectInput, PostObjectInput,
};
```

## Type aliases (the load-bearing fact: keys/prefixes are plain `String`, lists are `Vec`)

| Alias | Definition | gen.rs line |
|---|---|---|
| `BucketName` | `= String` | 833 |
| `ObjectKey` | `= String` | 14329 |
| `ObjectVersionId` | `= String` | 14840 |
| `Prefix` | `= String` | 16038 |
| `Delimiter` | `= String` | 5085 |
| `Token` | `= String` (used for `continuation_token`) | 20720 |
| `StartAfter` | `= String` | 20338 |
| `Marker` | `= String` (v1 pagination) | 13511 |
| `NextToken` | `= String` | 13868 |
| `MaxKeys` | `= i32` | 13519 |
| `KeyCount` | `= i32` | 11514 |
| `AccountId` | `= String` | 192 |
| `Quiet` | `= bool` | 18531 |
| `FetchOwner` | `= bool` | 7506 |
| `ObjectIdentifierList` | `= List<ObjectIdentifier>` → `Vec<ObjectIdentifier>` | 14327 |
| `OptionalObjectAttributesList` | `= List<OptionalObjectAttributes>` | 14916 |

All `*Input` structs are plain `#[non_exhaustive]`-free structs with `pub` fields (macro-free field decls; only `Debug`/builders are macro/hand-generated). Fields are freely mutable in place.

---

## DeleteObjectsInput — multi-delete keys path

`input.delete.objects[].key` — each is a `String`. `delete` is **required (non-Option)**; `objects` is **non-Option `Vec`**; `key` is **non-Option `String`**.

```rust
// generated.rs:4851
pub struct DeleteObjectsInput {
    pub bucket: BucketName,                              // 4870  (String, required)
    pub bypass_governance_retention: Option<BypassGovernanceRetention>,
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    pub delete: Delete,                                 // 4922  (required, NOT Option)
    pub expected_bucket_owner: Option<AccountId>,
    // ... mfa, request_payer (elided, not authz-relevant)
}

// generated.rs:3954
pub struct Delete {
    pub objects: ObjectIdentifierList,   // 3963  = Vec<ObjectIdentifier>, required
    pub quiet: Option<Quiet>,            // 3966  Option<bool>
}

// generated.rs:14275
pub struct ObjectIdentifier {
    pub e_tag: Option<ETag>,                         // 14281
    pub key: ObjectKey,                              // 14288  (String, required)
    pub last_modified_time: Option<LastModifiedTime>,// 14294
    pub size: Option<Size>,                          // 14299
    pub version_id: Option<ObjectVersionId>,         // 14304  Option<String>
}
```
Rewrite loop: `for oid in &mut input.delete.objects { oid.key = rewrite(&oid.key); }`

---

## CopyObjectInput — source is a **parsed enum**, not a raw string

`copy_source` is `CopySource` (a parsed enum), **not** a `String`. Dest is `bucket`/`key` (plain `String`s). All three required.

```rust
// generated.rs:1848
pub struct CopyObjectInput {
    pub bucket: BucketName,            // 1903  dest bucket (String, required)
    pub copy_source: CopySource,       // 2003  source (parsed enum, required)
    pub key: ObjectKey,                // 2154  dest key (String, required)
    // ...acl, metadata, tagging, sse_*, etc. elided
}
```

`CopySource` (`copy_source.rs:20`) — enum, three variants, all fields `Box<str>`:
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum CopySource {
    Bucket {
        bucket: Box<str>,
        key: Box<str>,
        version_id: Option<Box<str>>,
    },
    AccessPoint {
        partition: Box<str>, region: Box<str>, account_id: Box<str>,
        access_point_name: Box<str>, key: Box<str>, version_id: Option<Box<str>>,
    },
    Outpost {
        partition: Box<str>, region: Box<str>, account_id: Box<str>,
        outpost_id: Box<str>, key: Box<str>, version_id: Option<Box<str>>,
    },
}
```
Source bucket/key extraction: only `CopySource::Bucket` carries a bare `bucket`; `AccessPoint`/`Outpost` carry an ARN identity (no plain bucket — bucket is implied by the access-point/outpost). For authz you must match on the variant. Fields are `Box<str>` (rewrite via `key: rewritten.into()` when reconstructing the variant — fields aren't publicly mutable-in-place-friendly since it's an enum; rebuild the variant).

Relevant methods (`copy_source.rs`):
```rust
impl CopySource {
    pub fn parse(header: &str) -> Result<Self, ParseCopySourceError>;   // 263
    pub fn format_to_string(&self) -> String;                          // 295 (#[must_use]) — re-emit header
}
impl http::TryFromHeaderValue for CopySource {                          // 349
    type Error = ParseCopySourceError;
    fn try_from_header_value(val: &http::HeaderValue) -> Result<Self, Self::Error>;
}
```
`ParseCopySourceError` (`copy_source.rs:64`): `PatternMismatch | InvalidBucketName | InvalidKey | InvalidEncoding | InvalidArn | InvalidAccessPointName | InvalidAccountId`. To rewrite the copy source: mutate the `key`/`bucket`, then `format_to_string()` to regenerate the `x-amz-copy-source` header value.

---

## ListObjectsV2Input — prefix rewrite + re-pagination

`prefix`, `continuation_token`, `start_after`, `delimiter` are all `Option<String>`; `max_keys` is `Option<i32>`. `bucket` required.

```rust
// generated.rs:12807 — FULL field list
pub struct ListObjectsV2Input {
    pub bucket: BucketName,                                       // String, required
    pub continuation_token: Option<Token>,                       // Option<String>
    pub delimiter: Option<Delimiter>,                            // Option<String>
    pub encoding_type: Option<EncodingType>,
    pub expected_bucket_owner: Option<AccountId>,
    pub fetch_owner: Option<FetchOwner>,                         // Option<bool>
    pub max_keys: Option<MaxKeys>,                              // Option<i32>
    pub optional_object_attributes: Option<OptionalObjectAttributesList>,
    pub prefix: Option<Prefix>,                                 // Option<String>
    pub request_payer: Option<RequestPayer>,
    pub start_after: Option<StartAfter>,                        // Option<String>
}
```
Output side for re-pagination (`ListObjectsV2Output`, same region): `pub next_continuation_token: Option<NextToken>`, `pub is_truncated: Option<IsTruncated>`, `pub key_count: Option<KeyCount>`, `pub contents: Option<ObjectList>`, `pub common_prefixes: Option<CommonPrefixList>`, `pub prefix/delimiter/start_after/continuation_token` echoed.

## ListObjectsInput (v1)

v1 uses `marker`/`next_marker` instead of continuation tokens. `prefix`, `marker`, `delimiter` are `Option<String>`; `max_keys` `Option<i32>`.
```rust
// generated.rs:12618 — FULL field list
pub struct ListObjectsInput {
    pub bucket: BucketName,                    // String, required
    pub delimiter: Option<Delimiter>,          // Option<String>
    pub encoding_type: Option<EncodingType>,
    pub expected_bucket_owner: Option<AccountId>,
    pub marker: Option<Marker>,                // Option<String>  (v1 cursor)
    pub max_keys: Option<MaxKeys>,             // Option<i32>
    pub optional_object_attributes: Option<OptionalObjectAttributesList>,
    pub prefix: Option<Prefix>,                // Option<String>
    pub request_payer: Option<RequestPayer>,
}
```
v1 output cursor: `pub next_marker: Option<NextMarker>` (only populated when a `delimiter` is set).

---

## GetObject / PutObject / HeadObject — bucket/key are required `String`

All three: `bucket: BucketName` and `key: ObjectKey` — both **plain `String`, non-Option**.

```rust
// generated.rs:9022
pub struct GetObjectInput {
    pub bucket: BucketName,   // 9043
    pub key: ObjectKey,       // 9082
    // ...range, version_id: Option<ObjectVersionId>, part_number, sse_* etc.
}

// generated.rs:17433
pub struct PutObjectInput {
    pub bucket: BucketName,   // 17482
    pub key: ObjectKey,       // 17670
    // ...body: Option<StreamingBlob>, metadata, content_*, sse_*, tagging etc.
}

// generated.rs:10124
pub struct HeadObjectInput {
    pub bucket: BucketName,   // 10143
    pub key: ObjectKey,       // 10229
    // ...range, version_id, part_number etc.
}
```
Rewrite: `input.key = rewrite(&input.key);` directly (it's an owned `String`).

---

## POST form-upload — the blind spot: `PostObjectInput`

**A dedicated POST type exists.** `PostObject` is a **synthetic API in s3s** (not a real AWS SDK op) — see `generated.rs:37902` comment:
> `// NOTE: PostObject is a synthetic API in s3s.`
> `// PostObjectInput has extra fields for POST-specific behavior (success_action_redirect, success_action_status).`

The form-upload **key is carried on `PostObjectInput.key: ObjectKey`** (plain `String`, required) — same shape as PutObject. Bucket on `PostObjectInput.bucket: BucketName`.

```rust
// generated.rs:15331
pub struct PostObjectInput {
    pub bucket: BucketName,   // 15380  (String, required)
    // ...bucket_key_enabled, if_none_match, ...
    pub key: ObjectKey,       // 15568  (String, required)  <-- form-upload key lives here
    pub metadata: Option<Metadata>,
    // ...success_action_redirect / success_action_status (POST-only)
}
```
`PostObjectInput` has a hand-written `Debug` (`generated.rs:15737`), not derived. Conversions to/from `PutObjectInput` are `pub(crate)` and exist in-crate:
```rust
// generated.rs:37904 / 37952  (not public — for reference only)
pub(crate) fn put_object_input_into_post_object_input(x: PutObjectInput) -> PostObjectInput;
pub(crate) fn post_object_input_into_put_object_input(x: PostObjectInput) -> PutObjectInput;
```
Authz/rewrite for POST must be hooked on `PostObjectInput` (the `.key`) independently — it is a distinct operation from `PutObject` in s3s's `S3` trait, so a hook that only covers `put_object` misses form uploads.

---

## Rewrite cheat-sheet (all owned `String`/`Vec`, mutate in place)

| Op | Field path | Type | Mutability |
|---|---|---|---|
| GetObject/PutObject/HeadObject/PostObject | `input.key` | `String` | `input.key = ...` |
| DeleteObjects | `input.delete.objects[i].key` | `String` (in `Vec`) | iterate `&mut`, set `.key` |
| CopyObject (dest) | `input.key` | `String` | `input.key = ...` |
| CopyObject (source) | `input.copy_source` variant `key`/`bucket` | `Box<str>` in enum | rebuild variant, re-emit via `format_to_string()` |
| ListObjectsV2 | `input.prefix` / `.start_after` / `.continuation_token` / `.delimiter` | `Option<String>` | `input.prefix = Some(...)` |
| ListObjects v1 | `input.prefix` / `.marker` / `.delimiter` | `Option<String>` | same |

Bucket fields are `String` (required, non-Option) on every op above **except** `CopySource::AccessPoint`/`Outpost`, where there is no bare bucket — the source is an ARN identity you must match on.
