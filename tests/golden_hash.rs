//! Golden values for the two hashes that outlive a single process.
//!
//! An unstable hash is invisible in a single-toolchain test run and shows up in
//! production as a rebuild changing every bundle revision (a fleet-wide decision-cache
//! flush, and two replicas of a rolling update disagreeing about the policy they hold),
//! and as every outstanding list cursor rejected mid-rollout.
//!
//! These are checked-in constants, not self-consistency assertions: a test comparing
//! `f(x) == f(x)` would pass on an unstable hash. Each is reproducible with `sha256sum`.
//! A failure means the hash changed — a cursor- and cache-invalidating decision.

use s0::pdp::content_revision;
use s0::proxy::fanout::{Cursor, scope_hash};

#[test]
fn content_revision_is_pinned_sha256() {
    // `printf '' | sha256sum`
    assert_eq!(
        content_revision(""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // `printf '%s' '{"org_settings":{"freeze_writes":false}}' | sha256sum`
    assert_eq!(
        content_revision(r#"{"org_settings":{"freeze_writes":false}}"#),
        "b420bf2b60b7b13bb5086b2e56eaa7f2311ff57a17c581822bb2c9771d110127"
    );
    // `printf '%s' '{"a":1}' | sha256sum`
    assert_eq!(
        content_revision(r#"{"a":1}"#),
        "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
    );
}

#[test]
fn content_revision_is_content_addressed() {
    let a = content_revision(r#"{"a":1}"#);
    assert_eq!(a.len(), 64, "sha-256 hex digest");
    assert!(
        a.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_ne!(
        a,
        content_revision(r#"{"a":2}"#),
        "a grant change must be a new revision, or a revoked decision stays cached"
    );
}

#[test]
fn scope_hash_is_pinned() {
    // Domain-separated and length-prefixed:
    //   sha256( "s0.fanout.scope.v1\n" || u64be(n) || (u64be(len) || bytes)* )
    assert_eq!(
        scope_hash(&[]),
        "c9816a7d520867b785e393b2da66cbefba2d4cc22955768d81c91c7b65a2cf67"
    );
    assert_eq!(
        scope_hash(&["2024/".to_string()]),
        "4affeb572d187d00f06ed6afdb73775bceb3ed6d39a42a8fd0b2fe5e17cfddfe"
    );
    assert_eq!(
        scope_hash(&["2024/".to_string(), "2025/".to_string()]),
        "cb2960a2fa83fe57fcda51e44847e52a405c5f3c1598dfeb42386f7238b96f3e"
    );
}

#[test]
fn a_pinned_cursor_string_still_decodes_to_the_same_scope() {
    // An encoded cursor is handed to a client and comes back on the next page,
    // possibly to a different replica running a different build. This is the exact
    // string a client holds, byte for byte.
    const ISSUED: &str = "v1.4affeb572d187d00f06ed6afdb73775bceb3ed6d39a42a8fd0b2fe5e17cfddfe.\
                          323032342f7265706f72742e637376";
    let decoded = Cursor::decode(ISSUED).expect("a previously-issued cursor must still decode");
    assert_eq!(decoded.last_key, "2024/report.csv");
    assert_eq!(
        decoded.scope_hash,
        scope_hash(&["2024/".to_string()]),
        "a cursor issued by an earlier build must still match an unchanged grant scope"
    );
    assert_eq!(decoded.encode(), ISSUED, "round-trips byte-identically");
}
