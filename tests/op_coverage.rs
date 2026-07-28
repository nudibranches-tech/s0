//! `OP_TABLE` well-formedness: the table is a security artifact, so these are the
//! checks that hold it to reality rather than to itself.
//!
//! What these prove: the table covers exactly the operation set s3s can route, it is
//! internally consistent, and the enforced set is the reviewed one. What they cannot
//! prove is that a `DangerTier` is *right* — that is what two reviewers on every
//! `Denied → Enforced` diff are for.
//!
//! The companion file `tests/gate_invariants.rs` proves the other half: that every
//! `Enforced` entry really has a hook and a dispatch arm, and that a hook which does
//! not authorize cannot forward.

use std::collections::BTreeSet;

use s0::access::optable::{
    Coverage, DangerTier, FROZEN_VERBS, GateDenial, OP_TABLE, TODAYS_ACTIONS, enforced_ops,
    gate_op, spec,
};

/// The operation names `s3s` 0.14.1 can route, extracted from the pinned crate
/// source. See the regeneration command on `OP_TABLE`. Checked in rather than derived
/// because s3s exposes no enumeration of its operations.
const S3S_OPS: &str = include_str!("data/s3s-0.14.1-ops.txt");

/// s0's own manifest, so a s3s bump cannot silently leave the reference list behind.
const CARGO_TOML: &str = include_str!("../Cargo.toml");

/// The 29-op scope M4 exits on. Checked in now so the target is a diff against a
/// written-down set rather than a number someone remembers — and so that flipping an
/// op to `Enforced` that is NOT in this list is a visible, deliberate act.
const TARGET_ENFORCED: [&str; 29] = [
    // the 15 enforced today
    "AbortMultipartUpload",
    "CompleteMultipartUpload",
    "CopyObject",
    "CreateMultipartUpload",
    "DeleteObject",
    "DeleteObjects",
    "GetObject",
    "HeadObject",
    "ListMultipartUploads",
    "ListObjects",
    "ListObjectsV2",
    "ListParts",
    "PutObject",
    "UploadPart",
    "UploadPartCopy",
    // the 14 M4 adds (S4-tier1/tier2/tagging/getattrs/acl-full/postobject/listbuckets)
    "CreateBucket",
    "DeleteBucket",
    "DeleteBucketLifecycle",
    "DeleteObjectTagging",
    "GetBucketCors",
    "GetBucketLifecycleConfiguration",
    "GetBucketLocation",
    "GetBucketPolicy",
    "GetObjectAttributes",
    "GetObjectTagging",
    "HeadBucket",
    "ListBuckets",
    "PostObject",
    "PutBucketCors",
];

fn s3s_op_names() -> Vec<&'static str> {
    S3S_OPS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

#[test]
fn the_reference_op_list_matches_the_pinned_s3s_version() {
    // If s3s moves, `data/s3s-0.14.1-ops.txt` is stale and every check below is
    // measuring the table against the wrong reality.
    assert!(
        CARGO_TOML.contains("s3s = \"=0.14.1\""),
        "s3s is no longer pinned to =0.14.1; regenerate tests/data/s3s-0.14.1-ops.txt \
         (command is on OP_TABLE), rename it, and re-classify any new operations"
    );
    // s3s-aws is pinned just as hard, and this is the test that says why. The whole
    // "a denied op falls through to NotImplemented" argument rests on which `S3` methods
    // s3s-aws's generated `Proxy` impl overrides — a property of s3s-aws, not of s3s,
    // and one no test in this repo can observe directly. A patch bump that started
    // overriding one more method would turn a denial into a forward with every test
    // still green, so the version is the guard.
    assert!(
        CARGO_TOML.contains("s3s-aws = \"=0.14.1\""),
        "s3s-aws is no longer pinned to =0.14.1; re-read its generated Proxy impl and \
         confirm that the set of overridden S3 methods has not grown before re-pinning"
    );
}

#[test]
fn op_table_covers_every_s3s_operation_and_nothing_else() {
    let s3s: BTreeSet<&str> = s3s_op_names().into_iter().collect();
    let table: BTreeSet<&str> = OP_TABLE.iter().map(|s| s.name).collect();

    assert_eq!(
        s3s.len(),
        99,
        "the s3s 0.14.1 reference list must hold 99 ops"
    );
    assert_eq!(table.len(), OP_TABLE.len(), "OP_TABLE has duplicate names");

    let missing: Vec<_> = s3s.difference(&table).collect();
    let extra: Vec<_> = table.difference(&s3s).collect();
    assert!(
        missing.is_empty(),
        "s3s can route these but OP_TABLE does not classify them (they would be \
         denied as Unknown, but silently — classify them): {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "OP_TABLE classifies operations s3s cannot route: {extra:?}"
    );
}

#[test]
fn exactly_15_enforced_84_denied() {
    // Tightened to 29/70 as M4's exit criterion (task S4-op-scope-test).
    let enforced = enforced_ops();
    let denied = OP_TABLE.len() - enforced.len();
    assert_eq!(
        enforced.len(),
        15,
        "enforced set changed to {enforced:?} — a Denied → Enforced flip needs two \
         reviewers, its hook, its dispatch arm, and this number updated"
    );
    assert_eq!(denied, 84);
}

#[test]
fn every_enforced_op_is_in_the_target_scope() {
    // The target set is the review boundary: an op may only become Enforced if it was
    // already argued for. Adding one to TARGET_ENFORCED is the argument.
    let target: BTreeSet<&str> = TARGET_ENFORCED.into_iter().collect();
    assert_eq!(target.len(), 29, "TARGET_ENFORCED has duplicates");
    for op in enforced_ops() {
        assert!(
            target.contains(op),
            "{op} is Enforced but is not in the reviewed 29-op target scope"
        );
    }
    for op in TARGET_ENFORCED {
        assert!(
            spec(op).is_some(),
            "TARGET_ENFORCED names {op}, which is not an s3s operation"
        );
    }
}

#[test]
fn every_non_enforced_op_is_denied_at_the_gate() {
    // The whole point of the table: nothing without a hook may pass `check`. Driven
    // through `gate_op`, which is the exact function `check` calls — `S3AccessContext`
    // has crate-private fields, so a 99-row table test cannot go through `check`
    // itself. `tests/gate_blackbox.rs` closes that over real HTTP.
    for s in OP_TABLE {
        match s.coverage {
            Coverage::Enforced => {
                assert!(gate_op(s.name).is_ok(), "{} must pass the gate", s.name);
                assert_ne!(
                    s.tier,
                    DangerTier::NeverImplement,
                    "{} is both enforced and structurally unauthorizable",
                    s.name
                );
            }
            Coverage::Denied => {
                let expected = if s.tier == DangerTier::NeverImplement {
                    GateDenial::Unauthorizable
                } else {
                    GateDenial::NotEnforced
                };
                assert_eq!(gate_op(s.name), Err(expected), "{}", s.name);
            }
        }
    }
}

#[test]
fn the_two_structural_denials_are_never_implement() {
    // CreateSession hands the client credentials it uses DIRECTLY against the backend
    // — a permanent, total bypass of this gateway. WriteGetObjectResponse carries no
    // bucket and no key, so there is nothing to authorize. Neither may become
    // policy-deniable, i.e. neither may ever be merely `Denied`.
    let never: Vec<&str> = OP_TABLE
        .iter()
        .filter(|s| s.tier == DangerTier::NeverImplement)
        .map(|s| s.name)
        .collect();
    assert_eq!(never, vec!["CreateSession", "WriteGetObjectResponse"]);
}

#[test]
fn op_table_verbs_are_from_the_frozen_vocabulary() {
    for s in OP_TABLE {
        match s.verb {
            None => assert_eq!(
                s.tier,
                DangerTier::NeverImplement,
                "{} has no verb but is not structurally unauthorizable",
                s.name
            ),
            Some(v) => assert!(
                FROZEN_VERBS.contains(&v),
                "{} maps to {v}, which is not one of the 13 frozen grant verbs",
                s.name
            ),
        }
    }
}

#[test]
fn enforced_verbs_exist_in_todays_action_vocabulary() {
    // An Enforced op must be *decidable* now: its verb has to be one `Action` can
    // express, or the hook could not build an OpaInput for it. S2-verbs widens
    // `Action` to all 13 frozen verbs; until then this is the binding constraint on
    // what may flip to Enforced.
    for s in OP_TABLE.iter().filter(|s| s.coverage == Coverage::Enforced) {
        let verb = s.verb.expect("an enforced op has a verb");
        assert!(
            TODAYS_ACTIONS.iter().any(|a| a.as_str() == verb),
            "{} is Enforced with verb {verb}, which today's Action cannot express",
            s.name
        );
    }
}

#[test]
fn only_enforced_ops_carry_blind_spots() {
    // A blind spot is a statement about what a running hook fails to inspect. On an op
    // nothing reaches it is noise, and noise here erodes the one document a reviewer
    // reads before flipping an op on.
    for s in OP_TABLE {
        if s.coverage != Coverage::Enforced {
            assert!(
                s.blind_spots.is_empty(),
                "{} is denied but claims blind spots",
                s.name
            );
        }
    }
}

#[test]
fn the_acl_header_blind_spot_is_recorded_on_every_op_that_has_it() {
    // Regression guard for the retrofit S2-acl-deny closes: PutObject, CopyObject and
    // CreateMultipartUpload all accept `x-amz-acl` / `x-amz-grant-*`, and today's
    // hooks read only bucket and key. If someone lands the header deny, the fix is to
    // delete these entries — not to leave a stale claim of blindness.
    for op in ["PutObject", "CopyObject", "CreateMultipartUpload"] {
        let s = spec(op).unwrap();
        assert!(
            s.blind_spots
                .iter()
                .any(|b| b.contains("x-amz-acl") || b.contains("x-amz-grant")),
            "{op} must record the ACL-header blind spot until S2-acl-deny lands"
        );
    }
}
