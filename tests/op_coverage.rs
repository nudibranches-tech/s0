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
    Coverage, DangerTier, FROZEN_VERBS, GateDenial, OP_TABLE, action_for, enforced_ops, gate_op,
    spec,
};
use s0::model::Action;

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
    // the 14 M4 adds (S4-tier1/tier2/tagging/getattrs/postobject/listbuckets).
    //
    // This list was written before the M4 scope was settled and named
    // `GetBucketLifecycleConfiguration` / `DeleteBucketLifecycle`, which the settled
    // scope drops (there is no `manage_lifecycle` verb any more — it was deleted for
    // being a keyless whole-bucket allow), in favour of the write halves of the two
    // config pairs: shipping `GetBucketPolicy`/`GetBucketCors` without their `Put`
    // counterparts leaves an operator able to read a bucket's configuration and unable
    // to fix it.
    "CreateBucket",
    "DeleteBucket",
    "DeleteObjectTagging",
    "GetBucketCors",
    "GetBucketLocation",
    "GetBucketPolicy",
    "GetObjectAttributes",
    "GetObjectTagging",
    "HeadBucket",
    "ListBuckets",
    "PostObject",
    "PutBucketCors",
    "PutBucketPolicy",
    "PutObjectTagging",
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
fn exactly_29_enforced_70_denied() {
    // 15 at the end of M1, +13 for the mechanical half of the M4 op scope, +ListBuckets
    // — the one op that also filters a *response*. This is M4's exit criterion: the
    // reviewed 29-op scope, and the other 70 still refused at the gate.
    let enforced = enforced_ops();
    let denied = OP_TABLE.len() - enforced.len();
    assert_eq!(
        enforced.len(),
        29,
        "enforced set changed to {enforced:?} — a Denied → Enforced flip needs two \
         reviewers, its hook, its dispatch arm, and this number updated"
    );
    assert_eq!(denied, 70);
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
fn enforced_verbs_are_expressible_as_actions() {
    // An Enforced op must be *decidable*: its verb has to be one `Action` can express,
    // or the hook could not build an OpaInput for it.
    for s in OP_TABLE.iter().filter(|s| s.coverage == Coverage::Enforced) {
        let verb = s.verb.expect("an enforced op has a verb");
        assert!(
            action_for(s).is_some(),
            "{} is Enforced with verb {verb}, which `Action` cannot express",
            s.name
        );
    }
}

#[test]
fn the_write_set_matches_the_shipped_rego() {
    // `freeze_writes` is the only kill switch the live bundle carries, and it is
    // implemented twice: `Action::is_write` on the PEP side (which decides nothing
    // today but is what a future write-side guard reads) and `write_actions` in the
    // rego, which is what actually freezes. A verb one side calls a write and the other
    // does not is a freeze that silently does not cover it.
    let rego: &str = include_str!("../policy/gateway/authz.rego");
    let start = rego
        .find("write_actions := {")
        .expect("the shipped rego must define write_actions");
    let body = &rego[start..];
    let end = body.find('}').expect("write_actions is not closed");
    let mut from_rego: Vec<String> = body[..end]
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect();
    let mut from_rust: Vec<String> = Action::ALL
        .iter()
        .filter(|a| a.is_write())
        .map(|a| a.as_str().to_string())
        .collect();
    from_rego.sort();
    from_rust.sort();
    assert_eq!(
        from_rego, from_rust,
        "the rego's write_actions and Action::is_write disagree — freeze_writes covers \
         a different set of verbs on each side"
    );
    assert_eq!(from_rust.len(), 7, "the frozen write set is 7 verbs");
}

#[test]
fn every_bucket_scoped_verb_is_keyless_in_the_rego_too() {
    // The bucket verbs ignore grant prefixes (there is no key to test one against).
    // That is only sound while they are their own verbs — the moment an object verb
    // joined this set, a `read_objects` grant scoped to `2024/` would confer
    // whole-bucket access, which is precisely why `manage_lifecycle` was deleted.
    let rego: &str = include_str!("../policy/gateway/authz.rego");
    let start = rego
        .find("bucket_actions := {")
        .expect("the shipped rego must define bucket_actions");
    let body = &rego[start..];
    let end = body.find('}').expect("bucket_actions is not closed");
    let mut from_rego: Vec<String> = body[..end]
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect();
    let mut from_rust: Vec<String> = Action::ALL
        .iter()
        .filter(|a| a.is_bucket_scoped())
        .map(|a| a.as_str().to_string())
        .collect();
    from_rego.sort();
    from_rust.sort();
    assert_eq!(from_rego, from_rust);
    for verb in &from_rust {
        assert!(
            !verb.contains("objects"),
            "{verb} is keyless in the rego but names objects"
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
fn the_acl_and_retention_blind_spots_are_closed_not_merely_unrecorded() {
    // The inverse of the guard this replaces. Until the M4 retrofit, `PutObject`,
    // `CopyObject`, `CreateMultipartUpload`, `CreateBucket` and `PostObject` were
    // *required* to declare that they did not inspect `x-amz-acl` / `x-amz-grant-*`, and
    // the two delete ops that they did not inspect `x-amz-bypass-governance-retention`.
    // They do now (`s0::access::headers`, `s0::access::tagging`), so the entries had to
    // go — and a stale claim of blindness is worse than none, because the blind-spot list
    // is the document a reviewer reads before flipping an op on.
    //
    // This assertion is about the *table*. The behaviour it corresponds to is proved in
    // `tests/request_riders.rs`, hook by hook and against a wildcard-granted principal.
    for s in OP_TABLE {
        if s.coverage != Coverage::Enforced {
            continue;
        }
        for b in s.blind_spots {
            let claim = b.to_ascii_lowercase();
            // "x-amz-acl / x-amz-grant-* are not inspected" is now false. A blind spot
            // may still *mention* ACLs to explain a residual (CreateBucket's
            // object_ownership does), so the guard is on the header names themselves.
            assert!(
                !claim.contains("x-amz-acl") && !claim.contains("x-amz-grant-"),
                "{} still claims the ACL headers are uninspected; they are screened in \
                 code and authorized as write_object_acl. Delete the entry or fix the \
                 hook: {b}",
                s.name
            );
            assert!(
                !claim.contains("bypass-governance"),
                "{} still claims the governance-bypass header is uninspected; it is \
                 refused in code: {b}",
                s.name
            );
        }
    }

    // The two claims that must NOT have been deleted along with them: the retrofit
    // closed the ACL and the bypass, not object lock or the copy-inherited tag set.
    assert!(
        spec("PutObject")
            .unwrap()
            .blind_spots
            .iter()
            .any(|b| b.contains("object-lock")),
        "PutObject still forwards object-lock headers unauthorized; that residual has to \
         stay on the record"
    );
    assert!(
        spec("CopyObject")
            .unwrap()
            .blind_spots
            .iter()
            .any(|b| b.contains("tagging-directive")),
        "a COPY-directive copy still moves the source object's tags onto a new key \
         without a tag-write decision"
    );
}
