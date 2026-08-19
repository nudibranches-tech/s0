//! `OP_TABLE` well-formedness: the table is a security artifact, so these checks hold it
//! to reality rather than to itself — it covers exactly the operation set s3s can route,
//! it is internally consistent, and the enforced set is the reviewed one. Whether a
//! `DangerTier` is *right* is what two reviewers on every `Denied → Enforced` diff are
//! for.
//!
//! `tests/gate_invariants.rs` proves the other half: that every `Enforced` entry really
//! has a hook and a dispatch arm, and that a hook which does not authorize cannot
//! forward.

use std::collections::BTreeSet;

use s0::access::optable::{
    Coverage, DangerTier, GATEWAY_VERBS, GateDenial, NON_GATEWAY_VERBS, OP_TABLE, action_for,
    enforced_ops, gate_op, spec,
};
use s0::model::Action;

/// The operation names `s3s` 0.14.1 can route, extracted from the pinned crate
/// source. See the regeneration command on `OP_TABLE`. Checked in rather than derived
/// because s3s exposes no enumeration of its operations.
const S3S_OPS: &str = include_str!("data/s3s-0.14.1-ops.txt");

/// s0's own manifest, so a s3s bump cannot silently leave the reference list behind.
const CARGO_TOML: &str = include_str!("../Cargo.toml");

/// The reviewed enforced scope: 23 operations.
///
/// Checked in so the target is a diff against a written-down set rather than a number
/// someone remembers, and so that flipping an op to `Enforced` that is NOT in this list
/// is a visible, deliberate act. The ops deliberately kept out are named in
/// `RE_DENIED_2026_08_08` rather than silently absent.
const TARGET_ENFORCED: [&str; 23] = [
    // the object data plane
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
    // object tagging, object attributes, the form upload, and the three
    // bucket-EXISTENCE probes every S3 client makes on connect
    "DeleteObjectTagging",
    "GetBucketLocation",
    "GetObjectAttributes",
    "GetObjectTagging",
    "HeadBucket",
    "ListBuckets",
    "PostObject",
    "PutObjectTagging",
];

/// The six control-plane operations that are `Denied` **permanently** rather than
/// pending work, each with its reason.
///
/// The other half of `TARGET_ENFORCED`: that array says what may be enforced, this one
/// says what may not. Without it, adding `CreateBucket` to `TARGET_ENFORCED` would read
/// as restoring something dropped by accident.
const RE_DENIED_2026_08_08: [(&str, &str); 6] = [
    (
        "CreateBucket",
        "a bucket made through S3 has no HFBucket CR: unmanaged, unquota'd, invisible to \
         the console, and absent from the bucket_attributes the denylist is keyed on",
    ),
    (
        "DeleteBucket",
        "destroys a bucket the console still believes it manages",
    ),
    (
        "GetBucketPolicy",
        "the document names the tenant-owner ARN and describes a second, backend-side \
         PDP; reading it is a control-plane question",
    ),
    (
        "PutBucketPolicy",
        "a bucket policy IS a second PDP this gateway does not evaluate, so an Allow \
         written here widens access to a principal no projected grant named",
    ),
    (
        "GetBucketCors",
        "CORS is bucket posture, and posture is control-plane",
    ),
    (
        "PutBucketCors",
        "rule contents were never inspected, so a write-config grant permitted \
         AllowedOrigin `*`",
    ),
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
    // If s3s moves, `data/s3s-0.14.1-ops.txt` is stale and every check below measures
    // the table against the wrong reality.
    assert!(
        CARGO_TOML.contains("s3s = \"=0.14.1\""),
        "s3s is no longer pinned to =0.14.1; regenerate tests/data/s3s-0.14.1-ops.txt \
         (command is on OP_TABLE), rename it, and re-classify any new operations"
    );
    // s3s-aws is pinned just as hard: "a denied op falls through to NotImplemented"
    // rests on which `S3` methods s3s-aws's generated `Proxy` impl overrides, which no
    // test here can observe. A patch bump that overrode one more method would turn a
    // denial into a forward with every test still green, so the pin is the guard.
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
fn exactly_23_enforced_76_denied() {
    // The gateway is data-plane only. The other 76 ops are refused at the gate, before
    // deserialization.
    let enforced = enforced_ops();
    let denied = OP_TABLE.len() - enforced.len();
    assert_eq!(
        enforced.len(),
        23,
        "enforced set changed to {enforced:?} — a Denied → Enforced flip needs two \
         reviewers, its hook, its dispatch arm, and this number updated"
    );
    assert_eq!(denied, 76);
}

#[test]
fn the_re_denied_ops_are_not_quietly_re_enforced() {
    // The count above is the weak form of this claim: an edit could re-enforce
    // `PutBucketPolicy` and deny something else to keep 23/76 true. Naming the six also
    // asserts they are refused by the TABLE rather than by a hook that returns an error.
    let target: BTreeSet<&str> = TARGET_ENFORCED.into_iter().collect();
    for (op, why) in RE_DENIED_2026_08_08 {
        assert!(
            spec(op).is_some(),
            "RE_DENIED_2026_08_08 names {op}, which is not an s3s operation"
        );
        assert_eq!(
            spec(op).unwrap().coverage,
            Coverage::Denied,
            "{op} is Enforced again. It was removed from the gateway's scope on \
             2026-08-08 and the reason has not expired: {why}"
        );
        assert_eq!(gate_op(op), Err(GateDenial::NotEnforced), "{op}");
        assert!(
            !target.contains(op),
            "{op} is back in TARGET_ENFORCED; the two lists now contradict each other"
        );
    }
}

#[test]
fn every_enforced_op_is_in_the_target_scope() {
    // The target set is the review boundary: an op may only become Enforced if it was
    // already argued for. Adding one to TARGET_ENFORCED is the argument.
    let target: BTreeSet<&str> = TARGET_ENFORCED.into_iter().collect();
    assert_eq!(target.len(), 23, "TARGET_ENFORCED has duplicates");
    for op in enforced_ops() {
        assert!(
            target.contains(op),
            "{op} is Enforced but is not in the reviewed 23-op target scope"
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
fn op_table_verbs_are_grantable_or_explicitly_control_plane() {
    // Every row's verb is one of exactly two things: a verb a grant can carry, or a
    // label saying the authority belongs to the control plane. There is no third
    // category — "not classified yet" is how an op ends up Enforced under a verb nobody
    // argued for.
    for s in OP_TABLE {
        match s.verb {
            None => assert_eq!(
                s.tier,
                DangerTier::NeverImplement,
                "{} has no verb but is not structurally unauthorizable",
                s.name
            ),
            Some(v) => assert!(
                GATEWAY_VERBS.contains(&v) || NON_GATEWAY_VERBS.contains(&v),
                "{} maps to {v}, which is neither one of the six projected grant verbs \
                 nor a recorded control-plane label",
                s.name
            ),
        }
    }
    // The strong half: an ENFORCED row may only name a grantable verb. A control-plane
    // label on an enforced op would mean the gateway was deciding an authority no grant
    // can express — which is a decision made by nothing.
    for s in OP_TABLE.iter().filter(|s| s.coverage == Coverage::Enforced) {
        let v = s.verb.expect("an enforced op has a verb");
        assert!(
            GATEWAY_VERBS.contains(&v),
            "{} is Enforced under {v}, which is not a projected grant verb",
            s.name
        );
    }
}

#[test]
fn the_gateway_vocabulary_is_the_six_projected_verbs() {
    // The vocabulary a control plane projects grants into. Changing it is a cross-repo
    // contract change, not a local edit.
    let mut verbs = GATEWAY_VERBS.to_vec();
    verbs.sort_unstable();
    assert_eq!(
        verbs,
        [
            "delete_objects",
            "list_objects",
            "read",
            "read_objects",
            "write_object_tags",
            "write_objects",
        ],
        "the projected vocabulary changed; that is a cross-repo contract change, not a \
         local edit — the control plane's projection must agree"
    );
    let mut removed = NON_GATEWAY_VERBS.to_vec();
    removed.sort_unstable();
    assert_eq!(
        removed,
        [
            "create_bucket",
            "delete_bucket",
            "read_bucket_config",
            "write_bucket_config",
            "write_object_acl",
        ]
    );
    for v in NON_GATEWAY_VERBS {
        assert!(!GATEWAY_VERBS.contains(v), "{v} is in both sets");
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
    // `freeze_writes` is implemented twice: `Action::is_write` on the PEP side and
    // `write_actions` in the rego, which is what actually freezes. A verb one side calls
    // a write and the other does not is a freeze that silently does not cover it.
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
    assert_eq!(
        from_rust.len(),
        3,
        "the write set is 3 verbs: create_bucket, delete_bucket and \
         write_bucket_config left the vocabulary, and write_object_acl with them"
    );
}

#[test]
fn every_bucket_scoped_verb_is_keyless_in_the_rego_too() {
    // The bucket verbs ignore grant prefixes (there is no key to test one against).
    // That is only sound while they are their own verbs: if an object verb joined this
    // set, a `read_objects` grant scoped to `2024/` would confer whole-bucket access.
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
fn the_account_scope_reads_the_same_verb_the_bucket_scope_does() {
    // `read` answers "does this bucket exist, for me?" in both request shapes, and the
    // two sets sharing it is what stops `aws s3 ls` from coming back empty for a
    // principal whose next `head-bucket` succeeds. The sharing is also what makes the
    // rego's shape gates load-bearing, so both halves are asserted: the sets agree with
    // `Action`, and they overlap.
    let rego: &str = include_str!("../policy/gateway/authz.rego");
    let set = |name: &str| -> Vec<String> {
        let start = rego
            .find(&format!("{name} := {{"))
            .unwrap_or_else(|| panic!("the shipped rego must define {name}"));
        let body = &rego[start..];
        let end = body.find('}').expect("set is not closed");
        let mut v: Vec<String> = body[..end]
            .split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect();
        v.sort();
        v
    };
    let typed = |f: fn(Action) -> bool| -> Vec<String> {
        let mut v: Vec<String> = Action::ALL
            .iter()
            .copied()
            .filter(|a| f(*a))
            .map(|a| a.as_str().to_string())
            .collect();
        v.sort();
        v
    };
    assert_eq!(set("account_actions"), typed(Action::is_account_scoped));
    assert_eq!(set("bucket_actions"), typed(Action::is_bucket_scoped));
    assert_eq!(
        set("account_actions"),
        set("bucket_actions"),
        "the existence verb must be readable in both request shapes"
    );
    assert_eq!(set("account_actions"), vec!["read".to_string()]);

    // …and every rule that reads either set carries its shape gate. Stated as a
    // whole-file property because the failure it prevents is silent in opposite
    // directions: an ungated bucket rule lets any wildcard grant answer an account
    // question, and an ungated account rule hangs a `visible_buckets` obligation on a
    // HeadBucket — which `must_understand` turns into a hard deny for every principal.
    let mut checked = 0usize;
    for body in rule_bodies(rego) {
        for (set_name, gate) in [
            ("bucket_actions", "bucket_scoped"),
            ("account_actions", "account_scoped"),
        ] {
            if !body
                .iter()
                .any(|l| l.contains(&format!("input.action in {set_name}")))
            {
                continue;
            }
            checked += 1;
            assert!(
                body.iter().any(|l| l.trim() == gate),
                "a rule body reads `input.action in {set_name}` with no `{gate}` beside \
                 it:\n{}",
                body.join("\n")
            );
        }
    }
    assert!(
        checked >= 3,
        "the rule scanner found only {checked} bodies reading an action set — it has \
         stopped measuring anything (expected the bucket grant rule, the account grant \
         rule and the account obligations rule)"
    );
}

/// Every `{ … }` rule body in a rego module, as its comment-stripped code lines.
///
/// Deliberately dumb: this module is hand-written and one-brace-per-line, so a real
/// parser would be more machinery than the property is worth. If it ever stops finding
/// bodies, the `checked` floor above says so rather than the test silently passing.
fn rule_bodies(rego: &str) -> Vec<Vec<&str>> {
    let mut out = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in rego.lines() {
        let code = line.split('#').next().unwrap_or("");
        if code.trim_end().ends_with('{') {
            current = Some(Vec::new());
            continue;
        }
        if code.trim() == "}"
            && let Some(body) = current.take()
        {
            out.push(body);
            continue;
        }
        if let Some(body) = current.as_mut() {
            body.push(code);
        }
    }
    out
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
    // The ACL headers and the governance-bypass header ARE inspected
    // (`s0::access::headers`, `s0::access::tagging`), so no row may still claim
    // blindness to them: a stale claim is worse than none, because the blind-spot list
    // is the document a reviewer reads before flipping an op on. This is a check on the
    // *table*; the behaviour is proved in `tests/request_riders.rs`.
    for s in OP_TABLE {
        if s.coverage != Coverage::Enforced {
            continue;
        }
        for b in s.blind_spots {
            let claim = b.to_ascii_lowercase();
            // A blind spot may still *mention* ACLs to explain a residual (CreateBucket's
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

    // The two residuals that must stay on the record: object lock, and the tag set a
    // COPY-directive copy inherits.
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
