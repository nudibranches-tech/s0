//! The README claims a supported/unsupported operation split. This holds it to the
//! table: prose cannot be trusted to track a table, but a test can.

use s0::access::optable::{Coverage, DangerTier, GATEWAY_VERBS, OP_TABLE};

const README: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"));

#[test]
fn the_readme_operation_counts_match_the_table() {
    let total = OP_TABLE.len();
    let enforced = OP_TABLE
        .iter()
        .filter(|s| s.coverage == Coverage::Enforced)
        .count();
    let unauthorizable = OP_TABLE
        .iter()
        .filter(|s| s.tier == DangerTier::NeverImplement)
        .count();
    let refused = total - enforced;

    for (claim, what) in [
        (
            format!("**{total}** operations"),
            "the total operation count",
        ),
        (format!("**{enforced}** are enforced"), "the enforced count"),
        (
            format!("other **{refused}** are refused"),
            "the refused count",
        ),
        (
            format!("all {refused} are driven"),
            "the blackbox coverage count",
        ),
        (
            format!("Enforced ({enforced})"),
            "the enforced-section heading",
        ),
        (
            format!("Not supported ({refused})"),
            "the unsupported heading",
        ),
        (
            format!("Structurally unauthorizable — {unauthorizable} operations"),
            "the structurally-unauthorizable count",
        ),
    ] {
        assert!(
            README.contains(&claim),
            "README no longer states {what}: expected to find {claim:?}.\n\
             OP_TABLE now holds {total} operations — {enforced} enforced, {refused} \
             refused, of which {unauthorizable} are structurally unauthorizable.\n\
             Update the 'Supported operations' section rather than this test."
        );
    }
}

#[test]
fn every_enforced_operation_is_named_in_the_readme_table() {
    let missing: Vec<&str> = OP_TABLE
        .iter()
        .filter(|s| s.coverage == Coverage::Enforced)
        .map(|s| s.name)
        .filter(|op| !README.contains(&format!("`{op}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "these operations are Enforced but the README's supported table does not name \
         them: {missing:?}. A reader would believe they are refused."
    );
}

#[test]
fn every_grant_verb_is_named_in_the_readme_table() {
    let missing: Vec<&str> = GATEWAY_VERBS
        .iter()
        .copied()
        .filter(|v| !README.contains(&format!("`{v}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "these grant verbs are grantable but the README does not document them: \
         {missing:?}"
    );
}
