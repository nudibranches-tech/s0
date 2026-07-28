# s0 — data-plane object authorization policy.
#
# This policy does object/prefix/op-level authorization: finer-grained than a plain
# membership + per-bucket denylist check. It consumes a data-plane grant projection
# delivered in the bundle, alongside the membership, denylist, and `freeze_writes`
# data (`user_attributes`, `bucket_attributes`, `org_settings.freeze_writes`).
#
# This module is the gateway's compiled-in DEFAULT policy: what runs for local
# development, and the oracle the dual-engine parity check replays against. In
# production the control plane pushes the authoritative policy module and data as a
# bundle; a data-only bundle leaves this default in force.
#
# It is evaluated once per parsed request (or per sub-decision: one multi-delete
# key, or the source-read / dest-write halves of a copy — the PEP decomposes those
# blind-spot ops into separate questions). The engine reads the single rule
# `data.s3.authz.decision`.
#
# ── input ──────────────────────────────────────────────────────────────────────
#   input.principal.{sub,type,attributes.groups,attributes.<extra>}
#   input.backend.{id,kind}   input.tenant   input.organization_id
#   input.action  ∈ the 13 frozen verbs:
#       object-scoped : read_objects write_objects delete_objects
#                       read_object_tags write_object_tags write_object_acl
#       listing       : list_objects
#       bucket-scoped : read_bucket create_bucket delete_bucket
#                       read_bucket_config write_bucket_config
#       account       : list_buckets
#   input.bucket  — "" for the ACCOUNT scope (list_buckets). Every bucket-scoped rule
#                   below is gated on `input.bucket != ""`, or a `"bucket": "*"` grant
#                   would match the empty string and the per-bucket denylist would be
#                   keyed on a bucket nobody named (plan defect B-2).
#   input.object?  input.prefix?  input.copy_source?  input.delete_keys?
#   input.config_kind?    "policy" | "cors" — which sub-resource a *_bucket_config
#                         decision is about. The vocabulary does not split a verb per
#                         sub-resource, so this is what a policy discriminates on.
#   input.requested_tags? the tag set a write_object_tags request wants to INSTALL
#                         (not the object's current tags, which are input.object_tags
#                         and are never populated). A policy that conditions on tags
#                         should refuse a write that sets the keys it reads.
#   input.acl_grants      ALWAYS present, `[]` when the request asks for no ACL. The
#                         canned x-amz-acl and the five x-amz-grant-* headers,
#                         normalized to [{source, value}]. NOTE: a request carrying a
#                         real grant is decomposed by the PEP into a second decision on
#                         `write_object_acl` for the same object, so a policy does not
#                         have to notice this field to be safe — and a PUBLIC grant is
#                         refused in code before any decision is asked for, because a
#                         wildcard grant would otherwise confer it.
#   input.bypass_governance  ALWAYS present. x-amz-bypass-governance-retention. The PEP
#                         refuses it unconditionally (no verb in the frozen vocabulary
#                         expresses "may override object-lock retention"); it is on the
#                         wire so the attempt is on the audit record.
#
# ── data / grant contract ──────────────────────────────────────────────────────
#   data.org_settings.freeze_writes : bool
#   data.org_settings.reserved_tag_keys : ["hyperfluid/*", ...]
#     Read by the PEP (`s0::access::tagging`), NOT by this module — deliberately, so a
#     pushed policy cannot forget it. Tag keys no S3 caller may write, because a policy
#     may condition grants on them. ABSENT ⇒ every tag write is refused (tagging ships
#     inert). `["*"]` means the same thing explicitly; `[]` means nothing is reserved and
#     is a claim the control plane makes, not a default the gateway assumes.
#   data.tenants[t].user_attributes[sub] : {groups, attributes}
#   data.tenants[t].bucket_attributes[b].denylist[sub] : true
#   data.tenants[t].s3_grants[sub]     : [ Grant ]
#   data.tenants[t].group_grants[group]: [ Grant ]
#     Grant := { "bucket": "<name>" | "*",
#                "actions": ["read_objects", ...] | ["*"],
#                "prefixes": ["reports/", ...] }   # absent/[] ⇒ whole bucket
#
# Deny-by-default. Membership is necessary but NOT sufficient: an explicit
# data-plane grant must match the (action, bucket, object|prefix).

package s3.authz

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ── the single decision the engine reads ────────────────────────────────────────

decision := {
	"allow": allow,
	"reason": reason,
	"obligations": obligations,
}

default allow := false

allow if {
	not frozen
	not denylisted
	member
	grant_matches
}

# ── org-global and per-bucket denies (evaluated ahead of grants) ────────────────

# The verbs `freeze_writes` covers. This set MUST equal `Action::is_write` on the PEP
# side: a verb one side calls a write and the other does not is a hole in the only kill
# switch the live bundle carries. `tests/op_coverage.rs::the_write_set_matches_the_shipped_rego`
# extracts this literal and compares it, so a divergence fails the build.
write_actions := {
	"write_objects",
	"delete_objects",
	"write_object_tags",
	"write_object_acl",
	"create_bucket",
	"delete_bucket",
	"write_bucket_config",
}

# The keyless verbs. They carry no object key, so grant `prefixes` cannot narrow them —
# see `grant_matches` below for why that is safe here and was not for the deleted
# `manage_lifecycle`.
bucket_actions := {
	"read_bucket",
	"create_bucket",
	"delete_bucket",
	"read_bucket_config",
	"write_bucket_config",
}

# Truthy (not `== true`) so a malformed projected value ("true", 1, …) fails toward
# the SAFE direction — frozen/denied — instead of silently faulting open.
frozen if {
	input.action in write_actions
	data.org_settings.freeze_writes
}

# Gated on a non-empty bucket (plan defect B-2). `input.bucket` is "" for the
# account-scoped ops, and a rule keyed on it would then be asking about a bucket nobody
# named — silently false, which is the wrong direction for a *deny* rule to fail in.
# `subject_denylisted_anywhere` below is the account-scope replacement.
denylisted if {
	input.bucket != ""
	data.tenants[input.tenant].bucket_attributes[input.bucket].denylist[input.principal.sub]
}

member if data.tenants[input.tenant].user_attributes[input.principal.sub]

# ── effective grants: per-subject (pre-expanded from roles) ∪ per-group ─────────

grants contains g if some g in data.tenants[input.tenant].s3_grants[input.principal.sub]

# Group membership is read LIVE from the bundle (user_attributes[sub].groups), NOT
# from the caller's token. A token's groups are frozen at mint; sourcing group grants
# from them would make group removal non-revocable until token expiry. The bundle is
# re-projected on every revision, so a group removal lands immediately.
grants contains g if {
	some group in data.tenants[input.tenant].user_attributes[input.principal.sub].groups
	some g in data.tenants[input.tenant].group_grants[group]
}

applicable_grant(g) if {
	bucket_matches(g)
	action_matches(g)
}

bucket_matches(g) if {
	input.bucket != ""
	g.bucket == input.bucket
}

# Plan defect B-2: without the guard, `"bucket": "*"` matches the EMPTY string, so every
# account-scoped decision (input.bucket == "") would be covered by any wildcard grant
# through the ordinary bucket rules. The account scope has its own rules below, and they
# are the only way to reach it.
bucket_matches(g) if {
	input.bucket != ""
	g.bucket == "*"
}

action_matches(g) if input.action in g.actions

action_matches(g) if "*" in g.actions

# A grant with no `prefixes` (or an empty one) scopes the whole bucket.
whole_bucket(g) if not g.prefixes

whole_bucket(g) if count(g.prefixes) == 0

# ── grant matching per request shape ────────────────────────────────────────────

# object ops (get/put/delete-one/head): the key must fall under a granted prefix.
grant_matches if {
	input.object
	some g in grants
	applicable_grant(g)
	object_in_scope(g)
}

object_in_scope(g) if whole_bucket(g)

# Prefixes are LITERAL S3 key prefixes, matched exactly as S3 ListObjects/IAM do:
# a grant on "team" also matches "team-private/x". This is intentional and consistent
# with the backend's own prefix semantics (the key the PDP sees is the canonical key
# that is forwarded, so there is no parser-differential). To isolate a folder,
# author the grant with a trailing slash ("team/"). The projection SHOULD normalize
# folder-scoped grants to end in "/" (ADR-006).
object_in_scope(g) if {
	some p in g.prefixes
	startswith(input.object, p)
}

# Genuinely bucket-level actions — no key, no list semantics.
#
# Restricted to `bucket_actions` ON PURPOSE: a read/write/delete arriving with a
# MISSING object key must NOT fall through to a keyless whole-bucket allow (that
# would bypass the grant's prefix scope). Missing key on an object op ⇒ no rule
# matches ⇒ deny.
#
# These verbs ignore `prefixes`, and that is sound only because they are their OWN
# verbs: nothing here is reachable from a `read_objects`/`write_objects` grant, so a
# principal scoped to `2024/` gets `HeadBucket` if and only if someone granted it
# `read_bucket` on the bucket. This is exactly what made the deleted `manage_lifecycle`
# variant dangerous — it was a keyless whole-bucket allow waiting for an op to reach it.
# The projection SHOULD emit bucket-verb grants with `"prefixes": []` so the data never
# implies a scoping that is not applied (ADR-006).
grant_matches if {
	not input.object
	input.action in bucket_actions
	some g in grants
	applicable_grant(g)
}

# list ops: allowed if a whole-bucket grant applies, or the request overlaps a
# prefix grant (which then drives the narrowing obligation).
grant_matches if {
	input.action == "list_objects"
	not input.object
	whole_bucket_list
}

grant_matches if {
	input.action == "list_objects"
	not input.object
	count(scoped_arr) > 0
}

# ── ListBuckets: the account scope (input.bucket == "") ─────────────────────────
#
# Two separate questions, and conflating them is what makes bucket listings either
# useless or leaky:
#
#   1. MAY this principal enumerate at all?  It holds the `list_buckets` verb somewhere.
#   2. WHICH buckets may it see?             The ones it holds any grant on.
#
# (2) is deliberately not "the buckets it holds `list_buckets` on". A bucket a principal
# can already read or write is not hidden by being absent from its own bucket list — it
# is only made undiscoverable, which breaks `aws s3 ls` without withholding anything the
# caller could not already reach. Enumeration is the capability; visibility follows
# access.
#
# A denial here is NOT a 403 — the PEP answers an empty listing either way, so that "may
# not enumerate" and "has nothing" are indistinguishable to the client. The distinction
# is kept in the audit record. See `GatewayAccess::list_buckets`.
grant_matches if {
	input.action == "list_buckets"
	input.bucket == ""
	some g in grants
	action_matches(g)
}

# The account-scope reading of the per-bucket denylist. It is keyed on a bucket, and this
# decision names none, so the conservative substitution is: a subject denylisted on ANY
# bucket in the tenant loses the unrestricted view and falls back to the enumerated one.
subject_denylisted_anywhere if {
	some b
	data.tenants[input.tenant].bucket_attributes[b].denylist[input.principal.sub]
}

wildcard_bucket_grant if {
	some g in grants
	g.bucket == "*"
}

# Every bucket the subject holds a grant on, minus the ones it is denylisted from.
visible_bucket_set contains g.bucket if {
	some g in grants
	g.bucket != "*"
	not data.tenants[input.tenant].bucket_attributes[g.bucket].denylist[input.principal.sub]
}

visible_bucket_arr := [b | some b in visible_bucket_set]

# The ONLY unfiltered path, and it is not reachable by accident: it needs a wildcard
# grant AND no denylist entry anywhere. With a denylist entry the wildcard is dropped
# rather than trusted — the bundle cannot enumerate the tenant's buckets, so there is no
# way to emit "all except these". The cost is that a wildcard-granted subject with one
# denylisted bucket sees only its explicitly-named grants, which is conservative in the
# safe direction and is recorded as such.
unrestricted_bucket_view if {
	wildcard_bucket_grant
	not subject_denylisted_anywhere
}

bucket_obligations := {"all_buckets_visible": true} if unrestricted_bucket_view

bucket_obligations := {"visible_buckets": visible_bucket_arr} if {
	not unrestricted_bucket_view
	count(visible_bucket_arr) > 0
}

# Allowed to enumerate, nothing to enumerate. `{}` — and the PEP reads an ABSENT
# visible_buckets as NOTHING VISIBLE, the opposite of how it reads an absent
# allowed_prefixes. That asymmetry is the whole reason this branch is safe to leave
# empty.
bucket_obligations := {} if {
	not unrestricted_bucket_view
	count(visible_bucket_arr) == 0
}

# ── list-prefix narrowing: rewrite an unbounded/over-broad list to scope ─────────

requested_prefix := input.prefix

requested_prefix := "" if not input.prefix

whole_bucket_list if {
	some g in grants
	applicable_grant(g)
	whole_bucket(g)
}

# For each prefix grant overlapping the request, the concrete prefix to enumerate:
# the more specific of (grant prefix, requested prefix). Undefined ⇒ no overlap.
narrowed(p, req) := req if startswith(req, p)

narrowed(p, req) := p if {
	startswith(p, req)
	not startswith(req, p)
}

scoped_prefixes contains sp if {
	some g in grants
	applicable_grant(g)
	not whole_bucket(g)
	some p in g.prefixes
	sp := narrowed(p, requested_prefix)
}

scoped_arr := [sp | some sp in scoped_prefixes]

# obligations default to none; only list ops narrow. Ordering of allowed_prefixes
# is normalized in the PEP so the dual-engine parity gate is order-insensitive.
default obligations := {}

obligations := ob if {
	input.action == "list_objects"
	not input.object
	ob := list_obligations
}

obligations := ob if {
	input.action == "list_buckets"
	ob := bucket_obligations
}

list_obligations := {} if whole_bucket_list

list_obligations := {"allowed_prefixes": scoped_arr} if {
	not whole_bucket_list
	count(scoped_arr) > 1
}

list_obligations := {"narrow_prefix": scoped_arr[0]} if {
	not whole_bucket_list
	count(scoped_arr) == 1
	scoped_arr[0] != requested_prefix
}

list_obligations := {} if {
	not whole_bucket_list
	count(scoped_arr) == 1
	scoped_arr[0] == requested_prefix
}

# ── audit-facing reason (deny reasons matter as much as allow) ───────────────────

default reason := "deny: no grant matches action/scope"

reason := "deny: org writes frozen (freeze_writes)" if frozen

reason := "deny: principal on bucket denylist" if {
	not frozen
	denylisted
}

reason := "deny: principal not a tenant member" if {
	not frozen
	not denylisted
	not member
}

reason := "allow: grant matched" if allow
