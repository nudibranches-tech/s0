# Hyperfluid S3 Authorization Gateway — data-plane object authorization.
#
# This is NET-NEW policy (PROMPT §3.4: nothing in the in-RGW `ceph.rego` does
# object/prefix/op matching — it is membership + per-bucket denylist only). It
# consumes the *target* data-plane grant projection (§3.3, [NOT-YET-BUILT] on the
# console side) while reusing the bundle data that already exists today
# (`user_attributes`, `bucket_attributes`, `org_settings.freeze_writes`).
#
# It is evaluated once per parsed request (or per sub-decision: one multi-delete
# key, or the source-read / dest-write halves of a copy — the PEP decomposes those
# blind-spot ops into separate questions, §5). The engine reads the single rule
# `data.hyperfluid.gateway.decision`.
#
# ── input (PROMPT §5) ──────────────────────────────────────────────────────────
#   input.principal.{sub,type,attributes.groups,attributes.<extra>}
#   input.backend.{id,kind}   input.tenant   input.organization_id
#   input.action  ∈ {read_objects,list_objects,write_objects,delete_objects,manage_lifecycle}
#   input.bucket  input.object?  input.prefix?  input.copy_source?  input.delete_keys?
#
# ── data / grant contract (target projection) ──────────────────────────────────
#   data.org_settings.freeze_writes : bool                       # EXISTS today
#   data.tenants[t].user_attributes[sub] : {groups, attributes}  # EXISTS today
#   data.tenants[t].bucket_attributes[b].denylist[sub] : true    # EXISTS today
#   data.tenants[t].s3_grants[sub]     : [ Grant ]               # NOT-YET-BUILT
#   data.tenants[t].group_grants[group]: [ Grant ]               # NOT-YET-BUILT
#     Grant := { "bucket": "<name>" | "*",
#                "actions": ["read_objects", ...] | ["*"],
#                "prefixes": ["reports/", ...] }   # absent/[] ⇒ whole bucket
#
# Deny-by-default. Membership is necessary but NOT sufficient (unlike ceph.authz):
# an explicit data-plane grant must match the (action, bucket, object|prefix).

package hyperfluid.gateway

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

frozen if {
	input.action in {"write_objects", "delete_objects", "manage_lifecycle"}
	data.org_settings.freeze_writes == true
}

denylisted if data.tenants[input.tenant].bucket_attributes[input.bucket].denylist[input.principal.sub] == true

member if data.tenants[input.tenant].user_attributes[input.principal.sub]

# ── effective grants: per-subject (pre-expanded from roles) ∪ per-group ─────────

grants contains g if some g in data.tenants[input.tenant].s3_grants[input.principal.sub]

# Group membership is read LIVE from the bundle (user_attributes[sub].groups), NOT
# from the caller's token. A token's groups are frozen at mint; sourcing group grants
# from them would make group removal non-revocable until token expiry (violates §6.1).
# The bundle is re-projected on every revision, so a group removal lands immediately.
grants contains g if {
	some group in data.tenants[input.tenant].user_attributes[input.principal.sub].groups
	some g in data.tenants[input.tenant].group_grants[group]
}

applicable_grant(g) if {
	bucket_matches(g)
	action_matches(g)
}

bucket_matches(g) if g.bucket == input.bucket

bucket_matches(g) if g.bucket == "*"

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

object_in_scope(g) if {
	some p in g.prefixes
	startswith(input.object, p)
}

# bucket-level ops without a key or list semantics (e.g. manage_lifecycle).
grant_matches if {
	not input.object
	input.action != "list_objects"
	some g in grants
	applicable_grant(g)
}

# list ops: allowed if a whole-bucket grant applies, or the request overlaps a
# prefix grant (which then drives the narrowing obligation, §5.1).
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

# ── list-prefix narrowing (§5.1): rewrite an unbounded/over-broad list to scope ──

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

# ── audit-facing reason (deny reasons matter as much as allow, §6.6) ─────────────

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
