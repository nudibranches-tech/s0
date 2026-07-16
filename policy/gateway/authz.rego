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
# `data.s0.gateway.decision`.
#
# ── input ──────────────────────────────────────────────────────────────────────
#   input.principal.{sub,type,attributes.groups,attributes.<extra>}
#   input.backend.{id,kind}   input.tenant   input.organization_id
#   input.action  ∈ {read_objects,list_objects,write_objects,delete_objects,manage_lifecycle}
#   input.bucket  input.object?  input.prefix?  input.copy_source?  input.delete_keys?
#
# ── data / grant contract ──────────────────────────────────────────────────────
#   data.org_settings.freeze_writes : bool
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

package s0.gateway

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

# Truthy (not `== true`) so a malformed projected value ("true", 1, …) fails toward
# the SAFE direction — frozen/denied — instead of silently faulting open.
frozen if {
	input.action in {"write_objects", "delete_objects", "manage_lifecycle"}
	data.org_settings.freeze_writes
}

denylisted if data.tenants[input.tenant].bucket_attributes[input.bucket].denylist[input.principal.sub]

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

# Genuinely bucket-level actions (manage_lifecycle) — no key, no list semantics.
# Restricted to manage_lifecycle ON PURPOSE: a read/write/delete arriving with a
# MISSING object key must NOT fall through to a keyless whole-bucket allow (that
# would bypass the grant's prefix scope). Missing key on an object op ⇒ no rule
# matches ⇒ deny.
grant_matches if {
	not input.object
	input.action == "manage_lifecycle"
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
