# ADR-005: PDP engine posture — sidecar OPA by default, embedded regorus only behind a dual-engine parity gate

- **Status**: Accepted — implemented (src/pdp/, tests/parity.rs)
- **Date**: 2026-07-15
- **Scope**: Operationalizes the PDP topology (sidecar default, gated regorus) and the
  decision-cache design. It fixes what the posture leaves open: the definition of "identical
  decisions", the parity-gate CI algorithm and its go/no-go criteria, the engine/version
  pinning discipline, the bundle-feeding topology for the sidecar, and the conditions under
  which the revision-keyed cache stays "correct by construction". Consistent with the settled
  invariants and the engines-through-gateway posture; it does not reopen them.
- **Related**: ADR-001 (drift control *across* policy codebases — this ADR governs drift
  *across engines* evaluating one codebase; both replay the same corpus), ADR-002 (the audit
  record both engines' decisions land in), ADR-003 (tag-bearing inputs are never cached).

---

## Context

### The problem

The PDP is on the hot path of every S3 operation the gateway owns, and the gateway owns every
operation it does not deny. The performance bar: gateway-added latency p99 ≤ low single-digit
ms for non-buffering ops, PDP decision sub-ms cached / ≤ 2ms uncached (sidecar), zero body
copies on GET/PUT. Per-request evaluation is where p99 goes under agent/SDK workloads
(HeadObject/ListObjects storms), and naive TTL caching contradicts live revocation.

The engine posture is settled:

- **Ship with sidecar OPA on loopback.** The same engine as every other PEP in the platform,
  which uses OPA sidecars fed by the policy bundle. ~0.5–2ms per decision including
  serialization — acceptable, boring, zero engine-divergence risk.
- **The fast path is embedded regorus.** It passes the OPA test suite but is "mostly
  compliant": some builtins missing, crypto builtins unsupported by design.
- **Therefore the regorus swap is permitted only behind a dual-engine gate.** Every bundle
  release is replayed through OPA *and* regorus over the golden decision corpus; identical
  decisions required, in CI, before regorus serves traffic. The trait makes the swap a config
  change.

The topology is likewise settled: a gateway-owned sidecar OPA fed by the (superset) bundle
projection, with embedded regorus only behind the dual-engine gate (which the current policy
set would pass — no crypto builtins).

What this ADR decides is everything that turns that posture into an enforceable engineering
artifact: what "identical decisions" means down to field comparison, what the CI job actually
runs and against which pinned versions, what green means before `PdpConfig::Embedded` may
serve traffic, how the sidecar gets its policy and data without introducing version skew, and
which operational conditions the cache-correctness argument silently depends on.

### Why engine divergence is a security problem, not a perf detail

Across multiple policy codebases over one grants source, divergence *is* a bypass. The same
holds one level down for two engines evaluating *one* codebase: an engine that renders a deny
as an allow is an authorization bypass; one that renders an allow as a deny or an error is an
availability regression. Both are silent without a gate, and the divergence surfaces are not
hypothetical — they are verified against regorus 0.10.1:

- **Missing builtins**: all `crypto.*` (by design), all `io.jwt.*`, `graphql.*`,
  `json.patch`, `rego.metadata.*`, `rego.parse_module`,
  `net.cidr_intersects/merge/overlap/contains_matches`, `net.lookup_ip_addr`,
  `providers.aws.*`, `strings.render_template`.
- **`http.send` is a silent trap**: a registered no-op stub returning `Value::Undefined` —
  never performs I/O, never errors. It would not fail compilation and would diverge from OPA
  (which performs real I/O) only at decision time.
- **Error-model mismatch**: regorus defaults to strict builtin errors (builtins raise errors;
  OPA yields undefined; set false for OPA parity). Left at default, an input that trips a
  builtin type edge is an eval `Err` in regorus but a clean default-deny in OPA — observably
  different decisions *and* audit records.
- **Undefined semantics**: a rule whose body fails with no `default` returns `Value::Undefined`
  (Ok, not Err) — both engines must map undefined to deny identically.

The mitigating fact, also verified: the platform's entire Rego policy set stays inside
regorus's supported builtins (`startswith`/`split`/`count`/`contains`/`upper`/`sprintf`/
`some…in`; only one time-of-day rule uses `time.now_ns`/`time.clock`) — **no crypto builtins
anywhere**. The dual-engine parity gate below would pass today; keep new gateway rego inside
that subset.

### What exists vs what is planned (as relevant to this ADR)

**Implemented (this repository):**
- `src/pdp/mod.rs` — `trait Pdp { async fn decide(&self, input: &OpaInput) -> Result<Decision> }`,
  the day-one abstraction. Its contract: any error or undefined result must surface as a deny,
  never an allow.
- `src/pdp/sidecar.rs` — `SidecarPdp`: POSTs `{"input": …}` to OPA's Data API at
  `/v1/data/s3/authz/decision`; request timeout; non-2xx or transport error → `Err` (PEP
  denies); missing/undefined `result` → explicit `Decision::deny("opa: undefined decision")`.
- `src/pdp/embedded.rs` — `RegorusPdp`: data-less base `Engine` with the policy loaded and
  `set_strict_builtin_errors(false)`; per bundle revision it clones the base, `add_data`s the
  bundle, and builds a `regorus::CompiledPolicy` swapped in via `ArcSwap`; `Value::Undefined`
  → explicit `Decision::deny("regorus: undefined decision")`.
- `src/pdp/cache.rs` — `CachingPdp`, the revision-keyed cache (moka, capacity-bounded).
  Key = `revision ␟ full-principal-JSON ␟ resource_key`. Tag-bearing inputs bypass it; errors
  are never cached.
- `src/pdp/bundle.rs` — `GATEWAY_REGO` (the compiled-in default policy, `include_str!`-embedded
  — it is the local-dev policy and the parity oracle; in production the platform pushes the
  active policy as part of the bundle), `DECISION_RULE = "data.s3.authz.decision"`,
  `Bundle { revision, data }`, lock-free `BundleStore`.
- `src/config.rs` — `PdpConfig::Sidecar { base_url, cache_capacity, timeout_ms }` (shipping
  default) vs `PdpConfig::Embedded { cache_capacity }` — the config swap the posture promises.
- `src/authz/decision.rs` — one `Decision { allow, reason, obligations }` shape "produced
  identically by the regorus and sidecar engines so the dual-engine parity gate can compare
  them"; `src/authz/input.rs` — `resource_key()` and `has_on_demand_data()`.
- `policy/gateway/authz.rego` — the net-new gateway policy; uses only `startswith`, `count`,
  `some … in`, rule `contains`/`if`, and comprehensions — all inside regorus's supported set.
  It carries explicit `future.keywords` imports so one source parses under OPA (pre-1.0 and
  1.0) and regorus's default Rego-v1 parser, and it documents that `allowed_prefixes` ordering
  is normalized in the PEP "so the dual-engine parity gate is order-insensitive."
- `policy/testdata/corpus.json` — 23 golden cases over 2 fixture bundles, self-described as
  "engine-agnostic: replayed through BOTH regorus (fast path) and OPA (sidecar) by the
  dual-engine parity gate, and the seed of the conformance corpus."
- `tests/policy_corpus.rs` — the corpus runner. **Regorus-only today**; its header says the
  OPA replay is the missing half: "once the sidecar test harness exists, OPA replays these
  and must produce identical decisions."

**Implemented (control plane, external to this repository):**
- The per-organization gzipped bundle endpoint and bundle builder (implemented, but thin); the
  gateway reuses the delivery mechanism. Today's data shape is `tenants.*.user_attributes` /
  `bucket_attributes` / `org_settings.freeze_writes`; no grants yet.
- OPA sidecars as the platform-wide PEP engine, and the verified fact that the platform's rego
  set sits inside regorus's builtin subset.

**Planned (this repository — follow-ups F1–F6 below):**
- The OPA half of the parity harness and the cross-engine comparator (Mode A below).
- The builtin deny-list lint, the rego input-read-set check, the perf regression gate.
- The bundle poller: `GatewayConfig.bundle_path` is a static file today; production polls the
  control-plane endpoint. The poller carries the D6 ordering and revision-derivation rules.

**External (control plane — see the integration notes at the end):**
- A revision contract on the bundle builder; the bundle-release parity replay (Mode B); a
  pinned sidecar OPA version published to gateway CI; adoption of the corpus as a shared
  platform asset. The grant projection itself (`s3_grants` / `group_grants`) is control-plane
  integration and is only *consumed* here.

---

## Decision

### D1 — Default engine: a gateway-owned sidecar OPA on loopback, fed by the gateway

The gateway ships with `PdpConfig::Sidecar` (`src/config.rs`): one OPA process per gateway
instance, loopback only, no external listener. This is the same engine as every other PEP in
the platform — ~0.5–2ms per decision including serialization, acceptable, boring, zero
engine-divergence risk — with one refinement: it is **gateway-owned**, not a reuse of the
per-organization OPA that serves the in-backend defense-in-depth policy (external). Sharing
that instance would couple the authoritative path's failure domain and upgrade cadence to the
defense-in-depth path (those layers are kept deliberately distinct), and a non-loopback
instance forfeits the latency figure the posture is priced on.

`SidecarPdp` (`src/pdp/sidecar.rs`) is the implementation: OPA Data API, decision path fixed
to `/v1/data/s3/authz/decision` (matching `DECISION_RULE` in `src/pdp/bundle.rs`). Failure
mapping is fail-closed per the trait contract (`src/pdp/mod.rs`): transport error, timeout
(`timeout_ms`, default 2000 — a failure bound, not the latency target of ≤ 2ms), or non-2xx →
`Err` → the PEP denies; an OPA-undefined result → an explicit deny `Decision` with reason
`"opa: undefined decision"`, so the audit record (ADR-002) still carries a reasoned verdict.

**Feeding topology (decided here):** the *gateway* is the single bundle client. It polls the
control-plane bundle endpoint (reusing that delivery mechanism), and it feeds the sidecar over
OPA's REST API: the active policy module is pushed via the policy API, and the bundle's data is
pushed via the data API on install. **The platform pushes the policy (a rego module plus its
data) as the bundle; the compiled-in `GATEWAY_REGO` is the default the gateway loads when no
bundle policy is present, the local-dev policy, and the reference the parity gate replays
against.** The sidecar does **not** poll the control plane independently. Three reasons, each
load-bearing:

1. **No policy skew between engines.** The gateway pushes one policy module to the sidecar and
   loads the byte-identical module into regorus, so both engines evaluate the same rego. The
   parity gate then has exactly two variables: data and engine.
2. **Direct control of the D6(b) publish ordering** (engine data first, cache revision
   second) — impossible to guarantee if the sidecar activates bundles on its own schedule.
3. **One fetch path** for both `PdpConfig` modes, so the poller (F3) is written once.

### D2 — The engine is a config swap behind `trait Pdp`; embedded regorus exists but is gated

`trait Pdp` (`src/pdp/mod.rs`) is the only seam the request path knows; `SidecarPdp` and
`RegorusPdp` both deserialize into the single `Decision` type (`src/authz/decision.rs`), and
`CachingPdp` wraps either uniformly. Flipping engines is exactly the promised config change —
`PdpConfig::Sidecar` ↔ `PdpConfig::Embedded` (`src/config.rs`) — and nothing else.

**Binding rule:** `PdpConfig::Embedded` MUST NOT be set in any environment serving real
traffic unless the D5 go/no-go is green for the exact (policy content, regorus version, OPA
version) triple being deployed. Tests and dev tooling may use the embedded engine freely — it
is already the engine `tests/policy_corpus.rs` runs, which is deliberate: the fast path stays
continuously exercised even while gated out of production.

### D3 — Embedded-engine implementation posture (implemented; recorded because the parity argument depends on it)

Already in `src/pdp/embedded.rs`, matching the verified regorus API:

- **`CompiledPolicy` per (policy, bundle revision), `ArcSwap`-swapped.** Hot-path eval is
  `eval_with_input(&self, …)` — no lock, no per-request engine clone: all eval methods take
  `&mut self`, so one engine must not be shared behind a lock, and one `CompiledPolicy` per
  (policy, data-revision) is swapped on bundle update.
- **Fresh engine per data revision, cloned from a data-less base**, because regorus has no
  data replace (policies can only be added, never removed/replaced; `add_data` is merge-only).
  `RegorusPdp::reload` rebuilds and atomically swaps.
- **`set_strict_builtin_errors(false)`** (`src/pdp/embedded.rs:31-34`) — mandatory for parity:
  regorus's default is strict (builtins raise); OPA yields undefined. Strict mode would turn
  builtin type edges into regorus-only eval errors, i.e. divergence.
- **Undefined → explicit deny** in both engines (missing data ⇒ deny). Note the policy makes
  this a backstop, not a hot path: `authz.rego` defines `default allow := false` and a default
  `reason`, so `decision` is total and undefined arises only if the package itself were
  missing.

### D4 — Gateway rego stays inside regorus's supported builtin subset, enforced statically

The policy's builtin budget is fixed to regorus 0.10.1's supported set. Current usage complies:
`policy/gateway/authz.rego` uses only `startswith`, `count`, `some … in`, rule `contains`/`if`,
and comprehensions.

A CI lint (F2) fails any `policy/gateway/**.rego` matching the denied families:

```
crypto\. | io\.jwt\. | graphql\. | json\.patch | rego\.metadata | rego\.parse_module
net\.cidr_(intersects|merge|overlap|contains_matches) | net\.lookup_ip_addr
providers\.aws\. | strings\.render_template | http\.send
```

The first ten are regorus's verified "Missing" list — those at least fail loudly when a corpus
case exercises them. **`http.send` is banned although nominally "registered"**: it is a silent
no-op returning `Undefined` in regorus, so it cannot be caught by a compile failure and would
diverge from OPA's real I/O only at decision time. It is also architecturally wrong here
regardless of engine: on-demand data enters the decision through the input contract
(`object_tags` in `src/authz/input.rs`, ADR-003), never through policy-side I/O on the hot
path.

### D5 — The dual-engine parity gate

**Definition — "identical decisions."** Comparison happens on the typed `Decision`
(`src/authz/decision.rs`), not on raw JSON — serde already normalizes key order and number
formatting on both paths. Define:

```
canonical(d) := Decision {
    allow:       d.allow,
    reason:      d.reason,                        // byte-equal; reasons are policy-authored
                                                  // constants, so a reason mismatch is a
                                                  // rule-selection divergence signal
    obligations: {
        narrow_prefix:    d.obligations.narrow_prefix,
        allowed_prefixes: sort_lexicographic(d.obligations.allowed_prefixes),
    },
}
```

`allowed_prefixes` is the one order-insensitive field, by design: `authz.rego` builds it from
a set comprehension and documents that "ordering … is normalized in the PEP so the dual-engine
parity gate is order-insensitive"; the corpus asserts it as a multiset. Two decisions are
identical iff `canonical(d_regorus) == canonical(d_opa)` (derived `PartialEq`). **Any engine
`Err` is a gate failure**: production maps `Err` → deny, but that is a safety net, not a
license to diverge — an engine that errors where the other decides is divergent.

(The code comments say "byte-for-byte"; this canonical-struct equality with sorted prefixes is
the normative reading — it is byte-for-byte after the normalization the PEP applies anyway.)

**The corpus.** `policy/testdata/corpus.json`: 23 cases over 2 fixture bundles covering every
grant/prefix/deny/obligation branch, asserting `allow`, `reason_contains`, `narrow_prefix`,
`allowed_prefixes`, `no_obligations`. The policy under test is the compiled-in `GATEWAY_REGO`,
which is the parity oracle and the default the gateway ships; any policy the platform pushes
must clear the same gate before it can be served. The golden corpus is a shared platform
asset, not a repo-only asset; this file is its seed (ADR-001 D3).

**Mode A — repo CI (required check).** Triggers: any change under `policy/`, `src/pdp/`,
`src/authz/`; a regorus version change in `Cargo.lock`; a change to the pinned OPA version
(`.opa-version`); any corpus change.

Algorithm:

1. **Resolve pins.** `OPA_VERSION` from `.opa-version` — this MUST equal the OPA build the
   production sidecar image ships. Regorus comes from `Cargo.lock` (pinned/vendored per the
   dependency posture).
2. **Builtin lint** (D4) over `policy/gateway/**.rego`; fail on any denied builtin.
3. **`opa check --strict policy/gateway/`** under the pinned OPA — the policy must compile
   under OPA itself, not only under regorus.
4. **Dual replay.** For each fixture bundle `B` in the corpus:
   - regorus side: `RegorusPdp::new(GATEWAY_REGO, B)` — the production embedded path,
     including `set_strict_builtin_errors(false)` and `CompiledPolicy` (`src/pdp/embedded.rs`).
   - OPA side: launch the pinned `opa run --server` on loopback; push the policy and `B`
     exactly as production does (D1 feeding topology); drive it through `SidecarPdp`
     (`src/pdp/sidecar.rs`) at the production decision URL.
   - For each case with `case.bundle == B`, compute `d_r` and `d_o`; then:
     a. `Err` from either engine ⇒ **FAIL** (case name + error);
     b. `canonical(d_r) != canonical(d_o)` ⇒ **FAIL** (case name + both decisions);
     c. `canonical(d_r)` must also satisfy the case's golden `expect` ⇒ else **FAIL** —
        golden expectations catch the two engines being *identically wrong*.
5. **Coverage.** Evaluate the corpus under OPA's coverage reporting; any rule of `authz.rego`
   with zero hits ⇒ **FAIL**. A branch no case exercises is a branch the parity claim says
   nothing about. (`tests/policy_corpus.rs` promises full branch coverage by convention today;
   the gate makes it mechanical.)

Implementation note: step 4 is `tests/policy_corpus.rs` extended with the OPA side and the
comparator — one harness, one canonicalization, not a parallel test suite (F1).

**Mode B — bundle-release replay (control-plane CI).** Every bundle release is replayed
through OPA *and* regorus over the golden decision corpus. Fixture bundles cannot stand in for
released data: real projections can carry shapes — missing keys, unexpected types, degenerate
or huge grant lists — that trip builtin edges differently per engine. For each released bundle
revision with data `D`:

1. Replay all corpus case *inputs* against `D` through both engines; require identical
   canonical decisions. (No golden expectations — `D` is real data, the fixtures'
   expectations do not transfer; parity is the assertion. Corpus subjects mostly missing
   from `D` yields matched deny pairs, which is parity-valid but weak — hence step 2.)
2. Synthesized probes: for each grant in `D` (once `s3_grants`/`group_grants` land), generate
   one in-scope and one out-of-scope probe per (subject, bucket, action, prefix) and replay
   through both engines; require identical canonical decisions.
3. Any divergence blocks the bundle release while any embedded-engine gateway is live, and
   alerts the gateway owners regardless.

**Go/no-go — flipping `PdpConfig::Embedded` in a traffic-serving environment.** GO requires
ALL of:

1. Mode A green for the exact deployed triple: `authz.rego` content hash, regorus version
   from `Cargo.lock`, `OPA_VERSION` equal to the running sidecar's version. Zero mismatches,
   zero engine errors.
2. Builtin lint green (D4).
3. Coverage green: 100% of `authz.rego` rules exercised (Mode A step 5).
4. Mode B green over the current production bundle(s) of the organization(s) the flipping
   deployment serves. **Until Mode B exists, this criterion is unsatisfiable and embedded
   regorus is NO-GO in production even with Mode A green** — "every bundle release is
   replayed" is part of the permission, not decoration.
5. Perf-regression gate green with the embedded engine — the flip's benefit is measured, not
   assumed (a perf regression gate in CI, not a heroic optimization phase at the end).
6. Rollback documented as a config-only change back to `Sidecar`. Engine flips are deploys;
   the cache is in-process, so it restarts empty — no decision computed by one engine is ever
   served under the other (D6(d)).

Recommended (it strengthens criterion 4 with real input distributions the corpus cannot
cover): a shadow soak before the flip — the sidecar stays authoritative while regorus
evaluates the same inputs in-process (µs-scale, negligible added cost); a divergence counter
must read zero over the soak window (F6).

NO-GO on any of: a canonical mismatch, any engine error, an unexercised rule, a denied
builtin, or version skew between the CI pins and the deployed artifacts. **Parity is never
grandfathered**: any rego change, regorus bump, or OPA bump re-runs Mode A before deploy.

### D6 — The decision cache: revision-keyed, and why no invalidation logic exists

The design: key the cache on `(bundle_revision, principal, action, resource)`. A revocation
lands as a new bundle revision, so every stale entry misses by construction — no invalidation
logic exists. Cache correctness reduces to bundle-propagation latency, which was already the
policy-freshness bound. This also makes the cache coherent across meshed gateway instances for
free.

Implementation (`src/pdp/cache.rs`, `src/pdp/bundle.rs`, `src/authz/input.rs`):

```
key = revision ␟ principal-JSON ␟ resource_key
resource_key = backend.id ␟ tenant ␟ bucket ␟ action ␟ object ␟ prefix
```

with two deliberate strengthenings over the basic sketch:

- **Full principal, not just `sub`.** Grants expand through groups (`group_grants` in
  `authz.rego`), so two sessions for one `sub` with different group sets must never share a
  verdict (`src/pdp/cache.rs`). Because the key holds the *principal* (sub, type, attributes)
  and not the credential, STS session churn does not fragment the cache — all sessions of one
  identity share entries.
- **Errors are never cached** (`CachingPdp` propagates `Err` without insert) and **tag-bearing
  inputs bypass the cache entirely** (`has_on_demand_data()`): a decision whose input includes
  on-demand data (object tags) is not cached unless that data's version is part of the key, and
  ADR-003 resolves that it is not part of the key, so it is never cached.

**The correctness argument, spelled out:**

1. The policy is a pure function `decide(data, input)`. `authz.rego` reads exactly
   `input.{tenant, action, bucket, object, prefix, principal.sub,
   principal.attributes.groups}` plus `data` — nothing else (notably: it never reads
   `copy_source` or `delete_keys`; the PEP decomposes those blind-spot ops into sub-decisions
   whose `action`/`object` ARE keyed).
2. `data` is identified by the bundle revision (`Bundle { revision, data }`).
3. The key embeds the revision plus a superset of the policy's input read-set (1). Equal keys
   therefore imply equal decisions; every cache hit is sound.
4. A revocation — or any grant/denylist/`freeze_writes` change — lands as a new revision (live
   policy → projection). `BundleStore::store` swaps it atomically; every subsequent lookup keys
   on the new revision, so every entry under the old revision is *unreachable*, not merely
   stale. Staleness is bounded by bundle-propagation latency — which was already the
   policy-freshness bound with no cache at all. The cache adds zero staleness, hence no TTL.
5. **Why no invalidation logic exists:** none is needed, and none could be as safe.
   Invalidation code is code that can be wrong toward allow; unreachable-by-construction
   cannot. Dead entries are garbage, evicted by moka's capacity bound (`cache_capacity`,
   default 100,000 — `src/config.rs`): an efficiency knob, never a correctness one.
6. Mesh coherence is free: every instance pulls the same per-organization bundle
   (version-pinned); same pure function + same key space ⇒ coherent decisions across the mesh
   with no cross-instance channel.

**Conditions the argument depends on** (each enforced or assigned below):

- **(a) Revision uniqueness.** A data change under an unchanged revision would defeat step 4:
  stale allows would persist until capacity eviction — a live-revocation violation. Rather than
  trusting this, the poller (F3) *derives* the effective cache revision as
  `(upstream_revision, sha256(canonical(data)))` at install time — once per bundle, not per
  request. A builder that reuses a revision across differing data then degrades to a loud alert,
  never to staleness. (Hash-keying is sound even without monotonicity: if data genuinely
  reverts, re-reachable old entries are correct for that data — equal data ⇒ equal decisions.)
- **(b) Publish ordering.** The revision published to `BundleStore` must never lead the data
  in the engine. Install order on every bundle update: **(1) engine data first**
  (`RegorusPdp::reload`, or the sidecar data-API push acknowledged), **(2) then
  `BundleStore::store`**. Reversed, a request can compute a key under the *new* revision but
  evaluate against *old* data, caching a stale decision under the current revision —
  persistent poison, not a transient race. (The benign converse — old-revision key, new-data
  eval — self-heals: once the revision swaps, old keys are never looked up again.) The D1
  feeding topology exists partly to make this ordering enforceable in sidecar mode; had the
  sidecar polled the control plane itself, the gateway would have to correlate against OPA's
  reported activated revision instead of controlling the sequence.
- **(c) Key-superset discipline.** The policy's input read-set must remain a subset of the
  cache identity. Today's unkeyed input fields are sound by functional dependency or by
  non-use: `organization_id` and `backend.kind` are functions of `tenant`/`backend.id`;
  `copy_source`/`delete_keys`/`request.*` are never read by the rego. **Standing rule:** any
  policy change that reads a new input field must, in the same change, either extend
  `resource_key()` or route the field through `has_on_demand_data()` so the cache is
  bypassed. Enforced by F4 (a test that extracts `input.` references from `authz.rego` and
  asserts they fall within the documented cache-identity set) plus policy-PR review.
- **(d) No cross-engine carryover.** The cache is in-process; an engine flip is a redeploy
  and starts empty. Given D5 this is belt-and-braces (parity means the engines agree anyway),
  and it is why the key needs no engine identifier.

---

## Alternatives considered

1. **Embedded regorus as the ungated default.** Rejected: the regorus swap is permitted only
   behind a dual-engine gate. The grounds are concrete: regorus is "mostly compliant" with
   verified divergence surfaces (missing `crypto.*`/`io.jwt.*` et al., the `http.send` silent
   no-op, the strict-builtin-errors default), and in a PEP a divergence toward allow is a
   bypass. The µs win is also mostly redundant: the decision cache absorbs the
   HeadObject/ListObjects storms where p99 actually lives, and the sidecar's ~0.5–2ms already
   fits the ≤ 2ms uncached budget.
2. **Reuse the per-organization platform OPA instead of a gateway-owned sidecar.** Rejected:
   the resolved posture is a gateway-owned sidecar OPA fed by the (superset) bundle projection.
   Additionally, that instance serves the in-backend defense-in-depth policy (external) — a
   layer kept distinct from the authoritative path — and sharing couples failure domains and
   upgrade cadence across layers while forfeiting loopback locality.
3. **Sidecar polls the control-plane bundle endpoint itself** (symmetric with the external
   defense-in-depth OPA). Rejected in D1: it reintroduces policy-version skew between engines
   (the sidecar and regorus could load different policy versions), makes the D6(b) ordering
   unenforceable except by polling OPA's status API for the activated revision, and duplicates
   the fetch path. The delivery mechanism is still reused — the gateway is simply its client.
4. **TTL decision cache.** Rejected: naive TTL caching contradicts live revocation. A TTL'd
   allow outlives revocation by up to the TTL; no TTL is both useful and safe.
5. **Event-driven cache invalidation** (subscribe to grant changes, evict matching keys).
   Rejected: it reintroduces exactly the code the revision key designs away ("no invalidation
   logic exists"); correctness would hinge on event delivery — a new liveness dependency for a
   security property — and on match logic that can be wrong toward allow; the mesh would need
   an invalidation bus, forfeiting coherence-by-construction.
6. **OPA-compiled WASM in-process** as the fast path. Rejected: regorus is *the* fast path;
   WASM adds a third execution surface (runtime + SDK glue + its own builtin support matrix)
   that would still need the same parity gate — more moving parts for the same gated outcome.
7. **Permanent dual evaluation** (both engines every request, sidecar authoritative).
   Rejected as steady state: it never converges to the fast path and permanently doubles the
   operated code paths. Retained deliberately as the *bounded* shadow-soak tool in D5's
   go/no-go.
8. **No trait; hardcode the sidecar.** Rejected: the trait is mandated from day one; it
   already exists (`src/pdp/mod.rs`) and is what makes "the swap is a config change" true.

---

## Consequences

**Positive:**
- The default is boring and platform-aligned (same engine as every other PEP); engine
  divergence risk moves from production into a required CI check.
- Engine choice is invisible to the request path: one trait, one `Decision` shape, one cache.
- The p99 defense does not depend on the engine swap: the revision-keyed cache serves storm
  traffic either way, so flipping to regorus is an optimization decided on measurement (the
  perf gate), never a prerequisite for the budget.
- The corpus does triple duty: golden spec of `authz.rego` (`tests/policy_corpus.rs`),
  engine-parity fixture (this ADR), and seed of the cross-layer conformance suite (ADR-001 D3).

**Risks, and what must hold for the security claim:**
1. **Revision/data coherence is the single point of cache correctness.** D6(a) removes the
   trust dependency on the builder by hashing data locally; D6(b)'s publish ordering must be
   implemented in the poller (F3) and is the one place a routine plumbing bug becomes a
   persistent stale-allow. Both are conditions on live revocation holding under load.
2. **Parity is only as strong as the corpus.** An unexercised rego branch is an ungated
   branch. Mode A step 5 makes coverage mechanical; the standing discipline is that every
   policy PR lands with corpus cases for every new branch, and removing a case gets the same
   scrutiny as removing a test.
3. **`strict_builtin_errors(false)` makes builtin type errors silent undefineds in *both*
   engines** — a malformed rule can silently never fire. The failure direction is safe
   (`default allow := false` ⇒ deny), so the residual risk is an allow rule that stops
   allowing — which the golden expectations catch in CI.
4. **Version pinning is part of the claim.** Parity transfers only to the exact
   (rego, regorus, OPA) triple tested; OPA image bumps and `Cargo.lock` regorus bumps re-run
   Mode A before deploy. Never grandfathered.
5. **Cache-key discipline (D6(c)) is a standing obligation** — the one place a routine policy
   change can silently break cache soundness. F4 automates the read-set check.
6. **Sidecar unavailability means full deny** (fail closed) — an availability cost, not an
   integrity one, bounded by `timeout_ms` and mitigated by loopback co-location (partition ≈
   process failure). The gated embedded engine, once earned, removes the dependency.
7. **Until Mode B exists, embedded regorus is NO-GO in production**, however green Mode A is.
   Written into D5 criterion 4 explicitly so "CI is green, flip it" drift cannot happen.

**Follow-ups in this repository:**
- **F1** — OPA half of the parity harness: extend `tests/policy_corpus.rs` with the pinned
  `opa run --server` side driven through `SidecarPdp`, the `canonical()` comparator, and the
  `.opa-version` pin file; wire as a required CI check with the D5 triggers.
- **F2** — builtin deny-list lint over `policy/gateway/**.rego` (D4).
- **F3** — the bundle poller: poll the control-plane endpoint; derive the effective cache
  revision as `(upstream revision, data hash)`; enforce install order data-then-revision; push
  the active policy and data to the sidecar per install (D1/D6).
- **F4** — rego input read-set test: extracted `input.` references ⊆ documented cache
  identity (D6(c)).
- **F5** — perf regression gate: benchmark cached hit, sidecar uncached, embedded uncached
  from CI.
- **F6** — shadow-mode divergence counter behind a config flag (rollout tool for the D5 soak).

---

## Control-plane integration (out of scope for this repository)

These items are implemented by the control plane / platform operations against this
repository's policy and bundle contracts.

**Bundle builder + release pipeline:**

- **Revision contract.** Verify whether the bundle response already carries an etag/manifest
  revision; if not, add one. Guarantee: a new revision on **every** policy-relevant data
  change — `s3_grants`/`group_grants` (once landed), `user_attributes` (including group
  membership), `bucket_attributes.denylist`, `org_settings.freeze_writes`. Expose it
  retrievably so the gateway records it as `Bundle.revision` (`src/pdp/bundle.rs`). The gateway
  hash-guards against violations (D6(a)) but treats one as an incident, not a supported mode.
- **Mode B release gate.** In the bundle-release pipeline: replay the golden corpus inputs plus
  synthesized per-grant probes through pinned OPA *and* pinned regorus over each released
  bundle's data; identical canonical decisions required; divergence blocks release while any
  embedded-engine gateway is live and alerts gateway owners regardless.
- **Corpus adoption.** Take `policy/testdata/corpus.json` as the seed of the shared golden
  corpus; mechanics per ADR-001 D3 (the shared conformance suite across the in-backend
  defense-in-depth policy, an external analytics-engine PEP policy, and the gateway rego).

**Deployment / operations:**

- **OPA pin.** Pin the sidecar OPA image version and publish it to this repository (consumed as
  `.opa-version` by Mode A). OPA upgrades require a green Mode A run at the new version before
  rollout; skew between CI pin and deployed sidecar is a NO-GO condition.
- **Sidecar deployment shape.** One OPA container per gateway pod, loopback only, no external
  listener, no independent control-plane polling: the gateway feeds it the active policy at
  boot and bundle data on install (D1). Health/readiness of the sidecar gates the gateway pod's
  readiness (a gateway without a PDP can only deny).
