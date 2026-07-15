# ADR-005: PDP engine posture — sidecar OPA by default, embedded regorus only behind a dual-engine parity gate

- **Status**: Proposed
- **Date**: 2026-07-15
- **Scope**: Operationalizes the decided PDP topology of PROMPT §4.3.1 and the decision-cache
  design of §4.3.2. The brief settles the *posture* (sidecar default, gated regorus); it does
  not specify the gate's mechanics. This ADR fixes: the definition of "identical decisions",
  the parity-gate CI algorithm and its go/no-go criteria, the engine/version pinning
  discipline, the bundle-feeding topology for the sidecar, and the conditions under which the
  revision-keyed cache stays "correct by construction". Consistent with the §6 invariants and
  the §6.5 engines-through-gateway posture; it does not reopen them.
- **Related**: ADR-001 (drift control *across* policy codebases — this ADR governs drift
  *across engines* evaluating one codebase; both replay the same corpus), ADR-002 (the audit
  record both engines' decisions land in), ADR-003 (tag-bearing inputs are never cached —
  the §5.2 half of the §4.3.2 exclusion).

---

## Context

### The problem

The PDP is on the hot path of every S3 operation the gateway owns, and the gateway owns every
operation it does not deny (§6.2). The performance bar is written down in §9.5:

> "Target: gateway-added latency p99 ≤ low single-digit ms for non-buffering ops, PDP decision
> sub-ms cached / ≤ 2ms uncached (sidecar), zero body copies on GET/PUT."

and §4.3.2 names where that budget is actually spent:

> "Per-request evaluation is where p99 goes under agent/SDK workloads (HeadObject/ListObjects
> storms). Naive TTL caching contradicts §6.1 (live revocation)."

§4.3.1 already settles the engine posture — it is titled "decided posture":

> "**Ship with sidecar OPA on loopback.** Same engine as every other PEP in the platform (the
> platform uses OPA sidecars fed by the bundle in §3.4). ~0.5–2ms per decision including
> serialization — acceptable, boring, zero engine-divergence risk."
>
> "**The fast path is embedded [`regorus`]** … It passes the OPA test suite but is 'mostly
> compliant': some builtins missing, **crypto builtins unsupported by design**."
>
> "**Therefore: the regorus swap is permitted only behind a dual-engine gate.** Every bundle
> release is replayed through OPA *and* regorus over the golden decision corpus (§7.1);
> identical decisions required, in CI, before regorus serves traffic. The trait makes the swap
> a config change."

The open-questions list confirms the topology half is closed too:

> "**Resolved (§4.3.1):** gateway-owned sidecar OPA fed by the (superset) bundle projection;
> embedded regorus only behind the dual-engine gate (which the current policy set would pass —
> no crypto builtins)."

What the brief leaves open — and what this ADR decides — is everything that turns that
posture into an enforceable engineering artifact: what "identical decisions" means down to
field comparison, what the CI job actually runs and against which pinned versions, what
green means before `PdpConfig::Embedded` may serve traffic, how the sidecar gets its policy
and data without introducing version skew, and which operational conditions the §4.3.2 cache
argument silently depends on.

### Why engine divergence is a security problem, not a perf detail

§7.1 states, about multiple policy codebases over one grants source, that "divergence *is* a
bypass." The same holds one level down for two engines evaluating *one* codebase: an engine
that renders a deny as an allow is an authorization bypass; one that renders an allow as a
deny or an error is an availability regression. Both are silent without a gate, and the
divergence surfaces are not hypothetical — they are verified in
`/home/user/s0-gas/docs/substrate-api.md` §7 against regorus 0.10.1:

- **Missing builtins** (§7.8): all `crypto.*` ("by design"), all `io.jwt.*`, `graphql.*`,
  `json.patch`, `rego.metadata.*`, `rego.parse_module`,
  `net.cidr_intersects/merge/overlap/contains_matches`, `net.lookup_ip_addr`,
  `providers.aws.*`, `strings.render_template`.
- **`http.send` is a silent trap** (§7.8): "a registered no-op stub returning
  `Value::Undefined` — never performs I/O, never errors." It would not fail compilation and
  would diverge from OPA (which performs real I/O) only at decision time.
- **Error-model mismatch** (§7.8): regorus defaults to strict builtin errors ("builtins raise
  errors; OPA yields undefined. Set false for OPA parity"). Left at default, an input that
  trips a builtin type edge is an eval `Err` in regorus but a clean default-deny in OPA —
  observably different decisions *and* audit records.
- **Undefined semantics** (§7.5): "A rule whose body fails with no `default` returns
  `Value::Undefined` (Ok, not Err)" — both engines must map undefined to deny identically.

The mitigating fact, also verified (§4.3.1 v4 note): "the platform's entire Rego policy set
stays inside regorus's supported builtins (`startswith/split/count/contains/upper/sprintf/
some…in`; only a Trino office-hours rule uses `time.now_ns`/`time.clock`) — **no crypto
builtins anywhere**. The dual-engine parity gate below would pass today; keep new gateway
rego inside that subset."

### What EXISTS vs what is NOT-YET-BUILT (as relevant to this ADR)

**EXISTS (this repo):**
- `src/pdp/mod.rs` — `trait Pdp { async fn decide(&self, input: &OpaInput) -> Result<Decision> }`,
  the §4.3.1 day-one abstraction. Its contract: "any error or undefined result must surface as
  a deny, never an allow (§6.2)."
- `src/pdp/sidecar.rs` — `SidecarPdp`: POSTs `{"input": …}` to OPA's Data API at
  `/v1/data/hyperfluid/gateway/decision`; request timeout; non-2xx or transport error →
  `Err` (PEP denies); missing/undefined `result` → explicit
  `Decision::deny("opa: undefined decision")`.
- `src/pdp/embedded.rs` — `RegorusPdp`: data-less base `Engine` with the policy loaded and
  `set_strict_builtin_errors(false)`; per bundle revision it clones the base, `add_data`s the
  bundle, and builds a `regorus::CompiledPolicy` swapped in via `ArcSwap`; `Value::Undefined`
  → explicit `Decision::deny("regorus: undefined decision")`.
- `src/pdp/cache.rs` — `CachingPdp`, the §4.3.2 revision-keyed cache (moka, capacity-bounded).
  Key = `revision ␟ full-principal-JSON ␟ resource_key`. Tag-bearing inputs bypass it; errors
  are never cached.
- `src/pdp/bundle.rs` — `GATEWAY_REGO` (the policy, `include_str!`-embedded: "single source of
  truth for both the shipped rule and the tests"), `DECISION_RULE =
  "data.hyperfluid.gateway.decision"`, `Bundle { revision, data }`, lock-free `BundleStore`.
- `src/config.rs` — `PdpConfig::Sidecar { base_url, cache_capacity, timeout_ms }` (shipping
  default) vs `PdpConfig::Embedded { cache_capacity }` — the config swap §4.3.1 promises.
- `src/authz/decision.rs` — one `Decision { allow, reason, obligations }` shape "produced
  identically by the regorus and sidecar engines so the dual-engine parity gate (§4.3.1) can
  compare them"; `src/authz/input.rs` — `resource_key()` and `has_on_demand_data()`.
- `policy/gateway/authz.rego` — the net-new gateway policy; uses only `startswith`, `count`,
  `some … in`, rule `contains`/`if`, and comprehensions — all inside regorus's supported set.
  It carries explicit `future.keywords` imports so one source parses under OPA (pre-1.0 and
  1.0) and regorus's default Rego-v1 parser, and it documents that `allowed_prefixes`
  ordering is normalized in the PEP "so the dual-engine parity gate is order-insensitive."
- `policy/testdata/corpus.json` — 23 golden cases over 2 fixture bundles, self-described as
  "engine-agnostic: replayed through BOTH regorus (fast path) and OPA (sidecar) by the
  dual-engine parity gate (PROMPT §4.3.1), and the seed of the §7.1 conformance corpus."
- `tests/policy_corpus.rs` — the corpus runner. **Regorus-only today**; its header says the
  OPA replay is the missing half: "once the sidecar test harness exists, OPA replays these
  and must produce identical decisions."

**EXISTS (platform, per the brief — we do not have that repo):**
- The per-Org gzipped bundle endpoint and bundle builder (§3.4) — "[EXISTS, but thin]"; the
  gateway reuses the delivery mechanism. Today's data shape is `tenants.*.user_attributes` /
  `bucket_attributes` / `org_settings.freeze_writes`; no grants.
- OPA sidecars as the platform-wide PEP engine (§4.3.1), and the verified fact that the
  platform's rego set sits inside regorus's builtin subset (§4.3.1 v4 note).

**NOT-YET-BUILT (this repo — follow-ups F1–F6 below):**
- The OPA half of the parity harness and the cross-engine comparator (Mode A below).
- The builtin deny-list lint, the rego input-read-set check, the perf regression gate (§9.5).
- The bundle poller: `GatewayConfig.bundle_path` is a static file today; production polls the
  §3.4 endpoint. The poller carries the D6 ordering and revision-derivation rules.

**NOT-YET-BUILT (platform-side companion — checklist at the end):**
- A revision contract on the bundle builder (C1); the bundle-release parity replay, Mode B
  (C2); a pinned sidecar OPA version published to gateway CI (C3); adoption of the corpus as
  the platform asset §6.5 requires (C4). The grant projection itself (`s3_grants` /
  `group_grants`) is ADR-001/§3.3–§3.4 companion work and is only *consumed* here.

---

## Decision

### D1 — Default engine: a gateway-owned sidecar OPA on loopback, fed by the gateway

The gateway ships with `PdpConfig::Sidecar` (`src/config.rs`): one OPA process per gateway
instance, loopback only, no external listener. This is §4.3.1's choice verbatim — the same
engine as every other PEP in the platform, "~0.5–2ms per decision including serialization —
acceptable, boring, zero engine-divergence risk" — and the resolved open question's
refinement: **gateway-owned**, not a reuse of the per-Org OPA that serves `ceph.authz` to RGW.
Sharing that instance would couple the authoritative path's failure domain and upgrade
cadence to the defense-in-depth path (§6.5/§7.1 keep those layers deliberately distinct), and
a non-loopback instance forfeits the latency figure the posture is priced on.

`SidecarPdp` (`src/pdp/sidecar.rs`) is the implementation: OPA Data API, decision path fixed
to `/v1/data/hyperfluid/gateway/decision` (matching `DECISION_RULE` in `src/pdp/bundle.rs`).
Failure mapping is fail-closed per the trait contract (`src/pdp/mod.rs`): transport error,
timeout (`timeout_ms`, default 2000 — a failure bound, not the latency target; the target is
§9.5's ≤ 2ms), or non-2xx → `Err` → the PEP denies; an OPA-undefined result → an explicit
deny `Decision` with reason `"opa: undefined decision"`, so the audit record (§6.6, ADR-002)
still carries a reasoned verdict.

**Feeding topology (decided here):** the *gateway* is the single bundle client. It polls the
§3.4 console endpoint (reusing that delivery mechanism, as §3.4 instructs), and it feeds the
sidecar over OPA's REST API: the embedded policy (`GATEWAY_REGO`) is pushed once at sidecar
boot via the policy API, and each bundle's data is pushed via the data API on install. The
sidecar does **not** poll the console independently. Three reasons, each load-bearing:

1. **No policy skew between engines.** Both engines evaluate the byte-identical
   `include_str!`-embedded `policy/gateway/authz.rego` (`src/pdp/bundle.rs` already documents
   that "the rego itself … ships embedded in the binary, so a bundle here is data + revision
   only"). The parity gate then has exactly two variables: data and engine.
2. **Direct control of the D6(b) publish ordering** (engine data first, cache revision
   second) — impossible to guarantee if the sidecar activates bundles on its own schedule.
3. **One fetch path** for both `PdpConfig` modes, so the poller (F3) is written once.

### D2 — The engine is a config swap behind `trait Pdp`; embedded regorus exists but is gated

`trait Pdp` (`src/pdp/mod.rs`) is the only seam the request path knows; `SidecarPdp` and
`RegorusPdp` both deserialize into the single `Decision` type (`src/authz/decision.rs`), and
`CachingPdp` wraps either uniformly. Flipping engines is exactly the config change §4.3.1
promises — `PdpConfig::Sidecar` ↔ `PdpConfig::Embedded` (`src/config.rs`) — and nothing else.

**Binding rule:** `PdpConfig::Embedded` MUST NOT be set in any environment serving real
traffic unless the D5 go/no-go is green for the exact (policy content, regorus version, OPA
version) triple being deployed. Tests and dev tooling may use the embedded engine freely — it
is already the engine `tests/policy_corpus.rs` runs, which is deliberate: the fast path stays
continuously exercised even while gated out of production.

### D3 — Embedded-engine implementation posture (implemented; recorded because the parity argument depends on it)

Already in `src/pdp/embedded.rs`, matching the verified regorus API
(`docs/substrate-api.md` §7):

- **`CompiledPolicy` per (policy, bundle revision), `ArcSwap`-swapped.** Hot-path eval is
  `eval_with_input(&self, …)` — no lock, no per-request engine clone — per §7.6/§7.7 ("all
  eval methods take `&mut self` — do not share one engine behind a lock"; "One
  `CompiledPolicy` per (policy, data-revision); swap the shared handle … on bundle update").
- **Fresh engine per data revision, cloned from a data-less base**, because regorus has no
  data replace ("Policies can only be added, never removed/replaced", §7.2; `add_data` is
  merge-only, §7.3). `RegorusPdp::reload` rebuilds and atomically swaps.
- **`set_strict_builtin_errors(false)`** (`src/pdp/embedded.rs:31-34`) — mandatory for
  parity, per §7.8: regorus's default is strict (builtins raise); OPA yields undefined.
  Strict mode would turn builtin type edges into regorus-only eval errors, i.e. divergence.
- **Undefined → explicit deny** in both engines (§6.2 "missing data ⇒ deny"). Note the policy
  makes this a backstop, not a hot path: `authz.rego` defines `default allow := false` and a
  default `reason`, so `decision` is total and undefined arises only if the package itself
  were missing.

### D4 — Gateway rego stays inside regorus's supported builtin subset, enforced statically

Per the §4.3.1 v4 note ("keep new gateway rego inside that subset"), the policy's builtin
budget is fixed to regorus 0.10.1's supported set (`docs/substrate-api.md` §7.8). Current
usage complies: `policy/gateway/authz.rego` uses only `startswith`, `count`, `some … in`,
rule `contains`/`if`, and comprehensions.

A CI lint (F2) fails any `policy/gateway/**.rego` matching the denied families:

```
crypto\. | io\.jwt\. | graphql\. | json\.patch | rego\.metadata | rego\.parse_module
net\.cidr_(intersects|merge|overlap|contains_matches) | net\.lookup_ip_addr
providers\.aws\. | strings\.render_template | http\.send
```

The first ten are regorus's verified "Missing" list — those at least fail loudly when a
corpus case exercises them. **`http.send` is banned although nominally "registered"**: it is
a silent no-op returning `Undefined` in regorus (§7.8 trap), so it cannot be caught by a
compile failure and would diverge from OPA's real I/O only at decision time. It is also
architecturally wrong here regardless of engine: on-demand data enters the decision through
the input contract (§5.2, `object_tags` in `src/authz/input.rs`, ADR-003), never through
policy-side I/O on the hot path.

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
`Err` is a gate failure**: production maps `Err` → deny (§6.2), but that is a safety net, not
a license to diverge — an engine that errors where the other decides is divergent.

(The code comments say "byte-for-byte"; this canonical-struct equality with sorted prefixes is
the normative reading — it is byte-for-byte after the normalization the PEP applies anyway.)

**The corpus.** `policy/testdata/corpus.json`: 23 cases over 2 fixture bundles covering every
grant/prefix/deny/obligation branch, asserting `allow`, `reason_contains`, `narrow_prefix`,
`allowed_prefixes`, `no_obligations`. The policy under test is the embedded `GATEWAY_REGO` —
what is tested is what ships, by construction (`src/pdp/bundle.rs`). Per §6.5 the golden
corpus is "a platform asset, not a repo asset"; this file is its seed (C4, ADR-001 D3).

**Mode A — repo CI (required check).** Triggers: any change under `policy/`, `src/pdp/`,
`src/authz/`; a regorus version change in `Cargo.lock`; a change to the pinned OPA version
(`.opa-version`); any corpus change.

Algorithm:

1. **Resolve pins.** `OPA_VERSION` from `.opa-version` — this MUST equal the OPA build the
   production sidecar image ships (C3). Regorus comes from `Cargo.lock` (pinned/vendored per
   the §9.4 dependency posture).
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
   nothing about. (`tests/policy_corpus.rs` promises full branch coverage by convention
   today; the gate makes it mechanical.)

Implementation note: step 4 is `tests/policy_corpus.rs` extended with the OPA side and the
comparator — one harness, one canonicalization, not a parallel test suite (F1).

**Mode B — bundle-release replay (companion CI, console side — C2).** §4.3.1 requires that
"every bundle release is replayed through OPA *and* regorus over the golden decision corpus."
Fixture bundles cannot stand in for released data: real projections can carry shapes —
missing keys, unexpected types, degenerate or huge grant lists — that trip builtin edges
differently per engine. For each released bundle revision with data `D`:

1. Replay all corpus case *inputs* against `D` through both engines; require identical
   canonical decisions. (No golden expectations — `D` is real data, the fixtures'
   expectations do not transfer; parity is the assertion. Corpus subjects mostly missing
   from `D` yields matched deny pairs, which is parity-valid but weak — hence step 2.)
2. Synthesized probes: for each grant in `D` (once `s3_grants`/`group_grants` land,
   §3.3–§3.4/ADR-001), generate one in-scope and one out-of-scope probe per
   (subject, bucket, action, prefix) and replay through both engines; require identical
   canonical decisions.
3. Any divergence blocks the bundle release while any embedded-engine gateway is live, and
   alerts the gateway owners regardless.

**Go/no-go — flipping `PdpConfig::Embedded` in a traffic-serving environment.** GO requires
ALL of:

1. Mode A green for the exact deployed triple: `authz.rego` content hash, regorus version
   from `Cargo.lock`, `OPA_VERSION` equal to the running sidecar's version. Zero mismatches,
   zero engine errors.
2. Builtin lint green (D4).
3. Coverage green: 100% of `authz.rego` rules exercised (Mode A step 5).
4. Mode B green over the current production bundle(s) of the org(s) the flipping deployment
   serves. **Until C2 exists, this criterion is unsatisfiable and embedded regorus is NO-GO
   in production even with Mode A green** — §4.3.1's "every bundle release is replayed" is
   part of the permission, not decoration.
5. §9.5 perf-regression gate green with the embedded engine — the flip's benefit is measured,
   not assumed ("a perf regression gate in CI, not a heroic optimization phase at the end").
6. Rollback documented as a config-only change back to `Sidecar`. Engine flips are deploys;
   the cache is in-process, so it restarts empty — no decision computed by one engine is ever
   served under the other (D6(d)).

Recommended (not brief-required; it strengthens criterion 4 with real input distributions the
corpus cannot cover): a shadow soak before the flip — the sidecar stays authoritative while
regorus evaluates the same inputs in-process (µs-scale, negligible added cost); a divergence
counter must read zero over the soak window (F6).

NO-GO on any of: a canonical mismatch, any engine error, an unexercised rule, a denied
builtin, or version skew between the CI pins and the deployed artifacts. **Parity is never
grandfathered**: any rego change, regorus bump, or OPA bump re-runs Mode A before deploy.

### D6 — The decision cache: revision-keyed, and why no invalidation logic exists

§4.3.2, verbatim, is the design:

> "Key the cache on `(bundle_revision, principal, action, resource)`. A revocation lands as a
> new bundle revision, so every stale entry misses by construction — no invalidation logic
> exists. Cache correctness reduces to bundle-propagation latency, which was already the
> policy-freshness bound. This also makes the cache coherent across meshed gateway instances
> for free (§9.3)."

Implementation (`src/pdp/cache.rs`, `src/pdp/bundle.rs`, `src/authz/input.rs`):

```
key = revision ␟ principal-JSON ␟ resource_key
resource_key = backend.id ␟ tenant ␟ bucket ␟ action ␟ object ␟ prefix
```

with two deliberate strengthenings over the §4.3.2 sketch:

- **Full principal, not just `sub`.** Grants expand through groups
  (`group_grants` in `authz.rego`), so two sessions for one `sub` with different group sets
  must never share a verdict (`src/pdp/cache.rs`). Because the key holds the *principal*
  (sub, type, attributes) and not the credential, STS session churn does not fragment the
  cache — all sessions of one identity share entries.
- **Errors are never cached** (`CachingPdp` propagates `Err` without insert) and
  **tag-bearing inputs bypass the cache entirely** (`has_on_demand_data()`, per §4.3.2's "Do
  not cache decisions whose input includes on-demand data (object tags, §5.2) unless that
  data's version is part of the key" — resolved in ADR-003 as: it is not part of the key, so
  it is never cached).

**The correctness argument, spelled out:**

1. The policy is a pure function `decide(data, input)`. `authz.rego` reads exactly
   `input.{tenant, action, bucket, object, prefix, principal.sub,
   principal.attributes.groups}` plus `data` — nothing else (notably: it never reads
   `copy_source` or `delete_keys`; the PEP decomposes those blind-spot ops into sub-decisions
   whose `action`/`object` ARE keyed).
2. `data` is identified by the bundle revision (`Bundle { revision, data }`).
3. The key embeds the revision plus a superset of the policy's input read-set (1). Equal keys
   therefore imply equal decisions; every cache hit is sound.
4. A revocation — or any grant/denylist/`freeze_writes` change — lands as a new revision
   (§6.1 live policy → §3.4 projection). `BundleStore::store` swaps it atomically; every
   subsequent lookup keys on the new revision, so every entry under the old revision is
   *unreachable*, not merely stale. Staleness is bounded by bundle-propagation latency —
   "which was already the policy-freshness bound" with no cache at all. The cache adds zero
   staleness, hence no TTL.
5. **Why no invalidation logic exists:** none is needed, and none could be as safe.
   Invalidation code is code that can be wrong toward allow; unreachable-by-construction
   cannot. Dead entries are garbage, evicted by moka's capacity bound
   (`cache_capacity`, default 100,000 — `src/config.rs`): an efficiency knob, never a
   correctness one.
6. Mesh coherence is free (§9.3): every instance pulls "the same per-Org bundle
   (version-pinned)"; same pure function + same key space ⇒ coherent decisions across the
   mesh with no cross-instance channel.

**Conditions the argument depends on** (each enforced or assigned below):

- **(a) Revision uniqueness.** A data change under an unchanged revision would defeat step 4:
  stale allows would persist until capacity eviction — a §6.1 violation. Rather than trusting
  this, the poller (F3) *derives* the effective cache revision as
  `(upstream_revision, sha256(canonical(data)))` at install time — once per bundle, not per
  request. A builder that violates C1 then degrades to a loud alert (revision reused across
  differing data), never to staleness. (Hash-keying is sound even without monotonicity: if
  data genuinely reverts, re-reachable old entries are correct for that data — equal data ⇒
  equal decisions.)
- **(b) Publish ordering.** The revision published to `BundleStore` must never lead the data
  in the engine. Install order on every bundle update: **(1) engine data first**
  (`RegorusPdp::reload`, or the sidecar data-API push acknowledged), **(2) then
  `BundleStore::store`**. Reversed, a request can compute a key under the *new* revision but
  evaluate against *old* data, caching a stale decision under the current revision —
  persistent poison, not a transient race. (The benign converse — old-revision key, new-data
  eval — self-heals: once the revision swaps, old keys are never looked up again.) The D1
  feeding topology exists partly to make this ordering enforceable in sidecar mode; had the
  sidecar polled the console itself, the gateway would have to correlate against OPA's
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

1. **Embedded regorus as the ungated default.** Rejected by the brief: §4.3.1 — "the regorus
   swap is permitted only behind a dual-engine gate." The grounds are concrete: regorus is
   "mostly compliant" with verified divergence surfaces (missing `crypto.*`/`io.jwt.*` et
   al., the `http.send` silent no-op, the strict-builtin-errors default —
   `docs/substrate-api.md` §7.8), and in a PEP a divergence toward allow is a bypass. The µs
   win is also mostly redundant: the §4.3.2 cache absorbs the HeadObject/ListObjects storms
   where p99 actually lives, and the sidecar's ~0.5–2ms already fits §9.5's ≤ 2ms uncached
   budget.
2. **Reuse the per-Org platform OPA instead of a gateway-owned sidecar.** Rejected — the
   brief resolved it: "gateway-owned sidecar OPA fed by the (superset) bundle projection"
   (open questions, §4.3.1). Additionally: that instance serves `ceph.authz` to RGW — the
   defense-in-depth layer §6.5/§7.1 keep distinct from the authoritative path — and sharing
   couples failure domains and upgrade cadence across layers while forfeiting loopback
   locality.
3. **Sidecar polls the console bundle endpoint itself** (symmetric with today's `ceph.authz`
   OPA). Rejected in D1: it reintroduces policy-version skew between engines (the sidecar
   would need the rego delivered out-of-band from the binary that embeds it), makes the
   D6(b) ordering unenforceable except by polling OPA's status API for the activated
   revision, and duplicates the fetch path. The §3.4 delivery mechanism is still reused —
   the gateway is simply its client.
4. **TTL decision cache.** Rejected: §4.3.2 — "Naive TTL caching contradicts §6.1 (live
   revocation)." A TTL'd allow outlives revocation by up to the TTL; no TTL is both useful
   and safe.
5. **Event-driven cache invalidation** (subscribe to grant changes, evict matching keys).
   Rejected: it reintroduces exactly the code §4.3.2 designs away ("no invalidation logic
   exists"); correctness would hinge on event delivery — a new liveness dependency for a
   security property — and on match logic that can be wrong toward allow; the mesh would
   need an invalidation bus, forfeiting §9.3's coherence-by-construction.
6. **OPA-compiled WASM in-process** as the fast path. Rejected: the brief names regorus as
   *the* fast path (§4.3.1); WASM adds a third execution surface (runtime + SDK glue + its
   own builtin support matrix) that would still need the same parity gate — more moving
   parts for the same gated outcome.
7. **Permanent dual evaluation** (both engines every request, sidecar authoritative).
   Rejected as steady state: it never converges to the fast path and permanently doubles the
   operated code paths. Retained deliberately as the *bounded* shadow-soak tool in D5's
   go/no-go.
8. **No trait; hardcode the sidecar.** Rejected: §4.3.1 mandates the trait "from day one"; it
   already exists (`src/pdp/mod.rs`) and is what makes "the swap is a config change" true.

---

## Consequences

**Positive:**
- The default is boring and platform-aligned (same engine as every other PEP); engine
  divergence risk moves from production into a required CI check.
- Engine choice is invisible to the request path: one trait, one `Decision` shape, one cache.
- The p99 defense does not depend on the engine swap: the revision-keyed cache serves storm
  traffic either way, so flipping to regorus is an optimization decided on measurement (§9.5
  gate), never a prerequisite for the budget.
- The corpus does triple duty: golden spec of `authz.rego` (`tests/policy_corpus.rs`),
  engine-parity fixture (this ADR), and seed of the §7.1 cross-layer conformance suite
  (ADR-001 D3; platform asset per §6.5).

**Risks, and what must hold for the security claim:**
1. **Revision/data coherence is the single point of cache correctness.** D6(a) removes the
   trust dependency on the builder by hashing data locally; D6(b)'s publish ordering must be
   implemented in the poller (F3) and is the one place a routine plumbing bug becomes a
   persistent stale-allow. Both are conditions on §6.1 (live revocation) holding under load.
2. **Parity is only as strong as the corpus.** An unexercised rego branch is an ungated
   branch. Mode A step 5 makes coverage mechanical; the standing discipline is that every
   policy PR lands with corpus cases for every new branch, and removing a case gets the same
   scrutiny as removing a test.
3. **`strict_builtin_errors(false)` makes builtin type errors silent undefineds in *both*
   engines** — a malformed rule can silently never fire. The failure direction is safe
   (`default allow := false` ⇒ deny, §6.2), so the residual risk is an allow rule that stops
   allowing — which the golden expectations catch in CI.
4. **Version pinning is part of the claim.** Parity transfers only to the exact
   (rego, regorus, OPA) triple tested; OPA image bumps (C3) and `Cargo.lock` regorus bumps
   re-run Mode A before deploy. Never grandfathered.
5. **Cache-key discipline (D6(c)) is a standing obligation** — the one place a routine policy
   change can silently break cache soundness. F4 automates the read-set check.
6. **Sidecar unavailability means full deny** (fail closed, §6.2) — an availability cost, not
   an integrity one, bounded by `timeout_ms` and mitigated by loopback co-location (partition
   ≈ process failure). The gated embedded engine, once earned, removes the dependency.
7. **Until Mode B (C2) exists, embedded regorus is NO-GO in production**, however green Mode
   A is. Written into D5 criterion 4 explicitly so "CI is green, flip it" drift cannot
   happen.

**Follow-ups in this repo (not companion):**
- **F1** — OPA half of the parity harness: extend `tests/policy_corpus.rs` with the pinned
  `opa run --server` side driven through `SidecarPdp`, the `canonical()` comparator, and the
  `.opa-version` pin file; wire as a required CI check with the D5 triggers.
- **F2** — builtin deny-list lint over `policy/gateway/**.rego` (D4).
- **F3** — the bundle poller: poll the §3.4 endpoint; derive the effective cache revision as
  `(upstream revision, data hash)`; enforce install order data-then-revision; push policy at
  sidecar boot and data per install (D1/D6).
- **F4** — rego input read-set test: extracted `input.` references ⊆ documented cache
  identity (D6(c)).
- **F5** — §9.5 perf regression gate: benchmark cached hit, sidecar uncached, embedded
  uncached from CI.
- **F6** — shadow-mode divergence counter behind a config flag (rollout tool for the D5
  soak).

---

## Companion work (checklist for other teams)

**Console / platform (bundle builder + release pipeline):**
- **C1 — Revision contract.** Verify whether the §3.4 bundle response already carries an
  etag/manifest revision; if not, add one. Guarantee: a new revision on **every**
  policy-relevant data change — `s3_grants`/`group_grants` (once landed per ADR-001/§3.3),
  `user_attributes` (including group membership), `bucket_attributes.denylist`,
  `org_settings.freeze_writes`. Expose it retrievably so the gateway records it as
  `Bundle.revision` (`src/pdp/bundle.rs`). The gateway hash-guards against violations
  (D6(a)) but treats one as an incident, not a supported mode.
- **C2 — Mode B release gate.** In the bundle-release pipeline: replay the golden corpus
  inputs plus synthesized per-grant probes through pinned OPA *and* pinned regorus over each
  released bundle's data; identical canonical decisions required; divergence blocks release
  while any embedded-engine gateway is live and alerts gateway owners regardless. This is
  §4.3.1's "every bundle release is replayed" — it lives where bundles are released.
- **C4 — Corpus adoption.** Take `policy/testdata/corpus.json` as the seed of the
  platform-owned golden corpus (§6.5: "a platform asset, not a repo asset"); mechanics per
  ADR-001 D3 (the shared conformance suite across `ceph.authz` / `datadock.authz` / gateway
  rego).

**Platform ops / deployment:**
- **C3 — OPA pin.** Pin the sidecar OPA image version and publish it to the gateway repo
  (consumed as `.opa-version` by Mode A). OPA upgrades require a green Mode A run at the new
  version before rollout; skew between CI pin and deployed sidecar is a NO-GO condition.
- **C5 — Sidecar deployment shape.** One OPA container per gateway pod, loopback only, no
  external listener, no independent console polling: the gateway feeds it the embedded
  policy at boot and bundle data on install (D1). Health/readiness of the sidecar gates the
  gateway pod's readiness (a gateway without a PDP can only deny).
