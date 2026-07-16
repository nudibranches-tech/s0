# regorus 0.10.1 — Embedding API Reference (in-process PDP)

Crate: `regorus = "0.10.1"`, Microsoft, MIT. Default features = `["full-opa", "arc", "rvm"]`. With `arc` (default): `pub use alloc::sync::Arc as Rc;` (src/lib.rs:201-202) — **every `Rc<...>` in signatures below is `Arc`**. Error type everywhere is `anyhow::Result` (`use anyhow::{anyhow, bail, Result};`, engine.rs:19).

## 1. Construct

```rust
use regorus::{Engine, Value};           // both re-exported at crate root (lib.rs:169,180)
let mut engine = Engine::new();          // pub fn new() -> Self;  also impl Default
```

```rust
// engine.rs:23-31
#[derive(Debug, Clone)]
pub struct Engine {
    modules: Rc<Vec<Ref<Module>>>,
    interpreter: Interpreter,
    prepared: bool,
    rego_v1: bool,
    execution_timer_config: Option<ExecutionTimerConfig>,
    policy_length_config: PolicyLengthConfig,
}
```

## 2. Add policy (string)

```rust
// engine.rs:242 — returns the package path, e.g. "data.gateway.authz"
pub fn add_policy(&mut self, path: String, rego: String) -> Result<String>
// also: #[cfg(feature = "std")] pub fn add_policy_from_file<P: AsRef<std::path::Path>>(&mut self, path: P) -> Result<String>
```
Errors: parse errors via `anyhow::Error` (with source location text). Any `add_policy` sets `prepared = false` → next eval re-runs analysis. Policies can only be added, never removed/replaced — build a fresh `Engine` per policy revision.

## 3. Data (bundle)

```rust
pub fn add_data(&mut self, data: Value) -> Result<()>          // engine.rs:463 — MERGE; err if not object, err on conflicting key with different value
pub fn add_data_json(&mut self, data_json: &str) -> Result<()> // engine.rs:504 — add_data(Value::from_json_str(..)?)
pub fn clear_data(&mut self)                                   // engine.rs:430 — resets data doc to {}
pub fn get_data(&self) -> Value                                // engine.rs:500 — clone of init_data (cheap, Arc-backed)
```
**Replace per bundle revision:** no in-place replace. Either (a) `engine.clear_data(); engine.add_data(v)?;` — both flip `prepared=false`, so the *next* eval pays one re-prepare (module analysis/scheduling) — or (b) keep a policy-only base `Engine`, `let mut e = base.clone(); e.add_data(bundle)?;` per revision. Re-prepare cost is per-revision, not per-request (prepare is cached via the `prepared` flag; `set_input` does **not** invalidate it).

## 4. Input per request

```rust
pub fn set_input(&mut self, input: Value)                       // engine.rs:400
pub fn set_input_json(&mut self, input_json: &str) -> Result<()> // engine.rs:404
```
`Value` construction: `pub fn from_json_str(json: &str) -> Result<Value>` (value.rs:352), `pub fn to_json_str(&self) -> Result<String>` (value.rs:457, pretty-printed), `impl From<serde_json::Value> for Value` (value.rs:652), `Value: Serialize + Deserialize`.

## 5. Evaluate

```rust
pub fn eval_rule(&mut self, rule: String) -> Result<Value>                                 // engine.rs:820 — PREFERRED fast path
pub fn eval_query(&mut self, query: String, enable_tracing: bool) -> Result<QueryResults> // engine.rs:862
pub fn eval_bool_query(&mut self, query: String, enable_tracing: bool) -> Result<bool>    // engine.rs:903
pub fn eval_allow_query(&mut self, query: String, enable_tracing: bool) -> bool           // engine.rs:943 — Ok(true) only
pub fn eval_deny_query(&mut self, query: String, enable_tracing: bool) -> bool            // engine.rs:966
```
- `eval_rule` is documented "often faster than eval_query"; it lazily evaluates **only** the named rule (`ensure_rule_evaluated`, interpreter.rs:4387). Path must be a full rule path (`"data.gateway.authz.decision"`); `"data"` or a bare package errors with `"not a valid rule path"`. A rule whose body fails and has no `default` returns `Value::Undefined` (Ok, not Err).
- `QueryResults { pub result: Vec<QueryResult> }`; `QueryResult { pub expressions: Vec<Expression>, pub bindings: Value }`; `Expression { pub value: Value, pub text: Rc<str>, pub location: Location }` (lib.rs:354-498). Value at `results.result[0].expressions[0].value`.

**Value extraction** (value.rs:42-71, 834+, 1397+):
```rust
pub enum Value { Null, Bool(bool), Number(Number), String(Rc<str>),
                 Array(Rc<Vec<Value>>), Set(Rc<BTreeSet<Value>>),
                 Object(Rc<BTreeMap<Value, Value>>), Undefined }
pub fn as_bool(&self) -> Result<&bool>
pub fn as_string(&self) -> Result<&Rc<str>>       // Arc<str> under default features
pub fn as_object(&self) -> Result<&BTreeMap<Value, Value>>
pub fn as_i64(&self) -> Result<i64>               // + as_u64/as_f64/as_array/as_set...
impl ops::Index<&Value> for Value                  // missing key / wrong type → &Value::Undefined (never panics)
impl<T> ops::Index<T> for Value where Value: From<T>  // v["key"], v[0]
```

### Per-request path (exact code)

```rust
// startup / per bundle revision
let mut engine = regorus::Engine::new();                     // rego v1 by default
engine.set_strict_builtin_errors(false);                     // OPA-parity: undefined instead of error
engine.add_policy("gateway.rego".to_string(), policy_src.to_string())?;  // -> "data.gateway.authz"
engine.add_data_json(&bundle_json)?;                         // tenants/grants
// optional warm-up so clones never pay prepare:
let _ = engine.eval_rule("data.gateway.authz.decision".to_string());
let prepared = engine;                                       // share as template

// per request
let mut e = prepared.clone();                                // cheap: Arc bumps + small owned fields
e.set_input_json(&input_json)?;                              // or e.set_input(Value::from(serde_json_value))
let d = e.eval_rule("data.gateway.authz.decision".to_string())?;   // Value
let allow  = matches!(d["allow"], regorus::Value::Bool(true));      // or d["allow"].as_bool().copied().unwrap_or(false)
let reason = d["reason"].as_string().map(|s| s.to_string()).unwrap_or_default(); // Undefined-safe via Index
let prefix = d["rewritten_prefix"].as_string().ok().map(|s| s.to_string());
```

### Zero-clone alternative: `CompiledPolicy` (takes `&self`!)

```rust
pub fn compile_with_entrypoint(&mut self, rule: &Rc<str>) -> Result<CompiledPolicy>  // engine.rs:771
// compiled_policy.rs:32-35, 68
#[derive(Debug, Clone)] pub struct CompiledPolicy { pub(crate) inner: Rc<CompiledPolicyData> }
pub fn eval_with_input(&self, input: Value) -> Result<Value>   // &self — no lock, no clone
```
`compile()` snapshots `init_data` + `strict_builtin_errors` into `CompiledPolicyData` (interpreter.rs:4412-4418); each `eval_with_input` builds a throwaway pre-prepared `Engine` from the `Arc` snapshot and runs `eval_rule` on the compiled entrypoint. One `CompiledPolicy` per (policy, data-revision); swap the shared handle (e.g. `arc_swap`) on bundle update.
```rust
let compiled = engine.compile_with_entrypoint(&"data.gateway.authz.decision".into())?; // &Rc<str> = &Arc<str>
let d = compiled.eval_with_input(regorus::Value::from_json_str(&input_json)?)?;
```
Caveat: per-engine `ExecutionTimerConfig` is not carried into `eval_with_input` (falls back to global `regorus::utils::limits::set_fallback_execution_timer_config`).

## 6. Concurrency / cost model

- `Engine` **derives `Clone`** (engine.rs:23). Doc (engine.rs:845-847): "Either the same engine can be used to make multiple queries or the engine can be cloned to avoid having the reload the policies and data." Cloning a prepared engine keeps `prepared: true` → no re-analysis. Clone cost: refcount bumps on `Arc` modules/`Value` trees + copying small owned maps/vecs (COW via `Rc::make_mut` everywhere).
- **Send/Sync:** with default `arc` feature, `Rc = Arc`, `pub trait Extension: FnMut(Vec<Value>) -> anyhow::Result<Value> + Send + Sync` (lib.rs:503), `Interpreter` holds only owned data (no RefCell/Cell/Mutex — verified struct fields interpreter.rs:67-105) → `Engine`/`Value`/`CompiledPolicy` are auto `Send + Sync`. Proven by shipped test tests/arc.rs: `static ref ENGINE: Mutex<Engine>` + `static ref VALUE: Value` under `lazy_static` (requires `Engine: Send`, `Value: Sync`). All eval methods take `&mut self`, so concurrent use of one Engine requires a lock — **don't**; instead per request either (a) share a `CompiledPolicy` and call `eval_with_input(&self, ..)`, or (b) clone the prepared `Engine`, `set_input`, `eval_rule`.
- Each eval calls `clean_internal_evaluation_state()` (interpreter.rs:393-403): resets `data = init_data.clone()` (Arc bump), clears rule-value/builtin caches, restarts timer — evals are hermetic; no state leaks between requests on a reused engine.
- **Toggles:** `pub const fn set_rego_v0(&mut self, rego_v0: bool)` (engine.rs:119) — default is **Rego v1** (`rego_v1: true` in `new()`); do not call for v1 policies. `pub fn set_strict_builtin_errors(&mut self, b: bool)` (engine.rs:516) — **default `true`** (builtins raise errors; differs from OPA which yields undefined); set `false` for OPA parity. Optional DoS guard: `pub fn set_execution_timer_config(&mut self, config: ExecutionTimerConfig)` with `ExecutionTimerConfig { pub limit: Duration, pub check_interval: NonZeroU32 }` (`use regorus::utils::limits::ExecutionTimerConfig;`).

## 7. Builtins (default `full-opa` build) — verified from `src/builtins/*::register`

**Present (all requested ones):** `startswith`, `endswith`, `split`, `count`, `contains` (string), `upper`, `lower`, `sprintf`, `concat`, `indexof`, `indexof_n`, `replace`, `strings.replace_n`, `strings.count`, `strings.any_prefix_match`, `strings.any_suffix_match`, `substring`, `trim`/`trim_left`/`trim_right`/`trim_prefix`/`trim_suffix`/`trim_space`, `format_int`, `to_number`, `sort`, `sum`/`min`/`max`/`product`, `abs`/`ceil`/`floor`/`round`, `numbers.range(_step)`, `array.concat/reverse/slice`, `object.get/keys/filter/remove/subset/union/union_n`, `json.marshal/unmarshal/filter/remove/is_valid/match_schema/verify_schema`, `intersection`/`union`, `bits.*`, `type_name`/`is_*`, `walk`, `glob.match`/`glob.quote_meta`, `regex.match/is_valid/split/replace/find_n/template_match/globs_match`, `graph.reachable(_paths)`, `net.cidr_contains/cidr_expand/cidr_is_valid`, `base64.*`, `base64url.*`, `hex.*`, `urlquery.*`, `yaml.*`, `uuid.rfc4122/parse`, `semver.*`, `units.parse(_bytes)`, `rand.intn`, `opa.runtime`, `trace`, **`time.now_ns`** (+ `time.add_date/clock/date/diff/format/parse_duration_ns/parse_ns/parse_rfc3339_ns/weekday`). `time.now_ns` is cached per-eval (`must_cache`, builtins/mod.rs:123-131) → stable within one request, fresh per request. `some ... in` / `every` / `if` / `contains` (rule keyword) are v1 parser syntax, on by default (parser.rs:57).
- **Missing — crypto: NO `crypto.*` builtins exist at all** (zero grep hits for crypto/hmac/sha/md5 in src; README:378: "Cryptographic builtins are not supported by design" — use `add_extension`). Also missing: all `io.jwt.*`, `graphql.*`, `json.patch`, `rego.metadata.*`, `rego.parse_module`, `net.cidr_intersects/merge/overlap/contains_matches`, `net.lookup_ip_addr`, `providers.aws.*`, `strings.render_template`.
- **Trap:** `http.send` is registered but is a **no-op stub returning `Value::Undefined`** (builtins/http.rs:17-21) — it never performs network I/O; don't rely on it erroring either.

Custom builtins: `pub fn add_extension(&mut self, path: String, nargs: u8, extension: Box<dyn Extension>) -> Result<()>` (engine.rs:1283) — closures `FnMut(Vec<Value>) -> anyhow::Result<Value> + Clone + Send + Sync` auto-implement `Extension`; cannot be replaced/removed once added; cloned with the engine.

Files: `/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/regorus-0.10.1/src/engine.rs` (Engine), `src/lib.rs` (QueryResults/Extension/Rc alias), `src/value.rs` (Value), `src/compiled_policy.rs` (CompiledPolicy), `src/builtins/mod.rs` (builtin registry), `tests/arc.rs` (Send proof).
