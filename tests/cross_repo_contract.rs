//! Cross-repo contract gate: the strings s0 shares with the hyperfluid platform.
//!
//! ## The failure class this exists for
//!
//! Three production defects shipped at once, all of the same shape: s0 and the platform
//! disagreed about a **string**, and the disagreement was invisible to every test in
//! either repo because each side only ever tested itself.
//!
//! 1. **The decision entrypoint.** s0 evaluated `data.s0.gateway.decision`; the platform
//!    ships `package s3.authz` and pins `data.s3.authz.decision`. A gateway that polls a
//!    real bundle loads the platform's module and asks for a rule that is not in it. On
//!    the shipping sidecar engine that is **undefined**, which — correctly, by design —
//!    fails closed: a deny-all production authorization gateway on a healthy-looking
//!    pod, reported by nothing. (On the embedded engine it is a boot failure instead;
//!    both outcomes are measured by
//!    `a_module_the_entrypoint_does_not_address_can_never_produce_an_allow`.) It is the
//!    same failure that once cost this project 35 green tests over a deny-all policy.
//! 2. **The audit labels.** s0 emitted `s0.dev/record-type` and `s0.dev/organization-id`;
//!    the ingest extractor dispatches on `hyperfluid.nudibranches.tech/data-dock-type ==
//!    "s3-gateway"` and reads `hyperfluid.nudibranches.tech/organization-id`. Every
//!    gateway record fell off the end of the dispatch chain, was warn-logged and dropped
//!    — and the ingest endpoint answered **201 regardless**, so the producer could never
//!    find out. In a hospital or government tenancy a silently empty audit trail is worse
//!    than a loud outage.
//! 3. The record `path` (`s3/authz/decision`), which the platform's own fixture asserts.
//!
//! Fixing the three strings is not the point. **The point is that a string agreed in
//! prose across two repositories, with nothing checking it, will drift again.**
//!
//! ## The second wave: P2 and P3 added two more strings and a request shape
//!
//! Closing the unauthenticated bundle endpoint (P2) and building the console-mediated
//! session endpoint (P3) put three more things in the same position — agreed in prose,
//! implemented twice, checked by nothing:
//!
//! * **the shared-secret header name.** It carries both directions: the console
//!   presents it to s0 on the mint, and s0 presents it to the console on the bundle
//!   poll. The two failures are opposite and neither is loud. Wrong on the mint ⇒ 401
//!   on every session for an organization that has *already stopped* minting RGW STS
//!   tokens and never falls back — no credentials at all, not a degraded mode. Wrong on
//!   the poll ⇒ the console refuses the fetch and s0 keeps serving its last-good
//!   bundle, so the pod stays Ready, keeps deciding, and simply stops learning about
//!   revocations.
//! * **the session endpoint path.** A 404 on every mint, with the same no-fallback
//!   consequence.
//! * **the session request and response shape** — field names *and* the two
//!   `principal_type` literals, which are two different bundle key spaces (`user:` vs
//!   `sa:`). s0's `SessionRequest` carries `deny_unknown_fields`, so a rename on either
//!   side is a 400 rather than a silently dropped field; that is the safe direction,
//!   and it is why the rename must be caught here rather than in a cluster.
//!
//! Each of the three is pinned once in `mod platform` and then held from both sides,
//! and — the addition this file did not have before — the always-on half **runs the
//! production code** against the pins rather than only comparing them to s0's
//! constants. `the_running_session_endpoint_answers_the_pinned_path_on_the_pinned_header`
//! POSTs the console's own pinned document at the pinned path with the pinned header
//! through `internal::serve_on`, over a real socket, and gets back a real credential;
//! `the_bundle_poller_presents_the_pinned_header_on_the_wire` reads the header off the
//! bytes `bundle_refresh::spawn` puts on the wire. A constant that is correct and unread
//! passes an equality test and fails those two — which is precisely the P1 shape one
//! level down, where the entrypoint was right in one place and hand-copied wrong in
//! three others.
//!
//! ## The two halves, and why it is built this way
//!
//! Every literal is pinned once, below, in the `platform` module, with the hyperfluid
//! file it came from named next to it. Then:
//!
//! - **The always-on half** (`s0_agrees_with_the_pinned_platform_contract`, and friends)
//!   holds s0's own constants equal to those pins. It needs no sibling checkout, so it
//!   runs on every developer machine and in the public s0 CI, and it catches every
//!   drift introduced *from the s0 side* — which is the direction s0's own commits can
//!   actually move.
//! - **The cross-repo half** (`the_pinned_platform_contract_matches_the_real_hyperfluid_*`)
//!   reads the real hyperfluid sources and holds the pins equal to what the platform
//!   *actually ships*. It catches drift introduced from the platform side.
//!
//! ### The skip, stated explicitly
//!
//! `s0-gas` is a standalone repository; its CI cannot check out the private platform
//! repo. So when hyperfluid is absent the cross-repo half **skips, loudly** — it prints
//! a banner naming the repo, the branch-relative paths it wanted, and the environment
//! variables that control it. It is never a silent pass, and it is never the only thing
//! standing between an s0 edit and a broken contract: the pins are re-asserted by the
//! always-on half in the same file, so a developer who "fixes" a red cross-repo test by
//! editing a pin immediately turns the always-on test red instead.
//!
//! Set `S0_REQUIRE_HYPERFLUID=1` to turn the skip into a hard failure. Any pipeline that
//! *does* have both checkouts (the integration/release gate) must set it, or it is
//! running the same green-by-absence gate this file was written to abolish.
//!
//! This mirrors `tests/parity.rs` exactly, where a missing `opa` oracle is compensated
//! for by `the_opa_oracle_is_pinned_to_the_production_version_everywhere`, which needs
//! no oracle and therefore always runs.
//!
//! ## The third half: the strings are not the contract, the DECISION is
//!
//! Everything above compares *text*. Text that matches and still evaluates to
//! `undefined` is precisely the bug — so
//! `the_platforms_real_bundle_decides_through_s0s_real_loading_path` does not compare
//! anything: it takes the platform's **real serialized bundle**, pushes it through the
//! same `parse_bundle` → `Pdp::reload` → `Pdp::decide` path `bundle_refresh.rs` runs in
//! production, and asserts a granted request comes back **ALLOW**. An allow is the only
//! observation a deny-all cannot fake.
//!
//! The fixture (`tests/data/platform/s3_gateway_bundle.json`) is not hand-written: it
//! is the byte output of hyperfluid's own `compile_s3_projection` → `S3GatewayBundle::assemble`
//! → `seal` → `to_canonical_bytes`, and its `policy` field is byte-identical to
//! `hf_lib_vauban_rules/src/s3/authz/s3.rego` — which
//! `the_captured_platform_bundle_still_carries_the_module_hyperfluid_ships` re-checks
//! against the real checkout so the capture cannot rot.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use s0::audit::{DATA_DOCK_TYPE_VALUE, DECISION_PATH, LABEL_DATA_DOCK_TYPE, LABEL_ORG_ID};
use s0::pdp::{
    Bundle, BundleStore, CachingPdp, DECISION_RULE, GATEWAY_REGO, Pdp, RegorusPdp, SidecarPdp,
    content_revision, decision_rule_path, parse_bundle,
};

/// The other repository, by name. Every failure message in this file says it, because
/// the whole cost of these defects was a person not knowing where to look.
const OTHER_REPO: &str = "hyperfluid (branch feat/s3-gateway-integration)";

/// The contract, pinned. Each constant names the hyperfluid file that owns it.
mod platform {
    /// `package s3.authz` — `rust/hf_lib_vauban_rules/src/s3/authz/s3.rego`, and
    /// `S3_AUTHZ_PACKAGE` in
    /// `rust/hf_module_console_api/src/hf_console/inbound/http/handlers/vauban/s3_gateway_projection/bundle.rs`.
    pub const REGO_PACKAGE: &str = "s3.authz";

    /// `S3_AUTHZ_ENTRYPOINT` — same `bundle.rs`. The single rule the gateway evaluates.
    pub const ENTRYPOINT: &str = "data.s3.authz.decision";

    /// The entrypoint in decision-log `path` form. Asserted by hyperfluid's own
    /// `rust/hf_module_console_api/src/hf_console/domain/audit_logs/models/decision_log.rs`
    /// fixture.
    pub const DECISION_LOG_PATH: &str = "s3/authz/decision";

    /// `S3GatewayDecisionLogMetadataExtractor::is_handled` — `decision_log.rs`.
    pub const DATA_DOCK_TYPE_LABEL: &str = "hyperfluid.nudibranches.tech/data-dock-type";
    /// The value `is_handled` compares that label against.
    pub const DATA_DOCK_TYPE_VALUE: &str = "s3-gateway";

    /// `ORGANIZATION_ID_LABEL` — `rust/hf_lib_domain_core/src/labels.rs`, read by
    /// `S3GatewayDecisionLogMetadataExtractor::get_organization_id`.
    pub const ORGANIZATION_ID_LABEL: &str = "hyperfluid.nudibranches.tech/organization-id";

    // ── P2 / P3: the two internal machine-to-machine surfaces ───────────────────

    /// `SHARED_SECRET_HEADER` — `rust/hf_lib_config/src/lib.rs`. The platform-wide
    /// machine-to-machine auth header, sent by the console's `S3GatewayStsService`
    /// (`.header(SHARED_SECRET_HEADER, …)`) and validated by the console's own
    /// `guards/shared_secret_guard.rs`. s0 must read the *same* header name on the
    /// session endpoint and send it on the bundle poll.
    pub const SHARED_SECRET_HEADER: &str = "X-Shared-Secret";

    /// `GATEWAY_SESSION_PATH` — `s3_gateway_sts/mod.rs`. The console appends this to
    /// the gateway's in-cluster base URL. s0 serving it anywhere else is a 404 on
    /// every mint for an opted-in organization, with no fallback.
    pub const GATEWAY_SESSION_PATH: &str = "/internal/v1/sts/sessions";

    /// The exact JSON body hyperfluid's own contract test
    /// (`the_session_request_is_the_agreed_wire_contract`) asserts
    /// `GatewaySessionRequest` serializes to. Replayed through s0's real deserializer
    /// below — the strongest form of this check, because a field-name comparison that
    /// passes and still fails to deserialize is precisely the bug.
    pub const SESSION_REQUEST_BODY: &str = r#"{
        "sub": "svc-pipeline-runner",
        "principal_type": "service_account",
        "tenant": "acme-prod",
        "organization_id": "11111111-1111-1111-1111-111111111111",
        "groups": ["editor"],
        "duration_seconds": 3600
    }"#;

    /// The four field names hyperfluid's `MintedSession` deserializes from s0's
    /// answer (`#[serde(rename = …)]`, same `s3_gateway_sts/mod.rs`). Three of them
    /// are mandatory there; `Expiration` is `Option`.
    pub const MINTED_SESSION_FIELDS: &[&str] = &[
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "Expiration",
    ];

    /// The same four, with **whether the console requires them**, read off
    /// `MintedSession`'s declared types (`Option<…>` ⇒ not required).
    ///
    /// The distinction is the whole difference between a degraded field and a total
    /// outage: a missing `SessionToken` is `MalformedResponse` on *every* mint for an
    /// opted-in organization, while a missing `Expiration` is a lost log line. Pinned
    /// separately so a `String` → `Option<String>` (or the reverse) on either side is
    /// visible here rather than at 3 a.m.
    pub const MINTED_SESSION_REQUIRED: &[(&str, bool)] = &[
        ("AccessKeyId", true),
        ("SecretAccessKey", true),
        ("SessionToken", true),
        ("Expiration", false),
    ];

    /// `GatewaySessionRequest`'s fields — **name and declared type**, in declaration
    /// order — from `s3_gateway_sts/mod.rs`.
    ///
    /// The names are the wire contract (the struct carries no `rename`/`rename_all`,
    /// which
    /// [`the_consoles_session_request_struct_is_the_shape_s0_deserializes`] also
    /// checks, because a `rename_all` added later would move every name at once
    /// without touching a single identifier).
    ///
    /// The **types** are pinned too, because a rename is not the only realistic
    /// failure: `organization_id: String` → `Uuid` still serializes to a string, but
    /// `groups: Vec<String>` → `Option<Vec<String>>` starts emitting `null`, which
    /// s0's `#[serde(default)]` does *not* accept, and `duration_seconds: u32` → `i64`
    /// makes a negative expressible on a field s0 reads as `u64`.
    ///
    /// [`the_consoles_session_request_struct_is_the_shape_s0_deserializes`]: super::the_consoles_session_request_struct_is_the_shape_s0_deserializes
    pub const SESSION_REQUEST_FIELDS: &[(&str, &str)] = &[
        ("sub", "String"),
        ("principal_type", "GatewayPrincipalType"),
        ("tenant", "String"),
        ("organization_id", "String"),
        ("groups", "Vec<String>"),
        ("duration_seconds", "u32"),
    ];

    /// The two wire spellings of `principal_type`, which are **two different bundle
    /// key spaces** (`user:<oidc sub>` vs `sa:<client id>`).
    ///
    /// Pinned as literals rather than "it is an enum on both sides", because the enum
    /// being an enum is not the contract — the strings are. A variant renamed on the
    /// console side, or a `rename_all` dropped there (which would send `"User"` /
    /// `"ServiceAccount"`), is refused by s0's serde at the door: a 400 on every mint,
    /// for an organization that no longer has a legacy path to fall back to.
    pub const PRINCIPAL_TYPE_LITERALS: &[&str] = &["user", "service_account"];
}

/// Paths inside the hyperfluid checkout, so a failure can quote one.
mod hf_path {
    pub const RULES_REGO: &str = "rust/hf_lib_vauban_rules/src/s3/authz/s3.rego";
    pub const CONFIG_RS: &str = "rust/hf_lib_config/src/lib.rs";
    pub const STS_CLIENT_RS: &str =
        "rust/hf_module_console_api/src/hf_console/outbound/s3_gateway_sts/mod.rs";
    pub const BUNDLE_RS: &str = "rust/hf_module_console_api/src/hf_console/inbound/http/\
                                 handlers/vauban/s3_gateway_projection/bundle.rs";
    pub const DECISION_LOG_RS: &str =
        "rust/hf_module_console_api/src/hf_console/domain/audit_logs/models/decision_log.rs";
    pub const LABELS_RS: &str = "rust/hf_lib_domain_core/src/labels.rs";
    /// The console's own inbound half of the shared secret: the layer that validates
    /// what s0 presents on the **bundle poll** (P2).
    pub const SHARED_SECRET_GUARD_RS: &str =
        "rust/hf_module_console_api/src/hf_console/inbound/http/guards/shared_secret_guard.rs";
    /// The router that carries `GET …/{organization_id}/s3-gateway-bundle`.
    pub const VAUBAN_ROUTER_RS: &str =
        "rust/hf_module_console_api/src/hf_console/inbound/http/handlers/vauban/mod.rs";
    /// `hf_lib_config_fetcher::constants`, which the guard imports the header from.
    /// It must **re-export** `hf_lib_config`'s constant rather than declare a second
    /// one — see `the_console_validates_the_credential_s0_sends_on_the_bundle_poll`.
    pub const CONFIG_FETCHER_RS: &str = "rust/hf_lib_config_fetcher/src/lib.rs";
}

// ── the always-on half: s0's own constants against the pins ─────────────────────

/// s0 must ask the question the platform answers.
#[test]
fn s0_evaluates_the_entrypoint_the_platform_ships() {
    assert_eq!(
        DECISION_RULE,
        platform::ENTRYPOINT,
        "\ns0 evaluates {DECISION_RULE:?} but {OTHER_REPO} ships {:?} \
         ({}, S3_AUTHZ_ENTRYPOINT).\n\
         A bundle whose module declares a different package evaluates to UNDEFINED, and \
         this gateway fails closed on undefined — so this disagreement is a DENY-ALL \
         production authorization gateway with no error and no failing test anywhere.\n\
         Fix `DECISION_RULE` in src/pdp/bundle.rs, not this test.\n",
        platform::ENTRYPOINT,
        hf_path::BUNDLE_RS,
    );

    // The compiled-in default module must declare the same package, or the fallback
    // policy (what runs when a bundle carries data only) answers a different question
    // than a pushed one.
    let declared =
        rego_package(GATEWAY_REGO).expect("policy/gateway/authz.rego has a package line");
    assert_eq!(
        declared,
        platform::REGO_PACKAGE,
        "\npolicy/gateway/authz.rego declares `package {declared}` but {OTHER_REPO} \
         ships `package {}` ({}).\n\
         The compiled-in default is the fallback for a data-only bundle and the oracle \
         the parity gate replays against; if it declares a different package than the \
         pushed module, the two disagree about what is being evaluated.\n",
        platform::REGO_PACKAGE,
        hf_path::RULES_REGO,
    );

    // …and the entrypoint must actually address that package, which is the join between
    // the two assertions above.
    assert_eq!(
        DECISION_RULE,
        format!("data.{declared}.decision"),
        "\nthe entrypoint {DECISION_RULE:?} does not address `package {declared}`\n"
    );
}

/// Every place that spells the entrypoint out is derived from the one constant.
#[test]
fn nothing_holds_a_second_copy_of_the_entrypoint() {
    let path = decision_rule_path();
    assert_eq!(path, platform::DECISION_LOG_PATH);

    // The audit record's `path` field. hyperfluid's own decision-log fixture asserts
    // this literal, and a mismatch makes every s0 record look like it came from a rule
    // the platform has never heard of.
    assert_eq!(
        DECISION_PATH,
        platform::DECISION_LOG_PATH,
        "\ns0 stamps audit records with path {DECISION_PATH:?}; {OTHER_REPO} expects {:?} \
         ({}).\n",
        platform::DECISION_LOG_PATH,
        hf_path::DECISION_LOG_RS,
    );

    // The sidecar OPA URL. A sidecar posting to a path OPA does not resolve gets an
    // undefined result, which this PDP turns into a deny — the same silent deny-all,
    // reached by a different route.
    let pdp = SidecarPdp::new("http://127.0.0.1:8181", std::time::Duration::from_secs(1))
        .expect("build sidecar pdp");
    assert_eq!(
        pdp.decision_url(),
        format!(
            "http://127.0.0.1:8181/v1/data/{}",
            platform::DECISION_LOG_PATH
        ),
        "\nthe sidecar posts to a path that is not the slash form of {DECISION_RULE:?}\n"
    );
}

/// s0 must label records the way the ingest extractor dispatches.
#[test]
fn s0_labels_audit_records_the_way_the_extractor_routes() {
    assert_eq!(
        LABEL_DATA_DOCK_TYPE,
        platform::DATA_DOCK_TYPE_LABEL,
        "\ns0 emits the discriminator label {LABEL_DATA_DOCK_TYPE:?}; \
         S3GatewayDecisionLogMetadataExtractor::is_handled in {OTHER_REPO} matches {:?} \
         ({}).\n\
         A record that does not match falls off the end of the dispatch chain with \
         \"No metadata extractor found for decision log\": warn-logged, DROPPED, and \
         answered 201 — so the gateway never learns its audit trail is empty.\n",
        platform::DATA_DOCK_TYPE_LABEL,
        hf_path::DECISION_LOG_RS,
    );
    assert_eq!(
        DATA_DOCK_TYPE_VALUE,
        platform::DATA_DOCK_TYPE_VALUE,
        "\ns0 labels its records {DATA_DOCK_TYPE_VALUE:?}; the extractor in {OTHER_REPO} \
         routes on {:?} ({}).\n",
        platform::DATA_DOCK_TYPE_VALUE,
        hf_path::DECISION_LOG_RS,
    );
    assert_eq!(
        LABEL_ORG_ID,
        platform::ORGANIZATION_ID_LABEL,
        "\ns0 attributes records with {LABEL_ORG_ID:?}; \
         S3GatewayDecisionLogMetadataExtractor::get_organization_id in {OTHER_REPO} reads \
         ORGANIZATION_ID_LABEL = {:?} ({}).\n\
         An unreadable org is dropped fail-closed on ingest, so this mismatch also \
         deletes the trail rather than misattributing it.\n",
        platform::ORGANIZATION_ID_LABEL,
        hf_path::LABELS_RS,
    );

    // And a real record actually carries them — the constants being right is not the
    // same claim as them being used.
    let labels = sample_record_labels();
    assert_eq!(
        labels
            .get(platform::DATA_DOCK_TYPE_LABEL)
            .map(String::as_str),
        Some(platform::DATA_DOCK_TYPE_VALUE),
        "an emitted record does not carry the discriminator the extractor routes on: \
         {labels:?}"
    );
    assert!(
        labels.contains_key(platform::ORGANIZATION_ID_LABEL),
        "an emitted decision record carries no trusted org attribution: {labels:?}"
    );
}

/// Not "the label constants are right" — **run the extractor's conditions against a
/// record s0 actually emits.**
///
/// The three predicates below are transcribed from
/// `S3GatewayDecisionLogMetadataExtractor` and
/// `OPADecisionLog::try_into_create_audit_log_request` in the platform's
/// `domain/audit_logs/models/decision_log.rs` (see `hf_path::DECISION_LOG_RS`). Each one
/// is a silent drop when it fails: the ingest endpoint answers 201 either way, so the
/// gateway can never learn that its regulated trail is empty. A constant that spells
/// the label correctly but is attached to a record that fails one of the *other*
/// predicates loses exactly as much data.
#[test]
fn a_real_audit_record_passes_the_platforms_ingest_predicates() {
    let record = sample_decision_record();
    let json = serde_json::to_value(&record).expect("a record serializes");

    // 1. `is_handled` — labels.get(<label>).map(|v| v == "s3-gateway").unwrap_or(false)
    let dock_type = json["labels"][platform::DATA_DOCK_TYPE_LABEL].as_str();
    assert_eq!(
        dock_type,
        Some(platform::DATA_DOCK_TYPE_VALUE),
        "is_handled would be false: the record falls off the end of the dispatch chain \
         and is warn-logged and DROPPED behind a 201. labels = {}",
        json["labels"]
    );

    // 2. `get_organization_id` — labels.get(ORGANIZATION_ID_LABEL)?.parse::<Uuid>().ok()
    //    `?` and `.ok()` both mean None, and None here is
    //    `Err("...trusted organization_id not found — dropping")`. Note the PARSE: an
    //    org id that is not a UUID drops the record just as surely as a missing label.
    let org = json["labels"][platform::ORGANIZATION_ID_LABEL]
        .as_str()
        .expect("a decision record must carry the trusted org attribution");
    uuid::Uuid::parse_str(org).unwrap_or_else(|e| {
        panic!(
            "the org label {org:?} is not a UUID ({e}); \
             get_organization_id returns None and the record is DROPPED"
        )
    });

    // 3. `self.timestamp.parse::<DateTime<Utc>>()` — a parse failure is
    //    `Err("Failed to parse timestamp")`, i.e. dropped.
    let ts = json["timestamp"]
        .as_str()
        .expect("a record has a timestamp");
    ts.parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap_or_else(|e| panic!("the record's timestamp {ts:?} does not parse: {e}"));

    // 4. `requested_by` is the field the extractor takes the end-user identity from,
    //    and ADR-002 requires it to equal `input.principal.sub`.
    assert_eq!(json["requested_by"], json["input"]["principal"]["sub"]);
}

/// **OPEN DEFECT, pinned here so it cannot be rediscovered by an auditor.**
///
/// The platform's ingest is `Json(body): Json<Vec<OPADecisionLog>>`
/// (`handlers/audit_logs/create_opa_decision_logs.rs`). `OPADecisionLog::input` is a
/// bare `serde_json::Value` — **not** `Option`, and with no `#[serde(default)]` — so a
/// record that omits `input` fails to deserialize. Axum rejects the request body as a
/// whole, which means **one gate record poisons the entire batch**: every good decision
/// record shipped alongside it is lost too, `ControlPlaneBackend::ship` sees the non-2xx
/// and spills, and the retry fails identically forever.
///
/// s0's gate records omit `input` by design (`AuditRecord::gate_denial`, ADR-002 §D3:
/// no policy ran, so there is no input to report), and they are emitted on exactly the
/// traffic a regulated tenancy most wants recorded — unauthenticated and malformed
/// requests.
///
/// This test asserts the CURRENT state on both sides. It fails the moment either side
/// moves, which is the point: whoever fixes it (s0 emitting `input: {}`, or the platform
/// defaulting the field) has to come here and say so.
#[test]
fn a_gate_record_omits_a_field_the_platforms_ingest_type_requires() {
    use s0::audit::{AuditRecord, GateContext, GateStage};

    let gate = AuditRecord::gate_denial(
        "gate-contract".into(),
        "2026-07-28T00:00:00Z".into(),
        GateContext {
            operation: "GetObject".into(),
            stage: GateStage::Anonymous,
            access_key_id: None,
            tenant: None,
            suppressed_since_last: 0,
        },
        "anonymous request",
        String::new(),
    );
    let json = serde_json::to_value(&gate).expect("a gate record serializes");
    assert!(
        json.get("input").is_none(),
        "gate records now carry `input`; if that was the fix for the batch-poisoning \
         defect, delete this test and say so in ADR-002"
    );
    // It would be handled — the dispatch label is there — but it never gets that far.
    assert_eq!(
        json["labels"][platform::DATA_DOCK_TYPE_LABEL],
        serde_json::json!(platform::DATA_DOCK_TYPE_VALUE)
    );
}

// ── P2 / P3: the internal surfaces, always-on half ─────────────────────────────

/// The header name is the whole of the authentication contract for both new surfaces.
///
/// Get it wrong and the two failures are opposite and both silent-ish: on the session
/// endpoint every mint 401s for an organization that has already opted out of the
/// legacy path, so it gets *no* credentials and no fallback; on the bundle poll s0
/// sends a header the console ignores, the fetch succeeds unauthenticated, and the
/// gateway reports a perfectly healthy poll while P2 is still wide open.
#[test]
fn s0_speaks_the_platforms_machine_to_machine_auth_header() {
    assert_eq!(
        s0::internal::SHARED_SECRET_HEADER,
        platform::SHARED_SECRET_HEADER,
        "\ns0 reads {:?}; {OTHER_REPO} sends SHARED_SECRET_HEADER = {:?} ({}).\n\
         The console's S3GatewayStsService sets this header and nothing else, so a \
         mismatch is a 401 on every session mint for an opted-in organization — which \
         never falls back to the legacy RGW path, by design.\n",
        s0::internal::SHARED_SECRET_HEADER,
        platform::SHARED_SECRET_HEADER,
        hf_path::CONFIG_RS,
    );
}

/// The path the console POSTs to.
#[test]
fn s0_serves_the_session_endpoint_at_the_path_the_console_calls() {
    assert_eq!(
        s0::internal::SESSION_PATH,
        platform::GATEWAY_SESSION_PATH,
        "\ns0 serves {:?}; {OTHER_REPO} posts to GATEWAY_SESSION_PATH = {:?} ({}).\n",
        s0::internal::SESSION_PATH,
        platform::GATEWAY_SESSION_PATH,
        hf_path::STS_CLIENT_RS,
    );
}

/// **The fact half, not the text half.** The console's own pinned request body is
/// pushed through s0's real deserializer and its real validation.
///
/// A field-name comparison that passes and still fails to deserialize is exactly the
/// class of bug this file exists for: `SessionRequest` carries `deny_unknown_fields`,
/// so a field the console adds — or renames — is a hard refusal here, and this is the
/// test that says so before it reaches a cluster.
#[test]
fn the_consoles_session_request_deserializes_through_s0s_real_type() {
    use s0::internal::SessionRequest;
    use s0::model::PrincipalType;

    let parsed: SessionRequest = serde_json::from_str(platform::SESSION_REQUEST_BODY)
        .unwrap_or_else(|e| {
            panic!(
                "\nthe body {OTHER_REPO} pins in `the_session_request_is_the_agreed_wire_contract` \
                 ({}) does not deserialize into s0's `SessionRequest`: {e}\n\
                 Every console-mediated session mint would be a 400.\n",
                hf_path::STS_CLIENT_RS
            )
        });
    assert_eq!(parsed.sub, "svc-pipeline-runner");
    // The raw subject, never the prefixed key — the module composes `sa:<sub>` itself,
    // so a pre-prefixed value would look up `sa:sa:<sub>` and match no grant.
    assert!(!parsed.sub.starts_with("sa:") && !parsed.sub.starts_with("user:"));
    assert_eq!(parsed.principal_type, PrincipalType::ServiceAccount);
    assert_eq!(parsed.tenant, "acme-prod");
    assert_eq!(
        parsed.organization_id,
        "11111111-1111-1111-1111-111111111111"
    );
    assert_eq!(parsed.groups, vec!["editor".to_string()]);
    assert_eq!(parsed.duration_seconds, 3600);

    // The other side of the discriminator, in the vocabulary the two share. These two
    // strings are two different bundle key spaces (`user:` vs `sa:`); a session in the
    // wrong one finds no grants and fails closed on every request.
    assert_eq!(
        serde_json::to_value(PrincipalType::ServiceAccount).expect("serialize"),
        serde_json::json!("service_account")
    );
    assert_eq!(
        serde_json::to_value(PrincipalType::User).expect("serialize"),
        serde_json::json!("user")
    );
}

/// The pinned **field names** against s0's own deserializer, one field at a time.
///
/// The test above proves the whole pinned document parses. That is not the same claim:
/// a document can parse while a field s0 believes it read is silently absent. So this
/// one takes each pinned name, renames only that field, and requires the parse to
/// **fail** — which it does because `SessionRequest` carries `deny_unknown_fields`, and
/// which is exactly what would happen in production on the day either side renames one.
///
/// It is the always-on anchor for `platform::SESSION_REQUEST_FIELDS`: without it, that
/// pin would be held only by the cross-repo half, so on a machine with no hyperfluid
/// checkout someone could "fix" a red contract test by editing the pin and see green.
#[test]
fn s0s_session_request_requires_exactly_the_pinned_field_names() {
    use s0::internal::SessionRequest;

    let pinned: serde_json::Value =
        serde_json::from_str(platform::SESSION_REQUEST_BODY).expect("the pinned body is JSON");
    let object = pinned.as_object().expect("an object");

    let mut names: Vec<&str> = platform::SESSION_REQUEST_FIELDS
        .iter()
        .map(|(n, _)| *n)
        .collect();
    names.sort_unstable();
    let mut in_body: Vec<&str> = object.keys().map(String::as_str).collect();
    in_body.sort_unstable();
    assert_eq!(
        names, in_body,
        "the two pins disagree: SESSION_REQUEST_FIELDS names {names:?} but \
         SESSION_REQUEST_BODY carries {in_body:?}. One of them is not the contract."
    );

    for (name, _) in platform::SESSION_REQUEST_FIELDS {
        // Renamed: an unknown field AND a missing one, simultaneously.
        let mut renamed = object.clone();
        let value = renamed.remove(*name).expect("the field is in the body");
        renamed.insert(format!("{name}_renamed"), value.clone());
        assert!(
            serde_json::from_value::<SessionRequest>(serde_json::Value::Object(renamed)).is_err(),
            "\ns0 accepted a body with {name:?} renamed. That field is part of the \
             contract with {OTHER_REPO} ({}), and s0 silently ignoring it means the \
             console asserted a fact — a tenant, an organization, a principal class — \
             that the session was not actually minted with.\n",
            hf_path::STS_CLIENT_RS,
        );

        // Dropped: every pinned field except `groups` is mandatory. `groups` is
        // advisory (the module reads roles from the bundle, never from the session),
        // so its default is deliberate and is recorded here rather than left to be
        // rediscovered.
        let mut dropped = object.clone();
        dropped.remove(*name);
        let parsed = serde_json::from_value::<SessionRequest>(serde_json::Value::Object(dropped));
        if *name == "groups" {
            assert!(
                parsed.is_ok(),
                "`groups` is documented as advisory and defaulted; it no longer is"
            );
        } else {
            assert!(
                parsed.map(|_| ()).is_err(),
                "\ns0 minted a session with {name:?} absent from the body. Every one of \
                 these is a fact the console asserts and s0 validates against its own \
                 tables; a defaulted one is a session minted against a value nobody \
                 stated.\n"
            );
        }
    }

    // The two response pins must not drift from each other either.
    let required_names: Vec<&str> = platform::MINTED_SESSION_REQUIRED
        .iter()
        .map(|(n, _)| *n)
        .collect();
    assert_eq!(
        required_names,
        platform::MINTED_SESSION_FIELDS.to_vec(),
        "MINTED_SESSION_FIELDS and MINTED_SESSION_REQUIRED disagree about the response \
         shape"
    );
}

/// s0's answer must carry the four field names the console's `MintedSession` reads.
/// Built by minting through the real `StsAuthority`, not by hand.
#[test]
fn the_minted_session_carries_the_field_names_the_console_reads() {
    use s0::auth::sts::{SessionClaims, StsAuthority};
    use s0::mint::MintedCredentials;
    use s0::model::PrincipalType;

    let sts = StsAuthority::new(vec![4u8; 32], vec![8u8; 32]).expect("sts");
    let creds = sts
        .mint(
            "sid-contract",
            SessionClaims {
                sub: "svc-pipeline-runner".into(),
                principal_type: PrincipalType::ServiceAccount,
                groups: vec!["editor".into()],
                tenant: "acme-prod".into(),
                org: "11111111-1111-1111-1111-111111111111".into(),
                sid: "sid-contract".into(),
                exp: 4_102_444_800,
            },
        )
        .expect("mint");
    let json = serde_json::to_value(MintedCredentials::from(creds)).expect("serialize");
    let object = json.as_object().expect("an object");
    for field in platform::MINTED_SESSION_FIELDS {
        assert!(
            object.contains_key(*field),
            "\ns0's session response has no {field:?}; {OTHER_REPO}'s `MintedSession` \
             deserializes it ({}).\nA missing one of the first three is a \
             MalformedResponse on every mint.\nfound: {:?}\n",
            hf_path::STS_CLIENT_RS,
            object.keys().collect::<Vec<_>>(),
        );
    }
    // And nothing else, so a field added here cannot silently become part of the
    // contract without someone coming to this file.
    assert_eq!(object.len(), platform::MINTED_SESSION_FIELDS.len());
}

// ── P2 / P3: the pins, proven to be the ones the RUNNING code uses ─────────────
//
// Everything above this line compares a pin to an `s0::…` constant. That is only half
// the claim. A constant can be spelled perfectly and read by nothing — the P1 entrypoint
// defect was exactly that shape one level down (`DECISION_RULE` was right in one place
// and hand-copied wrong in three others), and it is why `nothing_holds_a_second_copy_of
// _the_entrypoint` exists. The three tests below take the pinned literals — never
// `s0::internal::…` — and drive them through the production accept loop and the
// production bundle poller over real sockets. They need no sibling checkout, so they run
// everywhere the always-on half does.

/// A gateway whose routing table binds exactly the tenant and organization the
/// console's own pinned request body names, so that body can be replayed verbatim.
fn contract_gateway_config() -> s0::config::GatewayConfig {
    let pinned: serde_json::Value =
        serde_json::from_str(platform::SESSION_REQUEST_BODY).expect("the pinned body is JSON");
    s0::config::GatewayConfig::from_json(
        &serde_json::json!({
            "listen": "127.0.0.1:0",
            "admin_listen": "127.0.0.1:0",
            "sts": { "master_key_hex": "00".repeat(32), "signing_key_hex": "11".repeat(32) },
            "pdp": { "mode": "embedded" },
            "audit": { "sink_url": "http://127.0.0.1:59999/none",
                       "spill_path": std::env::temp_dir()
                           .join(format!("s0-contract-{}.ndjson", uuid::Uuid::new_v4())) },
            "backends": [
                { "id": "bay-1", "kind": "ceph", "endpoint_url": "http://127.0.0.1:7480" }
            ],
            "tenants": [
                { "tenant": pinned["tenant"], "organization_id": pinned["organization_id"],
                  "backend_id": "bay-1", "owner_access_key": "OWNER",
                  "owner_secret_key": "SECRET" }
            ],
            "bundle_path": "/dev/null"
        })
        .to_string(),
    )
    .expect("config")
}

/// The value the two sides would share in a cluster. Its content is irrelevant; what is
/// under test is the header it travels in.
const CONTRACT_SECRET: &str = "platform-shared-secret-value";

/// Start the **production** internal accept loop on an ephemeral port.
async fn serve_internal(
    sts: Arc<s0::auth::sts::StsAuthority>,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    let api = Arc::new(s0::internal::InternalApi::new(
        &s0::config::InternalApiConfig {
            listen: "127.0.0.1:0".parse().expect("addr"),
            shared_secret: Some(s0::secret::Secret::from(CONTRACT_SECRET)),
            max_session_ttl_secs: 3600,
        },
        sts,
        Arc::new(
            s0::proxy::BackendRegistry::from_config(&contract_gateway_config()).expect("registry"),
        ),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = s0::internal::serve_on(api, listener, async {
            let _ = stopped.await;
        })
        .await;
    });
    (format!("http://{addr}"), stop)
}

fn contract_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("client")
}

/// **The pinned path and the pinned header, against the running server.**
///
/// The console's own contract document (`platform::SESSION_REQUEST_BODY`) is POSTed
/// verbatim to `platform::GATEWAY_SESSION_PATH` with `platform::SHARED_SECRET_HEADER`,
/// through `internal::serve_on` — the same accept loop `main.rs` spawns — and must come
/// back with a real credential in the field names the console's `MintedSession` reads.
/// Nothing in this test mentions `s0::internal::SESSION_PATH` or
/// `s0::internal::SHARED_SECRET_HEADER`: if either constant stopped being the one the
/// server uses, every equality test above would still pass and this one would not.
///
/// The three negative halves are what make it a proof rather than a demonstration:
///
/// * the header **name** is load-bearing — the same secret under any other name is a
///   401, so this cannot pass on a server that accepts anything;
/// * the path is load-bearing — the same credentialed request one character away is a
///   404, so this cannot pass on a server that answers every path;
/// * and an absent header is a 401, so it cannot pass on a server that authenticates
///   nothing.
#[tokio::test]
async fn the_running_session_endpoint_answers_the_pinned_path_on_the_pinned_header() {
    let sts =
        Arc::new(s0::auth::sts::StsAuthority::new(vec![4u8; 32], vec![8u8; 32]).expect("sts"));
    let (base, _stop) = serve_internal(sts.clone()).await;
    let url = format!("{base}{}", platform::GATEWAY_SESSION_PATH);

    // 1. The console's document, verbatim, on the console's header, at the console's
    //    path.
    let resp = contract_client()
        .post(&url)
        .header(platform::SHARED_SECRET_HEADER, CONTRACT_SECRET)
        .header("content-type", "application/json")
        .body(platform::SESSION_REQUEST_BODY)
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        200,
        "\ns0's running internal listener refused the exact request {OTHER_REPO} sends.\n\
         \x20 path    {:?}   ({}, GATEWAY_SESSION_PATH)\n\
         \x20 header  {:?}   ({}, SHARED_SECRET_HEADER)\n\
         \x20 body    the document pinned by the console's own \
         `the_session_request_is_the_agreed_wire_contract`\n\
         Every console-mediated mint for an opted-in organization fails, with no \
         fallback to the legacy RGW path.\nresponse: {}\n",
        platform::GATEWAY_SESSION_PATH,
        hf_path::STS_CLIENT_RS,
        platform::SHARED_SECRET_HEADER,
        hf_path::CONFIG_RS,
        resp.text().await.unwrap_or_default(),
    );
    let minted: serde_json::Value = resp.json().await.expect("a JSON credential");
    let object = minted.as_object().expect("an object");
    for (field, _) in platform::MINTED_SESSION_REQUIRED {
        assert!(
            object.contains_key(*field),
            "\nthe running endpoint's answer has no {field:?}; {OTHER_REPO}'s \
             `MintedSession` reads it ({}).\nfound: {:?}\n",
            hf_path::STS_CLIENT_RS,
            object.keys().collect::<Vec<_>>(),
        );
    }
    assert_eq!(
        object.len(),
        platform::MINTED_SESSION_FIELDS.len(),
        "the answer carries fields outside the pinned contract: {:?}",
        object.keys().collect::<Vec<_>>(),
    );
    // …and it is a real credential from the same ring the S3 front verifies with, not
    // a well-shaped placeholder.
    assert_eq!(
        sts.secret_for_access_key(object["AccessKeyId"].as_str().expect("AccessKeyId"))
            .as_deref(),
        object["SecretAccessKey"].as_str(),
        "the gateway cannot re-derive the secret it just handed the console"
    );

    // 2. The header NAME is what is read. Same value, any other name ⇒ refused.
    for other_name in [
        "Authorization",
        "X-Shared-Token",
        "X-Shared-Secret-Value",
        "Shared-Secret",
    ] {
        let resp = contract_client()
            .post(&url)
            .header(other_name, CONTRACT_SECRET)
            .header("content-type", "application/json")
            .body(platform::SESSION_REQUEST_BODY)
            .send()
            .await
            .expect("send");
        assert_eq!(
            resp.status(),
            401,
            "the secret presented under {other_name:?} was accepted — the endpoint is \
             not reading {:?} in particular, so the pinned header name proves nothing",
            platform::SHARED_SECRET_HEADER,
        );
    }
    // …and no header at all is refused, so the 200 above was not free.
    assert_eq!(
        contract_client()
            .post(&url)
            .header("content-type", "application/json")
            .body(platform::SESSION_REQUEST_BODY)
            .send()
            .await
            .expect("send")
            .status(),
        401,
    );

    // 3. The PATH is what is served. One character away, fully credentialed ⇒ 404.
    for near_miss in [
        "/internal/v1/sts/session",
        "/internal/v1/sts/sessions/",
        "/internal/v1/sessions",
        "/sts/sessions",
        "/",
    ] {
        let resp = contract_client()
            .post(format!("{base}{near_miss}"))
            .header(platform::SHARED_SECRET_HEADER, CONTRACT_SECRET)
            .header("content-type", "application/json")
            .body(platform::SESSION_REQUEST_BODY)
            .send()
            .await
            .expect("send");
        assert_eq!(
            resp.status(),
            404,
            "{near_miss:?} minted a session — the endpoint is not serving {:?} in \
             particular, so the pinned path proves nothing",
            platform::GATEWAY_SESSION_PATH,
        );
    }
}

/// **The enum literals, against the running server**, and the key space each lands in.
///
/// `principal_type` is not "a string the console sends": it selects which half of the
/// bundle the session's grants are read from (`user:<oidc sub>` vs `sa:<client id>`).
/// A spelling the console changes and s0 does not is a 400 on every mint; a spelling
/// both sides changed *differently* would be worse — a session that authenticates and
/// then matches no grant, which reads as a permissions problem rather than a contract
/// problem.
///
/// So: both pinned literals must be accepted, every near-miss spelling must be refused
/// at the door, and the accepted `service_account` must arrive at `input.principal.type
/// == "service_account"` through `Identity::resolve` — the same call the S3 data plane
/// makes on every request.
#[tokio::test]
async fn the_running_session_endpoint_accepts_exactly_the_pinned_principal_type_literals() {
    let sts =
        Arc::new(s0::auth::sts::StsAuthority::new(vec![4u8; 32], vec![8u8; 32]).expect("sts"));
    let (base, _stop) = serve_internal(sts.clone()).await;
    let url = format!("{base}{}", platform::GATEWAY_SESSION_PATH);
    let pinned: serde_json::Value =
        serde_json::from_str(platform::SESSION_REQUEST_BODY).expect("the pinned body is JSON");
    let with_type = |value: &str| {
        let mut body = pinned.clone();
        body["principal_type"] = serde_json::json!(value);
        body
    };
    let post = |body: serde_json::Value| {
        let url = url.clone();
        async move {
            contract_client()
                .post(url)
                .header(platform::SHARED_SECRET_HEADER, CONTRACT_SECRET)
                .json(&body)
                .send()
                .await
                .expect("send")
        }
    };

    for literal in platform::PRINCIPAL_TYPE_LITERALS {
        let resp = post(with_type(literal)).await;
        assert_eq!(
            resp.status(),
            200,
            "\ns0 refused principal_type {literal:?}, which {OTHER_REPO}'s \
             `GatewayPrincipalType` serializes to ({}).\n\
             Every mint for that principal class fails.\n",
            hf_path::STS_CLIENT_RS,
        );
    }

    // Near misses: the spellings a `rename_all` change, a manual `rename`, or a
    // hand-written body would actually produce. Each must be a refusal, never a
    // session in the other key space.
    for wrong in [
        "ServiceAccount",
        "serviceAccount",
        "SERVICE_ACCOUNT",
        "service-account",
        "User",
        "sa",
        "svc",
        "machine",
        "",
    ] {
        let resp = post(with_type(wrong)).await;
        assert_eq!(
            resp.status(),
            400,
            "principal_type {wrong:?} was accepted; only {:?} may be",
            platform::PRINCIPAL_TYPE_LITERALS,
        );
    }

    // …and each accepted literal reaches the key space the bundle is written in. Read
    // from the pin rather than retyped: a second copy of a shared literal inside the
    // test that guards it is the exact habit this file exists to break.
    let identity = s0::auth::Identity::new(
        sts.clone(),
        Arc::new(s0::auth::StaticCredentialStore::new()),
    );
    for literal in platform::PRINCIPAL_TYPE_LITERALS {
        let minted: serde_json::Value = post(with_type(literal)).await.json().await.expect("json");
        let principal = identity
            .resolve(
                minted["AccessKeyId"].as_str().expect("AccessKeyId"),
                minted["SessionToken"].as_str(),
            )
            .expect("the data plane resolves the session the console was handed");
        assert_eq!(
            serde_json::to_value(principal.to_opa_principal()).expect("serialize")["type"],
            serde_json::json!(literal),
            "\nthe console's principal_type {literal:?} did not survive to \
             `input.principal.type` — the field `s3.rego`'s `subject_key` sprintf reads.\n\
             The session evaluates against the other half of the bundle, matches no \
             grant, and fails closed on every request: a contract bug that presents as \
             a permissions bug.\n"
        );
    }
}

/// **P2's direction: the same header, on the bundle poll, on the wire.**
///
/// The console's `shared_secret_guard` reads one header name. s0's poller must send
/// that one. Getting it wrong here is the quiet failure of the pair: the guard answers
/// 401, s0 logs a failed poll and *keeps serving its last-good bundle*, so the gateway
/// looks healthy while every revocation stops landing.
///
/// Driven through `bundle_refresh::spawn` — the real polling task — against a raw TCP
/// socket that records the request head, because the claim is about bytes on the wire
/// and a client-level stub cannot make it.
#[tokio::test]
async fn the_bundle_poller_presents_the_pinned_header_on_the_wire() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let captured = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).await.expect("read");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&buf).to_string();
        let body = r#"{"data":{}}"#;
        let _ = stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
        let _ = stream.flush().await;
        head
    });

    let source = s0::bundle_refresh::BundleSource::http(
        format!("http://{addr}/api/internal/v1/organizations/x/s3-gateway-bundle"),
        std::time::Duration::from_secs(5),
        Some(s0::secret::Secret::from(CONTRACT_SECRET)),
    )
    .expect("source");
    let data = serde_json::json!({});
    let pdp: Arc<dyn Pdp> = Arc::new(RegorusPdp::new(GATEWAY_REGO, &data).expect("engine"));
    s0::bundle_refresh::spawn(
        pdp,
        Arc::new(BundleStore::new(Bundle::new("rev-0", data.clone()))),
        source,
        std::time::Duration::from_secs(30),
        Arc::new(s0::bundle_refresh::BundleHealth::new(true)),
    );

    let head = tokio::time::timeout(std::time::Duration::from_secs(10), captured)
        .await
        .expect("the poller did not reach the bundle endpoint within 10 s")
        .expect("capture task");

    // Header names are case-insensitive on the wire; the assertion is about the name,
    // not its casing.
    let sent: std::collections::BTreeMap<String, String> = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    assert_eq!(
        sent.get(&platform::SHARED_SECRET_HEADER.to_ascii_lowercase())
            .map(String::as_str),
        Some(CONTRACT_SECRET),
        "\nthe bundle poll did not carry the credential in {:?} ({} in {OTHER_REPO} \
         defines it, and `shared_secret_guard` reads exactly that name).\n\
         A poll the console refuses does not stop the gateway: it keeps its last-good \
         bundle and keeps deciding, so a revocation simply never lands.\nheaders sent: \
         {sent:?}\n",
        platform::SHARED_SECRET_HEADER,
        hf_path::CONFIG_RS,
    );
}

// ── the cross-repo half: the pins against the real hyperfluid tree ──────────────

/// P2 and P3's literals, read out of the real hyperfluid sources.
#[test]
fn the_pinned_platform_contract_matches_the_real_hyperfluid_internal_surfaces() {
    let Some(repo) = hyperfluid_repo("the shared-secret header and the session path") else {
        return;
    };

    let config_rs = read(&repo, hf_path::CONFIG_RS);
    let header = rust_str_const(&config_rs, "SHARED_SECRET_HEADER").unwrap_or_else(|| {
        panic!(
            "{} no longer defines SHARED_SECRET_HEADER — s0 authenticates the session \
             endpoint on that header and sends it on every bundle poll",
            hf_path::CONFIG_RS
        );
    });
    assert_eq!(
        header,
        platform::SHARED_SECRET_HEADER,
        "{}",
        drifted(
            hf_path::CONFIG_RS,
            "SHARED_SECRET_HEADER",
            platform::SHARED_SECRET_HEADER,
            &header
        )
    );

    let sts_rs = read(&repo, hf_path::STS_CLIENT_RS);
    let path = rust_str_const(&sts_rs, "GATEWAY_SESSION_PATH").unwrap_or_else(|| {
        panic!(
            "{} no longer defines GATEWAY_SESSION_PATH",
            hf_path::STS_CLIENT_RS
        );
    });
    assert_eq!(
        path,
        platform::GATEWAY_SESSION_PATH,
        "{}",
        drifted(
            hf_path::STS_CLIENT_RS,
            "GATEWAY_SESSION_PATH",
            platform::GATEWAY_SESSION_PATH,
            &path
        )
    );

    // The console really does send the header on the mint call, rather than merely
    // defining the constant somewhere. Narrowed to `mint_session`'s own body: the
    // constant appearing anywhere in a 600-line file is not the claim — the claim is
    // that *this request* carries it.
    let mint_fn = rust_fn_body(&sts_rs, "mint_session").unwrap_or_else(|| {
        panic!(
            "{} no longer declares `fn mint_session` — the console's only call into \
             s0's session endpoint",
            hf_path::STS_CLIENT_RS
        )
    });
    assert!(
        mint_fn.contains(".header(SHARED_SECRET_HEADER"),
        "{}: `mint_session` no longer sets the shared-secret header on its request. \
         s0 refuses every unauthenticated call to {:?}, and an opted-in organization \
         has no legacy path to fall back to.\n{mint_fn}",
        hf_path::STS_CLIENT_RS,
        platform::GATEWAY_SESSION_PATH,
    );
    // …and it POSTs, which is the only method s0's route accepts (anything else is a
    // 405 behind the auth check).
    assert!(
        mint_fn.contains(".post("),
        "{}: `mint_session` is no longer a POST; s0's session endpoint answers 405 to \
         every other method",
        hf_path::STS_CLIENT_RS,
    );

    // The URL it posts to is composed from the pinned path, not from a second copy of
    // it. (`session_url` is the join; `mint_url` picks which of the target's two base
    // URLs it joins onto — the S3 data plane is the wrong one, and was blocker P3.)
    let session_url = rust_fn_body(&sts_rs, "session_url").unwrap_or_else(|| {
        panic!(
            "{} no longer declares `fn session_url`",
            hf_path::STS_CLIENT_RS
        )
    });
    assert!(
        session_url.contains("GATEWAY_SESSION_PATH"),
        "{}: `session_url` no longer composes GATEWAY_SESSION_PATH — the constant this \
         file pins is no longer the path the console actually calls:\n{session_url}",
        hf_path::STS_CLIENT_RS,
    );

    // …and the request shape it pins is still the one replayed above. Comparing the
    // *field names* out of the console's own contract test, so a rename on that side
    // reddens here rather than in production.
    let pinned: serde_json::Value =
        serde_json::from_str(platform::SESSION_REQUEST_BODY).expect("the pinned body is JSON");
    for field in pinned.as_object().expect("object").keys() {
        assert!(
            sts_rs.contains(&format!("\"{field}\"")),
            "{}",
            drifted(
                hf_path::STS_CLIENT_RS,
                &format!("the session request field {field:?}"),
                field,
                "no longer appears in the console's pinned wire contract",
            )
        );
    }
}

/// **The request shape, read off the console's own type — not off its test.**
///
/// The console builds the mint body from a typed struct (`.json(request)` in
/// `mint_session`), so the struct *is* the wire contract and the struct is what this
/// reads: every field's name, its declared type, and the struct-level serde attributes
/// that could move all the names at once.
///
/// Why the names and not just "it deserializes": a rename is the realistic failure and
/// it is silent from the console's side. s0's `SessionRequest` carries
/// `deny_unknown_fields`, so a renamed field is *simultaneously* an unknown field and a
/// missing one — a 400 on every mint, for organizations that no longer have a legacy
/// path. The console's own suite stays green throughout, because it renamed both the
/// struct and its fixture.
///
/// Why the types too: `organization_id: String` → `Uuid` is harmless (same JSON), but
/// `groups: Vec<String>` → `Option<Vec<String>>` starts sending `null`, which s0's
/// `#[serde(default)]` rejects, and a signed `duration_seconds` makes a negative
/// expressible on a field s0 reads as `u64`. None of those is a rename, and all of them
/// are 400s.
#[test]
fn the_consoles_session_request_struct_is_the_shape_s0_deserializes() {
    let Some(repo) = hyperfluid_repo("the session request's field names and types") else {
        return;
    };
    let sts_rs = read(&repo, hf_path::STS_CLIENT_RS);

    let (attrs, fields) = rust_struct(&sts_rs, "GatewaySessionRequest").unwrap_or_else(|| {
        panic!(
            "{} no longer declares `struct GatewaySessionRequest` — the console builds \
             the mint body from that type, and this test can no longer see its shape",
            hf_path::STS_CLIENT_RS
        )
    });
    assert!(
        fields.len() >= 3,
        "the struct parser found {} field(s) in GatewaySessionRequest — this test would \
         be vacuous: {fields:?}",
        fields.len()
    );

    // A struct-level `rename_all` (or a per-field `rename`) moves wire names without
    // touching a single identifier, so it must be absent — not merely accounted for.
    // If one is ever wanted, this test has to be rewritten to apply it, deliberately.
    assert!(
        !attrs.iter().any(|a| a.contains("rename")),
        "{}",
        drifted(
            hf_path::STS_CLIENT_RS,
            "GatewaySessionRequest's serde attributes",
            "no rename/rename_all (the identifiers are the wire names)",
            &format!("{attrs:?}"),
        )
    );
    for f in &fields {
        assert!(
            f.rename.is_none(),
            "{}",
            drifted(
                hf_path::STS_CLIENT_RS,
                &format!("the field {:?}", f.ident),
                "sent under its own name",
                &format!("renamed to {:?}", f.rename.as_deref().unwrap_or("")),
            )
        );
    }

    let found: Vec<(String, String)> = fields
        .iter()
        .map(|f| (f.ident.clone(), f.ty.clone()))
        .collect();
    let pinned: Vec<(String, String)> = platform::SESSION_REQUEST_FIELDS
        .iter()
        .map(|(n, t)| ((*n).to_string(), (*t).to_string()))
        .collect();
    assert_eq!(
        found,
        pinned,
        "{}",
        drifted(
            hf_path::STS_CLIENT_RS,
            "GatewaySessionRequest's fields (name: type, in order)",
            &format!("{pinned:?}"),
            &format!("{found:?}"),
        )
    );

    // The pinned document replayed by
    // `the_consoles_session_request_deserializes_through_s0s_real_type` must be the
    // serialization of exactly this struct — otherwise the fact half is replaying a
    // body the console no longer sends.
    let body: serde_json::Value =
        serde_json::from_str(platform::SESSION_REQUEST_BODY).expect("the pinned body is JSON");
    let mut in_body: Vec<String> = body.as_object().expect("object").keys().cloned().collect();
    in_body.sort();
    let mut declared: Vec<String> = fields.iter().map(|f| f.ident.clone()).collect();
    declared.sort();
    assert_eq!(
        in_body, declared,
        "the pinned SESSION_REQUEST_BODY and the console's struct no longer carry the \
         same field set; the replay test is testing a body nobody sends"
    );

    // And the whole document still goes through s0's real deserializer — asserted here
    // as well as in the always-on half, because *this* is the half that just proved the
    // document matches the live struct.
    serde_json::from_str::<s0::internal::SessionRequest>(platform::SESSION_REQUEST_BODY)
        .map(|_| ())
        .unwrap_or_else(|e| {
            panic!(
                "\nthe body {OTHER_REPO} builds from `GatewaySessionRequest` ({}) does \
                 not deserialize into s0's `SessionRequest`: {e}\n",
                hf_path::STS_CLIENT_RS
            )
        });
}

/// **The enum literals, read off the console's own enum.**
///
/// `principal_type` selects a bundle key space (`user:` vs `sa:`), so its two spellings
/// are load-bearing strings, not a type. This reads `GatewayPrincipalType`'s variants
/// and its `rename_all`, computes what they serialize to, and holds that against both
/// the pin and s0's own `PrincipalType`.
///
/// The failure it is aimed at: someone drops the `#[serde(rename_all = "snake_case")]`
/// while refactoring. Nothing about the console's types changes, its own tests
/// (`the_principal_type_matches_the_gateways_vocabulary`) go red — but if they were
/// updated to match, the wire silently becomes `"ServiceAccount"`, s0's enum refuses
/// it, and every service-account mint is a 400. Service accounts are the primary
/// consumer of this gateway.
#[test]
fn the_consoles_principal_type_enum_spells_the_literals_s0_accepts() {
    let Some(repo) = hyperfluid_repo("the principal-type wire literals") else {
        return;
    };
    let sts_rs = read(&repo, hf_path::STS_CLIENT_RS);

    let literals = rust_enum_wire_literals(&sts_rs, "GatewayPrincipalType").unwrap_or_else(|| {
        panic!(
            "{} no longer declares `enum GatewayPrincipalType` — the discriminator \
             between the two bundle key spaces",
            hf_path::STS_CLIENT_RS
        )
    });
    let pinned: Vec<String> = platform::PRINCIPAL_TYPE_LITERALS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        literals,
        pinned,
        "{}",
        drifted(
            hf_path::STS_CLIENT_RS,
            "GatewayPrincipalType's wire literals",
            &format!("{pinned:?}"),
            &format!("{literals:?}"),
        )
    );

    // Both directions against s0's own enum: every literal the console can send must
    // deserialize, and s0 must not be able to produce one the console never sends.
    for literal in &literals {
        let parsed: s0::model::PrincipalType = serde_json::from_value(serde_json::json!(literal))
            .unwrap_or_else(|e| {
                panic!(
                    "\n{OTHER_REPO} can send principal_type {literal:?} ({}), and s0's \
                     `PrincipalType` refuses it: {e}\n\
                     `SessionRequest` types the field as that enum, so this is a 400 on \
                     every mint for that principal class.\n",
                    hf_path::STS_CLIENT_RS
                )
            });
        assert_eq!(
            serde_json::to_value(parsed).expect("serialize"),
            serde_json::json!(literal)
        );
    }
    for s0_side in [
        s0::model::PrincipalType::User,
        s0::model::PrincipalType::ServiceAccount,
    ] {
        let wire = serde_json::to_value(s0_side).expect("serialize");
        assert!(
            literals.contains(&wire.as_str().expect("a string").to_string()),
            "s0 has a principal class {wire} that {OTHER_REPO}'s GatewayPrincipalType \
             cannot express ({}); a grant projected for it could never be reached by a \
             console-mediated session",
            hf_path::STS_CLIENT_RS,
        );
    }
}

/// **The response shape, read off the console's own `MintedSession`.**
///
/// The console deserializes s0's answer into that struct; three of its four fields are
/// non-`Option`, so a name s0 stops emitting is `MalformedResponse` on every mint — and
/// the mint has already succeeded by then, which means s0 has minted a live credential
/// that the console throws away. The credential is valid, unused, and counted against
/// nothing until it expires.
#[test]
fn the_consoles_minted_session_reads_exactly_the_fields_s0_returns() {
    let Some(repo) = hyperfluid_repo("the session response's field names") else {
        return;
    };
    let sts_rs = read(&repo, hf_path::STS_CLIENT_RS);

    let (_, fields) = rust_struct(&sts_rs, "MintedSession").unwrap_or_else(|| {
        panic!(
            "{} no longer declares `struct MintedSession` — the type the console reads \
             s0's credential into",
            hf_path::STS_CLIENT_RS
        )
    });
    let found: Vec<(String, bool)> = fields
        .iter()
        .map(|f| {
            (
                // Every field is renamed to its AWS-shaped wire name; an un-renamed one
                // would be read as the snake_case identifier, which s0 never emits.
                f.rename.clone().unwrap_or_else(|| f.ident.clone()),
                !f.optional,
            )
        })
        .collect();
    let pinned: Vec<(String, bool)> = platform::MINTED_SESSION_REQUIRED
        .iter()
        .map(|(n, req)| ((*n).to_string(), *req))
        .collect();
    assert_eq!(
        found,
        pinned,
        "{}",
        drifted(
            hf_path::STS_CLIENT_RS,
            "MintedSession's fields (wire name, required)",
            &format!("{pinned:?}"),
            &format!("{found:?}"),
        )
    );

    // …and s0's real answer satisfies it. Minted through the production authority so
    // this cannot pass on a hand-written object.
    let minted = s0_minted_session_json();
    let object = minted.as_object().expect("an object");
    for (name, required) in &found {
        if *required {
            assert!(
                object.contains_key(name),
                "\ns0's session response omits {name:?}, which {OTHER_REPO} requires \
                 ({}).\nEvery mint returns MalformedResponse — after s0 has already \
                 issued a live credential the console then discards.\nfound: {:?}\n",
                hf_path::STS_CLIENT_RS,
                object.keys().collect::<Vec<_>>(),
            );
        }
    }
    assert_eq!(
        object.len(),
        found.len(),
        "s0 answers with fields outside the contract: {:?}",
        object.keys().collect::<Vec<_>>(),
    );
}

/// **P2, from s0's side: the console must still be checking what s0 sends.**
///
/// s0 now presents the platform shared secret on every bundle poll. That is worth
/// exactly nothing if the console stops validating it — and the failure is invisible
/// from here, because an unauthenticated fetch succeeds: s0 logs a healthy poll, serves
/// a correct bundle, and the endpoint is a change-detection oracle over the grant table
/// again (it supports 304, so a poller holding one revision learns the moment any grant
/// in the organization changes without reading a byte of it).
///
/// So this asserts three separable facts about the real console tree:
///
/// 1. the guard reads the same header constant s0 sends;
/// 2. that constant is a **re-export** of the one this file pins, not a second
///    declaration that could drift from it;
/// 3. the route s0 polls is inside the guarded router — the layer is applied to the
///    nested builder that carries `org_s3_gateway_bundle_handler`, so it cannot be lost
///    by someone adding a route to the outer one.
#[test]
fn the_console_validates_the_credential_s0_sends_on_the_bundle_poll() {
    let Some(repo) = hyperfluid_repo("the bundle endpoint's shared-secret guard") else {
        return;
    };

    // 1. The guard reads the header.
    let guard = read(&repo, hf_path::SHARED_SECRET_GUARD_RS);
    assert!(
        guard.contains("headers.get(SHARED_SECRET_HEADER)"),
        "{}",
        drifted(
            hf_path::SHARED_SECRET_GUARD_RS,
            "shared_secret_guard's header read",
            "headers.get(SHARED_SECRET_HEADER)",
            "not found — the guard no longer reads the header s0 presents",
        )
    );

    // 2. …and that constant is the one this file pins, re-exported rather than
    //    re-declared. A second `const SHARED_SECRET_HEADER` in the fetcher crate would
    //    let the inbound name drift from the outbound one inside a single repository,
    //    which no test in either repo would see.
    let fetcher = read(&repo, hf_path::CONFIG_FETCHER_RS);
    assert!(
        fetcher.contains("pub use hf_lib_config::SHARED_SECRET_HEADER"),
        "{}",
        drifted(
            hf_path::CONFIG_FETCHER_RS,
            "constants::SHARED_SECRET_HEADER",
            "a re-export of hf_lib_config::SHARED_SECRET_HEADER",
            "no longer a re-export — the guard and the client may now read two \
             different header names",
        )
    );
    assert!(
        !fetcher.contains("const SHARED_SECRET_HEADER:"),
        "{} declares its own SHARED_SECRET_HEADER; there must be exactly one, or the \
         header s0 sends and the header the guard checks can differ",
        hf_path::CONFIG_FETCHER_RS,
    );

    // 3. The route s0 polls is behind that guard.
    let router_rs = read(&repo, hf_path::VAUBAN_ROUTER_RS);
    let router = rust_fn_body(&router_rs, "internal_policies_router").unwrap_or_else(|| {
        panic!(
            "{} no longer declares `fn internal_policies_router` — the router carrying \
             the bundle endpoint s0 polls",
            hf_path::VAUBAN_ROUTER_RS
        )
    });
    let guarded = guarded_subrouter(router).unwrap_or_else(|| {
        panic!(
            "\n{} : `internal_policies_router` has no sub-router carrying \
             `.layer(` — the shared-secret guard is not applied to anything.\n\
             The s3-gateway bundle endpoint is unauthenticated again (runbook blocker \
             P2): it leaks the organization's whole grant projection, and its 304 makes \
             it a change-detection oracle over the grant table.\n{router}\n",
            hf_path::VAUBAN_ROUTER_RS
        )
    });
    assert!(
        guarded.contains("org_s3_gateway_bundle_handler"),
        "\n{} : `org_s3_gateway_bundle_handler` is no longer inside the guarded \
         sub-router.\nRunbook blocker P2 is open again — and s0 cannot detect it, \
         because an unauthenticated fetch SUCCEEDS: the poll looks healthy from every \
         angle s0 can see.\nguarded routes: {guarded}\n",
        hf_path::VAUBAN_ROUTER_RS,
    );
    assert!(
        router.contains("shared_secret_guard"),
        "{}: the router no longer mentions shared_secret_guard at all",
        hf_path::VAUBAN_ROUTER_RS,
    );
}

/// s0's real answer to a mint, as JSON. Built through the production `StsAuthority` and
/// `MintedCredentials`, never by hand.
fn s0_minted_session_json() -> serde_json::Value {
    use s0::auth::sts::{SessionClaims, StsAuthority};
    use s0::mint::MintedCredentials;
    use s0::model::PrincipalType;

    let sts = StsAuthority::new(vec![4u8; 32], vec![8u8; 32]).expect("sts");
    let creds = sts
        .mint(
            "sid-contract",
            SessionClaims {
                sub: "svc-pipeline-runner".into(),
                principal_type: PrincipalType::ServiceAccount,
                groups: vec!["editor".into()],
                tenant: "acme-prod".into(),
                org: "11111111-1111-1111-1111-111111111111".into(),
                sid: "sid-contract".into(),
                exp: 4_102_444_800,
            },
        )
        .expect("mint");
    serde_json::to_value(MintedCredentials::from(creds)).expect("serialize")
}

#[test]
fn the_pinned_platform_contract_matches_the_real_hyperfluid_policy_bundle() {
    let Some(repo) = hyperfluid_repo("the rego package and the decision entrypoint") else {
        return;
    };

    let rego = read(&repo, hf_path::RULES_REGO);
    let declared = rego_package(&rego).unwrap_or_else(|| {
        panic!("{} declares no `package` line", hf_path::RULES_REGO);
    });
    assert_eq!(
        declared,
        platform::REGO_PACKAGE,
        "{}",
        drifted(
            hf_path::RULES_REGO,
            "package",
            platform::REGO_PACKAGE,
            &declared
        )
    );

    let bundle_rs = read(&repo, hf_path::BUNDLE_RS);
    let pkg = rust_str_const(&bundle_rs, "S3_AUTHZ_PACKAGE").unwrap_or_else(|| {
        panic!("{} no longer defines S3_AUTHZ_PACKAGE", hf_path::BUNDLE_RS);
    });
    assert_eq!(
        pkg,
        platform::REGO_PACKAGE,
        "{}",
        drifted(
            hf_path::BUNDLE_RS,
            "S3_AUTHZ_PACKAGE",
            platform::REGO_PACKAGE,
            &pkg
        )
    );

    let entry = rust_str_const(&bundle_rs, "S3_AUTHZ_ENTRYPOINT").unwrap_or_else(|| {
        panic!(
            "{} no longer defines S3_AUTHZ_ENTRYPOINT",
            hf_path::BUNDLE_RS
        );
    });
    assert_eq!(
        entry,
        platform::ENTRYPOINT,
        "{}",
        drifted(
            hf_path::BUNDLE_RS,
            "S3_AUTHZ_ENTRYPOINT",
            platform::ENTRYPOINT,
            &entry
        )
    );
}

#[test]
fn the_pinned_platform_contract_matches_the_real_hyperfluid_audit_extractor() {
    let Some(repo) = hyperfluid_repo("the decision-log label literals") else {
        return;
    };

    let src = read(&repo, hf_path::DECISION_LOG_RS);
    let extractor = s3_gateway_extractor(&src).unwrap_or_else(|| {
        panic!(
            "{} no longer contains `impl DecisionLogMetadataExtractor for \
             S3GatewayDecisionLogMetadataExtractor` — the S3 gateway's audit records may \
             have no consumer at all",
            hf_path::DECISION_LOG_RS
        );
    });

    let is_handled = fn_body(extractor, "is_handled").unwrap_or_else(|| {
        panic!("{}: is_handled not found", hf_path::DECISION_LOG_RS);
    });
    let label = str_literal_after(is_handled, ".get(").unwrap_or_else(|| {
        panic!(
            "{}: is_handled reads no label literal",
            hf_path::DECISION_LOG_RS
        );
    });
    assert_eq!(
        label,
        platform::DATA_DOCK_TYPE_LABEL,
        "{}",
        drifted(
            hf_path::DECISION_LOG_RS,
            "is_handled's dispatch label",
            platform::DATA_DOCK_TYPE_LABEL,
            &label
        )
    );
    let value = str_literal_after(is_handled, "==").unwrap_or_else(|| {
        panic!(
            "{}: is_handled compares against no literal",
            hf_path::DECISION_LOG_RS
        );
    });
    assert_eq!(
        value,
        platform::DATA_DOCK_TYPE_VALUE,
        "{}",
        drifted(
            hf_path::DECISION_LOG_RS,
            "is_handled's dock-type value",
            platform::DATA_DOCK_TYPE_VALUE,
            &value
        )
    );

    // The org attribution is read through a shared constant rather than a literal, so
    // check both ends: that the extractor still uses it, and what it resolves to.
    let get_org = fn_body(extractor, "get_organization_id").unwrap_or_else(|| {
        panic!(
            "{}: get_organization_id not found",
            hf_path::DECISION_LOG_RS
        );
    });
    assert!(
        get_org.contains("ORGANIZATION_ID_LABEL"),
        "{}: get_organization_id no longer reads ORGANIZATION_ID_LABEL — s0's org label \
         is pinned to that constant and this test can no longer see what it reads:\n{get_org}",
        hf_path::DECISION_LOG_RS,
    );
    let labels_rs = read(&repo, hf_path::LABELS_RS);
    let org_label = rust_str_const(&labels_rs, "ORGANIZATION_ID_LABEL").unwrap_or_else(|| {
        panic!(
            "{} no longer defines ORGANIZATION_ID_LABEL",
            hf_path::LABELS_RS
        );
    });
    assert_eq!(
        org_label,
        platform::ORGANIZATION_ID_LABEL,
        "{}",
        drifted(
            hf_path::LABELS_RS,
            "ORGANIZATION_ID_LABEL",
            platform::ORGANIZATION_ID_LABEL,
            &org_label
        )
    );

    // The decision-log `path` the platform expects from s0.
    assert!(
        src.contains(&format!("{:?}", platform::DECISION_LOG_PATH)),
        "{}",
        drifted(
            hf_path::DECISION_LOG_RS,
            "the expected s0 decision-log path",
            platform::DECISION_LOG_PATH,
            "not present anywhere in the file",
        )
    );
}

/// The record s0 emits must **deserialize** into the platform's `OPADecisionLog`, or
/// nothing downstream of that ever runs.
///
/// Read from the real struct rather than transcribed: a field that is neither
/// `Option<…>` nor `#[serde(default)]` is required, and a batch containing one record
/// that omits it is rejected whole (`Json<Vec<OPADecisionLog>>`).
#[test]
fn the_platforms_decision_log_type_still_requires_only_fields_s0_sends() {
    let Some(repo) = hyperfluid_repo("the decision-log wire type") else {
        return;
    };
    let src = read(&repo, hf_path::DECISION_LOG_RS);
    let required = required_fields_of_struct(&src, "OPADecisionLog").unwrap_or_else(|| {
        panic!(
            "{} no longer declares `pub struct OPADecisionLog`",
            hf_path::DECISION_LOG_RS
        )
    });
    assert!(
        required.contains("labels") && required.contains("timestamp"),
        "the struct parser found nothing meaningful — this test would be vacuous: \
         {required:?}"
    );

    let record = serde_json::to_value(sample_decision_record()).expect("serializes");
    let obj = record.as_object().expect("a record is an object");
    let missing: Vec<&String> = required.iter().filter(|f| !obj.contains_key(*f)).collect();
    assert!(
        missing.is_empty(),
        "{}",
        drifted(
            hf_path::DECISION_LOG_RS,
            "OPADecisionLog's required fields",
            "every one present in s0's AuditRecord",
            &format!("s0 omits {missing:?}"),
        )
    );

    // The other half of `a_gate_record_omits_a_field_the_platforms_ingest_type_requires`:
    // this is the platform-side fact that makes a gate record poison its batch. When it
    // stops being true, both tests must be revisited together.
    assert!(
        required.contains("input"),
        "`OPADecisionLog::input` is no longer required — the gate-record batch-poisoning \
         defect recorded in `a_gate_record_omits_a_field_the_platforms_ingest_type_requires` \
         is fixed on the platform side; update both tests"
    );
}

/// Field names of `pub struct <name>` that serde requires on the wire: not `Option<…>`
/// and not carrying `#[serde(default)]`.
fn required_fields_of_struct(src: &str, name: &str) -> Option<std::collections::BTreeSet<String>> {
    let at = src.find(&format!("pub struct {name} {{"))?;
    let body = &src[at..];
    let end = body.find("\n}")?;
    let mut out = std::collections::BTreeSet::new();
    let mut defaulted = false;
    for line in body[..end].lines().skip(1) {
        let line = line.trim();
        if line.starts_with("#[serde(") && line.contains("default") {
            defaulted = true;
            continue;
        }
        if line.starts_with('#') || line.starts_with("//") || line.is_empty() {
            continue;
        }
        let Some(field) = line.strip_prefix("pub ") else {
            continue;
        };
        let Some((ident, ty)) = field.split_once(':') else {
            continue;
        };
        let optional = ty.trim().starts_with("Option<");
        if !defaulted && !optional {
            out.insert(ident.trim().to_string());
        }
        defaulted = false;
    }
    Some(out)
}

// ── the integration proof: a real bundle, decided through s0's real path ────────

/// The platform's bundle, verbatim.
///
/// Produced by executing hyperfluid's own projection and serializer — the same
/// `compile_s3_projection` / `S3GatewayBundle::assemble` / `seal` /
/// `to_canonical_bytes` chain behind
/// `GET /organizations/{organization_id}/s3-gateway-bundle` — over the grant rows in
/// `bundle.rs::tests::sample_bundle`, plus one deny grant so `s3_deny` is populated
/// rather than `{}`. Nothing about it is hand-typed; it is a capture, and
/// [`the_captured_platform_bundle_still_carries_the_module_hyperfluid_ships`] holds it
/// against the live checkout.
const PLATFORM_BUNDLE: &str = include_str!("data/platform/s3_gateway_bundle.json");

/// The org the captured bundle is published for. `s3.rego`'s `org_matches` gate
/// compares this against `input.organization_id` and denies on any mismatch, so it is
/// part of the input contract, not decoration.
const PLATFORM_BUNDLE_ORG: &str = "00000000-0000-0000-0000-000000000000";

/// **The proof that the two repositories agree.**
///
/// Every other test in this file compares strings. This one runs the thing. It takes
/// the platform's real bundle bytes and drives them through the exact sequence
/// `src/bundle_refresh.rs::refresh_once` and `src/gateway.rs::build_pdp` run in
/// production — `parse_bundle`, engine construction over the *pushed* module,
/// `Pdp::reload`, `Pdp::decide` on a real `OpaInput` — and asserts:
///
/// * a granted read comes back **ALLOW**, and
/// * a read one prefix outside the grant comes back **DENY**.
///
/// The allow is the load-bearing half. A wrong entrypoint, a package the module does
/// not declare, a `data` shape the rego cannot read, a regorus version that will not
/// compile the module — every one of those failures produces `undefined`, which this
/// gateway *correctly* turns into a deny. So a suite that only ever asserts denies is
/// green on a deny-all production gateway; that is the exact failure this project has
/// already paid for once. Only an allow distinguishes "enforcing" from "broken".
///
/// The deny is the control: it proves the allow came from a grant that matched, not
/// from a module that says yes to everything.
#[tokio::test]
async fn the_platforms_real_bundle_decides_through_s0s_real_loading_path() {
    let parsed = parse_bundle(PLATFORM_BUNDLE).expect("the platform's bundle parses");
    let pushed = parsed
        .policy
        .as_deref()
        .expect("the platform ships its rego module in the bundle's `policy` field");
    assert_ne!(
        pushed, GATEWAY_REGO,
        "the fixture is s0's own compiled-in policy, so this test would prove nothing \
         about the platform's module"
    );

    // Exactly `gateway.rs::build_pdp`'s embedded branch: the pushed module is
    // authoritative, the compiled-in default is only the fallback.
    let bundles = Arc::new(BundleStore::new(Bundle::new(
        content_revision(PLATFORM_BUNDLE),
        parsed.data.clone(),
    )));
    let engine: Arc<dyn Pdp> = Arc::new(
        RegorusPdp::new(pushed, &parsed.data)
            .expect("s0's engine compiles the module the platform ships"),
    );
    let pdp = CachingPdp::new(engine, bundles.clone(), 64);

    // …and `bundle_refresh.rs::refresh_once`: the poll path reinstalls the module and
    // the data on every new revision, so it must work too.
    pdp.reload(parsed.policy.as_deref(), &parsed.data)
        .await
        .expect("the refresh path reloads the platform's module");

    // GRANTED: `sa:pipeline` holds read_objects on acme-prod/warehouse under `team-a/`.
    let allowed = pdp
        .decide(&platform_input("team-a/report.csv"))
        .await
        .expect("the PDP answers");
    assert!(
        allowed.allow,
        "\nTHE TWO REPOSITORIES DO NOT AGREE.\n\
         s0 loaded {OTHER_REPO}'s real bundle through its own production path and \
         DENIED a request the bundle grants.\n\
         reason: {:?}\n\
         A reason of \"regorus: undefined decision\" means the entrypoint {DECISION_RULE} \
         does not resolve in the module the platform ships — i.e. a deny-all gateway. \
         Any other reason means the module and s0's `OpaInput` disagree about the \
         document.\n",
        allowed.reason,
    );
    assert_eq!(allowed.reason, "allow: grant matched");

    // NOT GRANTED: same principal, same bucket, a key outside the granted prefix.
    let denied = pdp
        .decide(&platform_input("team-b/report.csv"))
        .await
        .expect("the PDP answers");
    assert!(
        !denied.allow,
        "a key outside every granted prefix was allowed: {denied:?}"
    );
    assert_eq!(denied.reason, "deny: no grant matches action and scope");

    // …and the projected DENY grant overrides the allow inside its own prefix, which is
    // the half a v1 module would have read as an allow.
    let revoked = pdp
        .decide(&platform_input("team-a/secret/payroll.csv"))
        .await
        .expect("the PDP answers");
    assert!(!revoked.allow, "a projected deny grant did not fire");
    assert_eq!(revoked.reason, "deny: explicit deny grant");
}

/// What a package/entrypoint disagreement actually does — **measured**, not assumed.
///
/// The claim this whole file rests on is "a mismatch cannot produce an allow". That is
/// worth executing rather than believing, and the two engines get there differently:
///
/// * **embedded (regorus 0.10.1)** — `compile_with_entrypoint` rejects the entrypoint
///   outright (`compile: not a valid rule path`), so `build_pdp` returns `Err` and the
///   process never serves. Loud, at boot. Asserted below.
/// * **sidecar OPA (the shipping default, ADR-005)** — the Data API answers 200 with no
///   `result`, which `SidecarPdp` maps to an explicit
///   `Decision::deny("opa: undefined decision")`. Fail-closed, but **silent**: a healthy
///   pod that denies every request. That is the one this file exists to prevent, and it
///   is why the proof above asserts an ALLOW rather than the absence of an error.
#[tokio::test]
async fn a_module_the_entrypoint_does_not_address_can_never_produce_an_allow() {
    let parsed = parse_bundle(PLATFORM_BUNDLE).expect("the fixture parses");
    let shipped = parsed
        .policy
        .as_deref()
        .expect("the fixture carries a module");
    let renamed = shipped.replacen(
        &format!("package {}", platform::REGO_PACKAGE),
        "package s3.authz_renamed",
        1,
    );
    assert_ne!(
        shipped,
        renamed,
        "could not inject a package mismatch — `package {}` is no longer spelled that \
         way in the module the platform ships, so this test proved nothing",
        platform::REGO_PACKAGE
    );

    match RegorusPdp::new(&renamed, &parsed.data) {
        Err(e) => assert!(
            e.to_string().contains("compile"),
            "the engine refused the module for an unexpected reason: {e}"
        ),
        Ok(pdp) => {
            // If a future regorus accepts it, the only tolerable outcome is a deny.
            let decision = pdp
                .decide(&platform_input("team-a/report.csv"))
                .await
                .expect("the PDP answers");
            assert!(
                !decision.allow,
                "a module that does not declare the package {DECISION_RULE} addresses \
                 produced an ALLOW: {decision:?}"
            );
        }
    }
}

/// The capture must not rot into a fossil of a module the platform no longer ships.
#[test]
fn the_captured_platform_bundle_still_carries_the_module_hyperfluid_ships() {
    let parsed = parse_bundle(PLATFORM_BUNDLE).expect("the fixture parses");
    let captured = parsed.policy.expect("the fixture carries a module");

    let Some(repo) = hyperfluid_repo("the captured bundle's rego module") else {
        return;
    };
    let live = read(&repo, hf_path::RULES_REGO);
    assert_eq!(
        captured,
        live,
        "\ntests/data/platform/s3_gateway_bundle.json carries a rego module that is no \
         longer byte-identical to {} in {OTHER_REPO}.\n\
         The integration proof \
         (`the_platforms_real_bundle_decides_through_s0s_real_loading_path`) is \
         therefore evaluating a module the platform does not serve. Re-capture the \
         bundle from the platform's serializer rather than editing the fixture by \
         hand.\n",
        hf_path::RULES_REGO,
    );
}

/// `input.<path>` references the PLATFORM's module makes that s0 has never been
/// observed to emit — recorded, with the reason each is tolerated, rather than left
/// invisible.
///
/// Anything on this list is **inert**: the rego reference is undefined, so the rule it
/// appears in never matches. That is fail-closed, which is why it is a capability gap
/// and not a vulnerability — but "a restriction that silently never applies" is exactly
/// the thing an auditor must not discover on their own.
const PLATFORM_INPUT_PATHS_S0_DOES_NOT_EMIT: &[(&str, &str)] = &[(
    "request.attributes",
    "request-context ABAC. `s3.rego`'s `request_attributes` rule reads it and carries \
     `default request_attributes := {}`, so a grant conditioned on a REQUEST attribute \
     (`Condition::RequestAttributeEquals`, projected by the platform's serializer) can \
     never match: such a grant is inert end to end. s0's `RequestMeta` \
     (src/authz/input.rs) emits only `method`, `params` and `headers_subset`. Allow \
     grants so conditioned under-grant (fail-closed); DENY grants so conditioned are \
     the real cost — a revocation that does not revoke. Owed: an `attributes` field on \
     `RequestMeta`, populated from the parsed request.",
)];

/// The input half of the same contract: every `input.<path>` the PLATFORM's module
/// reads must be a path s0 has actually been observed to emit.
///
/// `tests/fixture_drift.rs::every_rego_input_reference_appears_in_a_captured_input`
/// enforces this for s0's own shipped rego, against the captured corpus. This is the
/// same check aimed across the repository boundary, which is the version that matters:
/// in production s0 evaluates the PLATFORM's module, not its own. A field that module
/// reads and s0 never sends is **undefined**, and undefined is not false — it is the
/// precise shape of the failure that produced 35 green tests over a deny-all policy.
#[test]
fn the_platform_module_reads_no_input_path_s0_never_sends() {
    let Some(repo) = hyperfluid_repo("the platform module's input references") else {
        return;
    };
    let rego = read(&repo, hf_path::RULES_REGO);
    let referenced = rego_input_references(&rego);
    assert!(
        referenced.contains("action") && referenced.contains("principal.sub"),
        "the reference extractor found nothing meaningful in {} — this test would be \
         vacuous: {referenced:?}",
        hf_path::RULES_REGO,
    );

    let corpus = captured_inputs();
    let tolerated: std::collections::BTreeMap<&str, &str> = PLATFORM_INPUT_PATHS_S0_DOES_NOT_EMIT
        .iter()
        .copied()
        .collect();

    let mut unsatisfied = Vec::new();
    for path in &referenced {
        let emitted = corpus
            .iter()
            .any(|doc| resolve(doc, path).is_some_and(|v| !v.is_null()));
        if !emitted && !tolerated.contains_key(path.as_str()) {
            unsatisfied.push(path.clone());
        }
    }
    assert!(
        unsatisfied.is_empty(),
        "\n{} in {OTHER_REPO} reads input.{unsatisfied:?}, which s0 has never been \
         observed to emit.\n\
         A rego reference to a field no producer sends is UNDEFINED, not false, so every \
         rule that depends on it is permanently inert. Either add the field to \
         `src/authz/input.rs` and re-record the capture corpus \
         (`S0_CAPTURE_REGENERATE=1 cargo test --test golden_capture`), or — if the gap \
         is deliberate and fail-closed — record it in \
         PLATFORM_INPUT_PATHS_S0_DOES_NOT_EMIT with the reason.\n",
        hf_path::RULES_REGO,
    );

    // The tolerated list must not outlive the gap it documents. Once s0 emits the
    // field, the entry has to go, or it would mask the *next* regression at that path.
    for (path, _) in PLATFORM_INPUT_PATHS_S0_DOES_NOT_EMIT {
        assert!(
            referenced.contains(*path),
            "PLATFORM_INPUT_PATHS_S0_DOES_NOT_EMIT records input.{path}, but {} no \
             longer reads it — delete the entry",
            hf_path::RULES_REGO,
        );
        assert!(
            !corpus
                .iter()
                .any(|doc| resolve(doc, path).is_some_and(|v| !v.is_null())),
            "s0 now emits input.{path}: delete its entry from \
             PLATFORM_INPUT_PATHS_S0_DOES_NOT_EMIT so the path is enforced again"
        );
    }
}

/// Every `input.<a>.<b>…` reference in a rego module, comments stripped. Same
/// extractor as `tests/fixture_drift.rs::rego_input_references`, which is deliberate:
/// the two tests must agree about what "the policy reads this" means.
fn rego_input_references(rego: &str) -> std::collections::BTreeSet<String> {
    let mut refs = std::collections::BTreeSet::new();
    for line in rego.lines() {
        let code = line.split('#').next().unwrap_or("");
        let bytes = code.as_bytes();
        let mut i = 0;
        while let Some(pos) = code[i..].find("input.") {
            let start = i + pos;
            let preceded_by_ident =
                start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
            i = start + "input.".len();
            if preceded_by_ident {
                continue;
            }
            let mut end = i;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_' || bytes[end] == b'.')
            {
                end += 1;
            }
            let path = code[start + "input.".len()..end].trim_end_matches('.');
            if !path.is_empty() {
                refs.insert(path.to_string());
            }
            i = end;
        }
    }
    refs
}

fn resolve<'a>(doc: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    path.split('.').try_fold(doc, |v, seg| v.get(seg))
}

/// The recorded corpus of inputs the gateway has actually emitted, plus the input this
/// file drives the platform's module with — so "s0 emits this" means observed, not
/// claimed.
fn captured_inputs() -> Vec<serde_json::Value> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/captured_inputs");
    let mut out = vec![
        serde_json::to_value(platform_input("team-a/report.csv")).expect("OpaInput serializes"),
    ];
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!("no captured corpus at {dir:?} ({e}); see tests/golden_capture.rs")
    }) {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        out.push(
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read"))
                .unwrap_or_else(|e| panic!("{path:?} is not JSON: {e}")),
        );
    }
    assert!(out.len() > 1, "the captured corpus is empty");
    out
}

/// A real `OpaInput`, built through s0's own types, for the captured bundle's
/// `sa:pipeline` grant on `acme-prod` / `warehouse`.
fn platform_input(object: &str) -> s0::authz::OpaInput {
    use s0::authz::{Backend, OpaInput, Principal, PrincipalAttributes, RequestMeta};
    use s0::model::{Action, BackendKind, PrincipalType};

    OpaInput {
        principal: Principal {
            // The module derives `sa:<sub>` itself, so a key-space mismatch cannot be
            // papered over here.
            sub: "pipeline".into(),
            kind: PrincipalType::ServiceAccount,
            attributes: PrincipalAttributes::default(),
        },
        backend: Backend {
            id: "default-rgw".into(),
            kind: BackendKind::Ceph,
        },
        tenant: "acme-prod".into(),
        organization_id: PLATFORM_BUNDLE_ORG.into(),
        action: Action::ReadObjects,
        bucket: "warehouse".into(),
        object: Some(object.into()),
        prefix: None,
        copy_source: None,
        delete_keys: None,
        object_tags: None,
        config_kind: None,
        requested_tags: None,
        acl_grants: vec![],
        bypass_governance: false,
        request: RequestMeta {
            method: "GET".into(),
            params: None,
            headers_subset: Default::default(),
        },
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────

fn drifted(file: &str, what: &str, pinned: &str, found: &str) -> String {
    format!(
        "\nCROSS-REPO CONTRACT DRIFT\n\
         \x20 repo    {OTHER_REPO}\n\
         \x20 file    {file}\n\
         \x20 item    {what}\n\
         \x20 pinned  {pinned:?}   (tests/cross_repo_contract.rs, mod `platform`)\n\
         \x20 found   {found:?}\n\n\
         The platform moved and s0 did not. Change s0 to match, then update the pin — \
         updating the pin alone will make the always-on tests in this same file fail, \
         which is the point.\n"
    )
}

/// Locate the sibling checkout. `None` ⇒ skip, loudly.
fn hyperfluid_repo(checking: &str) -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // An explicit `HYPERFLUID_REPO` is authoritative: if someone says where the platform
    // is, silently verifying a *different* checkout found by the sibling walk would be
    // worse than not verifying at all.
    let candidates: Vec<PathBuf> = match std::env::var("HYPERFLUID_REPO") {
        Ok(explicit) => vec![PathBuf::from(explicit)],
        Err(_) => {
            let mut v = Vec::new();
            let mut dir = manifest.as_path();
            while let Some(parent) = dir.parent() {
                v.push(parent.join("hyperfluid"));
                dir = parent;
            }
            v
        }
    };
    for c in &candidates {
        if c.join(hf_path::RULES_REGO).is_file() {
            return Some(c.clone());
        }
    }

    let required = std::env::var("S0_REQUIRE_HYPERFLUID").is_ok_and(|v| v != "0");
    let looked = candidates
        .iter()
        .map(|c| format!("      {}", c.display()))
        .collect::<Vec<_>>()
        .join("\n");
    let message = format!(
        "cross-repo contract NOT VERIFIED against {OTHER_REPO} — {checking}\n\
         \x20   looked for {} under:\n{looked}\n\
         \x20   set HYPERFLUID_REPO=/path/to/hyperfluid to point at a checkout;\n\
         \x20   set S0_REQUIRE_HYPERFLUID=1 to make this a hard failure (any pipeline \
         that has both checkouts MUST set it).\n\
         \x20   The pins in `mod platform` are still enforced against s0 by the \
         always-on tests in this file.",
        hf_path::RULES_REGO,
    );
    assert!(!required, "S0_REQUIRE_HYPERFLUID is set: {message}");
    eprintln!("\n!!! SKIPPED: {message}\n");
    None
}

fn read(repo: &Path, rel: &str) -> String {
    let p = repo.join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "cannot read {} from {OTHER_REPO} at {}: {e}\n\
             The file the contract is pinned against has moved or been deleted; s0's \
             {} may now be talking to nothing.",
            rel,
            p.display(),
            if rel.ends_with(".rego") {
                "decision entrypoint"
            } else {
                "audit labels"
            }
        )
    })
}

/// The `package …` line of a rego module, ignoring the comment header.
fn rego_package(src: &str) -> Option<String> {
    src.lines()
        .map(str::trim)
        .find(|l| l.starts_with("package "))
        .map(|l| l["package ".len()..].trim().to_string())
}

/// `pub const NAME: &str = "value";` → `value`.
fn rust_str_const(src: &str, name: &str) -> Option<String> {
    let needle = format!("const {name}:");
    let at = src.find(&needle)?;
    str_literal_after(&src[at..], "=")
}

/// The `impl DecisionLogMetadataExtractor` block for the S3 gateway extractor.
fn s3_gateway_extractor(src: &str) -> Option<&str> {
    let start =
        src.find("impl DecisionLogMetadataExtractor for S3GatewayDecisionLogMetadataExtractor")?;
    let rest = &src[start..];
    // The impl block ends at the first `}` in column 0.
    let end = rest.find("\n}\n").map(|i| i + 3).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The body of `fn <name>` inside an already-narrowed block, up to the next `fn ` or
/// the end.
fn fn_body<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    let at = block.find(&format!("fn {name}("))?;
    let rest = &block[at..];
    let end = rest[1..]
        .find("\n    fn ")
        .map(|i| i + 1)
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

// ── reading the other repository's Rust ────────────────────────────────────────
//
// These parse hyperfluid's real source rather than a copy of it. They are deliberately
// small and deliberately strict: every one of them `panic!`s with a message naming the
// file when it cannot find what it expects, because "the parser found nothing" and "the
// contract holds" must never be the same outcome. That is the failure mode of a grep-
// based contract test — it passes hardest exactly when the code it was watching is gone.

/// One field of a Rust struct, as it reaches the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RustField {
    ident: String,
    ty: String,
    /// `#[serde(rename = "…")]`, which is the wire name when present.
    rename: Option<String>,
    /// `Option<…>`, i.e. serde does not require it.
    optional: bool,
}

/// The span from `start` to its matching close, inclusive, skipping over string and
/// char literals and line comments so a brace inside `format!("{x}")` cannot end it.
fn balanced_from(src: &str, start: usize, open: u8, close: u8) -> Option<&str> {
    let bytes = src.as_bytes();
    let mut depth = 0usize;
    let mut i = start;
    let (mut in_str, mut in_char) = (false, false);
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
        } else if in_char {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'\'' {
                in_char = false;
            }
        } else if c == b'"' {
            in_str = true;
        } else if c == b'\''
            // A char literal (`'x'`, `'\n'`) rather than a lifetime (`'a`).
            && (bytes.get(i + 1) == Some(&b'\\') || bytes.get(i + 2) == Some(&b'\''))
        {
            in_char = true;
        } else if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        } else if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(&src[start..=i]);
            }
        }
        i += 1;
    }
    None
}

/// The body of `fn <name>`, brace-matched. Unlike [`fn_body`] this does not depend on
/// indentation, so it works on a free function as well as a method.
fn rust_fn_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let at = src.find(&format!("fn {name}("))?;
    let open = at + src[at..].find('{')?;
    balanced_from(src, open, b'{', b'}')
}

/// The `#[…]` attributes immediately above the item declared at `at`.
fn attrs_above(src: &str, at: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in src[..at].lines().rev() {
        let t = line.trim();
        if t.starts_with("#[") {
            out.push(t.to_string());
        } else if t.starts_with("///") || t.starts_with("//") || t.is_empty() {
            continue;
        } else {
            break;
        }
    }
    out.reverse();
    out
}

/// `(struct-level attributes, fields in declaration order)` for `struct <name> { … }`.
/// Matches both `pub struct` and a private one.
fn rust_struct(src: &str, name: &str) -> Option<(Vec<String>, Vec<RustField>)> {
    let decl = src.find(&format!("struct {name} {{"))?;
    let line_start = src[..decl].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let attrs = attrs_above(src, line_start);
    let body = balanced_from(src, decl + src[decl..].find('{')?, b'{', b'}')?;

    let mut fields = Vec::new();
    let mut rename: Option<String> = None;
    for line in body.lines() {
        let t = line.trim().trim_end_matches(',');
        if t.starts_with("#[") {
            if t.contains("rename = \"") {
                rename = str_literal_after(t, "rename =");
            }
            continue;
        }
        if t.starts_with("//") || t.is_empty() || t == "{" || t == "}" {
            continue;
        }
        let field = t.strip_prefix("pub ").unwrap_or(t);
        let Some((ident, ty)) = field.split_once(':') else {
            continue;
        };
        let ty = ty.trim().to_string();
        fields.push(RustField {
            ident: ident.trim().to_string(),
            optional: ty.starts_with("Option<"),
            ty,
            rename: rename.take(),
        });
    }
    Some((attrs, fields))
}

/// What `enum <name>`'s variants serialize to, in declaration order: an explicit
/// `#[serde(rename = "…")]` if present, else the variant name through the enum's
/// `#[serde(rename_all = "…")]`, else the variant name itself.
fn rust_enum_wire_literals(src: &str, name: &str) -> Option<Vec<String>> {
    let decl = src.find(&format!("enum {name} {{"))?;
    let line_start = src[..decl].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let rename_all = attrs_above(src, line_start)
        .iter()
        .find(|a| a.contains("rename_all"))
        .and_then(|a| str_literal_after(a, "rename_all ="));
    let body = balanced_from(src, decl + src[decl..].find('{')?, b'{', b'}')?;

    let mut out = Vec::new();
    let mut rename: Option<String> = None;
    for line in body.lines() {
        let t = line.trim().trim_end_matches(',');
        if t.starts_with("#[") {
            if t.contains("rename = \"") {
                rename = str_literal_after(t, "rename =");
            }
            continue;
        }
        if t.starts_with("//") || t.is_empty() || t == "{" || t == "}" {
            continue;
        }
        // Unit variants only; anything else is a shape this contract does not model,
        // and silently skipping it would understate the enum.
        if !t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        out.push(match (rename.take(), rename_all.as_deref()) {
            (Some(explicit), _) => explicit,
            (None, Some("snake_case")) => to_snake_case(t),
            (None, _) => t.to_string(),
        });
    }
    (!out.is_empty()).then_some(out)
}

fn to_snake_case(ident: &str) -> String {
    let mut out = String::new();
    for (i, c) in ident.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The argument of the first `.merge(…)` in a router builder that carries a `.layer(`
/// — i.e. the nested `Router` the guard is applied to.
///
/// The nesting is the point, and hyperfluid's own comment says so: the layer's reach is
/// the route list *inside* the nested builder, so a route added to the outer builder
/// cannot silently acquire — or lose — it. `None` means the router no longer has that
/// shape, which is a change that has to be read by a person rather than pattern-matched
/// by this test.
fn guarded_subrouter(router_body: &str) -> Option<&str> {
    let mut from = 0usize;
    while let Some(rel) = router_body[from..].find(".merge(") {
        let open = from + rel + ".merge(".len() - 1;
        let arg = balanced_from(router_body, open, b'(', b')')?;
        if arg.contains(".layer(") {
            return Some(arg);
        }
        from = open + arg.len();
    }
    None
}

/// The first double-quoted string literal appearing after `needle`.
fn str_literal_after(hay: &str, needle: &str) -> Option<String> {
    let at = hay.find(needle)? + needle.len();
    let rest = &hay[at..];
    let open = rest.find('"')?;
    let after = &rest[open + 1..];
    let close = after.find('"')?;
    Some(after[..close].to_string())
}

/// The labels a real decision record carries, built through the production
/// constructor so this test cannot pass on constants nobody uses.
fn sample_record_labels() -> std::collections::BTreeMap<String, String> {
    sample_decision_record().labels
}

/// A real decision record, built through the production constructor.
fn sample_decision_record() -> s0::audit::AuditRecord {
    use s0::audit::{AuditRecord, BackendOutcome, GatewayMeta, Outcome};
    use s0::authz::{Backend, Decision, OpaInput, Principal, PrincipalAttributes, RequestMeta};
    use s0::model::{Action, BackendKind, PrincipalType};

    let input = OpaInput {
        principal: Principal {
            sub: "alice".into(),
            kind: PrincipalType::User,
            attributes: PrincipalAttributes::default(),
        },
        backend: Backend {
            id: "backend-1".into(),
            kind: BackendKind::Ceph,
        },
        tenant: "acme".into(),
        organization_id: "3f8e2c1a-9d4b-4f6e-8a2d-7c5b9e0f1a2b".into(),
        action: Action::ReadObjects,
        bucket: "reports".into(),
        object: Some("2024/q1.csv".into()),
        prefix: None,
        copy_source: None,
        delete_keys: None,
        object_tags: None,
        config_kind: None,
        requested_tags: None,
        acl_grants: vec![],
        bypass_governance: false,
        request: RequestMeta::default(),
    };
    AuditRecord::new(
        "dec-contract".into(),
        "2026-07-28T00:00:00Z".into(),
        input,
        Decision::allow("grant matched"),
        GatewayMeta {
            backend_id: "backend-1".into(),
            backend_kind: "ceph".into(),
            outcome: Outcome::Allowed,
            denied_keys: vec![],
            backend: BackendOutcome::NotAttempted,
            backend_status: None,
        },
    )
}
