# ADR-009: SFTP front — a second protocol on the gateway core

- **Status**: Proposed
- **Date**: 2026-09-29
- **Extends**: ADR-002 (a new record shape and an optional `gateway.session` block, D13) and
  ADR-006 (a new verb and `grant_schema_version: 3`, D5, D7). Both stay in force; this ADR
  adds to their contracts and does not edit them.
- **Owners**: gateway team (this repository); projecting SFTP accounts, SSH keys and user CAs
  into the bundle is control-plane integration (out of scope for this repository)
- **Scope**: Adds SFTP as a second protocol front on the existing core (identity, PDP, bundle
  store, audit sink, backend registry, limits). Decides the process shape, the SSH transport
  and its algorithm floor, the SFTP protocol layer, the bundle contract for SFTP principals,
  the mapping of every SFTP request onto authorization decisions, create-only semantics, the
  object-store data path, limits, audit, and the extension point for future content
  inspection.
- **Related**: `src/gateway.rs`, `src/access/mod.rs`, `src/access/proof.rs`,
  `src/access/optable.rs`, `src/authz/input.rs`, `src/authz/decision.rs`, `src/pdp/bundle.rs`,
  `src/audit/record.rs`, `src/audit/sink.rs`, `src/config.rs`, `src/main.rs`,
  `policy/gateway/authz.rego`; ADR-002 (record shape), ADR-004 (list narrowing and fan-out),
  ADR-005 (engine parity and the cache), ADR-006 (grant projection and identity), ADR-007
  (response obligations, `must_understand`), ADR-008 (deny, never strip)

---

## Context

### The use case

Machine-to-machine file drops. A partner system runs a scheduled job that uploads files over
SFTP into one prefix of one bucket, and must not be able to read, overwrite or delete what is
already there. Interactive human use (browse, download, tidy up) is secondary but must not be
broken by construction.

### Why SFTP terminates in s0 rather than in a server placed in front of it

An off-the-shelf SFTP server in front of s0 must hold an S3 credential per account. Uploading
over SFTP makes that server stat the target first — `HeadObject`, then `ListObjectsV2` to
detect a directory — so the credential needs `read_objects` and `list_objects` as well as
`write_objects`. A leaked credential, or a bypassed server, can then read and overwrite the
whole prefix, and "upload only" exists only as configuration inside the SFTP server. s0 has no
create-only verb today: `write_objects` covers both create and overwrite.

With SFTP terminated in s0:

- the client holds an SSH key and nothing else — no S3 power at all;
- the stat an upload needs is issued **by s0**, with the tenant backend credential, after an
  authorization decision for the SFTP operation, and never returns object content;
- s0 sees the SFTP intent (the open flags) and can enforce create-only, in policy;
- there is one audit trail and one policy for both protocols.

This is the same argument ADR-001 makes about direct backend paths, applied one layer up: a
component that holds a broader credential than the principal it serves is an unaudited
direct path.

### What the code and the pinned dependencies actually provide

Several constraints in the brief for this work were checked against the code and against the
dependency versions the implementation would pin. Where one does not hold, this ADR says so
and decides around it rather than working around it silently.

| # | Finding | Evidence | Consequence |
|---|---|---|---|
| E1 | The enforce path is s3s-typed end to end. `ReqCtx` is built from extensions that only `S3Access::check` installs (principal, route, operation name), and `S3AccessContext` has `pub(crate)` fields, so `check` cannot be driven from outside an HTTP request. | `src/access/mod.rs` (`ReqCtx::new`, `check`); `docs/substrate-api.md` §2.3 | The decision funnel must be extracted into a protocol-neutral core before a second front can share it (D2). |
| E2 | `excluded_prefixes` is **not implemented** by s0. It is not in `IMPLEMENTED_OBLIGATIONS`; a pushed module that emits it with `must_understand` gets a denial, on S3 today. | `src/authz/decision.rs` (`IMPLEMENTED_OBLIGATIONS`); `tests/security_regressions.rs` | "excluded_prefixes apply to SFTP as to S3" holds literally: both **deny**. Neither front filters. D7 records it. |
| E3 | The `grant_schema_version` gate lives in the **pushed module** (exact match on 2). s0 itself only reads the field to warn about a module-less platform bundle. | `tests/data/platform/s3_gateway_bundle.json` (`schema_ok`); `src/pdp/bundle.rs` (`is_platform_data_missing_its_module`) | Bumping the version is a contract change the module enforces; s0 adds its own PEP-side gate on the SFTP section (D5). |
| E4 | s3s 0.14.1 carries `if_none_match` on `PutObjectInput` and `CompleteMultipartUploadInput`, and s3s-aws 0.14.1 converts both. `CopyObjectInput` carries only `copy_source_if_none_match`, a condition on the **source**. | `s3s-0.14.1/src/dto/generated.rs` (`CompleteMultipartUploadInput`, `PutObjectInput`, `CopyObjectInput`); `s3s-aws-0.14.1/src/conv/generated.rs` (`CompleteMultipartUploadInput`, `PutObjectInput` impls) | A conditional *create* is expressible for uploads, and for renames only as a multipart copy (D8). |
| E5 | russh 0.63.3 implements strict KEX (`kex-strict-s-v00@openssh.com`), `max_auth_attempts`, and rejects a channel-open whose handle is dropped. But `exec`, `shell`, `env`, `pty-req` and `subsystem` default to `Ok(())` **without replying**, like the s3s hooks default to `Ok(())`. | `russh-0.63.3/src/kex/mod.rs`, `src/server/mod.rs` (`Handler` defaults), `src/lib_inner.rs` (`ChannelOpenHandleInner::drop`), `src/server/encrypted.rs` | Every `Handler` method is overridden and pinned by a table test (D3). |
| E6 | russh 0.63.3's server public-key path hands the handler the **key only**. The signature algorithm the client used (`ssh-rsa` = SHA-1, or `rsa-sha2-256/512`) is verified but never exposed, and no check against a server preference list is visible on that path. For certificates, russh checks the validity window and the CA signature, and nothing else. | `russh-0.63.3/src/server/encrypted.rs`, `server_read_auth_request_pk` | "RSA-SHA2 only, no SHA-1" is **not enforceable** on the pinned API. RSA client keys are refused in v1 (D3). Every certificate property except those two is s0's to check (D5). |
| E7 | russh-sftp 3.0.1 decodes every protocol string with `String::from_utf8_lossy`; on any per-packet error its loop logs and keeps reading the same stream; it processes one request at a time. | `russh-sftp-3.0.1/src/buf.rs` (`try_get_string`); `src/server/mod.rs` (`run_with_config`) | Non-UTF-8 paths cannot be rejected (two different byte strings collapse onto one key), and an oversized or malformed packet desynchronizes the stream instead of ending it. An in-tree SFTP v3 codec is chosen (D4). |
| E8 | russh 0.63.3 pulls `rsa 0.10.0-rc.18` and `ssh-key 0.7.0-rc.11` (pre-releases) and `aws-lc-rs` (C, built by `aws-lc-sys`). RUSTSEC-2023-0071 (timing side channel) concerns **private-key** operations of the `rsa` crate. | `cargo metadata` over a probe crate depending on `russh = "0.63.3"`, `russh-sftp = "3.0.1"` | No RSA host keys, so s0 performs no RSA private-key operation (D3). Licence review below. |

**Licences.** Resolving `russh 0.63.3` and `russh-sftp 3.0.1` yields 192 crates, all under
permissive licences: Apache-2.0, MIT, BSD-3-Clause (`curve25519-dalek`, `ed25519-dalek`,
`subtle`), ISC (`aws-lc-rs`, `untrusted`), Zlib (`zlib-rs`), 0BSD, Unlicense and
`Unicode-3.0` only as alternatives or additions to MIT/Apache. `aws-lc-sys` is
`ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND …`. None is copyleft,
so all are compatible with distributing s0 under BUSL-1.1 and, after the change date, under
Apache-2.0. (That count was taken with `russh-sftp`, which D4 then dropped; the shipped set
is whatever `Cargo.lock` resolves.) The notices ship with the image and the release
archives: cargo-about generates `THIRD_PARTY_NOTICES` from `Cargo.lock` and the fetched
sources only (`--frozen`), and the image carries it under `/usr/share/doc/s0/`. A
`cargo deny check licenses` CI job (`deny.toml`, an explicit allow-list of permissive
licences) fails on any other licence, so a later bump cannot introduce a copyleft crate
unnoticed.

---

## Decision

### D1 — Process shape: same binary, same core, a front selected by config

- A new top-level `frontends` object holds one section per data-plane front, each switched
  by its own required `enabled` boolean (`GatewayConfig::s3_enabled`, `sftp_enabled`):
  - `frontends.s3` — **absent ⇒ the S3 front is enabled**, so every existing config keeps
    its behaviour. Present, it is `{ "enabled": bool, "listen"?: addr }`.
  - `frontends.sftp` — **absent ⇒ no SFTP listener**, exactly as with `sts_mint` and
    `internal`. Present, it carries `enabled`, `listen`, `host_keys`, `proxy_protocol` and
    `drain_secs`. A section kept with `enabled: false` binds nothing, but its shape is
    still validated, so flipping the switch later cannot be the moment a typo is found.
  - Both enabled is for development only and logged at `warn`. Both disabled is refused:
    the process would serve nothing.
  - An `s3` or `sftp` section written at the top level instead of under `frontends` is
    refused rather than ignored: it would load cleanly and switch nothing.
- An SFTP-only process (`frontends.s3.enabled: false` plus an enabled `frontends.sftp`)
  binds no S3 port. It still runs the bundle poller, the audit worker and the admin
  listener.
- **Config fields that only the S3 front needs become conditional.** Today `listen` and `sts`
  (including its signing key) are required, and `Gateway::build` always builds the STS
  authority. After this change the S3 listener — the top-level `listen` (its historical
  place) or `frontends.s3.listen`, never both — is required iff the S3 front is enabled, and
  refused when it is disabled, since a listener that is never bound reads exactly like one
  that is. `sts` is required iff the process serves S3 or the mint or internal listeners,
  which mint or verify STS sessions. An SFTP pod therefore carries no STS key material:
  `Gateway::build` gives it an authority keyed with ephemeral, process-local random keys,
  which no client can use.
  Every existing config has no `frontends`, so it still serves S3 alone, and its required
  fields do not change. The production shape is **two Deployments from one image**: a crash, a resource exhaustion or
  a memory-safety bug in SSH parsing takes down SFTP pods and never the S3 front.
- `frontends.sftp.listen` joins the listener-uniqueness check in `GatewayConfig::validate`.
- **The admin listener is unchanged**: no new route. Host-key fingerprints are published as a
  metric series, `s0_sftp_host_key_info{algorithm="ssh-ed25519",fingerprint="SHA256:…"} 1`,
  and logged once at startup at `info`. Operators publish them for client pinning.
- **Shutdown**: on SIGTERM readiness fails first (unchanged) and the SFTP listener stops
  accepting. A session with no open upload is closed at once; open read and directory
  handles are settled and cut. A session with open uploads gets up to
  `frontends.sftp.drain_secs` (default 20, read at startup) to CLOSE them; after that every
  open transfer is **aborted** (never committed). Each session is closed with a
  `disconnected{reason: "shutdown"}` record, and only then is the audit worker drained. The
  documented `terminationGracePeriodSeconds: 60` still covers it.

```jsonc
{
  "frontends": {
    "s3": { "enabled": false },
    "sftp": {
      "enabled": true,
      "listen": "0.0.0.0:2222",
      "host_keys": ["/etc/s0/sftp/ssh_host_ed25519_key", "/etc/s0/sftp/ssh_host_ecdsa_key"],
      "proxy_protocol": { "trusted_cidrs": ["198.51.100.0/28"] },
      "drain_secs": 20
    }
  },
  "backends": [
    { "id": "backend-eu-1", "conditional_create": "check_then_write" /* … */ }
  ]
}
```

### D2 — Architecture: extract the decision funnel, then build SFTP on it

E1 rules out driving the S3 hooks from SFTP. It also rules out a loopback design where the
SFTP front calls the S3 front over HTTP: that needs a credential, which is the design this ADR
exists to avoid.

1. **Extract the funnel, with no behaviour change for S3.** The protocol-neutral part of
   `GatewayAccess` — the `decide` funnel (the single PDP call site with the golden-capture
   tap), the `must_understand` check, audit-record assembly, `PendingAudit`, and proof
   minting — moves into an `Enforcer` (`src/access/enforcer.rs`). Its
   `decide(operation, &OpaInput)` is the single PDP call site; principal and route travel
   inside the `OpaInput`. It mints proofs only from allow decisions (`prove_s3`,
   `prove_sftp`), refusing any decision that carries an obligation the gateway does not
   implement. `GatewayAccess` is its first caller. The extraction landed together with the
   SFTP front (#42); the existing suite passes with only references renamed, and
   `tests/golden_capture.rs::decide_is_the_only_pdp_call_site_and_every_capture_round_trips`
   still holds exactly one call site, `Enforcer::decide`.
2. **The SFTP front is a second caller.** Modules: `sftp::transport` (russh), `sftp::codec`
   (the v3 wire format, pure and fuzzable), `sftp::session` (request dispatch),
   `sftp::paths` (the virtual root), `sftp::transfer` (the upload and download state
   machines), `sftp::account` (bundle-driven authentication), `sftp::limits`,
   `sftp::preauth` (the PROXY v2 reader, the strict-KEX guard and the connection kill
   switch) and `sftp::backend` (`SftpBackend`, the proof-checked backend client).
3. **Decide and forward from the same value.** Each SFTP request is mapped once to
   (bucket, key), never re-derived from the SFTP path string. The `OpaInput`s for its
   decisions are built from that mapping (`Session::input`, `object_input`, `list_input`).
   The backend is reached only through `BackendRegistry::proxy_for(route)`, by
   `SftpBackend`, under an `SftpProof` that the `Enforcer` mints on allow and that
   **enumerates the (operation, bucket, key) triples it licenses**; `SftpBackend` builds
   each typed s3s input from the licensed triple and checks `SftpProof::require` before
   every call. For example, a create-only upload's proof licenses `HeadObject`, `PutObject`
   (a small file), `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload` and
   `AbortMultipartUpload` on one key, and nothing else. A forward without a matching proof
   is an internal error, as it is for S3 (`src/access/proof.rs`).
4. SFTP's **closed set of operations** is the `codec::Request` enum, dispatched by an
   exhaustive `match` in `Session::handle`, which plays `check`'s deny-by-default role: a
   packet type or extension the enum does not name is parsed as `Unknown` or `Extended`
   and answered `SSH_FX_OP_UNSUPPORTED` (with id 0 if no id can be read).

### D3 — SSH transport: russh, pinned, with a code-constant algorithm floor

**Library.** `russh = "=0.63.3"`, pinned exactly, for the reason `s3s` is: the safety
argument depends on which `Handler` methods exist and what their defaults do (E5). A
`tests/data/russh-0.63.3-handler.txt` lists every `Handler` method of the pinned version.
Rust cannot reject a default method that was left in place, so the guarantee is a test, in
the style of `tests/op_coverage.rs`:

- `russh_is_pinned_exactly` asserts the `=0.63.3` pin in `Cargo.toml`, and the list holds
  exactly 34 methods;
- the list is compared against the `Handler` trait in the pinned russh source when that
  source is in the local cargo registry (the comparison is skipped otherwise);
- every listed method must appear as an `fn` in s0's `impl Handler`;
- a method with no override fails the suite, and so does a version bump, instead of
  silently opening a channel type.

**Algorithms** are `const` lists in `sftp::transport`, not configuration, so tightening them
ships with a release:

| Kind | Allowed, in preference order |
|---|---|
| KEX | `mlkem768x25519-sha256`, `curve25519-sha256`, `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521` (+ the `ext-info-s` and `kex-strict-s-v00@openssh.com` markers) |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com` — AEAD only, so no CBC and no CTR |
| MAC | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com` — unused under AEAD, and listed only because negotiation requires a list; no SHA-1 |
| Host key | `ssh-ed25519` (required), `ecdsa-sha2-nistp256` (optional, for older JVM clients) |
| Client key | `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, and their `-cert-v01@openssh.com` forms |
| Compression | `none` only — zlib is attack surface (decompression amplification) for no gain on already-compressed partner files |

- **Terrapin.** Strict KEX is **required**: a client that does not advertise
  `kex-strict-c-v00@openssh.com` is disconnected before authentication. Every client in the
  matrix below has shipped strict KEX since the 2023-12 disclosure. russh 0.63.3 gives a
  server no way to require it, so s0 enforces it in-tree: `sftp::preauth::StrictKexGuard`
  reads the client's cleartext KEXINIT before any byte reaches russh and closes the
  connection unless `kex-strict-c-v00@openssh.com` is advertised, recording
  `preauth_rejected`.
- **RSA client keys are refused in v1** (E6). The requirement was "RSA-SHA2 only, minimum 3072
  bits". The minimum size is checkable, but the SHA-1 exclusion is not, because the handler
  never sees the signature algorithm. Accepting RSA would therefore accept `ssh-rsa` SHA-1
  signatures. RSA returns when the signature algorithm is enforceable: an upstream change
  exposing it, or a filter in russh's verify path. At that point `rsa-sha2-256/512` only and
  `bits ≥ 3072` are both enforced, and each gets its own black-box test.
- **No RSA host keys** (E8). s0 performs no RSA private-key operation.
- **Authentication** is `publickey` only, with certificates arriving through the same method.
  `none` is answered with the method list and counts as an attempt. `password`,
  `keyboard-interactive`, `hostbased` and `gssapi-*` are rejected.
  `limits.sftp.max_auth_attempts` is 6 by default and configurable from 1 to 10; unlike
  most limits it is fixed when the listener starts (D12). russh's `auth_rejection_time` gives failures a
  constant delay, so an unknown login and a known login with a wrong key take the same time.
- **Key probes are capped separately.** russh does not count a probe — a public key offered
  without a signature — toward `max_auth_attempts` (its test
  `publickey_probes_do_not_burn_auth_attempts`), so the attempt cap alone does not bound
  probes. s0 counts them itself:
  - `limits.sftp.max_key_probes` per connection, default 10;
  - exceeding it disconnects, and counts as one authentication failure toward the ban (D12).
  - Failures count toward the ban only when the connection **ends without authenticating**.
    An agent holding several keys signs with the wrong ones before the right one; each
    rejection is audited, but a connection that then logs in is a legitimate client, and
    counting its rejections would ban a NAT'd partner after a few routine connections.
  - Only **credential mismatches** count: an unknown login, a key not authorized for it, a
    rejected certificate, a key type or source address the account does not accept, a
    refused method (`password`, `keyboard-interactive`), and the key-probe cap. Refusals
    that a correct credential also gets are audited as `auth_failed` but never counted:
    a bundle the gateway refuses (its gate, the fleet-wide denylist), and a matched
    credential refused admission (the subject is not a member of its tenant, the tenant
    cannot be routed, the subject is at its session cap). Counting them would ban an
    address — and every partner behind its NAT — for logging in correctly while the
    subject is at its cap or the bundle is bad.
    When the refused credential did match (admission), the connection's earlier
    mismatches are forgiven as well: an agent that signed with its other keys first is a
    legitimate client. The same holds for a subject removed from its tenant whose keys
    are still listed: its retries are refused every time, but never banned.
  - Probes are answered **uniformly**: any offered key of an accepted type (ed25519,
    ECDSA) is told to proceed to the signature, and the login is decided only once the
    signature verifies. A probe for an unknown login, an unauthorized key and an
    authorized (login, key) pair get the same answer, so a probe confirms no account,
    even to someone holding its public key. The cost is a signature verification per
    offered key. An RSA key is refused at the probe, as a credential mismatch.
- **Channels.** One `session` channel per connection, carrying one `subsystem` request whose
  name is exactly `sftp`.
  - Every other channel type that has a `Handler` method (`direct-tcpip`, `forwarded-tcpip`,
    `x11`, `direct-streamlocal@openssh.com`, a second `session`) is rejected with
    `ADMINISTRATIVELY_PROHIBITED`. Types with no `Handler` method in the pinned russh
    (`auth-agent@openssh.com`, `forwarded-streamlocal@openssh.com`, unknown types) are
    refused by russh itself, unknown types with `UNKNOWN_CHANNEL_TYPE`.
  - Every other channel request with a `Handler` method (`exec`, `shell`, `pty-req`,
    `x11-req`, `signal`, a second `subsystem`, …) gets `SSH_MSG_CHANNEL_FAILURE` and the
    channel is closed. Two exceptions: `env` is refused but **leaves the channel open**,
    because stock OpenSSH sends `SendEnv LANG LC_*` before `subsystem sftp`
    (`env_then_sftp_works_like_stock_openssh`); `auth-agent-req@openssh.com` closes the
    channel and russh answers it `SSH_MSG_REQUEST_FAILURE`. Requests with no `Handler`
    method (`break`, unknown names) get russh's own `CHANNEL_FAILURE`, channel left open.
  - The four forwarding global requests are refused by s0's handler; every other global
    request gets russh's own `SSH_MSG_REQUEST_FAILURE`.
  - Every `Handler` method is overridden (E5); what russh answers on its own is limited to
    requests it has no `Handler` method for, and each of those is a refusal.
- **Host keys** come from `frontends.sftp.host_keys`, which are paths to a mounted secret. A missing,
  unreadable, world-readable, encrypted, RSA or ECDSA P-384/P-521 key refuses startup, as
  does a key listed twice (by path or by fingerprint) or a set with no ed25519 key. There is no
  silent generation: a pod that regenerates its host key on restart teaches every partner to
  accept key changes, which is the MITM this pinning exists to stop. Rotation is additive:
  publish the new fingerprint, add the key, then remove the old one in a later release.

### D4 — SFTP protocol layer: an in-tree v3 codec, not russh-sftp

SFTP version 3 (draft-ietf-secsh-filexfer-02), the version every client in the matrix speaks,
is about twenty packet types, and the v3 draft has not changed since 2001.

| | russh-sftp 3.0.1 | In-tree v3 codec |
|---|---|---|
| Correctness | Lossy UTF-8 decoding (E7): two byte strings, one key. Continues reading after a parse error: stream desync. | Paths stay bytes until `sftp::paths` validates them. Any framing error ends the session. |
| Attack surface | Parses v3–v6 structures s0 will never serve, in a spawned task s0 does not control. | Parses exactly the requests in D7 and D11, as a pure `Bytes → Result<Request, CodecError>` function, fuzzed. |
| Maintenance | Single-maintainer crate on the critical path, a second pin to track. | About 1,000 lines against a frozen spec, owned here, and tested like the rest of the gateway. |
| Concurrency | One request at a time, reply before the next read. | Same ordering for requests, but WRITE data is accepted into a bounded transfer buffer so uploads pipeline (D9). |

**Codec rules.** The length prefix is checked against `max_sftp_packet_len` (default 262,144
bytes, which is what OpenSSH's server uses) *before* any allocation. Every string length is
bounded by the bytes remaining, and trailing bytes are an error. A malformed packet gets
`SSH_FX_BAD_MESSAGE` if its request id could be read, and then the channel closes. The
session is never resynchronized. `SSH_FXP_INIT` must be the first packet. The server answers
version 3 whatever higher version the client offers, and closes on a version below 3. The
cargo-fuzz targets `sftp_codec` (over `codec::parse`) and `proxy_v2_header` (the PROXY v2
parser, cross-checked against the stream reader) live in `fuzz/` and run for 60 s each in
the CI `fuzz` job.

### D5 — Identity and the bundle contract

An SFTP principal is an **existing bundle subject** — the same `subject_key` vocabulary
(`sa:<client id>`, `user:<oidc sub>`, `src/pdp/bundle.rs::principal_subject_key`) and the
same membership in `tenants[t].user_attributes`. There is no parallel identity space. What is
new is a way to *reach* a subject over SSH, and it lives in one new top-level section, read
PEP-side like `s3_key_epoch` and `reserved_tag_keys`.

```jsonc
{
  "grant_schema_version": 3,
  "sftp": {
    "version": 1,
    "user_cas": {
      "partner-ca-2026": {
        "key_type": "ssh-ed25519",
        "fingerprint": "SHA256:…",
        "tenants": ["acme"],                     // or ["*"]: every tenant in this org
        "revoked_serials": [17],
        "revoked_key_ids": ["alice@example.org"]
      }
    },
    "accounts": {
      "acme-partner-drop": {                     // the SSH login name
        "tenant": "acme",
        "subject_key": "sa:partner-drop",
        "home": { "bucket": "inbound", "prefix": "partner-x/" },
        "authorized_keys": [ { "key_type": "ssh-ed25519", "fingerprint": "SHA256:…" } ],
        "certificate_authorities": ["partner-ca-2026"],
        "allowed_source_cidrs": ["203.0.113.0/24"]
      }
    },
    "denied_source_cidrs": ["192.0.2.66/32"]
  },
  "tenants": { "acme": {
    "user_attributes": { "sa:partner-drop": { "groups": [], "attributes": {} } },
    "s3_grants": { "sa:partner-drop": [
      { "bucket": "inbound", "actions": ["create_objects"], "prefixes": ["partner-x/"] } ] } } }
}
```

**Why a top-level `accounts` map keyed by login.** The login is the only routing key SSH
offers before authentication. A map keyed by it is unique by construction, so one login can
never resolve to two tenants. The account names its tenant and its subject, and **confers
nothing**: authority still comes only from grants, decided by the PDP on every operation. A
login is `^[a-z0-9][a-z0-9._-]{0,63}$`, which excludes `@` and `:`, the separators clients
and the subject-key space already use.

**Public-key authentication.** The client sends its public key. s0 computes the SHA-256
fingerprint and accepts iff (key type, fingerprint) is in `authorized_keys` of the account the
login selects. A fingerprint is enough to authenticate: SHA-256 is collision-resistant and the
signature is verified against the key the client presented. The bundle therefore never
carries full key blobs.

**Certificate authentication — the exact mapping.** A certificate authenticates login `L`
iff **all** of the following hold:

1. `accounts[L]` exists and lists at least one entry in `certificate_authorities`;
2. the certificate is an OpenSSH **user** certificate;
3. its signing CA key matches, by type and fingerprint, a `user_cas[c]` with `c` in
   `accounts[L].certificate_authorities` and `accounts[L].tenant` in `user_cas[c].tenants`
   (or `tenants == ["*"]`). A CA trusted by one tenant cannot vouch for another tenant's
   login, and a CA an account does not name cannot vouch for it at all;
4. `valid principals` contains `L` literally. An **empty** principals list is refused. In
   OpenSSH an empty list means "any principal", which is exactly the implicit access this
   design rules out;
5. the validity window holds (russh checks it, and s0 re-checks with the same clock);
6. the serial is not in `revoked_serials` and the key id is not in `revoked_key_ids`;
7. critical options: `source-address` is enforced against the client address;
   `force-command` is accepted only with the value `internal-sftp`; **any other critical
   option refuses the certificate**, as OpenSSH requires for options it does not understand;
   extensions are ignored;
8. the CA key and the certified key both satisfy D3's client-key rules (so no RSA CA in v1).

The certificate **key id** and serial, the CA id, and the certified key's fingerprint go on
every audit record of the session (D13). A shared account used by several people through
per-person certificates still attributes each action to the person who performed it.

**Principal construction** happens per operation, from the current bundle: `subject_key` is
split into (`service_account` | `user`, `sub`) by the inverse of `principal_subject_key`, and
an unknown prefix makes the account unusable. The organization comes from s0's own routing
table for `accounts[L].tenant`, never from the bundle and never from the client. At
authentication time the subject must be a member and the tenant must be routable. The PDP
re-checks membership on every operation regardless.

**One subject, one key space — the one the module in force reads.** The bundle carries two
key spaces today:

- a control-plane module keys `user_attributes` and `s3_grants` by the prefixed subject key
  (`sa:<client id>`, `user:<oidc sub>`);
- the compiled-in default (`policy/gateway/authz.rego`) keys them by the raw
  `input.principal.sub`, and so do hand-written bundles such as `tests/e2e/bundle.e2e.json`.

If the login check read one space and the PDP the other, no subject could pass both: every
account would be refused at login, or denied on every operation. So the login check
(membership, and the groups placed on the principal) reads **the same key the PDP will
read**:

- the prefixed key when a pushed `policy` module is in force;
- the raw `sub` when the compiled-in default is in force.

Which one is in force is `Bundle::policy_module`, set when a pushed bundle carries a module
and kept by a data-only refresh, so a later data push does not flip the key space. One
function, `subject_lookup_key`, makes this choice, and a test runs a login and an operation
against both bundle kinds.
`accounts[L].subject_key` is always written in prefixed form, because it is the identity
contract; only the lookup follows the module. The STS door's membership check
(`bundle_knows_service_account`) always reads the prefixed key whatever module is in force.
That asymmetry predates this ADR and is out of its scope.

**Schema version and absence.** This is a contract change: `create_objects` (D7) and the
`sftp` section define **`grant_schema_version: 3`**. The pushed module's exact-match gate (E3)
makes the switch atomic, because data and module ship in the same document. s0 adds its own
PEP gate, which fails closed on every degenerate input:

| Bundle | SFTP authentication |
|---|---|
| no `sftp` section | every login rejected |
| `sftp.version` absent or `≠ 1` | every login rejected; `error` log once per revision |
| `grant_schema_version` present and `< 3` | every login rejected (a v2 module predates `create_objects`) |
| `grant_schema_version` absent (a hand-written bundle on the compiled-in module) | governed by `sftp.version` alone; the key space still follows the module in force (D5, key spaces) |
| account present but malformed (bad login, bad `subject_key`, empty or `/`-containing `home.bucket`, `home.prefix` not `/`-terminated or not canonical — a leading `/`, `//`, `.` or `..` —, a fingerprint without `SHA256:`, a non-array `allowed_source_cidrs`) | that account rejected, others unaffected; `error` log |
| account naming a tenant s0 does not know or the subject is not a member of | loads; every login refused at authentication (audited, not counted toward the ban, D3) |
| `denied_source_cidrs` not an array, or holding an invalid CIDR | the whole `sftp` section refused: every login rejected |
| a CA entry malformed | that CA dropped; `error` log |
| `authorized_keys` absent or `[]` and no usable CA | that account cannot authenticate |
| `allowed_source_cidrs` absent | no source restriction for that account |
| `allowed_source_cidrs: []` | no source allowed (explicit) |

Absence is never access. The one "absent means unrestricted" row is `allowed_source_cidrs`,
because it is an additional restriction on top of key possession, not a grant.

**Revocation, with no restart.**

- *New connections*: removing a key, an account, a CA, or the subject's membership, adding a
  revoked serial or key id, or changing the source CIDRs refuses the next authentication after
  the bundle refresh.
- *Open sessions* — **re-authorize every operation against the current bundle**:
  - The credential check is re-run whenever the bundle revision has moved since it last
    passed, and whenever a certificate has passed its `valid_before`. The result is memoized
    per revision, so a steady-state operation costs one string compare. The re-check also
    fails if the account now maps to a different tenant, subject or home.
  - Every operation takes a fresh PDP decision. The revision-keyed cache (ADR-005) makes a
    revision change a miss by construction.
  - A transfer in progress re-decides at the next WRITE or READ after a revision change, and
    an upload again at CLOSE (D9).
  - A failed credential re-check aborts any open transfer and closes the connection without
    answering the request; the `disconnected{reason: "credential_revoked"}` record is the
    audit trail.
  - Each session also subscribes to the `BundleStore` revision watch (`subscribe()`, sent in
    `store()` after the swap; `bundle_refresh` reloads the engine before storing) and
    re-validates its credential on every change. An idle session with a revoked key is
    therefore closed within one poll interval, not left open until its next request. The
    S3 front ignores the watch.
  - The revocation-latency bound is the one ADR-006 already documents: build + poll interval.

### D6 — The virtual root, and paths that cannot escape it

Each account is confined to **one tenant and one root**, `(home.bucket, home.prefix)`. The
bucket is not a path component: `/` is the root, and nothing a client sends can name another
bucket. `home.prefix` is either empty (the whole bucket) or `/`-terminated. ADR-006 R3's stem
pitfall — `partner-x` also matching `partner-x-old/` — is refused at bundle load.

Normalization, applied to every path argument before anything else:

1. the bytes must be valid UTF-8;
2. reject NUL, any control character (`char::is_control`: U+0000–U+001F and U+007F–U+009F)
   and `\`;
3. relative paths are resolved against `/`: the working directory lives in the client, and
   the server has none;
4. collapse runs of `/`, drop `.` components, drop a trailing `/`;
5. **`..` is rejected**, with one exception: `SSH_FXP_REALPATH` resolves `..` lexically and
   clamps at `/`, because `cd ..` sends `REALPATH("/a/..")` and REALPATH touches no storage.
   Every other request containing a `..` component is refused rather than resolved, so there
   is exactly one place where `..` means anything;
6. the key is `home.prefix + relative`, and must be at most 1,024 bytes;
7. an assertion that the key starts with `home.prefix` runs **after** mapping, as defence in
   depth. The PDP's grant scope is the independent second layer.

Any path refused by these rules (bad UTF-8, a refused character, too long) is answered
`SSH_FX_NO_SUCH_FILE` for a request that names an existing entry (STAT, OPEN without
`CREAT`, REMOVE, RMDIR, OPENDIR, a RENAME source), because no key can match it, and
`SSH_FX_FAILURE` ("invalid file name") for one that would create it (OPEN with `CREAT`,
MKDIR, a RENAME target). A path containing `..` is always `SSH_FX_FAILURE`.

No Unicode normalization is applied (NFC and NFD forms of one name are two keys), matching the
backend. Names read back from a listing are held to the same rules. An object whose name
component is empty, `.`, `..`, not UTF-8, or contains `\` or a control character (for example
the key `partner-x/../y` written over S3) is **omitted** from `READDIR`, counted on the audit
record, and unreachable by path. There are no symlinks, so there is nothing to follow.

### D7 — The authorization model

**A protocol dimension.** `RequestMeta` gains `protocol: "s3" | "sftp"`, **always
serialized** — the ADR-008 argument: a rego reference to an absent field is a silent deny-all.
For SFTP, `input.request.method` carries the SFTP request name (`OPEN`, `RENAME`, …) as
non-authoritative context, the way it carries the HTTP method for S3. Both fields enter the
cache key by construction (`OpaInput::resource_key`). Every existing capture is regenerated
with `"protocol": "s3"`: that change is additive for consumers (ADR-002 I6) and changes no
decision. The compiled-in module does not read `protocol`. A pushed module may, for example
to confine a subject to SFTP.

**A new verb, `create_objects`: write a key that does not exist.** The drop-box case is
expressed in policy, not only in code: a principal granted `create_objects` on `partner-x/`
can drop files and cannot overwrite them, and the grant says so where an administrator can
read it.

- **`write_objects` implies `create_objects`** (overwrite ⊇ create). The implication lives in
  the module (`action_matches(g) if { input.action == "create_objects"; "write_objects" in
  g.actions }`), because the module is the normative definition of what a grant means
  (ADR-006 D2). A pushed module must mirror it, and a corpus case pins it.
- `create_objects` joins `write_actions` in the rego and `Action::is_write` in the PEP, so
  `freeze_writes` covers it. `the_write_set_matches_the_shipped_rego` enforces the equality.
- It joins `GATEWAY_VERBS`, `Action::ALL`, the README verb table and
  `tests/readme_optable.rs`. The verb count is pinned to seven in
  `tests/op_coverage.rs::the_gateway_vocabulary_is_the_seven_projected_verbs`, the README's
  "one of seven grant verbs" and the doc comment on `Action` in `src/model.rs`.

  `create_objects` is the first verb no enforced S3 operation names. Any test assuming every
  verb has an operation is amended to say so explicitly, rather than weakened. Both fronts
  ask it. SFTP asks it for every create. S3 asks it for a `PutObject` or
  `CompleteMultipartUpload` carrying `If-None-Match: *` (and the multipart steps leading to
  such a commit) when `write_objects` is denied, and only on a backend declared
  `conditional_create: native`, since elsewhere the condition would not be honoured (F1,
  implemented; `tests/s3_create_objects.rs`, with its own corpus cases).

**No new verb for metadata.** STAT and READDIR are decided as **`list_objects`** on a prefix
equal to the target key (or `dir/` for a listing), not as `read_objects`. A `list_objects`
holder already sees the name, size and modification time of every key through
`ListObjectsV2`. A stat reveals exactly that and nothing more, so metadata visibility never
implies download, without a sixth object verb. A drop-box principal holding only
`create_objects` can stat nothing but its virtual root (see below), which is the intended
posture.

**Operation → decisions.** Every SFTP request that touches storage takes at least one decision
through the same `Enforcer`, PDP, cache and obligations as S3. All decisions of one request
are taken **before** its first backend call, with one exception: OPEN for create-or-replace
decides `create_objects`, then issues the existence `HeadObject` that decision licenses, and
only then decides `write_objects` if the key exists (D8).

| SFTP request | Decision(s) | Backend calls the proof licenses |
|---|---|---|
| `INIT`, `REALPATH`, `STAT("/")` | none — they touch no object and reveal only the account's own configuration; counted on the disconnect record | none |
| `STAT` / `LSTAT` `p` | `list_objects`, `prefix = key(p)` | `HeadObject(key)` (metadata only), `ListObjectsV2(prefix = key/, max-keys = 1)` |
| `FSTAT h` | none — answered from the handle's own state | none |
| `OPENDIR p` | `list_objects`, `prefix = dir(p)`; a decision carrying both `narrow_prefix` and `allowed_prefixes` is denied | none at open, unless the decision narrows the listing: then the whole listing is assembled at OPENDIR (`ListObjectsV2` per granted prefix, at most 100,000 entries, `SSH_FX_FAILURE` above) |
| `READDIR h` | re-decided on a revision change; a re-decision that changes the granted scope refuses the handle | `ListObjectsV2(prefix, delimiter = "/", continuation)` |
| `OPEN p` read | `read_objects`, `object = key` | `GetObject` (ranged on a non-sequential READ) |
| `OPEN p` write | `create_objects` or `write_objects` (D8) | `HeadObject`, `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `PutObject` |
| `REMOVE p` | `delete_objects`, `object = key` | `HeadObject` (for `NO_SUCH_FILE`), `DeleteObject` |
| `MKDIR p` | `create_objects`, `object = key/` | `native`: `PutObject(key/, empty, If-None-Match: *)`; `check_then_write`: `HeadObject(key/)` then a plain `PutObject` |
| `RMDIR p` | `delete_objects` on `key/` **and** `list_objects` on `key/`; a `list_objects` decision that comes back narrowed is denied (emptiness must be judged on the whole directory) | `ListObjectsV2(max-keys = 2)`, `DeleteObject(key/)`; a missing marker is `SSH_FX_NO_SUCH_FILE`, and `/` cannot be removed |
| `RENAME a b` | `read_objects` on `a`, `create_objects` on `b`, `delete_objects` on `a`; `a == b` is answered OK with no decision | `HeadObject`, `CreateMultipartUpload`, `UploadPartCopy`×n, `CompleteMultipartUpload` (`If-None-Match: *` on `native`; on `check_then_write`, the in-flight claim and a re-HEAD instead), `DeleteObject`; a zero-byte source is written with `PutObject`; a directory source is `SSH_FX_NO_SUCH_FILE` (D10) |
| `posix-rename@openssh.com a b` | `read_objects` on `a`, `write_objects` on `b`, `delete_objects` on `a` | `CopyObject` (or multipart copy above 5 GiB), `DeleteObject` |

RMDIR takes a `list_objects` decision because emptiness is a fact about the prefix, and every
bit returned to the client must be authorized. The internal `HeadObject` issued under a
write, delete or stat decision returns **no content**. Only existence, size and modification
time reach the client, and only where the table says so.

`dir(p)` is `key(p)` with a `/` appended, unless the key is empty (a home of the whole
bucket) or already ends in `/` (the virtual root, whose key is `home.prefix`). Listing `/`
under `home.prefix = "partner-x/"` therefore asks for `partner-x/`, never `partner-x//`. The
same rule builds the `key/` forms in this table (MKDIR, RMDIR) and in D10.

**Obligations, filters and denials apply exactly as on S3.**

- `freeze_writes` and the per-bucket denylist are decided by the PDP, identically.
- `narrow_prefix` / `allowed_prefixes` on a listing of directory `D` (prefix `P`): for each
  granted prefix `Q` under `P`, if `Q − P` contains `/` the first component is presented as
  a directory entry with no backend call; otherwise `ListObjectsV2(prefix = Q, delimiter =
  "/")` supplies the matching children of `D`. Results are merged, de-duplicated and sorted,
  bounded by `max_list_fanout` (fail closed above, as in ADR-004). This is how a principal
  scoped to `in/a/` can `cd in` and see `a`.
- On a STAT carrying such an obligation, the target is a directory iff some `Q` starts with
  `key/`, and no backend call is made — unless a granted prefix equals the key itself, which
  is then resolved on the backend like an unscoped STAT.
- `excluded_prefixes` with `must_understand` is **denied**, on SFTP as on S3 (E2). Neither
  front filters today. When s0 implements the obligation it applies to both through the
  shared `Enforcer`.
- `visible_buckets` does not arise: SFTP never enumerates buckets.
- An unbounded listing — a home of the whole bucket, listed by a prefix-scoped principal — is
  denied with the rego's own reason, as on S3.
- A refusal is `SSH_FX_PERMISSION_DENIED` with the decision's reason as the status message,
  the SFTP rendering of ADR-008's "a denial, never a silent strip".

### D8 — Open flags, create-only, and closing the race

| `pflags` (v3) | Meaning | Decision and behaviour |
|---|---|---|
| `READ` | download | `read_objects`. `READ` with `CREAT`, `TRUNC` or `EXCL` is `SSH_FX_OP_UNSUPPORTED`; `READ` on `/` is `SSH_FX_FAILURE` ("is a directory"). |
| `WRITE\|CREAT\|TRUNC` | create or replace (OpenSSH `put`, WinSCP, FileZilla, lftp, paramiko `"w"`, JSch/MINA default) | Decide `create_objects`; if allowed, `HeadObject`. **Absent** ⇒ create path. **Present** ⇒ decide `write_objects`: allowed ⇒ overwrite path; denied ⇒ `SSH_FX_PERMISSION_DENIED` ("file exists and overwrite is not granted") at OPEN, **before any byte is written**. |
| `WRITE\|CREAT\|EXCL` (± `TRUNC`) | must not exist | `create_objects` only; present ⇒ `SSH_FX_FAILURE` ("file exists"; v3 has no `FILE_ALREADY_EXISTS`). |
| `WRITE\|TRUNC` | replace an existing file | `write_objects`; absent ⇒ `SSH_FX_NO_SUCH_FILE`. |
| `WRITE\|CREAT` without `TRUNC` | create, or modify in place | absent ⇒ create path; present ⇒ `SSH_FX_OP_UNSUPPORTED` (in-place modification). |
| `WRITE` alone, any `APPEND`, `READ\|WRITE` | modify, resume or append | `SSH_FX_OP_UNSUPPORTED` in v1, documented and tested. |

`attrs` on OPEN and MKDIR (mode, owner, times) are **ignored**. Every client sends them on
every create, an object store has no modes, and refusing would break every upload. This is
the one place an SFTP request field is not honoured, and it is written here so it is a
decision rather than an accident. An explicit SETSTAT is refused (D11).

**Closing the check-then-write race.** The `HeadObject` at OPEN gives an early, byte-free
refusal. It does not close the race. What closes it depends on the backend, declared per
backend in `backends[].conditional_create` (a property of the backend, shared by both
fronts; the old `sftp.conditional_create` map is refused, not ignored):

- **`native`**: the commit is conditional — `PutObject` or `CompleteMultipartUpload` with
  `If-None-Match: *` (E4). A concurrent create makes the loser's commit fail with 412; s0
  aborts the upload and answers the CLOSE with `SSH_FX_FAILURE`. Renames to a create-only
  target use a **multipart copy** (`CreateMultipartUpload` + `UploadPartCopy` +
  conditional `CompleteMultipartUpload`) because `CopyObject` has no destination condition in
  s3s 0.14.1 (E4). For a small file that is three calls instead of one.
- **`check_then_write`** (the default): s0 re-issues `HeadObject` immediately before the commit
  and refuses if the key appeared. **Residual race**: the window between that final HEAD and
  the commit (one backend round trip). A create that loses the race overwrites. It is
  narrowed further by a per-process registry of in-flight create-only targets: a second
  create-only OPEN or rename onto a key a create-only transfer already holds in the same
  replica is refused with `SSH_FX_FAILURE` ("upload in progress"). The registry is used in
  both modes, `native` included; an OPEN that overwrites an existing key (`write_objects`)
  neither claims nor checks it. Across replicas, only `native` closes the race.

`native` is an operator **assertion**. A backend that silently ignores `If-None-Match` turns
create-only into overwrite with no error anywhere, so s0 never assumes support. The
conformance probe — two conditional writes to one fresh key, where the second must fail with
412 — is part of `tests/e2e/run.sh`, and the ADR's matrix is updated with its
results:

| Backend | `PutObject` + `If-None-Match: *` | `CompleteMultipartUpload` + `If-None-Match: *` | Destination condition on `CopyObject` | Verified in this repository |
|---|---|---|---|---|
| s3s / s3s-aws 0.14.1 (the forward path) | carried | carried | **not expressible** | yes (E4) |
| AWS S3 | documented by AWS | documented by AWS | — | no (no AWS in CI) |
| MinIO (e2e image `pgsty/silo`) | **verified** (412 on the second write) | **verified** (412 on the second commit) | — | yes — the `run.sh` probe, and SFTP create-only uploads against a backend declared `native` |
| Ceph RGW | reported | unverified, version-dependent | — | conformance harness (scaffolded, not yet wired) |
| any other S3 backend | unknown | unknown | — | run the probe before declaring `native` |

### D9 — The data path: an object store behind a file protocol

**Uploads stream to multipart, with no local disk.**

- A write handle fills an in-memory part buffer of `part_size` bytes (default 8 MiB,
  configurable within 5–64 MiB). A full part is sent as `UploadPart`, with up to
  `max_inflight_parts` parts outstanding (default 2, range 1–4).
- A file that never fills one part is committed with a single `PutObject` at CLOSE.
- A zero-byte file (OPEN then CLOSE) is an empty `PutObject`.
- `CreateMultipartUpload` is issued lazily, when the first part fills.
- The maximum object is `part_size × 10,000`. `max_file_size` (default 50 GiB) must not
  exceed it, which `validate` checks. A WRITE beyond it fails with `SSH_FX_FAILURE`
  ("file too large") and aborts the transfer.

**Memory is bounded per transfer, per session and per process.**

- *Per transfer*: at most `part_size × (1 + max_inflight_parts) + reorder_window`, which is
  26 MiB at the defaults.
- *Per session*: `max_write_handles` (default 2) transfers.
- *Per process*: `max_transfer_memory` (default 1 GiB, about 39 concurrent uploads at the
  defaults). A write OPEN **reserves its transfer's worst case up front**, so a transfer can
  never run out of memory halfway through. If the reservation cannot be made within 10 s, the
  OPEN fails with `SSH_FX_FAILURE` ("server busy"). A read OPEN reserves its `read_ahead`
  from the same budget for as long as the handle is open, under the same rule.
- *Backpressure*: when a transfer's buffers are full, the session stops reading from the
  channel, and SSH flow control stops the client. This relies on russh replenishing the
  window only as data is consumed.
- *A client that stops reading replies* cannot freeze its session: the idle check, the
  revocation sweep and drain still run, and tear it down. If it has stopped reading at the
  TCP level, russh's task is stuck in a socket write and cannot send the disconnect, and
  dropping russh's session handle would only detach that task, leaving the socket open and
  uncounted. The client stream is therefore wrapped (`StrictKexGuard`) with a kill switch
  that fails the stuck write and every later read and write, so russh's task ends and
  releases the socket. The connection stays counted toward `max_connections` until it does.
  Handing russh a disconnect only queues it, so success says nothing about a stall: every
  gateway-initiated disconnect (the SFTP teardown, the handshake timeout, and a connection
  that authenticated but has not started the `sftp` subsystem one `handshake_timeout_secs`
  after the deadline) gives russh's task 5 s to end, then fires the kill switch. If the
  disconnect cannot even be queued, it fires at once.

**Pipelined writes and the reorder window.** Clients keep many WRITEs outstanding (OpenSSH
keeps 64 × 32 KiB in flight).

- A WRITE at the next expected offset is appended.
- A WRITE ahead of it by no more than `reorder_window` (default 2 MiB, at most `part_size`)
  is held until the gap fills. Each held chunk is charged its length plus a fixed 256-byte
  overhead against the window, so many tiny writes cannot hold far more than the window.
- A WRITE that overlaps bytes already accepted, or lands beyond the window, is refused with
  `SSH_FX_OP_UNSUPPORTED` ("non-sequential write"). The refusal **poisons the transfer**:
  the next WRITE or the CLOSE aborts it. Stock clients CLOSE after a write error, and
  committing then would land a file missing the refused bytes.
- A CLOSE with a gap still open is refused and the transfer aborted.
- A WRITE's `SSH_FX_OK` means *accepted into the transfer*. Only CLOSE's `SSH_FX_OK` means
  *committed*.

**Abort, visibility and close.**

- The object becomes visible only when the commit succeeds. An S3 reader sees the whole
  object or nothing.
- A transfer is aborted (`AbortMultipartUpload`, and no `PutObject`) on:
  - a backend error;
  - a mid-transfer denial;
  - disconnect without CLOSE;
  - `transfer_idle_timeout` (default 120 s with no WRITE);
  - shutdown.
- **A client that closes without finishing** — for example an interrupted OpenSSH `put`,
  which still sends CLOSE — **commits what it sent**. The protocol offers nothing that would
  let s0 tell a short file from an interrupted one. This matches a POSIX server, which leaves
  the partial file, and it is atomic where POSIX is not. Partners who need integrity ship a
  checksum sidecar or a manifest.
- **Orphaned parts after a hard kill** — no abort ran — are the one leak s0 cannot close from
  the data plane. A bucket lifecycle rule (`AbortIncompleteMultipartUpload`) is an operator
  obligation for every bucket that is an SFTP home. s0 cannot set it, because bucket
  configuration is control-plane territory.

**Resume and append** are refused in v1 (D8). An OPEN with `APPEND`, or a first WRITE at a
non-zero offset, is `SSH_FX_OP_UNSUPPORTED`.

**Downloads.**

- OPEN(read) opens one streaming `GetObject` with a bounded read-ahead
  (`limits.sftp.read_ahead`, default 1 MiB, reserved from `max_transfer_memory`).
- Sequential READs are served from the stream. A non-sequential READ reopens with a `Range`.
- A READ past the end returns `SSH_FX_EOF`.

**Rename** is a server-side copy followed by a delete, authorized as a read of the source, a
write (create or overwrite) of the target, and a delete of the source (D7).

- It is **not atomic**: between the copy and the delete both keys exist, and if the delete
  fails both remain. s0 then answers `SSH_FX_FAILURE` naming the state, and the record says
  so.
- A create-only RENAME on a `check_then_write` backend is guarded like a create-only upload
  (D8): the target is claimed in the in-flight registry for the whole copy, and re-checked
  immediately before the commit.
- Directory renames, empty or not, are not supported in v1: the source has no object at its
  key, so RENAME answers `SSH_FX_NO_SUCH_FILE` ("directory renames are not supported").

### D10 — Directories are prefixes

- **mkdir** writes a zero-byte **marker object** `key/` under `create_objects`:
  conditionally (`If-None-Match: *`) on a `native` backend, as a `HeadObject` then a plain
  `PutObject` on `check_then_write`, with no in-flight claim. It is persistent across sessions, visible to S3 tools the way consoles
  already show folders, and needs no session state.
  - An existing marker ⇒ `SSH_FX_FAILURE`.
  - An *implicit* directory (objects under `key/`, no marker) gets a marker and `SSH_FX_OK`.
    That is a harmless deviation from POSIX `EEXIST`, and costs no extra list.
- **rmdir**:
  - a marker with nothing else under the prefix ⇒ the marker is deleted;
  - anything else under the prefix ⇒ `SSH_FX_FAILURE` ("directory not empty");
  - no marker and nothing under the prefix ⇒ `SSH_FX_NO_SUCH_FILE`.
- **Listing** shows common prefixes as directories and objects as files.
  - The marker of the listed directory itself is not an entry.
  - `.` and `..` are synthesized.
  - An empty directory lists as `.` and `..` only.
  - A file `x` and a directory `x/` can coexist in an object store. Both are listed, and STAT
    resolves to the file. A listing narrowed to granted prefixes (D7) shows a single entry
    named `x`.
- **Attributes** are synthesized: files get size and modification time from the backend,
  directories carry only their mode, and FSTAT on a handle reports a modification time of
  0. Modes are fixed (`0640` for files, `0750` for directories) and describe nothing about
  authorization.
  `longname` is rendered in `ls -l` form with owner and group `-`.

### D11 — Everything else, decided per operation

| Request | Answer | Why |
|---|---|---|
| `SETSTAT` / `FSETSTAT` with any attribute (mode, uid/gid, times, size) | `SSH_FX_OP_UNSUPPORTED` | An object store cannot honour it, and answering OK would be the strip ADR-008 rejects. `truncate` arrives here as a size change and is refused. |
| `SETSTAT` / `FSETSTAT` with an empty attribute set | `SSH_FX_OK` | Nothing was requested, so nothing is dishonoured. |
| `FSETSTAT` on a handle the session does not hold | `SSH_FX_FAILURE` ("invalid handle"), whatever the attributes | The handle is checked first. |
| `SYMLINK`, `READLINK` | `SSH_FX_OP_UNSUPPORTED` | No links in an object store, so no link can be followed out of the root. |
| `hardlink@openssh.com`, `copy-data`, `lsetstat@openssh.com`, `users-groups-by-id@openssh.com`, `expand-path@openssh.com`, `home-directory` | `SSH_FX_OP_UNSUPPORTED` | Not needed by any client in the matrix. |
| `statvfs@openssh.com`, `fstatvfs@openssh.com` | `SSH_FX_OP_UNSUPPORTED` | No meaningful answer, and the backend's capacity is not the client's business. |
| `fsync@openssh.com` | `SSH_FX_OP_UNSUPPORTED` | Durability is only established at CLOSE, and claiming otherwise would lie. Only `sftp -f` sends it. |
| `limits@openssh.com` | served | It advertises the packet length (`max_sftp_packet_len`), a 255 KiB read length, a write length of `max_sftp_packet_len − 1024`, and `max_write_handles + 64` open handles (write handles plus read and directory handles), so clients size their pipelining to the server. |
| `posix-rename@openssh.com` | served | Overwrite rename (D7). |
| any other `SSH_FXP_EXTENDED`, any unknown packet type | `SSH_FX_OP_UNSUPPORTED`; a framing error gets `SSH_FX_BAD_MESSAGE` (when its id is readable) and the channel closes (D4) | Closed set (D2). |

The `SSH_FXP_VERSION` reply advertises exactly `limits@openssh.com` and
`posix-rename@openssh.com`. Each row above is covered by a black-box test in
`tests/sftp_e2e.rs`.

### D12 — Limits and abuse resistance

All limits sit in `limits.sftp` inside the existing hot-reloadable `LimitsConfig` (loaded at
the point of use, per `Gateway::limits`). They apply to new connections and new transfers
without a restart, with two exceptions fixed when the listener starts, because they live in
russh's server config: `max_auth_attempts`, and russh's inactivity backstop
(`idle_timeout_secs` + 60 s; the session's own idle check reads the live value). Of the
listener settings, `frontends.sftp.listen`, `host_keys`, `proxy_protocol` and `drain_secs`
need a restart.

| Limit | Default | Scope |
|---|---|---|
| `max_connections` | 256 | process |
| `max_connections_per_ip` | 16 | process, per IPv4 /32 or IPv6 /64 |
| `max_sessions_per_subject` | 16 | process; rclone's defaults (4 transfers + 8 checkers) open about 13 connections |
| `preauth_rate_per_ip_per_min`, `preauth_burst_per_ip` | 10/min, burst 20 | process, token bucket per IP |
| `handshake_timeout_secs` | 30 | from TCP accept to authentication success, including the PROXY header, the version exchange and KEX; an authenticated connection that has not started the `sftp` subsystem one more timeout later is disconnected (D9) |
| `max_auth_attempts` | 6 (1–10) | connection; fixed at listener start |
| `max_key_probes` | 10 | connection, counted separately from attempts (D3) |
| `auth_failure_ban_threshold`, `auth_failure_window_secs`, `auth_failure_ban_secs` | 10 failures in 300 s ⇒ 900 s ban | process, per /32 or /64; only credential mismatches count, and only when their connection ends unauthenticated (D3) |
| `ban_table_size` | 65,536 | process; LRU bound on both the ban table and the pre-auth rate table |
| `idle_timeout_secs` | 300 | session, no SFTP request |
| `transfer_idle_timeout_secs` | 120 | transfer |
| `max_file_size` | 50 GiB | transfer |
| `bandwidth_bytes_per_sec` | 0 (unlimited) | per session, each direction held to the rate, at most 1 s of banked burst |
| `process_bandwidth_bytes_per_sec` | 0 (unlimited) | process, per direction, shared by every session: a session waits for the longer of its own and the process hold; at most 1 s of burst; a non-zero value must be ≥ `max_sftp_packet_len`. Time held is `s0_sftp_process_bandwidth_wait_milliseconds_total` |
| `part_size`, `max_inflight_parts`, `reorder_window`, `max_write_handles`, `max_transfer_memory` | D9 | transfer / session / process |
| `read_ahead` | 1 MiB | read handle; reserved from `max_transfer_memory`, which it must not exceed |
| `max_sftp_packet_len` | 262,144 | packet |

**Bans are per replica and reconstructible, not shared.** The failure counters live in
memory, so a restart forgets them, and an attacker spread across `R` replicas gets `R` times
the budget. Adding a shared store would bring a new dependency and a new failure domain onto
the pre-authentication path. Instead:

- the bound is written down;
- every `auth_failed` and `banned` event is on the audit stream (D13), so a consumer can
  rebuild the fleet-wide view;
- the control plane can publish long-lived blocks as `data.sftp.denied_source_cidrs`, which
  every replica enforces at accept time from the bundle it already polls.

The bundle is the only fleet-wide state channel s0 has, and it is reused rather than a second
one added.

**The client source IP** is needed for bans, per-IP limits, `allowed_source_cidrs`, the
certificate `source-address` option and audit. It reaches s0 in one of two ways:

- **Preserved source address** at the load balancer: pass-through TCP, with no SNAT of the
  client address.
- **PROXY protocol v2**, binary form only (v1 text is refused), accepted **only** from peers
  in `sftp.proxy_protocol.trusted_cidrs`:
  - a trusted peer that does not send the header is disconnected;
  - an untrusted peer that sends one is disconnected;
  - a `LOCAL` command (a load-balancer health check) is closed without an SSH banner;
  - the header parser is in-tree, bounded, and fuzzed alongside the SFTP codec.

With neither, every client appears as the load balancer. Bans then become a self-inflicted
denial of service, so a deployment that cannot preserve the source must configure PROXY v2.

### D13 — Audit

**One decision record per SFTP operation**, in the ADR-002 shape and through the same
`AuditSink`, backpressure, spill and shutdown drain:

- `path` stays `s3/authz/decision`, because the same rule was evaluated.
- `input` is the live `OpaInput`, now carrying `request.protocol = "sftp"` and
  `request.method = "<SFTP request>"`.
- A rename uses `copy_source` for its source, exactly as `CopyObject` does. Its aggregate
  reason names the half that denied it (`"rename source read: …"`, `"rename target write:
  …"`, `"rename source delete: …"`), following ADR-002 D4.
- **A file transfer is one operation.** OPEN to CLOSE is one record: the decision at OPEN,
  settled at CLOSE through the `PendingAudit` pattern with a `transfer` block: `commit` is
  `committed`, `aborted`, `rejected` or `denied` for an upload and `read` for a download
  (`parts: 0`), with the byte count, the part count and an optional `reason`. Per-packet records would
  mean 32,768 records per GiB carrying no extra information. A mid-transfer denial settles
  the same record as `denied`, naming the byte offset.
- A new optional `gateway.session` block, absent on S3 records:

```json
"session": {
  "protocol": "sftp",
  "session_id": "5f0c9a1e-3b7d-4e2a-9c4f-1d2e3f4a5b6c",
  "client_ip": "203.0.113.10",
  "login": "acme-partner-drop",
  "auth": { "method": "openssh-cert", "key_type": "ssh-ed25519", "key_fingerprint": "SHA256:…",
            "cert": { "key_id": "alice@example.org", "serial": 42, "ca": "partner-ca-2026",
                      "ca_fingerprint": "SHA256:…" } },
  "sftp_op": "OPEN",
  "open_flags": ["WRITE", "CREAT", "TRUNC"],
  "transfer": { "bytes": 7340032, "parts": 1, "commit": "committed" }
}
```

`omitted_entries` (D6) appears only on a listing's record, set when its directory handle
closes.

`session_id` is a gateway-generated UUID, not the SSH exchange hash, which is a protocol value
rather than an identifier. `sftp_op` sits next to the verb in `input.action`.

**Connection-level events** are a third record shape beside decision and gate records.
Exactly one of `input`, `gate` or `session_event` is present, and `path` is `sftp/session`:

A `session_event` carries the event kind, `protocol`, `session_id`, `client_ip`, and when
known `login`, `auth` and `tenant`; `disconnected` adds the duration, operation count and
bytes in each direction, and `auth_failed` adds `credential_mismatch`.

| Event | Attribution | Budgeted |
|---|---|---|
| `preauth_rejected` (connection cap, rate limit, ban, CIDR denylist, bad PROXY header, non-strict KEX) | none | yes — the gate-denial budget |
| `auth_failed` (unknown login, unknown key, revoked certificate, CIDR mismatch, …) | none; `login` recorded, org label **omitted** | yes |
| `banned` | none | no — bounded by the ban rate itself |
| `auth_succeeded` | principal and org label | no |
| `disconnected` (client close, connection lost, idle, credential revoked, shutdown, no `sftp` subsystem, session teardown timeout, protocol error) with duration, operation count and bytes in each direction — **authenticated sessions only**; a connection that ends unauthenticated leaves no `disconnected` record | principal and org label | no |

Every record still carries the required `result: Decision`. For a session event it states
what happened rather than a PDP answer, and `obligations` is always empty:

| Event | `result.allow` | `result.reason` |
|---|---|---|
| `preauth_rejected`, `auth_failed`, `banned` | `false` | `deny (gateway): <why>` — for example `deny (gateway): key not authorized for login` |
| `auth_succeeded` | `true` | `allow (gateway): publickey` or `allow (gateway): openssh-cert` |
| `disconnected` | `true` (emitted only for sessions that authenticated) | `disconnect: <reason>` |

The `(gateway)` prefix follows `GatewayAccess::refuse`: no policy was asked, and the reason
must not read as a policy verdict.

An `auth_failed` record also carries `credential_mismatch`: `true` when the credential did
not match, which counts toward the ban if the connection ends unauthenticated; `false` for a
refusal that never counts (a refused bundle, a matched credential refused admission). The
`s0_sftp_auth_credential_mismatch_total` metric counts the `true` subset of
`s0_sftp_auth_failed_total`.

**Consumer impact.** `sftp/session` is a new `path`, and `gateway.session` a new block.
ADR-002 I4 freezes path values per deployment, and I6 requires consumers to ignore unknown
fields. A consumer that routes by label still receives these records, but until it
recognizes the new shape it drops them with its warning. That is the same fail-closed
posture as ADR-002 R1, and it carries the same consequence: the connection-level trail is
not live until the consumer is extended. Decision records for SFTP operations keep `path =
s3/authz/decision` and are ingested with no change.

A failed authentication is attributed to no organization, as gate records are (ADR-002 R6):
the login is a client claim, and a scanner that guesses logins must not be able to write
records into a chosen organization's trail. Unauthenticated events share the gate budget, so
a pre-authentication flood cannot evict decision records. Suppression is counted, as for
gate records.

### D14 — A reserved extension point for content inspection

Nothing is inspected in v1. The ordering between "upload complete on the SFTP side" and
"object committed and visible" is fixed now, so a later inspection stage slots in without
moving commits:

1. OPEN authorized;
2. bytes streamed: each in-order chunk passes an **observer** (`transfer::Observer`, an
   `Arc<dyn Fn(&[u8])>` closure, a no-op in v1 with no way yet to install another) as it
   is appended; full parts are sent as `UploadPart` as they fill;
3. CLOSE received;
4. **final re-authorization** against the current bundle;
5. parts already in flight drained, then the **commit gate** —
   `CommitGate::before_commit(&TransferContext) -> CommitVerdict`, where `CommitVerdict` is
   `Commit`, `Reject { reason }` or `Quarantine { reason }`. v1 always returns `Commit`, and
   `Quarantine` is refused as unimplemented until a later ADR defines where quarantined
   objects go and who may read them;
6. the `check_then_write` re-check (D8), then the last partial part sent (or, for a file
   under `part_size`, the single `PutObject`), and the conditional commit;
7. audit settled;
8. `SSH_FX_OK` returned to CLOSE.

The gate therefore sees every byte through the observer, but runs before the last part
reaches the backend.

A `Reject` aborts the upload and answers `SSH_FX_FAILURE` with the reason, and the record says
`commit: "rejected"`. Inspection time adds to CLOSE latency, which a later ADR must weigh
against client timeouts.

---

## Threat model

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | Partner SSH key leaks | The key holds no S3 power. Its grant is `create_objects` on one prefix. Optional `allowed_source_cidrs`. Revocation within one poll, including open sessions (D5). | The thief can drop files until revoked. Every drop is audited with the key fingerprint. |
| T2 | Memory-safety or logic bug in SSH or SFTP parsing | Separate Deployment (D1). In-tree v3 codec with length checks before allocation, disconnect on any framing error, fuzzed in CI (D4). Pinned russh with a total `Handler` override (D3). | A russh transport bug below the handler is outside s0's code, and is bounded by process isolation. |
| T3 | Escape from the virtual root (`..`, NUL, `\`, encodings, stem prefixes) | D6 normalization, post-mapping prefix assertion, `/`-terminated homes, PDP grant scope as an independent second layer. | None known. Traversal is a named regression suite. |
| T4 | Overwrite or destroy existing drops | `create_objects` in policy. Existence refused at OPEN. Conditional commit, or re-check plus in-flight registry (D8). Delete requires `delete_objects`. | `check_then_write` backends: a one-round-trip cross-replica race. |
| T5 | Reading other drops through stat, readdir or rename | Stat and readdir need `list_objects`. Rename needs `read_objects` on the source. Internal HEADs return no content (D7). | A `list_objects` holder sees names, sizes and times, by design. |
| T6 | A revoked key keeps a session | Per-operation credential re-check, a re-check by every session on each bundle change, transfer re-decision (D5). | Up to one poll interval. |
| T7 | Pre-auth flood, brute force | Per-IP rate, connection caps, handshake timeout, constant-time rejection, auth-attempt and key-probe caps, bans, bundle-distributed CIDR denylist (D12). | Bans are per replica: an `R`× budget across `R` replicas. |
| T8 | Resource exhaustion by pipelined writes, many handles or slow clients | Up-front memory reservation, bounded reorder window, handle caps, idle timeouts, SSH flow control (D9, D12). | None beyond configured bounds. |
| T9 | Orphaned multipart parts consuming storage | Abort on every error path (D9). | A hard kill leaves parts; a lifecycle rule is an operator obligation. |
| T10 | Spoofed client IP | PROXY v2 only from trusted CIDRs, and required from them (D12). | s0 cannot detect a load balancer that rewrites the source without PROXY v2; that is a documented deployment requirement. |
| T11 | Host-key substitution (MITM) | Mounted host keys only, never generated. Fingerprints published as a metric and logged (D1, D3). | Partners who skip pinning. |
| T12 | Algorithm downgrade (Terrapin, SHA-1, CBC) | Code-constant AEAD-only lists; strict KEX required; RSA client keys refused until SHA-1 is excludable (D3, E6). | None known. |
| T13 | A CA of tenant A vouching for tenant B's login | The CA must be named by the account **and** scoped to its tenant; the principal must equal the login; empty principals refused (D5). | A compromised CA can impersonate every login that names it. Revoke the CA in the bundle. |
| T14 | Audit flooding by unauthenticated clients | Pre-auth events on the gate budget, counted when suppressed (D13). | Per-event detail sampled under flood; the count is kept. |
| T15 | Partial upload committed on client interrupt | Atomic commit; disconnect without CLOSE aborts (D9). | CLOSE after an interrupt commits a short file, as on POSIX. |
| T16 | Existence oracle through create-only | Inherent: create-only must refuse an existing key. Limited to keys inside the create grant. | 1 bit per probed key, audited. |
| T17 | Filename collisions through lossy decoding | No lossy decoding: invalid UTF-8 is refused (D4, D6, E7). | NFC vs NFD names are distinct keys, as on the backend. |
| T18 | Policy/PEP skew: new verb on an old module or binary | `grant_schema_version: 3` gate in the module; PEP gate on `sftp.version` and the schema version (D5); binary ships first (rollout). | None — skew fails closed. |
| T19 | A russh default opens a channel type or request | Every `Handler` method overridden; the method list pinned per russh version (D3). | None known. |
| T20 | SFTP load starves the S3 front | Separate processes in production (D1). | Shared backend capacity: a backend-side concern. |

---

## Alternatives considered

- **A1 — An off-the-shelf SFTP server in front of s0.** Rejected. It must hold an S3
  credential with `read_objects` and `list_objects` to stat before upload, so create-only
  lives only in its configuration, and a leak or bypass exposes the prefix (see Context). It
  also forks the audit trail.
- **A2 — russh-sftp.** Rejected on E7: lossy path decoding and stream desync after errors are
  correctness defects on the authorization path, and it parses far more than s0 serves.
  Revisit if a later version decodes strictly and fails the session on framing errors.
- **A3 — A separate binary for SFTP.** Rejected. Two binaries would drift on the core, and the
  isolation the brief asks for comes from running the same binary as a separate process
  (D1).
- **A4 — Drive the S3 typed hooks from SFTP by synthesizing `S3Request`s.** Rejected. `check`
  cannot run off-HTTP (E1). A create-only transfer spans several S3 operations under one
  decision, which the per-operation hooks cannot express. `UploadPart` would decide
  `write_objects` and refuse every create-only principal.
- **A5 — Terminate open sessions on every bundle change.** Rejected in favour of
  per-operation re-authorization plus a credential sweep: terminating on any grant change
  would drop every partner's upload whenever an unrelated grant moved.
- **A6 — Create-only in code, with no verb.** Rejected. It would make "this principal may
  drop but not overwrite" invisible to the control plane and to anyone reading grants.
- **A7 — A `stat_objects` verb.** Rejected. `list_objects` already discloses exactly what a
  stat returns (D7). A sixth object verb would double the grant surface for no difference in
  disclosure.
- **A8 — Virtual mkdir held in session memory.** Rejected. Directories would vanish between
  sessions and be invisible to S3 tools. Markers are the convention consoles already use.
- **A9 — Accept SETSTAT and chmod as no-ops.** Rejected under ADR-008: an OK for something
  not done is a lie. The single exception, `attrs` on OPEN and MKDIR, is argued in D8.
- **A10 — Full public keys in the bundle.** Unnecessary. A fingerprint authenticates, and the
  bundle stays smaller and carries no key material.
- **A11 — Login name equals `subject_key`.** Rejected. `:` in logins breaks clients, and an
  account needs a home and a tenant that a bare subject key cannot carry.
- **A12 — A shared ban store (Redis or similar).** Rejected for now. It is a new dependency and
  failure domain on the pre-auth path, and the bundle already distributes fleet-wide denials
  (D12).
- **A13 — Local disk spool for uploads.** Rejected by the brief and on its merits: disk is
  unbounded, needs cleanup, and adds a data-at-rest surface in the gateway.
- **A14 — Accept RSA with a 3072-bit floor now and accept the SHA-1 exposure.** Rejected. It
  would ship a known downgrade, when ed25519 and ECDSA cover every client in the matrix.

---

## Consequences

**Accepted:**

- A new verb, `create_objects`, and a contract version bump to 3. The control plane must ship
  the module and data together, and **the binary ships first** (ADR-007's ordering rule):
  - a v3 bundle on an older binary denies every `create_objects` question and serves no
    SFTP, which is loud and safe;
  - a newer binary on a v2 bundle serves S3 exactly as before and no SFTP.
- Every captured input gains `"protocol": "s3"`. The corpus is regenerated once. No S3
  decision changes, which the parity gate proves.
- The core refactor (D2) landed together with the SFTP front (#42); the existing suite and
  the parity gate pass on it with only references renamed.
- RSA partner keys are not accepted in v1.
- WinSCP's default transfer to a temporary name followed by rename, and its timestamp
  preservation, do not work for a create-only account (see the client matrix).
- A client that sends CLOSE after an interruption commits a short file.

**Residual:**

- `check_then_write` backends keep a one-round-trip cross-replica create race (D8).
- Bans are per replica (D12).
- Orphaned parts after a hard kill need a lifecycle rule (D9).
- Rename is not atomic (D9).
- `excluded_prefixes` still denies on both fronts (E2).

### Follow-ups

- **F1** — *done*: S3 `PutObject` / `CompleteMultipartUpload` with `If-None-Match: *` map
  onto `create_objects` on `native` backends, so the drop-box posture is available over S3
  too (D7).
- **F2** — RSA client keys, once the signature algorithm is enforceable (E6).
- **F3** — `excluded_prefixes`, for both fronts at once.
- **F4** — the content-inspection stage (D14).
- **F5** — resume and append, once there is a design that does not need in-place writes.

---

## Client matrix and partner settings

OpenSSH `sftp`, lftp and paramiko are exercised against the real stack by `tests/e2e/run.sh`
(login, put, get, ls, host key pinned); paramiko negotiates `aes128-gcm@openssh.com`, within
D3's floor. WinSCP, FileZilla and the JVM clients cannot run headless in CI: their rows are
expected behaviour, to be checked by hand. The expected settings are:

| Client | Upload behaviour | Settings a create-only partner must use |
|---|---|---|
| OpenSSH `sftp` (batch, `-b`) | `OPEN(WRITE\|CREAT\|TRUNC)`, no stat unless the destination is a directory | Name the full remote path (`put f dir/f`) when `dir` is not listable. No `-a` (resume) and no `-p` (preserve). |
| WinSCP | Temporary name then rename, preserves timestamps | Turn off *Transfer to temporary filename* and *Preserve timestamp* (or enable *Ignore permission errors*). The rename needs `read_objects` and `delete_objects`, which a drop-box does not hold. |
| FileZilla | Lists the directory, then `OPEN(WRITE\|CREAT\|TRUNC)` | Grant `list_objects` if the partner uses the GUI, or upload with a CLI instead. |
| lftp (`sftp://`) | `OPEN(WRITE\|CREAT\|TRUNC)`, optional stat | Leave `xfer:use-temp-file` off (its default); a temporary name needs rename rights. |
| paramiko | `open(path, "w")` → `WRITE\|CREAT\|TRUNC` | Call `put(..., confirm=False)`: the default `confirm=True` stats after upload and needs `list_objects`. Its AEAD support meets D3 (`aes128-gcm@openssh.com` negotiated in `run.sh`). |
| JVM (JSch fork ≥ 0.2.15, Apache MINA SSHD ≥ 2.12) | `OPEN(WRITE\|CREAT\|TRUNC)` | ed25519 or ECDSA keys; strict KEX support required. |

---

## Test plan

- **Unit tests** per module: codec, paths, account and certificate matching, transfer state
  machine, limits.
- **Golden corpus and dual-engine parity** for every decision change: `create_objects` allow
  and deny, the write-implies-create implication, `freeze_writes` over `create_objects`, and
  SFTP-shaped inputs captured at the `Enforcer` funnel so `fixture_drift` sees
  `input.request.protocol`.
- **Black box**, in the style of `tests/gate_blackbox.rs`, table-driven so a new entry cannot
  slip in:
  - every SSH channel type, channel request, global request and authentication method other
    than the allowed ones is refused;
  - every SFTP packet type and extended request in D11 gets its documented answer;
  - the tables are pinned to the russh version's method list and to the v3 packet-type range.
- **Security regressions**:
  - path traversal and root escape through encoded, relative and backslash forms;
  - names in listings that look like links (`..`, empty components);
  - overwrite without `write_objects`;
  - content read through stat or readdir;
  - a write after a key is revoked mid-session;
  - a bundle without `sftp`, with the wrong version, and with `grant_schema_version: 2`;
  - oversized packets, malformed length fields, truncated strings;
  - a non-strict-KEX client, an RSA client key, an SHA-1 signature attempt (refused at the
    probe; server-sig-algs advertises no RSA algorithm, so no SHA-1 signature is ever
    verified), a key-probe flood (counted toward the ban);
  - a login and an operation against a bundle with a pushed module (prefixed keys) and one on
    the compiled-in default (raw `sub`), both succeeding;
  - certificates with empty principals, a foreign-tenant CA, an unknown critical option, and a
    revoked serial or key id.
- **Fuzzing**: cargo-fuzz targets `sftp_codec` and `proxy_v2_header`, run for a bounded time
  in CI.
- **Real-stack e2e** (`tests/e2e/run.sh`, MinIO) covers:
  - upload (small and multipart);
  - create-only refusal, the `If-None-Match: *` conformance probe, and create-only uploads
    on a backend declared `native`, including a concurrent create during the upload;
  - list narrowing to granted prefixes;
  - rename;
  - revocation mid-session (an idle session is closed by the bundle push);
  - `freeze_writes`, over SFTP and S3;
  - abort on disconnect (no object and no multipart upload left);
  - the client matrix (OpenSSH, lftp, paramiko).

## Implementation slicing

The slicing below was the plan. In practice the `Enforcer` extraction, `request.protocol` and
`create_objects`, and the whole SFTP front landed together in one PR (#42); the list is kept
as a map of the pieces.

0. This ADR.
1. `refactor(access)`: extract the `Enforcer`. No behaviour change, and the existing suite is
   the proof.
2. `feat(authz)`: `request.protocol`, `create_objects`, corpus, parity, README tables. This
   can land before any SFTP code.
3. `feat(sftp)`: SSH transport and authentication — config, `frontends`, host keys, algorithm
   constants, bundle accounts and certificates, the channel-refusal black box.
4. `feat(sftp)`: the read-only subsystem — codec, paths, STAT, OPENDIR/READDIR, REALPATH, and
   the fuzz target.
5. `feat(sftp)`: sequential upload — multipart streaming, memory bounds, abort.
6. `feat(sftp)`: create-only and overwrite semantics — open flags, conditional commit, the
   backend probe.
7. `feat(sftp)`: MKDIR, REMOVE, RMDIR, RENAME.
8. `feat(sftp)`: limits and bans — PROXY v2, rate limits, the bundle CIDR denylist.
9. `feat(audit)`: SFTP decision and session records.
10. `test(sftp)`: the e2e scenarios and the client matrix, with partner documentation.

Downloads (OPEN for read) land with slice 4's read-only subsystem.

## Control-plane integration (out of scope for this repository)

The control plane must:

- **Project `data.sftp`** in the D5 shape, alongside the existing data, in the same
  per-organization document.
  - Logins must be unique per organization and match the login grammar.
  - `subject_key` must name a subject present in that tenant's `user_attributes`.
  - `home.prefix` must be `/`-terminated or empty.
  - Fingerprints must be `SHA256:` base64 without padding, as OpenSSH prints them.
  - CA scopes must be explicit.
- **Emit `create_objects`** as a grantable verb, and bump to `grant_schema_version: 3` with a
  module that implements it, including the write-implies-create rule, and ignores
  `input.request.protocol` unless it deliberately conditions on it.
- **Revoke** by removing keys or accounts, or by adding `revoked_serials` /
  `revoked_key_ids`. Serialization stays byte-stable and every mutation changes the bytes
  (ADR-006 D3), so revocation latency stays the poll interval.
- **Optionally** derive `denied_source_cidrs` from the `auth_failed` and `banned` audit
  events.

Deployment assumptions:

- SFTP runs as its own Deployment from the same image, with `frontends.s3.enabled: false`
  and an enabled `frontends.sftp` section.
- The load balancer preserves the client source address, or speaks PROXY v2 from the
  configured CIDRs.
- Host keys are mounted secrets.
- Every home bucket carries an `AbortIncompleteMultipartUpload` lifecycle rule.
- The tenant backend credential already configured for the S3 front is sufficient: SFTP uses
  no operation outside the 23 enforced ones.
