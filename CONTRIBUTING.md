# Contributing to s0

Thanks for your interest in improving **s0**, an OPA/ABAC-enforcing,
S3-compatible authorization gateway. This document explains how to build, test,
and submit changes.

## Prerequisites

- A stable Rust toolchain. The crate uses **edition 2024**, so the minimum
  supported Rust version (MSRV) is **1.85**.
- [Open Policy Agent](https://www.openpolicyagent.org/) (`opa`) **1.13.1** on your
  `PATH` — the same version production deploys, and the version CI installs. The
  dual-engine parity test ([`tests/parity.rs`](tests/parity.rs)) replays the golden
  corpus through both the embedded regorus engine and a real `opa` binary, and it is
  the only check that licenses the embedded engine to serve traffic. It therefore
  **fails** rather than skips when `opa` is missing:

  ```bash
  curl -sSL -o ~/.local/bin/opa \
    https://openpolicyagent.org/downloads/v1.13.1/opa_linux_amd64_static
  chmod +x ~/.local/bin/opa
  ```

  The major version matters: OPA ≥ 1.0 parses rego **v1**, 0.x parses **v0**, so a
  0.x binary is a different oracle rather than an older one. If you genuinely cannot
  install it, `S0_ALLOW_NO_OPA=1 cargo test` degrades the gate to "regorus alone" and
  says so on stderr — do not merge on that basis.
- [Docker](https://www.docker.com/) to run the real-stack end-to-end suite
  ([`tests/e2e/run.sh`](tests/e2e/run.sh)).

## Building and testing

Run all checks locally before opening a PR. These mirror CI
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```bash
# Format check
cargo fmt --all -- --check

# Lints — warnings are errors
cargo clippy --all-targets --all-features -- -D warnings

# Tests (unit + typed-hook e2e + golden corpus + parity)
cargo test --all-targets

# Real-stack end-to-end (client → gateway → MinIO, embedded OPA). Needs Docker.
bash tests/e2e/run.sh
```

## House rules

The gateway is on the security path, so a few conventions are non-negotiable:

1. **Fail closed.** Every ambiguous or error condition must deny, never allow.
   A PDP error, a missing key, an unmodelled operation — all resolve to a 403.
   New code that can widen access must be covered by a golden-corpus case.
2. **Deny by default.** Operations the gateway does not explicitly own are
   denied, not passed through. Do not add a raw passthrough path.
3. **Decide and forward from the same value.** The authorization decision and
   the forwarded request must derive from the same parsed `S3Request`; never
   re-parse or trust a raw header for the forward.
4. **Keep comments lean.** Prefer readable code over narration. A comment should
   explain *why*, not restate *what*; drop comments that duplicate the code, and
   keep them under a few lines.
5. **Errors are `thiserror` enums** ([`src/error.rs`](src/error.rs)); propagate
   with `?`. Avoid `.unwrap()`/`.expect()`/`panic!` on the request path.
6. **Tests travel with code.** Every module carries unit tests; decision-logic
   changes come with a corpus case that both engines must agree on.

## Commit and PR conventions

- Use [Conventional Commits](https://www.conventionalcommits.org/) for messages,
  e.g. `feat(authz): add attribute cache`, `fix(access): reject skewed dates`.
- Keep commits focused and logically scoped; rebase noisy WIP history before
  requesting review.
- Reference related issues with `Closes #123`.

## Reporting security issues

Please do **not** open public issues for vulnerabilities. See
[`SECURITY.md`](SECURITY.md) for the private disclosure process.

## Licensing of contributions

s0 is distributed under the Business Source License 1.1 ([`LICENSE`](LICENSE)),
which converts to Apache-2.0 on the change date and is also offered under
separate commercial licenses. So that both paths stay possible, by submitting a
contribution you agree that it is licensed under the terms of [`LICENSE`](LICENSE),
and you grant Nudibranches a perpetual, worldwide, non-exclusive, royalty-free,
irrevocable license to use, reproduce, modify, sublicense and distribute your
contribution, including under the Change License and under commercial license
terms. You keep the copyright on what you write.

Sign off your commits (`git commit -s`) to certify the
[Developer Certificate of Origin](https://developercertificate.org/).

## Code of Conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
