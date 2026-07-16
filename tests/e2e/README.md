# Real-stack end-to-end tests

`run.sh` exercises the gateway the way a real deployment does: an off-the-shelf
S3 client (aws-cli) talks to **s0-gas**, which authorizes each request against a
pushed policy bundle and re-signs to a real **MinIO** backend. Nothing here is
mocked — it is the client, the gateway binary, and a real S3 server.

The typed-hook tests in [`tests/access_e2e.rs`](../access_e2e.rs) prove the
decision path in-process (no backend). This suite proves the same properties
**through the wire**, including the ones only a real backend can show:

| Scenario | Property |
|---|---|
| GET/PUT on the granted `pub/` prefix | allow on scope |
| GET off-prefix (`private/`) or on an ungranted bucket (`secret`) | deny by default |
| **COPY whose source is denied** | the Ceph RGW-OPA copy-source gap is closed — source read is authorized, so the copy is blocked before it reaches the backend |
| COPY where both source and dest are granted | allow |
| `ListObjectsV2` narrowed to the granted prefix | denied keys never appear in the listing |
| `DeleteObjects` mixing allowed + denied keys | the denied key is stripped from the forward; only the allowed key is deleted |
| anonymous / unknown access key | `403` / `InvalidAccessKeyId` |
| **grant revoked in the bundle** | the next request denies — policy is live, not baked into the credential |

## Running locally

Needs Docker and a Rust toolchain:

```bash
bash tests/e2e/run.sh
```

The script starts MinIO in a container (`--network host`), seeds buckets and
objects with the backend credentials, builds and launches the gateway with
[`gateway.e2e.json`](gateway.e2e.json) + [`bundle.e2e.json`](bundle.e2e.json),
then runs every scenario and prints a pass/fail tally. It cleans up the
container, the gateway process, and its scratch state under `/tmp/s0-gas-e2e`
on exit.

Useful overrides: `GW_BIN` (skip the build and use a prebuilt binary),
`MINIO_IMAGE`, `AWSCLI_IMAGE`, `GW_ENDPOINT`, `MINIO_ENDPOINT`.

## In CI

[`.github/workflows/e2e.yml`](../../.github/workflows/e2e.yml) builds the binary
and runs this suite on every push and pull request.

## The fixtures

- **`gateway.e2e.json`** — one tenant (`acme`) fronting MinIO as a `remote_s3`
  backend. `owner_*` are the MinIO root creds the gateway re-signs with; two
  virtual credentials (`AKIAOPEN`, `AKIAADMIN`) stand in for platform-issued
  identities. Embedded regorus PDP, bundle re-read every 2s.
- **`bundle.e2e.json`** — the pushed policy data. `open-user` is scoped to the
  `pub/` prefix of `open`; `admin-user` holds the whole tenant. In production
  the platform projects and pushes this; here it is a static fixture.
