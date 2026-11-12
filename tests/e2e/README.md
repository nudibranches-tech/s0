# Real-stack end-to-end tests

`run.sh` exercises the gateway the way a real deployment does: an off-the-shelf
S3 client (aws-cli) and a stock OpenSSH `sftp` client talk to **s0**, which authorizes each request against a
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

The SFTP scenarios run a stock OpenSSH `sftp` (from the host, so it must be installed)
against the SFTP front, with the host key pinned in `known_hosts`:

| Scenario | Property |
|---|---|
| upload a small file and a 20 MiB one | lands byte for byte; the large one goes multipart under OpenSSH's pipelined writes |
| upload over an existing file with only `create_objects` | refused; the original is untouched |
| download with only `create_objects` | refused |
| list and download as an operator | the download matches the upload |
| `rename` (posix-rename, overwrites) without `write_objects` | refused |
| `rename -l` (legacy RENAME, create-only target) | to a fresh name: done; onto an existing file: refused, both files intact |
| a TCP client that never sends its version line | disconnected at `handshake_timeout_secs`, not held until the transport's inactivity timeout |
| 12 logins whose client tries a wrong key before the right one | none banned; 10 connections that never log in then ban the address |
| `ls` as a login granted two sub-prefixes of its home (`nar/in/a/`, `nar/in/b/`) | narrowed: the home shows only `in`, `in` only `a` and `b`; `nar/top.txt` and `in/c` never appear, and `ls in/c` is refused |
| `freeze_writes: true` pushed in the bundle | an `sftp put` (and an S3 `PutObject`) is refused and nothing lands; `get` (and `GetObject`) still work; thawing restores `put` |
| a throttled 32 MiB `put` whose client (sftp and ssh) is killed once a multipart upload is open | the upload is aborted: no object, no multipart upload left (`list-multipart-uploads`), the transfer audited `aborted` |
| `native` probe: two `PutObject` and two `CompleteMultipartUpload` with `If-None-Match: *` on one fresh key each, straight to MinIO | the second of each is `412 PreconditionFailed` (the image passes) |
| tenant `beta` on a backend declared `conditional_create: "native"`: create-only upload, then over an existing key | created; then refused, original intact |
| the same, but the key is created by another writer while the upload streams (6 MiB single PUT, 16 MiB multipart) | refused at `CLOSE` by the conditional commit; the other writer's object survives; no upload left; MinIO's trace shows `If-None-Match: *` on the `PutObject` and the `CompleteMultipartUpload` |
| lftp (`alpine` package) and paramiko (pinned pip release), in containers, host key pinned | login + put + get + ls; paramiko's negotiated cipher/MAC meets ADR-012 D3 (AEAD, or EtM) |
| an idle session whose account the next bundle removes | closed by the gateway before the client sends anything; audited `disconnected` with `credential_revoked`; the key cannot log in again |
| `auth_failed` session records | `outcome: denied` |

The ban scenario runs last among them: it bans the test address on the SFTP front.

The client matrix stops at OpenSSH, lftp and paramiko. WinSCP and FileZilla are GUI
clients with no headless mode worth driving in CI, and the JVM clients (JSch, Apache MINA
SSHD) would need a harness of their own; their settings in ADR-012's client matrix are
documented, not exercised here.

## Running locally

Needs Docker and a Rust toolchain:

```bash
bash tests/e2e/run.sh
```

The script starts MinIO in a container (`--network host`), seeds buckets and
objects with the backend credentials, builds and launches the gateway with
[`gateway.e2e.json`](gateway.e2e.json) + [`bundle.e2e.json`](bundle.e2e.json),
then runs every scenario and prints a pass/fail tally. It cleans up the
container, the gateway process, and its scratch state under `/tmp/s0-e2e`
on exit.

Useful overrides: `GW_BIN` (skip the build and use a prebuilt binary),
`MINIO_IMAGE`, `AWSCLI_IMAGE`, `LFTP_IMAGE`, `PARAMIKO_IMAGE`, `PARAMIKO_VERSION`,
`GW_ENDPOINT`, `MINIO_ENDPOINT`. `PDP_MODE=sidecar` runs the same scenarios against a
real OPA container instead of the embedded engine.

## In CI

[`.github/workflows/e2e.yml`](../../.github/workflows/e2e.yml) builds the binary
and runs this suite on every push and pull request.

## The fixtures

- **`gateway.e2e.json`** — one tenant (`acme`) fronting MinIO as a `remote_s3`
  backend, and a second (`beta`) fronting the same MinIO through a second backend
  declared `conditional_create: "native"`, with the SFTP front on `127.0.0.1:2222` (host key generated by `run.sh`), a
  5 s handshake timeout and a pre-auth burst sized for the suite. `owner_*` are the MinIO root creds the gateway re-signs with; two
  virtual credentials (`AKIAOPEN`, `AKIAADMIN`) stand in for platform-issued
  identities. Embedded regorus PDP, bundle re-read every 2s.
- **`bundle.e2e.json`** — the pushed policy data. `run.sh` adds the `sftp` section
  (accounts `acme-drop`, `acme-ops` and `acme-revoke` on `open/drop/`, `acme-narrow` on
  `open/nar/`, and `beta-drop` on `native/drop/`, keyed by freshly generated client
  keys) and their grants before the gateway starts. `open-user` is scoped to the
  `pub/` prefix of `open`; `admin-user` holds the whole tenant. In production
  the platform projects and pushes this; here it is a static fixture.
