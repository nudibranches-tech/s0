# Releasing s0

s0 ships as a **container image**, from its own repository, on its own version line — the
same treatment Keycloak, Lakekeeper and OPA get in the platforms that consume them. A
consumer pins a tag; it never builds s0.

> **CI is the only thing that publishes this image.** There is no
> `docker build && docker push` route — not for production, not for a dev cluster, not
> once. The binary that decides who may read what is built by
> [`../.github/workflows/release.yml`](../.github/workflows/release.yml) from a tagged
> commit, or it is not shipped, so the running bytes always trace to a commit anyone can
> check out. [`../scripts/release-image.sh`](../scripts/release-image.sh) enforces this
> rather than asking: run with `PUSH=1` anywhere but GitHub Actions and it refuses.

## The procedure

```bash
# 1. bump the version — Cargo.toml is the single source of truth
$EDITOR Cargo.toml                       # package.version = "0.3.0"
cargo check                              # updates Cargo.lock to match
git commit -am 'chore(release): 0.3.0'

# 2. tag it. The tag must be v<that exact version>; CI checks and fails in ~5s if not.
git tag v0.3.0
git push && git push --tags
```

On that one tag event CI re-runs the full [`ci`](../.github/workflows/ci.yml) suite on the
tagged commit, builds and publishes `registry.hyperfluid.cloud/hyperfluid/s0:0.3.0`, and attaches the binary
tarballs and the image digest to a GitHub Release. It **refuses to overwrite** a version
already in the registry — a published tag names one immutable set of bytes, forever.
Re-releasing means bumping the version.

The consuming platform then bumps its pin and deploys normally.

## The Change Date travels with the version

[`../LICENSE`](../LICENSE) carries a fixed `Change Date`, and the BSL applies it
*per version*: a version converts to Apache-2.0 on that date **or** on its own
fourth anniversary, whichever comes first. Freeze the date and every later release
inherits a shorter and shorter BSL window — a version cut in 2029 would go
Apache-2.0 after a year. So move it with the version bump, in step 1:

```bash
$EDITOR LICENSE     # Change Date: <release date + 4 years>
$EDITOR README.md   # the same date in the License section, and in COMMERCIAL.md
```

What is already published is unaffected: releasing 0.4.0 with a later Change Date
does not move 0.3.2's. Each version keeps the terms it shipped under.

## Why there is no shortcut, and why the tag has to move

A consumer pins a tag with `imagePullPolicy: IfNotPresent`. Push different bytes under a
tag a node already cached and *nothing happens*: the pod template is a function of the
image string, so an unchanged string is an unchanged template, so there is no rollout — and
even a pod that did restart would be served the node's cached layer.

That is not a Kubernetes quirk to route around with digests and imperative `kubectl`; it is
the contract of a pinned tag. Honour it — one version, one tag, one immutable set of bytes —
and the consumer's deploy is a one-line values change with nothing imperative anywhere. The
cost is that a dev iteration takes a version bump and a CI run instead of a 90-second local
push. That is the accepted trade, and it is the same trade for everyone.

## Checking that the image still builds

The build itself is not privileged, and a developer trying something on their own cluster
should not be blocked. What is withheld is *publication*:

```bash
scripts/release-image.sh          # builds locally, loads into your docker daemon.
                                  # Cannot publish — the push path is CI-gated.
```

Nothing stops you from `docker tag`-ing that image to a registry of your own for an
experiment. It is simply not how a release happens.

## The decisions, briefly

| | | |
|---|---|---|
| **Registry** | `registry.hyperfluid.cloud/hyperfluid/s0` | The organisation's own registry. CI authenticates with the `REGISTRY_USERNAME` / `REGISTRY_TOKEN` repository secrets; that token is a standing key to exactly the artifact this care is about, so it is scoped to push on `hyperfluid/s0` alone. The registry is private — give the pulling cluster a pull secret. An air-gapped consumer copies the tag onward (`skopeo copy` / `crane copy`): a byte-for-byte move, never a rebuild. |
| **Tag** | the crate version, and only that | No `latest`, no floating `0.3`, no branch tag. A second, moving name for the same image is something a consumer can pin by accident, which is the failure this whole page exists to prevent. |
| **Source of truth** | `Cargo.toml` → [`../scripts/crate-version.sh`](../scripts/crate-version.sh) | No step in the pipeline accepts a hand-typed version; the git tag is *checked against* the crate rather than being an input. The same script fails when `Cargo.lock` disagrees — the classic half-done bump, which otherwise surfaces as a `--locked` failure ten minutes into a release. |
| **Trigger** | a `v*` git tag | Not a published GitHub Release: the tag is what the release commit already creates and what `git describe` reports from a checkout, and it needs no click at the moment the artifact's identity is fixed. The Release object is an *output* of the workflow. |
| **Platforms** | `linux/amd64` only | A decision, not an omission: every target cluster is amd64; arm64 would mean QEMU cross-compilation (tens of minutes for a Rust release build) or a second runner, and the result is an OCI index — a shape some registry-mirroring paths handle worse than a plain manifest. One line in `PLATFORMS` when there is an arm64 node to run it on. |
| **Digest** | published as a record, not as the pin | Every release records `…@sha256:…` in its job summary, on the Release, and as an artifact — for verifying a mirror copied the same bytes, or for an incident. Consumers still pin the **tag**: `tag: "0.3.0"` names a release in a code review; `@sha256:4df714…` names nothing without a registry lookup. |
| **Tarballs** | **kept** | The image is the primary artifact and the only supported way to *deploy* s0. The `x86_64` gnu/musl tarballs answer a different question — running the binary outside a container, on an ops box or bare metal. They are built by the same job on the same tag under the same gate, so they cost one already-existing matrix entry and can never diverge from the image. |
