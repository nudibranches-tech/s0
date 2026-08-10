#!/usr/bin/env bash
#
# Build the s0 container image, tagged with the crate version.
#
# PUBLISHING IS CI-ONLY, AND THIS SCRIPT ENFORCES THAT RATHER THAN ASKING.
# `.github/workflows/release.yml` runs this script on a `v*` tag with PUSH=1; run
# anywhere else it builds and refuses to publish, with the release procedure in the
# message. There is no supported `docker build && docker push` route to ship s0 — not for
# production, not for a dev cluster, not "just this once". The binary that decides who may
# read what is built by CI from a tagged commit, or it is not shipped: that is what makes
# the deployed bytes traceable to a commit anyone can check out, and a laptop-built image
# in a hospital's cluster is exactly the thing the rule exists to prevent.
#
# Locally this is a VERIFICATION tool — "does the image still build?" — and nothing more:
#
#   scripts/release-image.sh          # build only; cannot publish, by construction
#
# WHY THE TAG IS THE WHOLE POINT. s0 ships to hyperfluid the way Keycloak and Lakekeeper
# do: a pinned tag in the chart values. A pinned tag only works if a new build is a NEW
# tag — push different bytes under a tag a node already cached and nothing rolls, because
# the pod template never changed, and `IfNotPresent` is satisfied by the stale layer. That
# is not a Kubernetes quirk to work around with digests and imperative `kubectl`; it is
# the contract of a pinned tag. Honour it — one version, one tag, one immutable set of
# bytes — and the consumer's deploy is a one-line values change with nothing imperative
# anywhere. The tag is never an argument here: it comes from `Cargo.toml` via
# `scripts/crate-version.sh`, so no step in the pipeline accepts a hand-typed version.
#
# Environment (CI sets these; a local run needs none of them):
#   REGISTRY          default ghcr.io
#   IMAGE_REPOSITORY  default nudibranches-tech/s0-gas
#   PLATFORMS         default linux/amd64  (see "Releasing" in the README for why)
#   PUSH              1 to publish — honoured ONLY under GitHub Actions
#   S0_DIGEST_OUT     file to write the pushed digest to (CI records it on the release)
#
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

registry="${REGISTRY:-ghcr.io}"
# Lower-cased on the way in. CI passes `github.repository`, which preserves the
# capitalisation of the GitHub org/repo, and GHCR rejects an upper-case path — a failure
# that would only appear the first time someone renames the org with a capital in it.
repository="$(printf '%s' "${IMAGE_REPOSITORY:-nudibranches-tech/s0-gas}" | tr '[:upper:]' '[:lower:]')"
platforms="${PLATFORMS:-linux/amd64}"
push="${PUSH:-0}"

# The one gate. `GITHUB_ACTIONS` is set to "true" by the runner and by nothing else on a
# workstation; a shell that exports it to get past this line is not a mistake anyone makes
# by accident, and the audit trail (a tag, a workflow run, a commit) is the point rather
# than the mechanism.
if [ "$push" = "1" ] && [ "${GITHUB_ACTIONS:-}" != "true" ]; then
  cat >&2 <<'EOF'
Refusing to publish: this image is published by CI only.

To release s0:

  1. bump `package.version` in Cargo.toml (and Cargo.lock), commit
  2. git tag v<version> && git push --tags
  3. .github/workflows/release.yml builds and publishes the image from that tag
  4. bump the pin in hyperfluid: operator.config.s3Gateway.image.tag
  5. deploy hyperfluid the normal way

There is deliberately no local publish path, for dev clusters either — see "Releasing" in
README.md. Re-run without PUSH=1 to build the image locally and check that it still
builds.
EOF
  exit 1
fi

# Via `bash`, not the exec bit: a checkout that lost the mode (a zip export, a Windows
# clone, a `git apply` of a patch without it) would otherwise fail here rather than at the
# one place a version is read.
version="$(bash scripts/crate-version.sh)"
image="${registry}/${repository}:${version}"

revision="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# An image nobody can trace back to a commit is not reviewable, and "reviewable" is the
# entire reason this artifact is pinned by tag rather than floated. CI publishes from a
# tag, so a dirty tree here means the workflow was tampered with or a step wrote into the
# checkout before the build.
if [ "$push" = "1" ] && [ -n "$(git status --porcelain 2>/dev/null || true)" ]; then
  echo "::error::refusing to publish ${image} from a dirty checkout (revision ${revision})" >&2
  git status --porcelain >&2
  exit 1
fi

echo "==> s0 image"
echo "    version    $version   (Cargo.toml)"
echo "    revision   $revision"
echo "    image      $image"
echo "    platforms  $platforms"
echo "    push       $([ "$push" = "1" ] && echo 'yes (CI)' || echo 'no (local build only)')"
echo

metadata_file="$(mktemp -t s0-image-meta.XXXXXX.json)"
trap 'rm -f "$metadata_file"' EXIT

output_args=()
if [ "$push" = "1" ]; then
  output_args+=(--push)
elif [ "$platforms" = "${platforms%,*}" ]; then
  # Single platform and not pushing: leave it in the local daemon so it can be run.
  output_args+=(--load)
else
  # Multi-platform images cannot be loaded into the docker daemon; just prove it builds.
  output_args+=(--output=type=cacheonly)
fi

# --provenance/--sbom off, deliberately. With them on, buildx publishes an OCI *index*
# carrying attestation manifests instead of a plain image manifest; the digest you get
# back is the index's, and several registries and mirroring tools in the private-cloud
# path either reject the attestation media types or drop them silently on copy. A single
# self-contained manifest is what `skopeo copy` / `crane copy` move losslessly into an
# air-gapped registry, which is the deployment this image exists for. Traceability is
# carried by the OCI labels below instead; signing (cosign) is a separate, later decision.
docker buildx build \
  --platform "$platforms" \
  --file Dockerfile \
  --tag "$image" \
  --provenance=false \
  --sbom=false \
  --label "org.opencontainers.image.title=s0" \
  --label "org.opencontainers.image.description=An OPA/ABAC-enforcing, S3-compatible authorization gateway." \
  --label "org.opencontainers.image.version=${version}" \
  --label "org.opencontainers.image.revision=${revision}" \
  --label "org.opencontainers.image.created=${created}" \
  --label "org.opencontainers.image.source=https://github.com/nudibranches-tech/s0-gas" \
  --label "org.opencontainers.image.licenses=BUSL-1.1" \
  --metadata-file "$metadata_file" \
  "${output_args[@]}" \
  .

if [ "$push" != "1" ]; then
  cat <<EOF

Built ${image} locally, and NOTHING WAS PUBLISHED — this path cannot publish. That is the
whole check: the image still builds. To ship this version, tag it and let CI publish it
(README.md, "Releasing").
EOF
  exit 0
fi

digest=""
if command -v jq >/dev/null 2>&1; then
  digest="$(jq -r '."containerimage.digest" // empty' "$metadata_file")"
else
  digest="$(sed -n 's/.*"containerimage.digest": *"\([^"]*\)".*/\1/p' "$metadata_file" | head -1)"
fi

if [ -z "$digest" ]; then
  echo "::error::pushed, but could not read the digest back from buildx metadata" >&2
  exit 1
fi

if [ -n "${S0_DIGEST_OUT:-}" ]; then
  printf '%s\n' "$digest" > "$S0_DIGEST_OUT"
fi

cat <<EOF

Published
  image   $image
  digest  $digest

The digest is printed for the record — for verifying that a mirror copied the same bytes,
or for an incident. It is NOT how this image is deployed: consumers pin the TAG, because a
tag names a release in a code review and a digest names nothing without a registry lookup.

Next: bump the pin in hyperfluid (charts/hyperfluid/values.yaml)

  operator:
    config:
      s3Gateway:
        image:
          repository: hyperfluid/s3-gateway
          tag: "$version"

…and deploy hyperfluid the normal way. A cluster that pulls from its own registry mirrors
this exact tag into it first — a registry-to-registry copy of these bytes, never a rebuild:

  skopeo copy docker://$image \\
              docker://<your-registry>/hyperfluid/s3-gateway:$version
EOF
