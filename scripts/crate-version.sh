#!/usr/bin/env bash
#
# Print the version of the `s0` crate — the ONE place anything is allowed to learn it.
#
# The image tag, the git tag and the consumer's pin all have to be the same
# string, and every previous way of getting there involved a human retyping it somewhere.
# So: `Cargo.toml` is the source of truth, this script is the only reader, and both the
# release workflow and `scripts/release-image.sh` call it rather than parsing their own
# copy. A hand-typed tag cannot enter the pipeline because no step accepts one.
#
# It also refuses when `Cargo.lock` disagrees with `Cargo.toml`, because that is the
# classic half-done bump: the version moves, the lock is forgotten, everything looks fine
# until `cargo build --locked` inside the image fails ten minutes into a release. Failing
# here costs a second and names the fix.
#
#   scripts/crate-version.sh          -> 0.2.0
#
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/Cargo.toml"
lock="$repo_root/Cargo.lock"

[ -f "$manifest" ] || { echo "no Cargo.toml at $manifest" >&2; exit 1; }

# The first `version = "…"` inside the [package] table, and nothing else: a bare grep
# would happily return `rust-version` or the first dependency it met.
version="$(
  awk '
    /^\[/            { in_package = ($0 ~ /^\[package\]/); next }
    !in_package      { next }
    /^[[:space:]]*version[[:space:]]*=/ {
      if (match($0, /"[^"]+"/)) { print substr($0, RSTART + 1, RLENGTH - 2); exit }
    }
  ' "$manifest"
)"

if [ -z "$version" ]; then
  echo "could not read package.version from $manifest" >&2
  exit 1
fi

# A container tag has to survive being a tag: no slashes, no spaces, no leading dot.
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)*$'; then
  echo "package.version '$version' is not a semver string usable as an image tag" >&2
  exit 1
fi

if [ -f "$lock" ]; then
  locked="$(
    awk -v want='name = "s0"' '
      $0 == want { found = 1; next }
      found && /^version = / {
        if (match($0, /"[^"]+"/)) { print substr($0, RSTART + 1, RLENGTH - 2) }
        exit
      }
    ' "$lock"
  )"
  if [ -n "$locked" ] && [ "$locked" != "$version" ]; then
    cat >&2 <<EOF
Cargo.lock disagrees with Cargo.toml about this crate's version:

  Cargo.toml  $version
  Cargo.lock  $locked

The image builds with \`cargo build --locked\`, so this would fail the build (or ship a
mislabelled binary). Run \`cargo check\` and commit the updated Cargo.lock with the bump.
EOF
    exit 1
  fi
fi

printf '%s\n' "$version"
