#!/usr/bin/env bash
# The cross-repo LIVE proof for runbook blocker P2.
#
# s0's bundle poller and hyperfluid's bundle endpoint are the two halves of one
# contract that lives in two repositories, and every defect this workstream has paid
# for was the two halves agreeing about a string while disagreeing about behaviour.
# The always-on gates (tests/cross_repo_contract.rs here, s3_gateway_bundle_auth.rs
# there) read each other's source. This script *runs* both:
#
#   1. starts hyperfluid's `serve_the_real_internal_router_for_the_cross_repo_live_proof`,
#      which stands the real `internal_policies_router` — real guard included — on a
#      loopback port backed by a real testcontainers Postgres, and writes a handshake
#      file naming that port;
#   2. waits for the handshake;
#   3. runs `tests/live_console_bundle.rs`, which drives `bundle_refresh::spawn` — the
#      real polling task — at that port, with and without the platform credential, and
#      checks the OPA-polled sibling routes are still open;
#   4. drops the stop file so the server exits.
#
# Requires: a working Docker/Podman socket (testcontainers) for the hyperfluid half.
#
# Usage:  scripts/live-cross-repo-proof.sh [/path/to/hyperfluid]
set -euo pipefail

S0_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HYPERFLUID_REPO="${1:-${HYPERFLUID_REPO:-$(cd "$S0_REPO/.." && pwd)/hyperfluid}}"

if [[ ! -f "$HYPERFLUID_REPO/rust/hf_module_console_api/Cargo.toml" ]]; then
  echo "not a hyperfluid checkout: $HYPERFLUID_REPO" >&2
  echo "usage: $0 [/path/to/hyperfluid]   (or set HYPERFLUID_REPO)" >&2
  exit 2
fi

WORK="$(mktemp -d)"
HANDSHAKE="$WORK/handshake.json"
SERVER_LOG="$WORK/console-server.log"
cleanup() {
  touch "$HANDSHAKE.stop" 2>/dev/null || true
  if [[ -n "${SERVER_PID:-}" ]]; then
    # Give the graceful shutdown a moment, then insist.
    for _ in $(seq 1 50); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.2; done
    kill -0 "$SERVER_PID" 2>/dev/null && kill "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "== 1/4  starting hyperfluid's real internal router (testcontainers Postgres) =="
(
  cd "$HYPERFLUID_REPO/rust"
  SQLX_OFFLINE=true HF_S3_BUNDLE_LIVE_HANDSHAKE="$HANDSHAKE" \
    cargo test -p hyperfluid --test mod -- --ignored --nocapture --exact \
    hf_console::s3_gateway_bundle_live::serve_the_real_internal_router_for_the_cross_repo_live_proof
) >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

echo "== 2/4  waiting for the handshake (compile + container start can take a while) =="
for _ in $(seq 1 900); do
  [[ -s "$HANDSHAKE" ]] && break
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "the hyperfluid server exited before serving:" >&2
    tail -40 "$SERVER_LOG" >&2
    exit 1
  fi
  sleep 1
done
if [[ ! -s "$HANDSHAKE" ]]; then
  echo "timed out waiting for $HANDSHAKE" >&2
  tail -40 "$SERVER_LOG" >&2
  exit 1
fi
echo "   peer: $(cat "$HANDSHAKE")"

echo "== 3/4  driving s0's real bundle poller against it =="
set +e
(
  cd "$S0_REPO"
  S0_LIVE_CONSOLE_HANDSHAKE="$HANDSHAKE" \
    cargo test --test live_console_bundle -- --ignored --nocapture
)
RESULT=$?
set -e

echo "== 4/4  stopping the console server =="
touch "$HANDSHAKE.stop"
wait "$SERVER_PID" 2>/dev/null || true
unset SERVER_PID

if [[ $RESULT -ne 0 ]]; then
  echo "LIVE PROOF FAILED (console server log: $SERVER_LOG)" >&2
  exit $RESULT
fi
echo "LIVE PROOF PASSED"
