#!/usr/bin/env bash
# E2E smoke playbook for the docker-compose quickstart stack (roadmap #78).
#
# Invoked by `make e2e-docker` AFTER the stack is up. It waits for the proxy to
# report healthy, then asserts the sample policy's allow/deny decisions through
# the proxy:
#
#   GET /anything/allow  -> 200 (allow, proxied to upstream)
#   GET /anything/deny   -> 403 (explicit deny)
#   GET /anything/secret -> 403 (deny-by-default)
#
# Exits non-zero on the first failed assertion. Makes no Docker calls itself —
# lifecycle (up/down) is owned by the Makefile target so teardown always runs.
set -euo pipefail

PROXY="${PROXY_BASE_URL:-http://localhost:8081}"

wait_healthy() {
  local url="$1" timeout="${2:-90}" deadline
  deadline=$(( $(date +%s) + timeout ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" || true)" = "200" ]; then
      return 0
    fi
    sleep 2
  done
  echo "timed out waiting for $url to become healthy" >&2
  return 1
}

assert_status() {
  local path="$1" want="$2" got
  got="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${PROXY}${path}")"
  if [ "$got" != "$want" ]; then
    echo "FAIL  GET $path -> $got (want $want)" >&2
    exit 1
  fi
  echo "PASS  GET $path -> $got"
}

echo "[e2e] waiting for proxy health at ${PROXY}/healthz ..."
wait_healthy "${PROXY}/healthz"

echo "[e2e] asserting allow/deny decisions through the proxy ..."
assert_status "/anything/allow"  200
assert_status "/anything/deny"   403
assert_status "/anything/secret" 403

echo "[e2e] all assertions passed."
