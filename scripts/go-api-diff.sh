#!/usr/bin/env bash
#
# go-api-diff.sh — public Go API-diff gate for pkg/**.
#
# The Go analogue of the `buf breaking` proto gate (docs/COMPATIBILITY.md §3):
# it diffs the exported API of every package under pkg/** between a BASE
# checkout (the PR merge base with main) and a HEAD checkout (the PR head) and
# fails on INCOMPATIBLE changes. Additive changes (new packages, new exported
# symbols, new struct fields on DTOs) are allowed.
#
# Scope is deliberately pkg/** only — internal/** is excluded from the v1
# stability contract, and proto/gen/go is already guarded by `buf breaking`.
#
# Tool: golang.org/x/exp/cmd/apidiff (per-package export-data comparison).
# apidiff prints incompatible findings to stdout but ALWAYS exits 0 when it can
# load both sides, so this script fails on *output presence*, not on its exit
# code. A package that existed on base but is gone on head is reported as an
# incompatible removal here (apidiff cannot load the missing side itself).
#
# Usage:
#   scripts/go-api-diff.sh <BASE_DIR> <HEAD_DIR>
#
# Both arguments are paths to module checkouts (each containing go.mod). The
# script writes export data from inside each module dir (apidiff requires that)
# and compares package-by-package.
#
# Env:
#   APIDIFF_VERSION  pinned golang.org/x/exp module version for `go run`
#                    (default: the version pinned below).

set -euo pipefail

# Pinned so the gate is reproducible. golang.org/x/exp ships pseudo-versions
# only (no semver tags), so this is the resolved pseudo-version. Bump
# deliberately; do not float to @latest in CI.
APIDIFF_VERSION="${APIDIFF_VERSION:-v0.0.0-20260603202125-055de637280b}"
APIDIFF="golang.org/x/exp/cmd/apidiff@${APIDIFF_VERSION}"

BASE_DIR="${1:?usage: go-api-diff.sh <BASE_DIR> <HEAD_DIR>}"
HEAD_DIR="${2:?usage: go-api-diff.sh <BASE_DIR> <HEAD_DIR>}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
export_dir="$workdir/export"
mkdir -p "$export_dir"

# pkg_list <module-dir> — print the import paths of every package under pkg/**.
pkg_list() {
  ( cd "$1" && go list ./pkg/... )
}

# safe name for an import path used as an export-data filename.
safe_name() { echo "$1" | sed 's#[/.]#_#g'; }

echo "== Go API-diff gate (pkg/**) =="
echo "base: $BASE_DIR"
echo "head: $HEAD_DIR"
echo "tool: $APIDIFF"
echo

base_pkgs="$(pkg_list "$BASE_DIR")"
head_pkgs="$(pkg_list "$HEAD_DIR")"

if [ -z "$base_pkgs" ]; then
  echo "no packages under pkg/** on base — nothing to gate."
  exit 0
fi

# Write export data for every base package, from inside the base module.
( cd "$BASE_DIR"
  for p in $base_pkgs; do
    go run "$APIDIFF" -w "$export_dir/$(safe_name "$p").base" "$p"
  done
)

incompatible=0

for p in $base_pkgs; do
  name="$(safe_name "$p")"

  if ! echo "$head_pkgs" | grep -qxF "$p"; then
    echo "INCOMPATIBLE: package removed: $p"
    incompatible=1
    continue
  fi

  # Compare base export data against the live head source for this package.
  out="$( cd "$HEAD_DIR" && go run "$APIDIFF" -incompatible "$export_dir/$name.base" "$p" )"
  if [ -n "$out" ]; then
    echo "INCOMPATIBLE changes in $p:"
    echo "$out" | sed 's/^/  /'
    incompatible=1
  else
    echo "ok: $p"
  fi
done

# Report (but do not fail on) newly added packages — purely informational.
for p in $head_pkgs; do
  if ! echo "$base_pkgs" | grep -qxF "$p"; then
    echo "added (ok): $p"
  fi
done

echo
if [ "$incompatible" -ne 0 ]; then
  echo "Go API-diff gate FAILED: incompatible change(s) to pkg/** public API."
  echo "If this is intentional, it is a breaking change — bump the major version"
  echo "and call it out per docs/COMPATIBILITY.md §3."
  exit 1
fi

echo "Go API-diff gate passed: pkg/** public API is backward-compatible."
