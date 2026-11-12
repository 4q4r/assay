#!/usr/bin/env bash
# goreleaser-split-parity-test.sh — mutation red-check for the parity gate.
#
# The parity gate (goreleaser-split.sh parity) must be BIDIRECTIONAL: it has
# to fail when a pinned §4.4 target is dropped from .goreleaser.yaml AND when
# the config carries a target outside the pin. History: the original gate
# checked only pin ⊆ config and its pin omitted linux_arm64, so a config edit
# that silently dropped a shipped target passed green (S4 review P1-1). This
# test mutates the real config both ways and proves the gate goes red. It
# runs in CI (release-config job) right after the parity step, so a future
# weakening of the gate or the pin fails CI instead of shipping a release
# with a missing asset.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
split="$repo_root/scripts/goreleaser-split.sh"
src="$repo_root/.goreleaser.yaml"

fail() {
	echo "goreleaser-split-parity-test: FAIL — $1" >&2
	exit 1
}

command -v yq >/dev/null 2>&1 ||
	fail "yq (mikefarah/yq v4) is required but not on PATH"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Green control: the committed config must pass.
if ! bash "$split" parity "$src" >/dev/null 2>&1; then
	fail "parity is red on the UNMUTATED config — fix the config or the gate first"
fi
echo "goreleaser-split-parity-test: OK — parity green on the unmutated config"

# Mutation 1 (the S4-review defect): drop a PINNED target (linux arm64) from
# the config. The gate must fail, naming the dropped target as missing.
yq '(.builds[] | select(.goos[] == "linux") | .goarch) |= map(select(. != "arm64"))' \
	"$src" >"$tmp/drop-arm64.yaml"
if out="$(bash "$split" parity "$tmp/drop-arm64.yaml" 2>&1)"; then
	fail "a dropped pinned target (linux_arm64) passed parity green:
$out"
fi
grep -q "missing: .*linux_arm64" <<<"$out" ||
	fail "parity went red on the dropped target but did not name it as missing:
$out"
echo "goreleaser-split-parity-test: OK — dropping a pinned target fails parity (missing: linux_arm64)"

# Mutation 2: add a target outside the pin. The REVERSE direction must fail,
# naming the extra target.
yq '(.builds[] | select(.goos[] == "linux") | .goarch) |= . + ["s390x"]' \
	"$src" >"$tmp/extra-target.yaml"
if out="$(bash "$split" parity "$tmp/extra-target.yaml" 2>&1)"; then
	fail "a target outside the pin (linux_s390x) passed parity green:
$out"
fi
grep -q "extra: .*linux_s390x" <<<"$out" ||
	fail "parity went red on the extra target but did not name it:
$out"
echo "goreleaser-split-parity-test: OK — a target outside the pin fails parity (extra: linux_s390x)"

echo "goreleaser-split-parity-test: all mutation red-checks passed"
