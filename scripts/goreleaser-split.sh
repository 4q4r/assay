#!/usr/bin/env bash
# goreleaser-split.sh — per-OS partial goreleaser config generation.
#
# goreleaser OSS cannot split one release across runners (split & merge is
# Pro-only, crossplatform-plan.md §0), so the release pipeline splits ITSELF:
# this script GENERATES a per-OS partial config from the single source of
# truth (.goreleaser.yaml) by filtering the builds list, and release.yml runs
# one partial per native runner with --skip=publish. The final publish job
# assembles the artifacts and is gated by `needs:` on every partial job, so
# R3 (a failed target aborts the release BEFORE publish) is preserved.
#
# yq requirement: mikefarah/yq v4 (single static Go binary). CI pins the
# version in the workflow setup step (YQ_VERSION env; currently v4.54.3 —
# keep in sync with the local-install line below). Local install:
#
#   curl -fsSL -o yq \
#     https://github.com/mikefarah/yq/releases/download/v4.54.3/yq_linux_amd64
#   chmod +x yq   # (macos: yq_darwin_arm64.tar.gz; windows: yq_windows_amd64.exe)
#
# Usage:
#   goreleaser-split.sh generate <goos> <out-file> [source-config]
#       Write the partial config carrying ONLY the builds whose goos list
#       contains <goos>. Everything else (before/checksum/changelog/release/
#       archives) is copied verbatim — no hand-maintained duplicates.
#   goreleaser-split.sh generate-all <out-dir> [source-config]
#       Write <out-dir>/<goos>.yaml for every OS in OS_LIST.
#   goreleaser-split.sh parity [source-config]
#       The parity gate (runs locally AND as a required CI step):
#         1. the full-matrix targets == the pinned release matrix (§4.4),
#         2. the union of the generated partials' targets == the full matrix,
#         3. every partial carries ONLY its own OS's targets (no bleed).
set -euo pipefail

DEFAULT_CONFIG=".goreleaser.yaml"
OS_LIST="linux darwin windows"

# The pinned release matrix (plan §4.4): linux amd64/arm64/386/armv7,
# darwin amd64/arm64, windows amd64/arm64/386. NO windows/arm7 — upstream
# Xray-core ships no arm32 windows asset, so the managed core is impossible
# there (plan §2.2.13/§4.4). Canonical target strings are goos_goarch[_goarm]
# — the BASE target without goreleaser's microarch-level suffixes; both
# comparison sides are extracted from config files, so the convention is
# self-consistent.
EXPECTED_MATRIX="darwin_amd64 darwin_arm64 linux_386 linux_amd64 linux_arm_7 windows_386 windows_amd64 windows_arm64"

die() {
	echo "goreleaser-split: $1" >&2
	exit 1
}

need_yq() {
	if ! command -v yq >/dev/null 2>&1; then
		die "yq (mikefarah/yq v4) is required but not on PATH — see the install command in this script's header"
	fi
}

check_os_arg() {
	case "$1" in
	linux | darwin | windows) ;;
	*)
		die "unknown goos '$1' (expected one of: $OS_LIST)"
		;;
	esac
}

# config_targets <file> — print the canonical target set (one per line) of
# the builds list: the goos x goarch cross product, with goarm values applied
# only to the arm arch (goreleaser semantics: goarm is ignored for other
# arches).
config_targets() {
	local file="$1"
	local builds goos_list goarch_list goarm_list os_ arch armv
	builds=$(yq '.builds | length' "$file")
	if [ "$builds" -eq 0 ]; then
		die "$file has zero builds entries"
	fi
	for ((i = 0; i < builds; i++)); do
		goos_list=$(yq ".builds[$i].goos[]" "$file" | tr '\n' ' ')
		goarch_list=$(yq ".builds[$i].goarch[]" "$file" | tr '\n' ' ')
		goarm_list=$(yq ".builds[$i].goarm // [] | .[]" "$file" | tr '\n' ' ')
		for os_ in $goos_list; do
			for arch in $goarch_list; do
				if [ "$arch" = "arm" ] && [ -n "$goarm_list" ]; then
					for armv in $goarm_list; do
						echo "${os_}_${arch}_${armv}"
					done
				else
					echo "${os_}_${arch}"
				fi
			done
		done
	done | LC_ALL=C sort
}

# generate_partial <goos> <out-file> <source-config>
generate_partial() {
	local os_="$1" out="$2" src="$3"
	check_os_arg "$os_"
	# The OS value is whitelisted above, so the interpolation below cannot
	# inject into the yq expression.
	yq ".builds |= map(select(.goos[] == \"$os_\"))" "$src" >"$out"
	local count
	count=$(yq '.builds | length' "$out")
	if [ "$count" -eq 0 ]; then
		die "partial for '$os_' ($out) has zero builds — the source config carries no such goos"
	fi
}

cmd_generate() {
	local os_="$1" out="$2" src="${3:-$DEFAULT_CONFIG}"
	need_yq
	[ -f "$src" ] || die "source config not found: $src"
	mkdir -p "$(dirname "$out")"
	generate_partial "$os_" "$out" "$src"
	echo "goreleaser-split: wrote $out ($(yq '.builds | length' "$out") builds, $(config_targets "$out" | tr '\n' ' '))"
}

cmd_generate_all() {
	local outdir="$1" src="${2:-$DEFAULT_CONFIG}"
	need_yq
	[ -f "$src" ] || die "source config not found: $src"
	mkdir -p "$outdir"
	local os_
	for os_ in $OS_LIST; do
		generate_partial "$os_" "$outdir/$os_.yaml" "$src"
		echo "goreleaser-split: wrote $outdir/$os_.yaml"
	done
}

cmd_parity() {
	local src="${1:-$DEFAULT_CONFIG}"
	need_yq
	[ -f "$src" ] || die "source config not found: $src"

	# full_targets/union_targets/tmp are deliberately GLOBAL: the EXIT trap
	# (set below) fires after this function returns, where locals are gone —
	# referencing a local there is an unbound-variable error under set -u.
	local full_targets missing_in_full missing_in_union os_ partial_targets bleed
	full_targets=$(config_targets "$src")
	union_targets=""

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	for os_ in $OS_LIST; do
		generate_partial "$os_" "$tmp/$os_.yaml" "$src"
		partial_targets=$(config_targets "$tmp/$os_.yaml")
		# Constraint 3: a partial must carry ONLY its own OS.
		bleed=$(echo "$partial_targets" | grep -v "^${os_}_" || true)
		if [ -n "$bleed" ]; then
			die "partial '$os_.yaml' carries foreign targets: $(echo "$bleed" | tr '\n' ' ')"
		fi
		union_targets=$(printf '%s\n%s\n' "${union_targets:-}" "$partial_targets" |
			grep -v '^$' | LC_ALL=C sort -u)
	done

	# Constraint 1: full matrix == pinned release matrix.
	missing_in_full=$(comm -23 <(echo "$EXPECTED_MATRIX" | tr ' ' '\n' | LC_ALL=C sort) \
		<(echo "$full_targets"))
	if [ -n "$missing_in_full" ]; then
		die "full-matrix targets missing from the pinned release matrix (plan §4.4):
  missing: $(echo "$missing_in_full" | tr '\n' ' ')
  full config: $(echo "$full_targets" | tr '\n' ' ')
  expected:    $EXPECTED_MATRIX"
	fi

	# Constraint 2: union of partials == full matrix (both directions).
	missing_in_union=$(comm -23 <(echo "$full_targets") <(echo "$union_targets"))
	if [ -n "$missing_in_union" ]; then
		die "targets present in the full config but NOT covered by any per-OS partial:
  uncovered: $(echo "$missing_in_union" | tr '\n' ' ')
  full:   $(echo "$full_targets" | tr '\n' ' ')
  union:  $(echo "$union_targets" | tr '\n' ' ')"
	fi
	missing_in_full=$(comm -13 <(echo "$full_targets") <(echo "$union_targets"))
	if [ -n "$missing_in_full" ]; then
		die "partial union covers targets the full config does not declare (drift):
  extra:  $(echo "$missing_in_full" | tr '\n' ' ')
  full:   $(echo "$full_targets" | tr '\n' ' ')
  union:  $(echo "$union_targets" | tr '\n' ' ')"
	fi

	echo "goreleaser-split parity: OK — 9 targets pinned, union of partials == full matrix"
	echo "  targets: $(echo "$full_targets" | tr '\n' ' ')"
}

case "${1:-}" in
generate)
	[ $# -ge 3 ] || die "usage: $0 generate <goos> <out-file> [source-config]"
	cmd_generate "$2" "$3" "${4:-}"
	;;
generate-all)
	[ $# -ge 2 ] || die "usage: $0 generate-all <out-dir> [source-config]"
	cmd_generate_all "$2" "${3:-}"
	;;
parity)
	cmd_parity "${2:-}"
	;;
*)
	die "usage: $0 {generate <goos> <out-file> [src] | generate-all <out-dir> [src] | parity [src]}"
	;;
esac
