#!/bin/sh
# Release smoke probe (R3): prove a built assay binary loads and runs on
# its target ABI and prints a stamped version line, exiting 0.
#
# Invoked per build target as a goreleaser post-build hook
# (.goreleaser.yaml builds.hooks.post), so any failure aborts the release
# BEFORE publish. Cross-arch targets run under qemu-user-static
# (installed by release.yml); amd64 runs natively on the ubuntu runner.
#
# Usage: smoke.sh <target> <binary-path>
#   e.g. smoke.sh linux_arm_7 dist/assay_linux_arm_7/assay
set -eu

target="${1:-}"
bin="${2:-}"

if [ -z "$target" ] || [ -z "$bin" ]; then
	echo "usage: $0 <target> <binary-path>" >&2
	exit 1
fi
if [ ! -f "$bin" ]; then
	echo "smoke: binary not found: $bin" >&2
	exit 1
fi

case "$target" in
# Target names observed from goreleaser v2.14 (`.Target`): the amd64 /
# arm64 / 386 variants carry a microarch-level suffix (linux_amd64_v1,
# linux_arm64_v8.0, linux_386_sse2), so those branches match by prefix —
# the qemu runner choice is invariant across those levels; arm keeps an
# exact match because the goarm suffix comes from our own config.
linux_amd64*) runner="" ;;
linux_arm64*) runner="qemu-aarch64-static" ;;
linux_arm_7) runner="qemu-arm-static" ;;
linux_386*) runner="qemu-i386-static" ;;
*)
	echo "smoke: unexpected target '$target'" >&2
	exit 1
	;;
esac

# set -eu makes a nonzero probe exit (missing qemu, broken ELF, bad flag)
# abort here; the case below additionally rejects an empty/garbled
# version line so a silent-print binary cannot pass.
# $runner is UNQUOTED on purpose: empty = native exec, otherwise exactly
# one word (the qemu interpreter name); POSIX word-splitting is safe here.
out=$($runner "$bin" -v)
echo "smoke [$target]: $out"
case "$out" in
assay\ *) ;;
*)
	echo "smoke: version output does not start with 'assay ': '$out'" >&2
	exit 1
	;;
esac
