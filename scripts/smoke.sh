#!/bin/sh
# Release smoke probe (R3): prove a built assay binary loads and runs on
# its target ABI and prints a stamped version line, exiting 0.
#
# Invoked per build target as a goreleaser post-build hook
# (.goreleaser.yaml builds.hooks.post, through `bash` — see the config
# comment), so any failure aborts the release BEFORE publish.
#
# Execution strategy — DIRECT exec first, per OS:
#
#   linux:   native targets (amd64 on the amd64 runner) need no emulator;
#            foreign targets run transparently once release.yml's
#            qemu-user-binfmt has registered the binfmt_misc handler for
#            their arch. Only when direct exec fails with a "never ran"
#            signal (bash 126 exec-format/permission or 127 not-found;
#            dash ENOEXEC script-fallback = exit 2 with empty stdout) do we
#            fall back to the explicit qemu interpreter from the qemu-user
#            package. A probe that actually RAN and exited nonzero is a
#            genuine failure: it is never retried under the emulator and
#            aborts the smoke (and the release) with that exit code.
#
#   darwin:  direct exec only — arm64 binaries run natively on the arm64
#            runner; amd64 binaries run transparently under Rosetta 2 once
#            provisioned (release.yml installs it and hard-probes
#            `arch -x86_64`). With Rosetta present the direct attempt just
#            works; without it the direct attempt is refused (never-ran)
#            and the `arch -x86_64` fallback fails loud — the release dies
#            right here, exactly as R3 demands (never a silent skip). No
#            emulator fallback exists for arm64-on-intel or vice versa.
#
#   windows: direct exec only — amd64 natively on the x64 runner, 386 via
#            WOW64 (x86-on-x64), arm64 natively on the windows-11-arm
#            runner. Windows has no user-mode cross-arch emulator we could
#            invoke, so a never-ran signal on a windows target is terminal.
#
# Delegation escape hatch (windows/arm64 ONLY, R3-guarded structurally): the
# x64 windows runner cannot execute arm64 binaries at all, so the
# release-windows job sets SMOKE_DELEGATED_TARGETS="windows_arm64" and the
# matching target exits 0 here with a loud DELEGATED line. This is NOT a
# silent skip: publish is gated by `needs:` on the release-windows-arm64
# job, which either smokes windows/arm64 natively or (runner unavailability
# only) ships the smoke-gap artifact that the release body then warns about
# loudly.
#
# Usage: smoke.sh <target> <binary-path>
#   e.g. smoke.sh linux_arm_7 dist/assay_linux_arm_7/assay
#        smoke.sh windows_amd64_v1 'dist\assay_windows_amd64_v1\assay.exe'
set -eu

target="${1:-}"
bin="${2:-}"

if [ -z "$target" ] || [ -z "$bin" ]; then
	echo "usage: $0 <target> <binary-path>" >&2
	exit 1
fi

# goreleaser on windows hands us backslash paths (dist\...\assay.exe).
# Forward slashes are accepted by every exec path we use, including
# git-bash on windows; normalize so the -f check and the execs below are
# OS-uniform. (tr keeps this script POSIX-sh; the HOOK invokes it via bash
# only because windows cannot shebang-exec a .sh directly.)
# shellcheck disable=SC1003  # '\'' is the POSIX way to put a quote in a single-quoted string
bin=$(printf '%s' "$bin" | tr '\\' '/')

if [ ! -f "$bin" ]; then
	echo "smoke: binary not found: $bin" >&2
	exit 1
fi

# Delegation check first: a delegated target is owned by another REQUIRED
# job of the same release (see the header) — say so loudly and move on.
for prefix in ${SMOKE_DELEGATED_TARGETS:-}; do
	case "$target" in
	"$prefix"*)
		echo "smoke [$target]: DELEGATED — native smoke owned by another required release job (publish gates on it)"
		exit 0
		;;
	esac
done

case "$target" in
# Target names observed from goreleaser v2.14+ (`.Target`): the amd64 /
# arm64 / 386 variants carry a microarch-level suffix (linux_amd64_v1,
# linux_arm64_v8.0, linux_386_sse2), so those branches match by prefix —
# the emulator/runner choice is invariant across those levels; arm keeps an
# exact match because the goarm suffix comes from our own config.
#
# Interpreter names = the qemu-user package's binary names on
# ubuntu-26.04 (resolute): /usr/bin/qemu-aarch64, /usr/bin/qemu-arm,
# /usr/bin/qemu-i386. The legacy "-static" names of the old
# qemu-user-static package do not exist on resolute (qemu-user-static is
# a virtual package there) — invoking them was the v0.1.0 exit-127
# failure.
#
# $runner values may be MULTI-WORD ("arch -x86_64"): the unquoted
# expansion below word-splits on purpose and every word is a fixed
# literal, so the split is safe.
linux_amd64*) runner="" ;;
linux_arm64*) runner="qemu-aarch64" ;;
linux_arm_7) runner="qemu-arm" ;;
linux_386*) runner="qemu-i386" ;;
darwin_arm64*) runner="" ;;
darwin_amd64*) runner="arch -x86_64" ;;
windows_amd64* | windows_386* | windows_arm64*) runner="" ;;
*)
	echo "smoke: unexpected target '$target'" >&2
	exit 1
	;;
esac

# Attempt 1: DIRECT exec. stderr stays attached so the CI log keeps the
# exact kernel/shell diagnosis for any failure. set -eu makes a nonzero
# FINAL probe exit (missing qemu, broken binary, bad flag) abort here; the
# case below additionally rejects an empty/garbled version line so a
# silent-print binary cannot pass.
set +e
out=$("$bin" -v)
direct_rc=$?
set -e

# Did the direct attempt actually run the binary, or did the kernel or
# the shell refuse it? "Never ran" signals only:
#   126/127 — bash's exec-format ("cannot execute binary file"),
#             permission, or not-found diagnostics.
#   2 with EMPTY stdout — dash has no binary-magic guard: on ENOEXEC it
#             re-parses a foreign binary as a shell script and dies with a
#             syntax error before executing anything. A binary that ran
#             and really exited 2 WITH output is NOT routed to fallback.
never_ran=0
case "$direct_rc" in
126 | 127)
	never_ran=1
	;;
2)
	if [ -z "$out" ]; then
		never_ran=1
	fi
	;;
esac

if [ "$never_ran" -eq 0 ]; then
	# The probe genuinely ran directly: rc 0 falls through to the
	# version-line check below; any other rc is a real probe failure
	# with the real exit code preserved.
	if [ "$direct_rc" -ne 0 ]; then
		echo "smoke [$target]: probe exited $direct_rc" >&2
		exit "$direct_rc"
	fi
elif [ -z "$runner" ]; then
	# Native target the kernel refused to run (corrupt binary et al.): no
	# emulator fallback exists or applies.
	echo "smoke [$target]: native exec failed (rc=$direct_rc)" >&2
	exit "$direct_rc"
else
	# Attempt 2: explicit runner. $runner is UNQUOTED on purpose: it is
	# either "" or fixed literal words (one emulator name, or
	# "arch -x86_64"); POSIX word-splitting is safe here. Any failure —
	# e.g. the emulator not installed, Rosetta absent, exit 127 — aborts
	# via set -e and takes the release with it, exactly as before.
	# shellcheck disable=SC2086  # runner is "" or fixed literal words
	out=$($runner "$bin" -v)
fi

echo "smoke [$target]: $out"
case "$out" in
assay\ *) ;;
*)
	echo "smoke: version output does not start with 'assay ': '$out'" >&2
	exit 1
	;;
esac
