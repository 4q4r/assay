//go:build darwin

package platform

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// vmStatPath is macOS's fixed-location VM statistics reporter. A var so a
// test can repoint it at a fixture binary if one ever needs the full read
// path (the parser itself is covered by the fixture tests below).
var vmStatPath = "/usr/bin/vm_stat"

// MemAvailable returns a darwin APPROXIMATION of the linux MemAvailable
// semantic: (Pages free + Pages speculative) × page size, read from the
// vm_stat tool's text report. Those two pools are the immediately
// reclaimable pages macOS hands out without paging — the closest native
// analog of the kernel's MemAvailable estimate. UNITS AND HONEST BOUNDS:
// vm_stat reports page COUNTS (dimensionless), scaled by the "page size of
// N bytes" header its own output declares (4096 on Intel, 16384 on Apple
// Silicon — parsed, never assumed); darwin has no single kernel-computed
// "available" figure, so purgeable/compressed pages are NOT counted — the
// approximation errs on the conservative side (reports LESS available than
// the kernel would), which for a gate holding heavy allocation phases is
// the safe direction: it may hold a little longer than strictly necessary,
// never wave into a thrashing box under a too-optimistic reading. A missing
// or truncated report is a loud error — the gate fail-opens on read errors,
// and a silent zero would hold every wave forever.
func MemAvailable() (uint64, error) {
	out, err := exec.Command(vmStatPath).Output()
	if err != nil {
		return 0, fmt.Errorf("run %s: %w", vmStatPath, err)
	}
	return parseVMStat(string(out))
}

// parseVMStat parses vm_stat's text report: the "(page size of N bytes)"
// header plus the "Pages free:" and "Pages speculative:" lines (integer
// page counts, period-terminated).
func parseVMStat(report string) (uint64, error) {
	const (
		freePrefix        = "Pages free:"
		speculativePrefix = "Pages speculative:"
		pageSizePrefix    = "(page size of "
	)
	pageSize := uint64(0)
	free := uint64(0)
	speculative := uint64(0)
	haveFree := false
	haveSpeculative := false
	for line := range strings.SplitSeq(report, "\n") {
		if value, ok := cutPageCount(line, freePrefix); ok {
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse vm_stat %q: %w", freePrefix, err)
			}
			free, haveFree = v, true
			continue
		}
		if value, ok := cutPageCount(line, speculativePrefix); ok {
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse vm_stat %q: %w", speculativePrefix, err)
			}
			speculative, haveSpeculative = v, true
			continue
		}
		if idx := strings.Index(line, pageSizePrefix); idx >= 0 {
			rest := line[idx+len(pageSizePrefix):]
			end := strings.IndexByte(rest, ' ')
			if end < 0 {
				end = len(rest)
			}
			v, err := strconv.ParseUint(strings.TrimSpace(rest[:end]), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse vm_stat page size: %w", err)
			}
			pageSize = v
		}
	}
	if pageSize == 0 {
		return 0, fmt.Errorf("parse vm_stat: no page-size header")
	}
	if !haveFree || !haveSpeculative {
		return 0, fmt.Errorf("parse vm_stat: missing %q or %q line", freePrefix, speculativePrefix)
	}
	return (free + speculative) * pageSize, nil
}

// cutPageCount extracts the integer page count a "Pages …:" line carries,
// stripping vm_stat's trailing period and any whitespace.
func cutPageCount(line, prefix string) (string, bool) {
	value, ok := strings.CutPrefix(line, prefix)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, ".")
	return strings.TrimSpace(value), true
}
