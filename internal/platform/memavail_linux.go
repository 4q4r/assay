//go:build linux

package platform

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// meminfoPath is the linux host-memory source. A var only so tests can
// repoint it in-process if a future fixture needs the full read path.
var meminfoPath = "/proc/meminfo"

// MemAvailable returns the kernel's MemAvailable estimate in bytes — the
// amount of memory the kernel reports as allocatable WITHOUT pushing the
// host into swap (reclaimable caches included; the honest signal for "can
// this process afford a heavy allocation churn phase right now").
// /proc/meminfo reports the value in kB units; the kB column is binary
// kibibytes (Linux Documentation/filesystems/proc.rst), so the byte value
// is kB × 1024. A missing or unparseable MemAvailable line is a loud error
// — the memory gate fail-opens on read errors, and a silent zero would
// hold every wave forever.
func MemAvailable() (uint64, error) {
	data, err := os.ReadFile(meminfoPath)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", meminfoPath, err)
	}
	return parseMemAvailable(string(data))
}

// parseMemAvailable extracts MemAvailable from /proc/meminfo content:
// the "MemAvailable:" line's kB value × 1024. Every other line is noise
// (MemFree/MemTotal/Cached and friends).
func parseMemAvailable(proc string) (uint64, error) {
	for line := range strings.SplitSeq(proc, "\n") {
		value, ok := strings.CutPrefix(line, "MemAvailable:")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			break
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse MemAvailable from %s: %w", meminfoPath, err)
		}
		return kb * 1024, nil
	}
	return 0, fmt.Errorf("parse %s: no MemAvailable line (kernel too old or content unexpected)", meminfoPath)
}
