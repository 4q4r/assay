//go:build !windows

package cli

import (
	"errors"
	"io"
)

// serviceLogSink refuses outside windows: the file log sink is the windows
// service-context feature (§2.2.6 — service stdout goes nowhere there;
// darwin has launchd StandardOutPath redirects and linux has journald).
// The windows service entrypoint never runs on this GOOS — the refusal is
// the loud, honest dead-path contract, never a silent success.
func serviceLogSink(dataDir string) (io.WriteCloser, error) {
	return nil, errors.New("the service file log sink is a windows service-context feature; " +
		"this GOOS logs through its own transport (launchd redirects / journald) — path " + dataDir)
}
