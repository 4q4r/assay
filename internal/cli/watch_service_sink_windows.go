//go:build windows

package cli

import (
	"io"
	"path/filepath"

	"assay/internal/platform"
)

// serviceLogSink opens the windows service-context file log sink (§2.2.6):
// a service's stdout goes nowhere, so the daemon logs to
// <data>/logs/watch.log — the launchd StandardOutPath contract's windows
// mirror (§4.2 "Service logs" row).
func serviceLogSink(dataDir string) (io.WriteCloser, error) {
	return platform.NewFileLogSink(filepath.Join(dataDir, "logs", "watch.log"))
}
