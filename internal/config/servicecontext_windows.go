//go:build windows

package config

import (
	"sync"

	"golang.org/x/sys/windows/svc"
)

// windowsServiceContextDetected is the production detection: the SAME
// svc.IsWindowsService() process-token check the service entrypoint gates
// on (cmd/assay svc_windows.go). Cached once per process — a process never
// switches between the SCM context and an interactive session.
var windowsServiceContextDetected = sync.OnceValues(func() (bool, error) {
	return svc.IsWindowsService()
})

// detectWindowsServiceContext reports whether this process is an SCM-started
// service (LocalSystem or a configured service account): a token-query error
// reads as "not a service" only for the RESOLUTION guard — the entrypoint's
// own detection keeps its separate fail-loud handling.
func detectWindowsServiceContext() bool {
	inSvc, err := windowsServiceContextDetected()
	return err == nil && inSvc
}
