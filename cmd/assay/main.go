// Command assay is the assay pipeline CLI (D11: Go single binary).
//
// Windows service gate (plan §2.2.1): when the SCM started this process
// through the service dispatcher, serviceEntrypoint() handles the whole
// run (svc.Run) and main exits with its code; every other invocation —
// and every non-windows GOOS (svc_other.go) — falls through to the plain
// CLI.
package main

import (
	"os"

	"assay/internal/cli"
)

func main() {
	if handled, code := serviceEntrypoint(); handled {
		os.Exit(code)
	}
	if err := cli.New().Execute(); err != nil {
		os.Exit(1)
	}
}
