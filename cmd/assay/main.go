// Command assay is the assay pipeline CLI (D11: Go single binary).
package main

import (
	"os"

	"assay/internal/cli"
)

func main() {
	if err := cli.New().Execute(); err != nil {
		os.Exit(1)
	}
}
