// Command publicvpn is the public_vpn pipeline CLI (D11: Go single binary).
package main

import (
	"os"

	"public_vpn/internal/cli"
)

func main() {
	if err := cli.New().Execute(); err != nil {
		os.Exit(1)
	}
}
