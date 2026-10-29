// socksport.go resolves the health check's socks port from the rendered
// config itself: the port definition lives in the owner's template (single
// source of truth — no duplicate knob), and the health check must probe
// exactly the listener the client is about to open.

package cli

import (
	"encoding/json"
	"os"
	"strconv"
)

// extractSocksPort returns the port of the FIRST socks inbound in the
// rendered config; 0 when the config carries no parseable socks inbound
// (numeric or string form). A 0 is not an error — the health check degrades
// to the unit-state leg and its verdict says the port probe was skipped.
func extractSocksPort(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var doc struct {
		Inbounds []struct {
			Protocol string `json:"protocol"`
			Port     any    `json:"port"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return 0
	}
	for _, in := range doc.Inbounds {
		if in.Protocol != "socks" {
			continue
		}
		switch p := in.Port.(type) {
		case float64:
			return int(p)
		case string:
			if n, err := strconv.Atoi(p); err == nil {
				return n
			}
		}
		return 0 // a socks inbound whose port is not parseable — say 0, probe nothing
	}
	return 0
}
