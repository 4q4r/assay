package cli

import (
	"testing"

	"public_vpn/internal/config"

	"github.com/stretchr/testify/assert"
)

// TestProbeOptionsWiresConfig pins the config→Options translation: max_passed
// and the check-preset/speedtest precedence must reach the probe wave
// (review finding 7 — max_passed was a lying knob pre-fix, declared in TOML
// but never copied into probe.Options).
func TestProbeOptionsWiresConfig(t *testing.T) {
	cfg := &config.Config{
		Probe: config.ProbeConfig{
			MaxPassed:           7,
			Threads:             11,
			CheckPreset:         "global",
			Speedtest:           true,
			URLSuccessThreshold: 0.9,
		},
	}

	opts := probeOptions(cfg, false, "")
	assert.Equal(t, 7, opts.MaxPassed, "probe.max_passed must reach the wave")
	assert.Equal(t, 11, opts.Threads)
	assert.Equal(t, "global", opts.CheckPreset, "config preset used when no flag")
	assert.True(t, opts.Speedtest, "config speedtest=true holds without a flag")
	assert.InDelta(t, 0.9, opts.URLSuccessThreshold, 0.0001)

	cfg.Probe.CheckPreset = ""
	opts = probeOptions(cfg, false, "cloudflare")
	assert.Equal(t, "cloudflare", opts.CheckPreset, "flag preset overrides config")
}
