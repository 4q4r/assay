package config

// The [probe].instance_port_band seam (deferred-minors wave): the temp
// probe-instance scan band is config-injectable so the live daemon's waves
// and a locally-run CLI test batch can take DISJOINT bands on the same
// machine — the shared 18xxx default is exactly the cross-process
// contention class the "no free port in [18500,18999]" journal failures
// exposed. Structural validation only (the owner's no-floor/ceiling
// ruling): the grammar is checked, values are not recommended.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePortBand(t *testing.T) {
	t.Run("production default parses verbatim", func(t *testing.T) {
		minPort, maxPort, err := ParsePortBand(DefaultProbeInstancePortBand)
		require.NoError(t, err)
		assert.Equal(t, 18500, minPort)
		assert.Equal(t, 18999, maxPort)
	})
	t.Run("single-port band is structurally valid", func(t *testing.T) {
		minPort, maxPort, err := ParsePortBand("28000-28000")
		require.NoError(t, err)
		assert.Equal(t, 28000, minPort)
		assert.Equal(t, 28000, maxPort)
	})
	for _, bad := range []string{
		"",
		"18500",         // missing separator
		"18500-",        // missing max
		"-18999",        // missing min
		"a-b",           // non-numeric
		"18999-18500",   // min above max
		"0-100",         // port 0 is never a bindable band
		"1-65536",       // beyond the port space
		"18500-18999-1", // more than one separator
	} {
		_, _, err := ParsePortBand(bad)
		require.Error(t, err, "band %q must fail loud, not guess", bad)
	}
}

func TestApplyProbeDefaultsInstancePortBand(t *testing.T) {
	var p ProbeConfig
	applyProbeDefaults(&p)
	assert.Equal(t, DefaultProbeInstancePortBand, p.InstancePortBand)
	assert.Equal(t, "18500-18999", p.InstancePortBand, "the default ships verbatim — the production scan band is unchanged")

	p = ProbeConfig{InstancePortBand: "28000-28499"}
	applyProbeDefaults(&p)
	assert.Equal(t, "28000-28499", p.InstancePortBand, "an explicit band survives defaults untouched")
}

func TestValidateProbeInstancePortBand(t *testing.T) {
	err := validateProbe(ProbeConfig{InstancePortBand: "18999-18500"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "probe.instance_port_band")

	assert.NoError(t, validateProbe(ProbeConfig{InstancePortBand: "28000-28499"}))
}
