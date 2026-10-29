package config_test

import (
	"testing"

	"public_vpn/internal/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Round-7 item 6 — the plugin circuit breaker knob. Owner spec: «автоотклю-
// чение неотвечающих плагинов, 5 ошибок по дефолту отключают его». Unset →
// DefaultMaxConsecutiveFailures (5); an explicit 0 = unlimited (the breaker
// is OFF — same owner no-floor/ceiling ruling class as run_timeout "0s");
// negative is structurally invalid.
func TestMaxConsecutiveFailuresConfigParsesAndDefaults(t *testing.T) {
	cfg := load(t, w6Base+"")
	require.NotNil(t, cfg.Plugins.MaxConsecutiveFailures, "the knob resolves to a value even when unset")
	assert.Equal(t, config.DefaultMaxConsecutiveFailures, *cfg.Plugins.MaxConsecutiveFailures,
		"unset max_consecutive_failures = the 5-failure default")

	cfg = load(t, w6Base+"[plugins]\nmax_consecutive_failures = 3\n")
	require.NotNil(t, cfg.Plugins.MaxConsecutiveFailures)
	assert.Equal(t, 3, *cfg.Plugins.MaxConsecutiveFailures, "explicit value passes through")

	cfg = load(t, w6Base+"[plugins]\nmax_consecutive_failures = 0\n")
	require.NotNil(t, cfg.Plugins.MaxConsecutiveFailures)
	assert.Equal(t, 0, *cfg.Plugins.MaxConsecutiveFailures,
		"explicit 0 = unlimited (breaker off — owner no-floor ruling)")
}

func TestMaxConsecutiveFailuresNegativeIsLoud(t *testing.T) {
	_, err := config.Load(writeCfg(t, w6Base+"[plugins]\nmax_consecutive_failures = -1\n"))
	require.Error(t, err, "a negative breaker limit is structurally invalid")
	assert.Contains(t, err.Error(), "plugins.max_consecutive_failures")
}
