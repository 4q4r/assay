package probe_test

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"public_vpn/internal/checker"
	"public_vpn/internal/model"
	"public_vpn/internal/probe"
	"public_vpn/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPortBand is the DISJOINT temp-instance scan band this smoke boots into
// — MUST match the checker suite's band (instance_internal_test.go): both
// binaries boot through the same StartTempXray scan, and the production
// watch daemon churns the 18xxx band hourly on this box (full -race runs
// used to flake against that live churn — live-ops fix).
const (
	testPortBandMin = 28500
	testPortBandMax = 28799
)

// TestMain pins the smoke's temp instances to the disjoint test band BEFORE
// any test runs: real temp instances must boot OUTSIDE the production 18xxx
// band — the live watch daemon churns it hourly on this box, and full -race
// runs used to flake against that live churn (live-ops fix).
func TestMain(m *testing.M) {
	checker.SetTestPortBand(testPortBandMin, testPortBandMax)
	os.Exit(m.Run())
}

// bootSmokeFamilies covers EVERY rendered protocol family the pool can
// carry (round-7 owner ruling 14b: the smoke is part of the test loop).
// Targets are TEST-NET-1 (RFC 5737 — never routable), so the wave is
// hermetic loopback + guaranteed-dead uplinks: the smoke proves the core
// BOOTS each family's outbound and the probe CLASSIFIES the dead target
// cleanly — the old "unknown whether the tool supports hysteria2" question
// has no successor: the real core is the prober now.
func bootSmokeFamilies() []struct {
	name   string
	scheme string
	params map[string]string
} {
	return []struct {
		name   string
		scheme string
		params map[string]string
	}{
		{"vless-tcp-tls", "vless", map[string]string{"type": "tcp", "security": "tls", "sni": "donor.example", "flow": "xtls-rprx-vision"}},
		{"vmess-ws-tls", "vmess", map[string]string{"type": "ws", "path": "/vm", "host": "vm.example", "security": "tls", "sni": "donor.example"}},
		{"trojan-tcp-tls", "trojan", map[string]string{"type": "tcp", "security": "tls", "sni": "donor.example"}},
		{"ss-tls", "ss", map[string]string{"type": "tcp", "method": "aes-128-gcm", "password": "ss-pw", "security": "tls", "sni": "donor.example"}},
		{"hysteria2-tls", "hysteria2", map[string]string{"sni": "hy.example"}},
	}
}

const bootSmokeXrayBin = "/usr/bin/xray"

// TestBootSmokeEveryProtocolFamily pins, per family: the temp single-node
// instance BOOTS with the family's rendered outbound (the core accepts the
// config), a probe attempt through it against a dead target classifies
// CLEANLY (dial-fail/timeout family — never a crash, never a fake success),
// and the instance closes without leaking.
func TestBootSmokeEveryProtocolFamily(t *testing.T) {
	if _, err := os.Stat(bootSmokeXrayBin); err != nil {
		t.Skipf("xray binary not present at %s", bootSmokeXrayBin)
	}
	for _, fam := range bootSmokeFamilies() {
		t.Run(fam.name, func(t *testing.T) {
			n := model.NewNode("smoke", fam.scheme, "smoke-cred-1", "192.0.2.1", 443, fam.params)
			workDir := t.TempDir()
			factory := checker.NewXrayFactory(bootSmokeXrayBin, workDir, render.Config{})

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			inst, err := factory(ctx, n)
			require.NoError(t, err, "family %s: the core must boot the rendered outbound", fam.name)

			// The smoke boots through the SAME scan as the suite: the port
			// must land in the disjoint test band, never the production
			// 18xxx band the live daemon owns (live-ops fix).
			_, portStr, perr := net.SplitHostPort(inst.Addr())
			require.NoError(t, perr, "family %s", fam.name)
			port, aerr := strconv.Atoi(portStr)
			require.NoError(t, aerr, "family %s", fam.name)
			assert.GreaterOrEqual(t, port, testPortBandMin, "family %s: instance must boot inside the disjoint test band", fam.name)
			assert.LessOrEqual(t, port, testPortBandMax, "family %s: instance must boot inside the disjoint test band", fam.name)

			probeFactory := probe.Factory(func(_ context.Context, _ *model.Node) (probe.SocksInstance, error) {
				return inst, nil
			})
			results, err := probe.Run(ctx, []*model.Node{n}, probeFactory, probe.Options{
				Timeout:  3 * time.Second,
				Attempts: 1,
				URL:      "https://192.0.2.1/cdn-cgi/trace",
				Threads:  1,
				Progress: nil,
			}, "")
			require.NoError(t, err, "family %s: the probe attempt must classify, never crash", fam.name)
			require.Len(t, results, 1)
			r := results[0]
			assert.False(t, r.Alive, "family %s: a TEST-NET target is never alive", fam.name)
			assert.Equal(t, "failed", r.Status, "family %s: dead target = failed wave", fam.name)
			assert.NotEmpty(t, r.FailureKind, "family %s: the failure class is recorded", fam.name)
			assert.Contains(t, []string{"dial-fail", "timeout", "read-timeout", "error"},
				r.FailureKind, "family %s: the class is an honest transport class", fam.name)

			require.NoError(t, inst.Close(), "family %s: close is clean", fam.name)
		})
	}
}
