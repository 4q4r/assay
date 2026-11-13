package probe_test

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"assay/internal/checker"
	"assay/internal/model"
	"assay/internal/probe"
	"assay/internal/render"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPortBand is this smoke's OWN temp-instance scan band — DISJOINT from
// the checker suite's 28500-28799 on purpose. The old "MUST match the
// checker band" sharing is exactly what flaked the checker boot-death tests:
// under a full -race run both binaries are concurrent PROCESSES, this smoke
// boots a REAL xray whose bind lands ~100ms after spawn, and the checker's
// boot-death children BIND NOTHING — so the smoke's delayed bind answered
// the death test's readiness dial and a startup exit was reported as a
// successful boot (diag-proved: the failing run's ss carried
// users:(("xray",...fd=3)) on 127.0.0.1:28500 while the checker.test child
// was an exiting fake). Concurrent processes must not share a boot band.
// Still below the kernel ephemeral range (32768+) and clear of the
// production 18xxx band the live daemon churns (live-ops fix, kept).
const (
	testPortBandMin = 29500
	testPortBandMax = 29799
)

// TestMain pins the smoke's temp instances to its own disjoint band BEFORE
// any test runs: real temp instances must boot OUTSIDE the production 18xxx
// band (the live watch daemon churns it hourly) and OUTSIDE every other
// test binary's band — cross-process band sharing is the false-ready class.
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
		off := false // pre-filter off: TEST-NET targets are dead by design (see Options comment below)
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
				// The smoke pins BOOT + CLASSIFY on TEST-NET targets that are
				// unreachable BY DESIGN — the wave-1 TCP pre-filter would
				// drop them before any boot (its verdict path is covered by
				// the prefilter tests), so it is explicitly off here.
				TCPPrefilter: &off,
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
