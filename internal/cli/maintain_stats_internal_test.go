package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"assay/internal/config"
	"assay/internal/model"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// W7 item 9: the stats stage's error classes.
//
//   - INFO  — the first-run shapes (target lacks the rendered api/stats
//     shape, or the loopback endpoint refuses connections): the wave prints
//     an INFO line and continues; the exit status is unaffected; xray is
//     never exec'd.
//   - WARNING — the endpoint is reachable but the poll fails at the
//     protocol level (today's behavior, preserved).
//   - LOUD — a fold/write failure into the geo-base fails the wave: traffic
//     data loss is never silent (this also retires the old behavior where
//     ANY stats-stage error was printed as "stats poll unavailable",
//     masking write failures).
//
// Every pin is hermetic: a fake target file, a real (bound or closed)
// loopback port, and a fake xray script that must never be exec'd on the
// INFO arms. No real systemctl, no real xray.

// statsStageCfg builds a config whose DataDir/target/port are all under the
// test's control, plus a sentinel xray script: every exec appends to
// execMarker, so the INFO arms can prove xray was never launched.
func statsStageCfg(t *testing.T, dir string, port int) (*config.Config, string) {
	t.Helper()
	bin := filepath.Join(dir, "sentinel-xray.sh")
	body := "#!/bin/sh\necho executed >> " + filepath.Join(dir, "xray-executed.marker") + "\nexit 0\n"
	require.NoError(t, os.WriteFile(bin, []byte(body), 0o755))
	cfg := &config.Config{
		DataDir: dir,
		Core: config.CoreConfig{
			XrayBin:   bin,
			APIPort:   port,
			SocksPort: port + 1,
			HTTPPort:  port + 2,
		},
	}
	return cfg, filepath.Join(dir, "xray-executed.marker")
}

// writeTarget renders a target file with (shaped) or without (plain) the
// api/stats block the renderer emits.
func writeTarget(t *testing.T, path string, shaped bool, port int) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750), "the rendered dir must exist for the own live path")
	var body string
	if shaped {
		body = fmt.Sprintf(`{
  "api": {"tag": "api", "services": ["StatsService"]},
  "inbounds": [
    {"tag": "api-in", "listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door"}
  ],
  "stats": {},
  "policy": {"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}}
}`, port)
	} else {
		body = `{"inbounds": [], "outbounds": []}`
	}
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

// closedLoopbackPort returns a loopback address guaranteed to refuse
// connections: bind, note the port, close.
func closedLoopbackPort(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// noopStage is a silent stand-in for the non-stats wave stages.
func noopStage(name string, order *[]string) func(*cobra.Command, *config.Config) error {
	return func(*cobra.Command, *config.Config) error {
		*order = append(*order, name)
		return nil
	}
}

func statsOnlyStages(order *[]string) *maintainStages {
	return &maintainStages{
		fetch:    noopStage("fetch", order),
		parse:    noopStage("parse", order),
		filter:   noopStage("filter", order),
		probe:    noopStage("probe", order),
		stats:    runStatsStage,
		prune:    noopStage("prune", order),
		selectS:  noopStage("select", order),
		render:   noopStage("render", order),
		activate: noopStage("activate", order),
	}
}

func TestStatsFirstRunTargetLacksAPIShapeIsINFO(t *testing.T) {
	dir := t.TempDir()
	port := 15491
	cfg, marker := statsStageCfg(t, dir, port)
	writeTarget(t, ownLivePath(newPaths(cfg)), false, port) // plain config: never activated

	order := []string{}
	buf := &bytes.Buffer{}
	require.NoError(t, runMaintain(buf, cfg, maintainOptions{}, statsOnlyStages(&order)),
		"the first run (target without the api shape) must not fail the wave")

	out := buf.String()
	assert.Contains(t, out, "INFO:", "the first-run shape must be an INFO line, not a warning")
	assert.Contains(t, out, "stats will be available after the first activation + the daemon's core restart; skipping accounting this wave")
	assert.NotContains(t, out, "WARNING:", "an expected first run is never a warning")
	_, err := os.Stat(marker)
	assert.True(t, os.IsNotExist(err), "the poll must not exec xray when the target lacks the api shape")
	// "stats" is the real stage under test (not a recorder), so the recorded
	// order carries the other nine — the wave continued through ALL of them.
	assert.Equal(t, []string{"fetch", "parse", "filter", "probe", "prune", "select", "render", "activate"},
		order, "the wave continues through every stage after the INFO")
}

func TestStatsEndpointRefusedIsINFO(t *testing.T) {
	dir := t.TempDir()
	cfg, marker := statsStageCfg(t, dir, 0)
	addr := closedLoopbackPort(t) // the service never restarted
	_, portStr, _ := net.SplitHostPort(addr)
	port, convErr := strconv.Atoi(portStr)
	require.NoError(t, convErr)
	cfg.Core.APIPort = port
	writeTarget(t, ownLivePath(newPaths(cfg)), true, port) // shape present...

	order := []string{}
	buf := &bytes.Buffer{}
	require.NoError(t, runMaintain(buf, cfg, maintainOptions{}, statsOnlyStages(&order)),
		"connection refused (activation not yet restarted) must not fail the wave")

	out := buf.String()
	assert.Contains(t, out, "INFO:")
	assert.Contains(t, out, "stats will be available after the first activation + the daemon's core restart; skipping accounting this wave")
	assert.NotContains(t, out, "WARNING:")
	_, err := os.Stat(marker)
	assert.True(t, os.IsNotExist(err), "a refused endpoint must not reach the xray exec")
}

func TestStatsEndpointUnexpectedResponseIsWARNING(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := statsStageCfg(t, dir, 0)
	// The endpoint IS listening (dial succeeds) but the poll fails at the
	// protocol level: replace the sentinel xray with a failing one.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck // test listener
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, convErr := strconv.Atoi(portStr)
	require.NoError(t, convErr)
	cfg.Core.APIPort = port
	writeTarget(t, ownLivePath(newPaths(cfg)), true, port)
	failing := filepath.Join(dir, "failing-xray.sh")
	require.NoError(t, os.WriteFile(failing,
		[]byte("#!/bin/sh\necho 'rpc error: unavailable' >&2\nexit 1\n"), 0o755))
	cfg.Core.XrayBin = failing

	order := []string{}
	buf := &bytes.Buffer{}
	require.NoError(t, runMaintain(buf, cfg, maintainOptions{}, statsOnlyStages(&order)),
		"a protocol-level poll failure stays accounting-only: the wave continues")

	out := buf.String()
	assert.Contains(t, out, "WARNING: stats poll unavailable", "today's warning behavior is preserved")
	assert.NotContains(t, out, "INFO:", "a reachable endpoint is not the first-run shape")
	assert.Equal(t, []string{"fetch", "parse", "filter", "probe", "prune", "select", "render", "activate"},
		order, "the wave continues past a WARNING (stats is the real stage under test)")
}

func TestStatsWriteFailureFailsTheWaveLoud(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := statsStageCfg(t, dir, 0)
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck // test listener
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, convErr := strconv.Atoi(portStr)
	require.NoError(t, convErr)
	cfg.Core.APIPort = port
	writeTarget(t, ownLivePath(newPaths(cfg)), true, port)

	// The poll succeeds (real-shaped counters for pool-de-01) and the geo-base
	// carries the matching record — the fold updates it, so the stage MUST
	// write. Make the write impossible: the data dir loses write permission.
	polling := filepath.Join(dir, "polling-xray.sh")
	require.NoError(t, os.WriteFile(polling, []byte(`#!/bin/sh
cat <<'EOF'
{"stat":[{"name":"outbound>>>pool-de-01>>>traffic>>>uplink","value":5120}]}
EOF
exit 0
`), 0o755))
	cfg.Core.XrayBin = polling
	geoBase := filepath.Join(dir, "geo-base.jsonl")
	rec := &model.GeoRecord{Tag: "pool-de-01", Scheme: "vless", Host: "de1.example.com", Port: 443}
	require.NoError(t, storeAppendGeoBase(t, geoBase, rec))
	require.NoError(t, os.Chmod(dir, 0o500)) // read-only data dir: WriteGeo must fail
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })

	buf := &bytes.Buffer{}
	err = runMaintain(buf, cfg, maintainOptions{}, statsOnlyStages(&[]string{}))
	require.Error(t, err, "a fold/write failure is data loss — it must FAIL the wave, never print a warning")
	assert.Contains(t, err.Error(), "geo-base", "the loud failure must name the store it refused to corrupt")
	assert.NotContains(t, buf.String(), "WARNING: stats poll unavailable",
		"the old catch-all warning must not mask a write failure")
}

// storeAppendGeoBase writes one record as a jsonl line (the store's on-disk
// shape) without importing the store package's write API — the read side is
// what the stage consumes.
func storeAppendGeoBase(t *testing.T, path string, rec *model.GeoRecord) error {
	t.Helper()
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	return os.WriteFile(path, line, 0o600)
}
