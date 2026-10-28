package probe_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"public_vpn/internal/model"
	"public_vpn/internal/probe"
	"public_vpn/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func node(t *testing.T, name string) *model.Node {
	t.Helper()
	return model.NewNode("s", "vless", "uuid-"+name, name+".example.com", 443, map[string]string{"security": "tls", "type": "tcp"})
}

type fakeRunner struct {
	results []probe.RawResult
	calls   int
}

func (f *fakeRunner) Run(_ context.Context, _ []string, _ probe.Options) ([]probe.RawResult, error) {
	f.calls++
	return f.results, nil
}

func TestStageMapsAliveAndDead(t *testing.T) {
	a, b, c := node(t, "alive"), node(t, "dead"), node(t, "noresult")
	fr := &fakeRunner{results: []probe.RawResult{
		{Link: a.Link(), Status: "passed", IP: "5.6.7.8", Delay: 120.5, SuccessCount: 1, TotalCount: 1},
		{Link: b.Link(), Status: "failed", IP: "null", Delay: -1, FailureKind: "tcp-timeout", Reason: "deadline"},
	}}
	out, err := probe.Run(context.Background(), []*model.Node{a, b, c}, fr, probe.Options{}, filepath.Join(t.TempDir(), "probe-results.jsonl"))
	require.NoError(t, err)
	require.Len(t, out, 3)

	alive := out[0]
	assert.Equal(t, a.Key, alive.Key)
	assert.True(t, alive.Alive)
	assert.Equal(t, "5.6.7.8", alive.ExitIP, "exit IP comes from the tunnel probe (D8), not the advertised host")
	assert.InDelta(t, 120.5, alive.RTTMs, 0.001)
	assert.Equal(t, 1, alive.Checks)

	dead := out[1]
	assert.False(t, dead.Alive)
	assert.Empty(t, dead.ExitIP, `"null" sentinel must not become a literal IP`)
	assert.Equal(t, "tcp-timeout", dead.FailureKind)
	assert.Equal(t, 0, dead.Checks)

	missing := out[2]
	assert.False(t, missing.Alive, "no knife result = not alive this wave")
	assert.Empty(t, missing.Status)
}

func TestStageSemiPassedCountsAsAliveWithChecks(t *testing.T) {
	n := node(t, "semi")
	fr := &fakeRunner{results: []probe.RawResult{
		{Link: n.Link(), Status: "semi-passed", IP: "9.9.9.9", Delay: 200, SuccessCount: 2, TotalCount: 3},
	}}
	out, err := probe.Run(context.Background(), []*model.Node{n}, fr, probe.Options{}, filepath.Join(t.TempDir(), "p.jsonl"))
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.True(t, out[0].Alive, "semi-passed = tunnel works, panel grading partial")
	assert.Equal(t, 2, out[0].Checks)
	assert.Equal(t, 3, out[0].TotalChecks)
}

func TestStageAppendsToProbeLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe-results.jsonl")
	n := node(t, "logged")
	fr := &fakeRunner{results: []probe.RawResult{
		{Link: n.Link(), Status: "passed", IP: "1.2.3.4", Delay: 42},
	}}
	_, err := probe.Run(context.Background(), []*model.Node{n}, fr, probe.Options{}, path)
	require.NoError(t, err)

	latest, err := store.LatestProbeByKey(path)
	require.NoError(t, err)
	require.Contains(t, latest, n.Key)
	assert.True(t, latest[n.Key].Alive)
	assert.WithinDuration(t, time.Now().UTC(), latest[n.Key].CheckedAt, time.Minute)
}

func TestStageLoudOnUnmappedLink(t *testing.T) {
	n := node(t, "known")
	fr := &fakeRunner{results: []probe.RawResult{
		{Link: "vless://someoneelse@h:443?security=tls&type=tcp", Status: "passed"},
	}}
	_, err := probe.Run(context.Background(), []*model.Node{n}, fr, probe.Options{}, filepath.Join(t.TempDir(), "p.jsonl"))
	require.Error(t, err, "a knife result we cannot attribute is a contract breach — fail loud")
	assert.Contains(t, err.Error(), "unmapped")
}

// --- KnifeRunner against a scripted fake binary: verifies command
// construction (flags) and JSONL parsing without any real network. ---

func TestKnifeRunnerBuildsCommandAndParsesJSONL(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-knife.sh")
	// The fake writes a script of its own argv next to the output file, then
	// emits one alive + one failed record.
	require.NoError(t, os.WriteFile(script, []byte(`#!/bin/sh
echo "$@" > "$FAKE_ARGV"
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
cat > "$out" <<'JSONEOF'
{"link":"vless://uuid-alive@alive.example.com:443?security=tls&type=tcp","status":"passed","ip":"5.6.7.8","delay":111.5,"download":2048,"upload":512,"successCount":1,"totalCount":1,"failureKind":"","reason":""}
{"link":"vless://uuid-dead@dead.example.com:443?security=tls&type=tcp","status":"failed","ip":"null","delay":-1,"download":0,"upload":0,"successCount":0,"totalCount":1,"failureKind":"tls-reset","reason":"x"}
JSONEOF
`), 0o755))

	// The FAKE_ARGV channel is a TEST seam (review finding 8): production
	// subprocesses get no such variable — the runner only forwards TestEnv.
	runner := &probe.KnifeRunner{BinPath: script, TestEnv: []string{"FAKE_ARGV=" + filepath.Join(dir, "FAKE_ARGV")}}
	opts := probe.Options{
		Timeout:             8 * time.Second,
		Threads:             20,
		URL:                 "https://cloudflare.com/cdn-cgi/trace",
		Speedtest:           true,
		CheckPreset:         "global",
		URLSuccessThreshold: 0.75,
		DBPath:              filepath.Join(dir, "knife.db"),
		WorkDir:             dir,
	}
	res, err := runner.Run(context.Background(), []string{
		"vless://uuid-alive@alive.example.com:443?security=tls&type=tcp",
		"vless://uuid-dead@dead.example.com:443?security=tls&type=tcp",
	}, opts)
	require.NoError(t, err)
	require.Len(t, res, 2)

	assert.Equal(t, "passed", res[0].Status)
	assert.Equal(t, "5.6.7.8", res[0].IP)
	assert.InDelta(t, 111.5, res[0].Delay, 0.001)
	assert.InDelta(t, 2048, res[0].Download, 0.001)

	argv, err := os.ReadFile(filepath.Join(dir, "FAKE_ARGV"))
	require.NoError(t, err)
	args := string(argv)
	assert.Contains(t, args, "http", "subcommand must be http")
	assert.Contains(t, args, "-x jsonl", "all-results JSONL output")
	assert.Contains(t, args, "-S", "speedtest flag forwarded")
	assert.Contains(t, args, "--check-preset global")
	assert.Contains(t, args, "--url-success-threshold 0.75")
	assert.Contains(t, args, "8000", "timeout ms forwarded")
	assert.Contains(t, args, "-t 20", "threads forwarded")
	assert.NotContains(t, args, "--save-db", "probe must not grow the knife database")
}

// TestKnifeRunnerSetsNoFakeArgvInProduction pins the seam contract: without
// TestEnv the knife subprocess environment carries no FAKE_ARGV (review
// finding 8 — production subprocesses must not inherit test channels).
func TestKnifeRunnerSetsNoFakeArgvInProduction(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-knife.sh")
	require.NoError(t, os.WriteFile(script, []byte(`#!/bin/sh
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
echo "FAKE_ARGV=[${FAKE_ARGV:-unset}]" > "$out.env"
cat > "$out" <<'JSONEOF'
{"link":"vless://u@h1.example.com:443?security=tls&type=tcp","status":"passed","ip":"5.6.7.8","delay":12,"download":0,"upload":0,"successCount":1,"totalCount":1}
JSONEOF
`), 0o755))

	runner := &probe.KnifeRunner{BinPath: script}
	res, err := runner.Run(context.Background(),
		[]string{"vless://u@h1.example.com:443?security=tls&type=tcp"},
		probe.Options{WorkDir: dir})
	require.NoError(t, err)
	require.Len(t, res, 1)

	reports, err := filepath.Glob(filepath.Join(dir, "results-*.jsonl.env"))
	require.NoError(t, err)
	require.Len(t, reports, 1, "the fake reported its environment")
	b, err := os.ReadFile(reports[0])
	require.NoError(t, err)
	assert.Contains(t, string(b), "FAKE_ARGV=[unset]",
		"production subprocess env must not carry the test channel")
}

func TestKnifeRunnerMissingBinaryIsLoud(t *testing.T) {
	runner := &probe.KnifeRunner{BinPath: filepath.Join(t.TempDir(), "no-such-binary")}
	_, err := runner.Run(context.Background(), []string{"vless://u@h:443?security=tls&type=tcp"}, probe.Options{WorkDir: t.TempDir()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "xray-knife")
}

func TestKnifeRunnerParsesRealCLIOutputShape(t *testing.T) {
	// Regression pin: the JSONL record observed live from xray-knife v11.4.1.
	raw := `{"link":"vless://x@192.0.2.1:1?type=tcp&security=tls","protocol":{"remark":"deadnode","protocol":"vless","address":"192.0.2.1","port":"1"},"status":"failed","reason":"timeout; diagnosis: tcp-timeout","tls":"tls","ip":"null","delay":-1,"code":-1,"download":0,"upload":0,"location":"null","ttfb":0,"connectTime":0,"successCount":0,"totalCount":1,"endpoints":[],"endpointSummary":"","rttMin":0,"rttAvg":0,"rttMax":0,"jitter":0,"rttSamples":0,"colo":"","warp":"","failureKind":"tcp-timeout"}`
	var res probe.RawResult
	require.NoError(t, json.Unmarshal([]byte(raw), &res))
	assert.Equal(t, "failed", res.Status)
	assert.Equal(t, "tcp-timeout", res.FailureKind)
	assert.Equal(t, "192.0.2.1", res.Protocol.Address)
	assert.InDelta(t, -1.0, res.Delay, 0.001)
}
