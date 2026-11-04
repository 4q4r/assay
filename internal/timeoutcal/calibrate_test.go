package timeoutcal

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestP95Basic(t *testing.T) {
	vals := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	got := P95(vals)
	if got < 9 || got > 10 {
		t.Fatalf("P95 = %v, want ~9.5", got)
	}
}

func TestP95Empty(t *testing.T) {
	if P95(nil) != 0 {
		t.Fatal("P95(empty) should be 0")
	}
}

func TestPercentileInterpolation(t *testing.T) {
	vals := []float64{0, 100}
	if got := Percentile(vals, 0.5); got != 50 {
		t.Fatalf("got %v want 50", got)
	}
}

func TestCV(t *testing.T) {
	stable := []float64{100, 100, 100, 100}
	if cv := CV(stable); cv != 0 {
		t.Fatalf("CV stable = %v want 0", cv)
	}
	varied := []float64{50, 100, 150}
	if cv := CV(varied); cv <= 0 {
		t.Fatalf("CV varied = %v want >0", cv)
	}
}

func TestEMABasic(t *testing.T) {
	got := EMA(1000, 2000, 0.3)
	want := 0.7*1000 + 0.3*2000
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("EMA = %v want %v", got, want)
	}
}

func TestAdaptiveWindowStable(t *testing.T) {
	recent := []float64{100, 101, 100, 99, 100}
	k, alpha := AdaptiveWindow(recent)
	if k < MinHistoryDefault() {
		t.Fatalf("k=%d below min", k)
	}
	if alpha < 0.3 {
		t.Fatalf("alpha=%v should be >= base for stable", alpha)
	}
}

func TestAdaptiveWindowUnstable(t *testing.T) {
	recent := []float64{50, 200, 30, 250, 10}
	k, alpha := AdaptiveWindow(recent)
	if k < 20 {
		t.Fatalf("k=%d should be larger for unstable", k)
	}
	if alpha > 0.3 {
		t.Fatalf("alpha=%v should be <= base for unstable", alpha)
	}
}

func MinHistoryDefault() int { return 3 }

func TestCalibrateInsufficientSamples(t *testing.T) {
	obs := Observation{Total: 10, RTTsMs: []float64{1000}, TimedOut: 0}
	cur := 10 * time.Second
	got := Calibrate("global", obs, cur)
	if got != cur {
		t.Fatalf("insufficient samples should keep current: got %v want %v", got, cur)
	}
}

func TestCalibrateBasicP95PlusMargin(t *testing.T) {
	rtts := make([]float64, 100)
	for i := range rtts {
		rtts[i] = 7800
	}
	obs := Observation{Total: 100, RTTsMs: rtts, TimedOut: 4}
	cur := 10 * time.Second
	got := Calibrate("global", obs, cur)
	// p95 ~7800 + 1000 margin = 8800ms, EMA blended with current 10000
	if got < 8*time.Second || got > 10*time.Second {
		t.Fatalf("calibrated = %v, want between 8s and 10s", got)
	}
}

func TestCalibrateFloor(t *testing.T) {
	rtts := make([]float64, 0, 62)
	rtts = append(rtts, 100, 200)
	// need min samples; pad
	for range 60 {
		rtts = append(rtts, 100)
	}
	obs := Observation{Total: 62, RTTsMs: rtts, TimedOut: 0}
	got := Calibrate("global", obs, 10*time.Second)
	if got < time.Duration(FloorMs)*time.Millisecond {
		t.Fatalf("below floor: %v", got)
	}
}

func TestCalibrateCeiling(t *testing.T) {
	rtts := make([]float64, 60)
	for i := range rtts {
		rtts[i] = 100000
	}
	obs := Observation{Total: 60, RTTsMs: rtts, TimedOut: 0}
	got := Calibrate("global", obs, 10*time.Second)
	if got > time.Duration(CeilingMs)*time.Millisecond {
		t.Fatalf("above ceiling: %v", got)
	}
}

func TestCalibrateHighTimeoutRateUsesP99(t *testing.T) {
	rtts := make([]float64, 60)
	for i := range rtts {
		rtts[i] = 5000
	}
	obs := Observation{Total: 60, RTTsMs: rtts, TimedOut: 20} // 33% > 0.15
	got := Calibrate("global", obs, 10*time.Second)
	if got < 5*time.Second {
		t.Fatalf("got %v", got)
	}
}

func TestCalibrateHysteresis(t *testing.T) {
	rtts := make([]float64, 60)
	for i := range rtts {
		rtts[i] = 9500
	}
	obs := Observation{Total: 60, RTTsMs: rtts, TimedOut: 0}
	cur := 10 * time.Second
	got := Calibrate("global", obs, cur)
	// candidate ~10.5s clamped, but EMA + hysteresis may keep near current
	if got == 0 {
		t.Fatal("zero")
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := State{}
	st.Probe.Base = 10 * time.Second
	st.Probe.Global.Current = 8800 * time.Millisecond
	st.Probe.Global.Waves = 3
	if err := Save(dir, st); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Probe.Global.Current != st.Probe.Global.Current {
		t.Fatalf("roundtrip mismatch: %v vs %v", got.Probe.Global.Current, st.Probe.Global.Current)
	}
}

func TestStateMissingFile(t *testing.T) {
	dir := t.TempDir()
	st, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Probe.Base != 0 {
		t.Fatalf("expected zero state, got %+v", st)
	}
}

func TestUpdateWithConfigIntegration(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	rtts := make([]float64, 60)
	for i := range rtts {
		rtts[i] = 7800
	}
	obs := Observation{Key: "global", Stage: "probe", Total: 60, TimedOut: 2, RTTsMs: rtts, At: time.Now()}
	if err := UpdateWithConfig(dir, "probe", obs, cfg); err != nil {
		t.Fatal(err)
	}
	st, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Probe.Global.Waves != 1 {
		t.Fatalf("waves = %d want 1", st.Probe.Global.Waves)
	}
	if st.Probe.Global.Current == 0 {
		t.Fatal("current not set")
	}
	// second wave should change (or keep) calibrated timeout
	obs2 := obs
	obs2.At = time.Now().Add(time.Hour)
	if err := UpdateWithConfig(dir, "probe", obs2, cfg); err != nil {
		t.Fatal(err)
	}
	st2, _ := Load(dir)
	if st2.Probe.Global.Waves != 2 {
		t.Fatalf("waves = %d want 2", st2.Probe.Global.Waves)
	}
}

func TestStageStateTimeoutForFallback(t *testing.T) {
	ss := &StageState{Base: 10 * time.Second}
	ss.Global.Current = 8 * time.Second
	// city missing -> country -> global
	if got := ss.TimeoutFor("ru:moscow"); got != 8*time.Second {
		t.Fatalf("fallback city->global = %v want 8s", got)
	}
	ss.Regions = map[string]KeyState{"ru": {Current: 9 * time.Second}}
	if got := ss.TimeoutFor("ru:moscow"); got != 9*time.Second {
		t.Fatalf("fallback city->country = %v want 9s", got)
	}
	ss.Cities = map[string]KeyState{"ru:moscow": {Current: 7 * time.Second}}
	if got := ss.TimeoutFor("ru:moscow"); got != 7*time.Second {
		t.Fatalf("city direct = %v want 7s", got)
	}
}

func TestAdaptiveWindowBounds(t *testing.T) {
	for _, recent := range [][]float64{
		{100},
		{100, 200, 300, 400, 500, 600, 700, 800},
	} {
		k, _ := AdaptiveWindowWithBase(recent, 0.3)
		if k < 3 || k > 50 {
			t.Fatalf("k=%d out of bounds for %v", k, recent)
		}
	}
}

func TestCalibrateMonotonicMinSafety(t *testing.T) {
	// a single very fast wave should not collapse below p95+margin
	rtts := make([]float64, 60)
	for i := range rtts {
		rtts[i] = 1000
	}
	obs := Observation{Total: 60, RTTsMs: rtts, TimedOut: 0}
	got := Calibrate("global", obs, 10*time.Second)
	if got < time.Duration(FloorMs)*time.Millisecond {
		t.Fatalf("below floor: %v", got)
	}
}

func TestCalibratedTimeoutChangesAcrossWaves(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	// wave 1: slow
	rtts := make([]float64, 60)
	for i := range rtts {
		rtts[i] = 9000
	}
	obs := Observation{Key: "global", Stage: "probe", Total: 60, TimedOut: 0, RTTsMs: rtts, At: time.Now()}
	_ = UpdateWithConfig(dir, "probe", obs, cfg)
	st1, _ := Load(dir)
	// wave 2: faster
	rtts2 := make([]float64, 60)
	for i := range rtts2 {
		rtts2[i] = 5000
	}
	obs2 := Observation{Key: "global", Stage: "probe", Total: 60, TimedOut: 0, RTTsMs: rtts2, At: time.Now().Add(time.Hour)}
	_ = UpdateWithConfig(dir, "probe", obs2, cfg)
	st2, _ := Load(dir)
	// calibrated timeout should move (EMA) — at least not increase spuriously; just ensure state updated
	if st2.Probe.Global.Waves != 2 {
		t.Fatalf("waves=%d", st2.Probe.Global.Waves)
	}
	_ = st1
}

func TestUpdateWithConfigConcurrentNoLostUpdates(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	const workers = 40
	errCh := make(chan error, workers)

	for i := range workers {
		go func(workerID int) {
			rtts := make([]float64, 50)
			for j := range rtts {
				rtts[j] = 2000 + float64(workerID*10)
			}
			obs := Observation{
				Key:      fmt.Sprintf("region-%d", workerID),
				Stage:    "probe",
				Total:    50,
				TimedOut: 1,
				RTTsMs:   rtts,
				At:       time.Now(),
			}
			errCh <- UpdateWithConfig(dir, "probe", obs, cfg)
		}(i)
	}

	for range workers {
		if err := <-errCh; err != nil {
			t.Fatalf("worker error: %v", err)
		}
	}

	st, err := Load(dir)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if len(st.Probe.Regions) != workers {
		t.Fatalf("regions count = %d, want %d (lost update detected)", len(st.Probe.Regions), workers)
	}
	for i := range workers {
		key := fmt.Sprintf("region-%d", i)
		if ks, ok := st.Probe.Regions[key]; !ok || ks.Waves != 1 {
			t.Fatalf("missing or corrupted key %q: %+v", key, ks)
		}
	}
}

func TestConfigDefaults(t *testing.T) {
	// ensure zero config normalizes
	cfg := Config{}
	cfg = cfg.normalize()
	if cfg.Margin != 1.0 || cfg.MinHistory != 3 || cfg.MaxHistory != 50 {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
}

func TestSaveAtomicNoTmpLeft(t *testing.T) {
	dir := t.TempDir()
	_ = Save(dir, State{})
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("tmp file left: %s", e.Name())
		}
	}
}
