// Package store owns the on-disk pipeline artifacts: the working node set,
// the DESIGN.md §5 geo-base.jsonl cold store, probe results, and the
// selection manifest. All writes are atomic (temp file + rename).
package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"public_vpn/internal/model"
)

// ProbeResult is one node's outcome from a probe wave (the W14 real-xray
// engine: a temp single-node xray per node — the xray-knife tool is gone).
type ProbeResult struct {
	Key         string    `json:"key"`
	Host        string    `json:"host"`
	Alive       bool      `json:"alive"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason,omitempty"`
	ExitIP      string    `json:"exit_ip,omitempty"`
	RTTMs       float64   `json:"rtt_ms"`
	SpeedBPS    int64     `json:"speed_bps"`
	Checks      int       `json:"checks"`
	TotalChecks int       `json:"total_checks"`
	FailureKind string    `json:"failure_kind,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
}

// WriteNodes persists the working node set as JSONL. Nodes/filtered are
// intermediate artifacts rewritten every wave, so the write is atomic but
// not fsynced (drop fsync from intermediates).
func WriteNodes(path string, nodes []*model.Node) error {
	return writeJSONL(path, len(nodes), false, func(i int) (any, error) {
		return nodes[i], nil
	})
}

// ReadNodes loads the working node set; a missing file is an empty set.
func ReadNodes(path string) ([]*model.Node, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var nodes []*model.Node
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var n model.Node
		if err := json.Unmarshal([]byte(line), &n); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		nn := n
		nodes = append(nodes, &nn)
	}
	return nodes, sc.Err()
}

// UpsertGeo merges records into the cold store by identity. Existing fields
// that later waves leave empty survive; first_seen and a previously assigned
// tag are never clobbered. The merged set is written sorted by identity, so
// two runs over identical logical data produce a byte-identical file (Go map
// iteration order must never reach the disk).
func UpsertGeo(path string, records []*model.GeoRecord) error {
	existing, err := ReadGeo(path)
	if err != nil {
		return err
	}
	byIdentity := make(map[string]*model.GeoRecord, len(existing))
	for _, e := range existing {
		byIdentity[model.GeoIdentity(e)] = e
	}
	for _, r := range records {
		byIdentity[model.GeoIdentity(r)] = mergeGeoRecord(byIdentity, r)
	}
	merged := make([]*model.GeoRecord, 0, len(byIdentity))
	for _, v := range byIdentity {
		merged = append(merged, v)
	}
	sort.Slice(merged, func(i, j int) bool {
		return model.GeoIdentity(merged[i]) < model.GeoIdentity(merged[j])
	})
	if err := writeJSONL(path, len(merged), true, func(i int) (any, error) {
		return merged[i], nil
	}); err != nil {
		return err
	}
	fadviseDontNeed(path)
	return nil
}

// mergeGeoRecord folds the incoming record into the previous one: fresh
// values win, previous values survive where the wave left blanks, and
// first_seen plus an assigned tag are immutable.
//
//nolint:cyclop // blank-fold matrix: one flat guard per field class; splitting hides the fold contract
func mergeGeoRecord(byIdentity map[string]*model.GeoRecord, r *model.GeoRecord) *model.GeoRecord {
	prev, ok := byIdentity[model.GeoIdentity(r)]
	if !ok {
		return r
	}
	if prev.FirstSeen != "" {
		r.FirstSeen = prev.FirstSeen
	}
	if r.Tag == "" {
		r.Tag = prev.Tag
	}
	if r.IP == "" {
		r.IP = prev.IP
	}
	if r.Country == "" {
		r.Country = prev.Country
	}
	if r.City == "" {
		r.City = prev.City
	}
	if r.ASN == "" {
		r.ASN = prev.ASN
	}
	if r.ASName == "" {
		r.ASName = prev.ASName
	}
	if r.ISP == "" {
		r.ISP = prev.ISP
	}
	if r.GeoSource == "" {
		// Provenance follows the fields it describes: when the wave left the
		// geo fields blank (no evidence), the surviving fields keep pointing
		// at the wave that produced them.
		r.GeoSource = prev.GeoSource
	}
	if r.LastProbe == "" {
		// The incoming wave carries no probe outcome: previous probe telemetry
		// must survive intact. Overwriting Alive/RTT/Speed here would zero a
		// probed record's outcomes while keeping its stale last_probe.
		r.LastProbe = prev.LastProbe
		r.Alive = prev.Alive
		r.RTTMs = prev.RTTMs
		r.SpeedBPS = prev.SpeedBPS
		r.BytesUp = prev.BytesUp
		r.BytesDown = prev.BytesDown
	}
	// Phase-1 blank-fold: -1/"" = "this wave ran no unlock stage" — the
	// previous verdict survives (same contract as the geo fields above).
	// Booleans (IsResidential/IsHosting/IsProxy/IsMobile) have no
	// distinguishable "unchecked" zero, so they are NOT folded here: the
	// geo path always carries prev (mergeGeoRecords starts rec from prev),
	// which is the guarantee for them.
	if r.RiskScore < 0 {
		r.RiskScore = prev.RiskScore
	}
	if r.ScamalyticsScore < 0 {
		r.ScamalyticsScore = prev.ScamalyticsScore
	}
	if r.AbuseScore < 0 {
		r.AbuseScore = prev.AbuseScore
	}
	if r.IPType == "" {
		r.IPType = prev.IPType
	}
	if r.MediaUnlocks.CheckedAt == "" {
		r.MediaUnlocks = prev.MediaUnlocks
	}
	return r
}

// ReadGeo loads the cold store; a missing file is empty.
func ReadGeo(path string) ([]*model.GeoRecord, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var recs []*model.GeoRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var g model.GeoRecord
		if err := json.Unmarshal([]byte(line), &g); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		recs = append(recs, &g)
	}
	return recs, sc.Err()
}

// WriteGeo atomically rewrites the cold store with the given records (W4
// prune path: same temp+rename discipline as every other store write).
func WriteGeo(path string, records []*model.GeoRecord) error {
	if err := writeJSONL(path, len(records), true, func(i int) (any, error) {
		return records[i], nil
	}); err != nil {
		return err
	}
	fadviseDontNeed(path)
	return nil
}

// RewriteGeoWithBackup backs the pre-prune store up next to itself as
// <name>.bak-<ts> (0600), applies the [maintain].prune_backup_keep retention
// (keep = N newest .bak-<ts> files; 0 = unlimited), and only then atomically
// rewrites the store with the pruned records. A missing store has nothing to
// back up: the backup path is empty and only the write happens. Retention
// runs BEFORE the rewrite on purpose: a retention failure aborts loud with
// the store untouched — rollback depth is never silently reduced.
func RewriteGeoWithBackup(path string, records []*model.GeoRecord, now time.Time, keep int) (string, error) {
	backupPath := ""
	_, statErr := os.Stat(path)
	switch {
	case statErr == nil:
		bp, err := backupFile(path, now)
		if err != nil {
			return "", fmt.Errorf("backup before prune rewrite: %w", err)
		}
		backupPath = bp
		if err := KeepNewestBackups(filepath.Dir(path), filepath.Base(path), keep); err != nil {
			return "", fmt.Errorf("prune backup retention (prune_backup_keep=%d): %w", keep, err)
		}
	case os.IsNotExist(statErr):
		// A missing store has nothing to back up: only the write happens.
	default:
		// Any OTHER stat error (permissions, ENOTDIR, ...) must not be read
		// as "nothing to back up" — that would silently reduce the rollback
		// depth (adversarial review F10). Fail loud, store untouched.
		return "", fmt.Errorf(
			"stat pre-prune store %s: %w — refusing to rewrite without knowing the rollback state",
			path, statErr)
	}
	if err := WriteGeo(path, records); err != nil {
		return "", err
	}
	return backupPath, nil
}

// KeepNewestBackups retains only the keep newest <prefix>.bak-<ts> files in
// dir and deletes the older ones (keep = 0 or less is a no-op: unlimited).
// It must run AFTER a successful new backup write. Deletion failures are
// LOUD: never silently lose rollback depth without an error.
func KeepNewestBackups(dir, prefix string, keep int) error {
	if keep <= 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("list backups in %s: %w", dir, err)
	}
	// Backup names carry the fixed YYYYMMDD-HHMMSS stamp, so lexicographic
	// order is chronological; descending = newest first.
	var backups []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, prefix+".bak-") {
			backups = append(backups, name)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(backups)))
	for _, name := range backups[keep:] {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("delete old backup %s (rollback depth must never shrink silently): %w", name, err)
		}
	}
	return nil
}

// backupFile copies path to <path>.bak-<YYYYMMDD-HHMMSS> in the same
// directory (the activate-stage backup convention, applied to stores).
func backupFile(path string, now time.Time) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	dst := path + ".bak-" + now.UTC().Format("20060102-150405")
	//nolint:gosec // G703: the store path comes from the owner's config.toml —
	// the config file IS the trust root (same class as the activate-stage backup)
	return dst, os.WriteFile(dst, data, 0o600)
}

// WriteSelection persists the select-stage manifest.
func WriteSelection(path string, sel *model.Selection) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return writeFileAtomic(path, func(f *os.File) error {
		b, err := json.MarshalIndent(sel, "", "  ")
		if err != nil {
			return err
		}
		_, err = f.Write(append(b, '\n'))
		return err
	})
}

// WriteManifest persists the fetch manifest via the shared atomic-0600 path.
func WriteManifest(path string, manifestJSON []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return writeFileAtomic(path, func(f *os.File) error {
		_, err := f.Write(append(manifestJSON, '\n'))
		return err
	})
}

// ReadSelection loads the selection manifest; a missing file yields nil.
func ReadSelection(path string) (*model.Selection, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sel model.Selection
	if err := json.Unmarshal(b, &sel); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &sel, nil
}

// AppendProbeResults merges one wave of probe outcomes into the store, keeping
// the latest outcome per key (compact: latest-per-key). The file is rewritten
// atomically so it never grows unbounded across waves. probe-results is an
// intermediate, so the write is not fsynced; large-write page cache is dropped
// afterwards.
func AppendProbeResults(path string, results []ProbeResult) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	existing, err := ReadProbeResults(path)
	if err != nil {
		return err
	}
	byKey := make(map[string]ProbeResult, len(existing)+len(results))
	merge := func(r ProbeResult) {
		if prev, ok := byKey[r.Key]; ok && r.CheckedAt.Before(prev.CheckedAt) {
			return
		}
		byKey[r.Key] = r
	}
	for _, r := range existing {
		merge(r)
	}
	for _, r := range results {
		merge(r)
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	merged := make([]ProbeResult, 0, len(keys))
	for _, k := range keys {
		merged = append(merged, byKey[k])
	}
	if err := writeFileAtomicNoSync(path, func(f *os.File) error {
		w := bufio.NewWriter(f)
		for _, r := range merged {
			b, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if _, err := w.Write(append(b, '\n')); err != nil {
				return err
			}
		}
		return w.Flush()
	}); err != nil {
		return err
	}
	fadviseDontNeed(path)
	return nil
}

// ReadProbeResults loads every recorded probe outcome in file order.
func ReadProbeResults(path string) ([]ProbeResult, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []ProbeResult
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r ProbeResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// LatestProbeByKey reduces the probe log to the newest outcome per node key.
func LatestProbeByKey(path string) (map[string]ProbeResult, error) {
	all, err := ReadProbeResults(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]ProbeResult, len(all))
	for _, r := range all {
		if prev, ok := out[r.Key]; !ok || !r.CheckedAt.Before(prev.CheckedAt) {
			out[r.Key] = r
		}
	}
	return out, nil
}

// KnownAliveRecord is an alias of model.KnownAliveRecord so callers may
// reference it through either package (store.KnownAliveRecord or
// model.KnownAliveRecord).
type KnownAliveRecord = model.KnownAliveRecord

// ReadKnownAlive loads the known-alive set; a missing file is an empty set.
func ReadKnownAlive(path string) (map[string]KnownAliveRecord, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return map[string]KnownAliveRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := map[string]KnownAliveRecord{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r KnownAliveRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		if r.Key == "" {
			continue
		}
		out[r.Key] = r
	}
	return out, sc.Err()
}

// WriteKnownAlive atomically persists the known-alive set as JSONL, sorted by
// key for deterministic output.
func WriteKnownAlive(path string, m map[string]KnownAliveRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return writeFileAtomic(path, func(f *os.File) error {
		w := bufio.NewWriter(f)
		for _, k := range keys {
			r := m[k]
			if r.Key == "" {
				r.Key = k
			}
			b, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if _, err := w.Write(append(b, '\n')); err != nil {
				return err
			}
		}
		return w.Flush()
	})
}

// PruneKnownAlive removes entries whose LastSeen is older than ttl from now.
// It mutates m in place AND returns it so callers may use either style.
// A ttl <= 0 disables pruning (retain everything).
func PruneKnownAlive(m map[string]KnownAliveRecord, now time.Time, ttl time.Duration) map[string]KnownAliveRecord {
	if ttl <= 0 {
		return m
	}
	for k, r := range m {
		if now.Sub(r.LastSeen) >= ttl {
			delete(m, k)
		}
	}
	return m
}

func writeJSONL(path string, n int, sync bool, at func(int) (any, error)) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	write := writeFileAtomic
	if !sync {
		write = writeFileAtomicNoSync
	}
	return write(path, func(f *os.File) error {
		w := bufio.NewWriter(f)
		for i := range n {
			v, err := at(i)
			if err != nil {
				return err
			}
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			if _, err := w.Write(append(b, '\n')); err != nil {
				return err
			}
		}
		return w.Flush()
	})
}

// WaveState is the small daemon state file (wave-state.json) tracking the
// current wave sequence number.
type WaveState struct {
	CurrentWaveSeq uint64 `json:"currentWaveSeq"`
}

// ReadWaveState returns the current wave sequence (0 if file missing/corrupt).
// A corrupt file is never a silent reset: the damaged bytes are backed up
// next to the original as <name>.corrupt-<unix-ts>, the reset is announced
// loud on stderr (adversarial review F9), and availability is preserved —
// the wave sequence restarts at 0 instead of failing the daemon.
func ReadWaveState(path string) (WaveState, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return WaveState{}, nil
	}
	if err != nil {
		return WaveState{}, err
	}
	defer func() { _ = f.Close() }()
	var st WaveState
	dec := json.NewDecoder(f)
	if err := dec.Decode(&st); err != nil {
		// corrupt → back the damaged file up, warn loud, reset to 0.
		backup := path + ".corrupt-" + strconv.FormatInt(time.Now().Unix(), 10)
		if rerr := os.Rename(path, backup); rerr != nil {
			fmt.Fprintf(os.Stderr,
				"WARNING: wave state %s is corrupt and the corrupt-file backup failed (%v) — resetting to 0\n",
				path, rerr)
		} else {
			fmt.Fprintf(os.Stderr,
				"WARNING: wave state %s is corrupt — backed up to %s, resetting the sequence to 0\n",
				path, backup)
		}
		return WaveState{}, nil
	}
	return st, nil
}

// ReadWaveSeq is a convenience returning just the sequence number.
func ReadWaveSeq(path string) (uint64, error) {
	st, err := ReadWaveState(path)
	if err != nil {
		return 0, err
	}
	return st.CurrentWaveSeq, nil
}

// ReadCurrentWaveSeq alias.
// ReadCurrentWaveSeq is an alias.
func ReadCurrentWaveSeq(path string) (uint64, error) { return ReadWaveSeq(path) }

// LoadWaveState is an alias.
func LoadWaveState(path string) (WaveState, error) { return ReadWaveState(path) }

// GetWaveState is an alias.
func GetWaveState(path string) (WaveState, error) { return ReadWaveState(path) }

// WriteWaveState atomically persists the wave state.
func WriteWaveState(path string, state WaveState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return writeFileAtomic(path, func(f *os.File) error {
		b, err := json.Marshal(state)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			return err
		}
		return nil
	})
}

// WriteWaveSeq persists a sequence number.
func WriteWaveSeq(path string, seq uint64) error {
	return WriteWaveState(path, WaveState{CurrentWaveSeq: seq})
}

// WriteWaveStateAny accepts either a WaveState or a uint64.
func WriteWaveStateAny(path string, v any) error {
	switch val := v.(type) {
	case WaveState:
		return WriteWaveState(path, val)
	case uint64:
		return WriteWaveSeq(path, val)
	case int:
		if val < 0 {
			return errors.New("negative wave seq")
		}
		return WriteWaveSeq(path, uint64(val))
	default:
		return fmt.Errorf("unsupported wave state value %T", v)
	}
}

// PersistWaveState alias.
// PersistWaveState is an alias.
func PersistWaveState(path string, state WaveState) error { return WriteWaveState(path, state) }

// SaveWaveState is an alias.
func SaveWaveState(path string, state WaveState) error { return WriteWaveState(path, state) }

// IncrementWaveState reads, increments, persists, and returns the new seq.
func IncrementWaveState(path string) (uint64, error) {
	st, err := ReadWaveState(path)
	if err != nil {
		return 0, err
	}
	st.CurrentWaveSeq++
	if err := WriteWaveState(path, st); err != nil {
		return st.CurrentWaveSeq, err
	}
	return st.CurrentWaveSeq, nil
}

// IncrementWaveSeq is an alias.
func IncrementWaveSeq(path string) (uint64, error) { return IncrementWaveState(path) }

// NextWaveSeq is an alias.
func NextWaveSeq(path string) (uint64, error) { return IncrementWaveState(path) }

// NextWaveState is an alias.
func NextWaveState(path string) (uint64, error) { return IncrementWaveState(path) }

// WriteFileAtomic is the exported form of writeFileAtomic (durability-critical
// callers outside the store package, e.g. the rendered config).
func WriteFileAtomic(path string, write func(*os.File) error) error {
	return writeFileAtomic(path, write)
}

// WriteFileAtomicNoSync is the exported no-fsync variant.
func WriteFileAtomicNoSync(path string, write func(*os.File) error) error {
	return writeFileAtomicNoSync(path, write)
}

// writeFileAtomic writes via a temp file in the same directory then renames
// over the target, so a crash never leaves a truncated artifact. The artifact
// mode is an explicit 0600 (state files are owner-private by design), not a
// CreateTemp side effect (review finding 11).
func writeFileAtomic(path string, write func(*os.File) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := write(tmp); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// writeFileAtomicNoSync is the no-fsync variant for intermediate artifacts
// (nodes.jsonl, filtered.jsonl, probe-results). Atomicity (temp+rename) is
// preserved; only the fsync is dropped, since these files are rewritten
// every wave and a crash just re-derives them from cache.
func writeFileAtomicNoSync(path string, write func(*os.File) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := write(tmp); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// fadviseDontNeed drops a just-written file from the page cache. Used for
// large writes (probe-results, geo-base) to avoid evicting hotter pages.
func fadviseDontNeed(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	_ = unix.Fadvise(int(f.Fd()), 0, fi.Size(), unix.FADV_DONTNEED)
}
