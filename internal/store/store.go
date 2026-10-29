// Package store owns the on-disk pipeline artifacts: the working node set,
// the DESIGN.md §5 geo-base.jsonl cold store, probe results, and the
// selection manifest. All writes are atomic (temp file + rename).
package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

// WriteNodes persists the working node set as JSONL.
func WriteNodes(path string, nodes []*model.Node) error {
	return writeJSONL(path, len(nodes), func(i int) (any, error) {
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
	return writeJSONL(path, len(merged), func(i int) (any, error) {
		return merged[i], nil
	})
}

// mergeGeoRecord folds the incoming record into the previous one: fresh
// values win, previous values survive where the wave left blanks, and
// first_seen plus an assigned tag are immutable.
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
	return writeJSONL(path, len(records), func(i int) (any, error) {
		return records[i], nil
	})
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
	if _, err := os.Stat(path); err == nil {
		bp, err := backupFile(path, now)
		if err != nil {
			return "", fmt.Errorf("backup before prune rewrite: %w", err)
		}
		backupPath = bp
		if err := KeepNewestBackups(filepath.Dir(path), filepath.Base(path), keep); err != nil {
			return "", fmt.Errorf("prune backup retention (prune_backup_keep=%d): %w", keep, err)
		}
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

// AppendProbeResults appends one wave of probe outcomes.
func AppendProbeResults(path string, results []ProbeResult) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	w := bufio.NewWriter(f)
	for _, r := range results {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return w.Flush()
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

func writeJSONL(path string, n int, at func(int) (any, error)) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return writeFileAtomic(path, func(f *os.File) error {
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
