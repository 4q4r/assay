package cli

import (
	"strings"
	"testing"
	"time"

	"assay/internal/probe"
	"assay/internal/store"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The bounded orphan disclosure (allocation audit M4/F7, the S7
// journal-flood lesson): entries retained by the known-alive TTL after
// leaving the source lists are journaled as ONE summary line with the count,
// plus at most orphanDisclosureLimit named examples — a wave that drops a
// whole source must not print a per-node line per orphan.

func TestUpdateKnownAliveOrphanDisclosureCapped(t *testing.T) {
	now := time.Now().UTC()
	ka := map[string]store.KnownAliveRecord{}
	for i := range 8 {
		key := "orphan-" + string(rune('a'+i))
		ka[key] = store.KnownAliveRecord{
			Key:      key,
			Host:     key + ".example.com",
			LastSeen: now.Add(-time.Minute), // far inside any TTL: retained, disclosed
		}
	}
	nodeKeys := map[string]bool{"present-1": true}
	results := []store.ProbeResult{
		{Key: "present-1", Host: "present.example.com", Alive: true, Status: "passed", CheckedAt: now},
	}
	ka["present-1"] = store.KnownAliveRecord{Key: "present-1", LastSeen: now, LastStatus: "passed"}

	cmd := &cobra.Command{}
	var out strings.Builder
	cmd.SetOut(&out)
	opts := probe.Options{KnownAliveTTL: 24 * time.Hour}

	require.NoError(t, updateKnownAliveSet(cmd, opts, ka, nodeKeys, results, now))

	journal := out.String()
	assert.Equal(t, 1, strings.Count(journal, "entries absent from sources"),
		"the disclosure is ONE bounded summary line (M4)")
	assert.Equal(t, orphanDisclosureLimit, strings.Count(journal, "known-alive but absent from sources"),
		"at most orphanDisclosureLimit orphans are named individually")
	assert.Contains(t, journal, "8", "the summary carries the retained count")
	// The surviving retained set is untouched by the disclosure change.
	require.Len(t, ka, 9, "retained orphans stay in the set")
}

// TestUpdateKnownAliveSmallOrphanSetNamesAll pins the small-wave shape:
// when every orphan fits the example cap there is no truncation and the
// journal still gets exactly one summary.
func TestUpdateKnownAliveSmallOrphanSetNamesAll(t *testing.T) {
	now := time.Now().UTC()
	ka := map[string]store.KnownAliveRecord{}
	for i := range 3 {
		key := "few-" + string(rune('a'+i))
		ka[key] = store.KnownAliveRecord{Key: key, Host: key + ".example.com", LastSeen: now.Add(-time.Minute)}
	}
	nodeKeys := map[string]bool{}
	cmd := &cobra.Command{}
	var out strings.Builder
	cmd.SetOut(&out)
	opts := probe.Options{KnownAliveTTL: 24 * time.Hour}

	require.NoError(t, updateKnownAliveSet(cmd, opts, ka, nodeKeys, nil, now))

	journal := out.String()
	assert.Equal(t, 1, strings.Count(journal, "entries absent from sources"),
		"one summary line regardless of set size")
	assert.Equal(t, 3, strings.Count(journal, "known-alive but absent from sources"),
		"a small orphan set is fully named inside the cap")
}

// TestUpdateKnownAlivePrunesExpiredOrphans guards the semantics around the
// disclosure: expired entries still leave the set (the TTL rule is
// untouched by the disclosure rework).
func TestUpdateKnownAlivePrunesExpiredOrphans(t *testing.T) {
	now := time.Now().UTC()
	ka := map[string]store.KnownAliveRecord{
		"expired": {Key: "expired", Host: "expired.example.com", LastSeen: now.Add(-100 * 24 * time.Hour)},
		"fresh":   {Key: "fresh", Host: "fresh.example.com", LastSeen: now.Add(-time.Minute)},
	}
	nodeKeys := map[string]bool{}
	cmd := &cobra.Command{}
	cmd.SetOut(&strings.Builder{})
	opts := probe.Options{KnownAliveTTL: 24 * time.Hour}

	require.NoError(t, updateKnownAliveSet(cmd, opts, ka, nodeKeys, nil, now))
	assert.NotContains(t, ka, "expired", "expired orphans are pruned")
	assert.Contains(t, ka, "fresh", "retained orphans stay (and are disclosed, bounded)")
}
