package install

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// managedCoreLayout plants the D4 managed-core layout inside a data dir.
func managedCoreLayout(t *testing.T, dataDir string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(dataDir, "bin"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "bin", "xray"), []byte("CORE"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dataDir, "share", "xray"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "share", "xray", "geoip.dat"), []byte("GEOIP"), 0o644))
}

// TestUninstallRemovesManagedCoreArtifacts pins the D4 teardown inside the
// install package: the managed core binary and the managed asset dir are
// removed, the empty parent dirs are tidied, and NOTHING ELSE in the data
// dir is touched (that is --purge's explicit job).
func TestUninstallRemovesManagedCoreArtifacts(t *testing.T) {
	home := t.TempDir()
	unitDir := filepath.Join(home, "units")
	dataDir := filepath.Join(home, "data")
	managedCoreLayout(t, dataDir)
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "nodes.jsonl"), []byte("{}\n"), 0o600))

	res, err := Uninstall(UninstallOptions{
		UnitDir:            unitDir,
		Exec:               &fakeExecutor{},
		ManagedCoreDataDir: dataDir,
	})
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(dataDir, "bin", "xray"))
	assert.True(t, os.IsNotExist(err), "the managed core binary is removed")
	_, err = os.Stat(filepath.Join(dataDir, "share", "xray"))
	assert.True(t, os.IsNotExist(err), "the managed asset dir is removed")
	_, err = os.Stat(filepath.Join(dataDir, "nodes.jsonl"))
	require.NoError(t, err, "user pipeline data is untouched by the core removal")

	assert.Contains(t, res.CoreRemoved, filepath.Join(dataDir, "bin", "xray"))
	assert.Contains(t, res.CoreRemoved, filepath.Join(dataDir, "share", "xray"))
}

// TestUninstallCoreRemovalToleratesAbsent: a data dir with no managed core
// (never installed, or already removed) is the clean no-op — no error, no
// bogus report.
func TestUninstallCoreRemovalToleratesAbsent(t *testing.T) {
	home := t.TempDir()
	res, err := Uninstall(UninstallOptions{
		UnitDir:            filepath.Join(home, "units"),
		Exec:               &fakeExecutor{},
		ManagedCoreDataDir: filepath.Join(home, "data"),
	})
	require.NoError(t, err)
	assert.Empty(t, res.CoreRemoved, "nothing removed when nothing exists")

	// An empty data-dir string means "nothing to remove" — never a guess at
	// the caller's cwd.
	res, err = Uninstall(UninstallOptions{
		UnitDir: filepath.Join(home, "units"),
		Exec:    &fakeExecutor{},
	})
	require.NoError(t, err)
	assert.Empty(t, res.CoreRemoved)
}
