// Package cli wires the assay command tree: the W1–W3 stages (fetch,
// parse, filter, probe, geo, select, render, activate, status) and the W4
// maintenance surface (maintain wave with stats poll + pruning).
package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"assay/internal/config"

	"github.com/spf13/cobra"
)

// Build coordinates injected at link time by goreleaser (see
// .goreleaser.yaml ldflags); these defaults are what plain `go build`
// produces. Commit and Date stay informational; Version alone is the
// release smoke-probe token.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// New builds the root command.
func New() *cobra.Command {
	var cfgPath string
	root := &cobra.Command{
		Use: "assay",
		Short: "Self-held public-node location pool: a managed xray core + local " +
			"proxy inbounds fed by a re-verified third-party node pool",
		SilenceUsage:  true,
		SilenceErrors: false,
		CompletionOptions: cobra.CompletionOptions{
			HiddenDefaultCmd: true,
		},
		Version: fmt.Sprintf("%s (%s) %s", Version, Commit, Date),
	}
	root.SetVersionTemplate("assay {{.Version}}\n")
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "",
		"path to the TOML configuration file (optional — resolution: this path, else "+
			config.ShareConfigDisplay+", else ./config.toml, else built-in defaults; "+
			"one file wins whole, nothing is ever merged)")

	root.AddCommand(
		newFetchCommand(&cfgPath),
		newParseCommand(&cfgPath),
		newFilterCommand(&cfgPath),
		newProbeCommand(&cfgPath),
		newSelectCommand(&cfgPath),
		newRenderCommand(&cfgPath),
		newActivateCommand(&cfgPath),
		newApplyCommand(&cfgPath),
		newStatusCommand(&cfgPath),
		newMaintainCommand(&cfgPath),
		newWatchCommand(&cfgPath),
		newListCommand(&cfgPath),
		newInstallCommand(&cfgPath),
		newUninstallCommand(&cfgPath),
		newCheckCommand(&cfgPath),
		newXrayUpdateCommand(&cfgPath),
	)
	return root
}

// stage paths derived from the config data dir.
type paths struct {
	dataDir      string
	cacheDir     string
	manifest     string
	nodes        string
	filtered     string
	probeResults string
	knownAlive   string
	geoBase      string
	waveState    string
	selection    string
	renderedDir  string
	backupDir    string
	workDir      string
}

func newPaths(cfg *config.Config) paths {
	dataDir := config.ExpandHome(cfg.DataDir)
	cacheDir := filepath.Join(dataDir, "cache")
	// renderedDir is the fixed own-config home (S4: <data>/rendered —
	// live.json and candidate.json live here; there is no path knob).
	renderedDir := filepath.Join(dataDir, "rendered")
	return paths{
		dataDir:      dataDir,
		cacheDir:     cacheDir,
		manifest:     filepath.Join(cacheDir, "manifest.json"),
		nodes:        filepath.Join(dataDir, "nodes.jsonl"),
		filtered:     filepath.Join(dataDir, "filtered.jsonl"),
		probeResults: filepath.Join(dataDir, "probe-results.jsonl"),
		knownAlive:   filepath.Join(dataDir, "known-alive.jsonl"),
		geoBase:      filepath.Join(dataDir, "geo-base.jsonl"),
		waveState:    filepath.Join(dataDir, "wave-state.json"),
		selection:    filepath.Join(dataDir, "selection.json"),
		renderedDir:  renderedDir,
		// backupDir is the FIXED D8 rollback source (S4: the backup-dir knob
		// is retired — the core manager's rollback globs exactly
		// <data>/backups/config.json.bak-<ts>, so the writer must use the
		// same fixed dir; a movable one would break the remedy silently).
		backupDir: filepath.Join(dataDir, "backups"),
		workDir:   filepath.Join(os.TempDir(), "opencode", "probe-work"),
	}
}
