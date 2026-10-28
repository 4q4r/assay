// Package cli wires the publicvpn command tree: the W1–W3 stages (fetch,
// parse, filter, probe, geo, select, render, activate, status) and the W4
// maintenance surface (maintain wave with stats poll + pruning).
package cli

import (
	"path/filepath"

	"public_vpn/internal/config"

	"github.com/spf13/cobra"
)

// New builds the root command.
func New() *cobra.Command {
	var cfgPath string
	root := &cobra.Command{
		Use:           "publicvpn",
		Short:         "Third-party public-node location pool pipeline for the owner's xray client",
		SilenceUsage:  true,
		SilenceErrors: false,
		CompletionOptions: cobra.CompletionOptions{
			HiddenDefaultCmd: true,
		},
	}
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "",
		"path to the TOML configuration file (optional — resolution: this path, else "+
			config.HomeConfigDisplay+", else ./config.toml, else built-in defaults; "+
			"one file wins whole, nothing is ever merged)")

	root.AddCommand(
		newFetchCommand(&cfgPath),
		newParseCommand(&cfgPath),
		newFilterCommand(&cfgPath),
		newProbeCommand(&cfgPath),
		newGeoCommand(&cfgPath),
		newSelectCommand(&cfgPath),
		newRenderCommand(&cfgPath),
		newActivateCommand(&cfgPath),
		newStatusCommand(&cfgPath),
		newMaintainCommand(&cfgPath),
		newWatchCommand(&cfgPath),
		newListCommand(&cfgPath),
		newInstallCommand(&cfgPath),
		newUninstallCommand(&cfgPath),
		newCheckCommand(&cfgPath),
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
	geoBase      string
	selection    string
	renderedDir  string
	rendered     string
	backupDir    string
	knifeDB      string
	workDir      string
}

func newPaths(cfg *config.Config) paths {
	dataDir := config.ExpandHome(cfg.DataDir)
	cacheDir := filepath.Join(dataDir, "cache")
	renderedDir := filepath.Join(dataDir, config.ExpandHome(cfg.Render.OutputDir))
	return paths{
		dataDir:      dataDir,
		cacheDir:     cacheDir,
		manifest:     filepath.Join(cacheDir, "manifest.json"),
		nodes:        filepath.Join(dataDir, "nodes.jsonl"),
		filtered:     filepath.Join(dataDir, "filtered.jsonl"),
		probeResults: filepath.Join(dataDir, "probe-results.jsonl"),
		geoBase:      filepath.Join(dataDir, "geo-base.jsonl"),
		selection:    filepath.Join(dataDir, "selection.json"),
		renderedDir:  renderedDir,
		rendered:     filepath.Join(renderedDir, "config.json"),
		backupDir:    filepath.Join(dataDir, config.ExpandHome(cfg.Activate.BackupDir)),
		knifeDB:      filepath.Join(dataDir, config.ExpandHome(cfg.Probe.DBPath)),
		workDir:      filepath.Join(dataDir, "probe-work"),
	}
}
