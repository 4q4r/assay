package cli

import (
	"errors"
	"fmt"
	"path/filepath"

	"public_vpn/internal/config"
	"public_vpn/internal/xrayupdate"

	"github.com/spf13/cobra"
)

// newXrayUpdateCommand wires `publicvpn xray-update` (W14): fetch the latest
// Xray-core release, verify its published sha256, validate the new binary
// with `xray run -test`, and atomically replace [activate].xray_bin with a
// date-stamped backup. A root-owned target prints the EXACT privileged
// commands and exits 1 — never half-applied. The GitHub API host reuses the
// [fetch].api_base mirror knob (one mirror surface for the whole pipeline).
func newXrayUpdateCommand(cfgPath *string) *cobra.Command {
	var (
		checkOnly bool
		binPath   string
		assumeYes bool
	)
	cmd := &cobra.Command{
		Use: "xray-update",
		Short: "Update the managed xray binary: release fetch + sha256 verify + -test gate + " +
			"atomic replace (backup first; unwritable target → exact sudo lines)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			color, err := commandColor(cmd, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			reportConfigSourceStyled(cmd.OutOrStdout(), res, color)
			return runXrayUpdate(cmd, res.Config, checkOnly, binPath, assumeYes, color)
		},
	}
	attachColorFlags(cmd)
	cmd.Flags().BoolVar(&checkOnly, "check", false,
		"report the latest release vs the current binary version; download nothing")
	cmd.Flags().StringVar(&binPath, "bin", "", "target binary path override (default: [activate].xray_bin)")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "skip the confirmation prompt (required for non-interactive runs)")
	return cmd
}

func runXrayUpdate(cmd *cobra.Command, cfg *config.Config,
	checkOnly bool, binPath string, assumeYes bool, color bool,
) error {
	p := newPaths(cfg)
	target := config.ExpandHome(cfg.Activate.XrayBin)
	if binPath != "" {
		target = config.ExpandHome(binPath)
	}
	opts := xrayupdate.Options{
		CheckOnly:  checkOnly,
		TargetPath: target,
		AssumeYes:  assumeYes,
		Color:      color,
		APIBase:    cfg.Fetch.APIBase,
		StagingDir: filepath.Join(p.dataDir, "xray-staged"),
		Stdin:      cmd.InOrStdin(),
		Stdout:     cmd.OutOrStdout(),
		Stderr:     cmd.ErrOrStderr(),
	}
	res, err := xrayupdate.Run(opts)
	if err != nil {
		if errors.Is(err, xrayupdate.ErrPrivilegedTarget) {
			// The error text + exact commands are already on stderr; exit 1
			// via the standard cobra error path, nothing re-printed.
			return err
		}
		return err
	}
	if res != nil && res.Updated {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "restart xray-raw to pick up the new binary (explicit owner action)")
	}
	return nil
}
