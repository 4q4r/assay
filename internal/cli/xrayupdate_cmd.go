package cli

import (
	"fmt"
	"path/filepath"

	"assay/internal/config"
	"assay/internal/xrayupdate"

	"github.com/spf13/cobra"
)

// newXrayUpdateCommand wires `assay xray-update` (W14, managed-only since
// the self-held-core pivot): fetch the latest Xray-core release, verify its
// published sha256, validate the new binary with `xray run -test`, and
// atomically replace the target — [core].xray_bin (the S1 knob, the managed
// core by default) — with a date-stamped backup of the old binary. The
// update surface is managed-only (S5): the core is user-owned, no
// privileged path exists, and an unwritable target refuses loud before
// anything is applied. The GitHub API host reuses the [fetch].api_base
// mirror knob (one mirror surface for the whole pipeline).
func newXrayUpdateCommand(cfgPath *string) *cobra.Command {
	var (
		checkOnly bool
		binPath   string
		assumeYes bool
	)
	cmd := &cobra.Command{
		Use: "xray-update",
		Short: "Update the managed xray binary: release fetch + sha256 verify + -test gate + " +
			"atomic replace (backup first; an unwritable target is a loud refusal)",
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
	cmd.Flags().StringVar(&binPath, "bin", "", "target binary path override (default: [core].xray_bin — the managed core)")
	cmd.Flags().BoolVar(&assumeYes, "yes", false, "skip the confirmation prompt (required for non-interactive runs)")
	return cmd
}

func runXrayUpdate(cmd *cobra.Command, cfg *config.Config,
	checkOnly bool, binPath string, assumeYes bool, color bool,
) error {
	p := newPaths(cfg)
	// The S1 single binary knob (T5 managed-core path): the manual update
	// targets [core].xray_bin — the managed default <data>/bin/xray or the
	// system override. The retired [activate].xray_bin knob is dead here.
	target := config.ExpandHome(cfg.CoreXrayBin())
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
		return err
	}
	if res != nil && res.Updated {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(),
			"the running core keeps the old binary until its next restart (activate-if-changed, "+
				"a wave's auto-update, or restart the daemon unit)")
	}
	return nil
}
