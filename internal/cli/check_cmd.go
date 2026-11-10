package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"assay/internal/checker"
	"assay/internal/config"
	"assay/internal/render"
	"assay/internal/ui"

	"github.com/spf13/cobra"
)

// checkFlags is the CLI surface of `assay check` (W8). All knobs are
// CLI-side; no config-schema keys were added (flags carry sensible defaults,
// structural validation only — owner ruling).
type checkFlags struct {
	countries   string
	limit       int
	attempts    int
	timeout     time.Duration
	top         int
	concurrency int
	withDead    bool
	color       string
	noColor     bool
	save        string
}

func newCheckCommand(cfgPath *string) *cobra.Command {
	var f checkFlags
	cmd := &cobra.Command{
		Use:   "check <url|domain>...",
		Short: "Site-to-location check: rank pool nodes by how well they serve the given URLs (read-only, out-of-band)",
		Long: `Probes the given URLs THROUGH each pool node — one temporary single-node
xray instance per node (socks on 127.0.0.1, resolution at the EXIT, socks5h
semantics) — and ranks countries/cities by success rate, latency and speed,
so pool_routes matching rules can be aimed at the locations that actually
serve the site (blockpage answers are classified, never counted as success).

READ-ONLY by construction: the cold base and the live client are never
touched, nothing is rendered or activated, all dialing is out-of-band.
Liveness and exit classification come from the LAST probe wave — re-run ` + "`assay probe`" + `
(classification is merged into the probe pass, or ` + "`assay maintain`" + ` for a
full wave) for freshness; a staleness hint prints when data is older than
geo.ttl.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := resolveCommand(*cfgPath)
			if err != nil {
				return err
			}
			reportConfigSource(cmd.OutOrStdout(), res)
			return runCheck(cmd, res.Config, args, f)
		},
	}
	cmd.Flags().StringVar(&f.countries, "countries", "",
		"comma-separated ISO country codes to filter the pool (e.g. \"NL,DE\")")
	cmd.Flags().IntVar(&f.limit, "limit", 0,
		"max nodes to test (0 = all alive nodes, capped at 60)")
	cmd.Flags().IntVar(&f.attempts, "attempts", checker.DefaultAttempts,
		"HTTP attempts per node per URL")
	cmd.Flags().DurationVar(&f.timeout, "timeout", checker.DefaultTimeout,
		"per-request timeout")
	cmd.Flags().IntVar(&f.top, "top", 10, "geo-summary/recommendation rows per block")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", checker.DefaultConcurrency,
		"parallel temp xray instances (each is a full process — keep modest)")
	cmd.Flags().BoolVar(&f.withDead, "with-dead", false,
		"include nodes not alive in the last probe")
	cmd.Flags().StringVar(&f.color, "color", "auto",
		"colorize output: auto (terminal-detected), always, never")
	cmd.Flags().BoolVar(&f.noColor, "no-color", false,
		"deprecated alias for --color=never (NO_COLOR env is honored too)")
	cmd.Flags().StringVar(&f.save, "save", "",
		"write the JSON report under the data dir (relative path) or at an absolute path")
	return cmd
}

// resolveColor applies the --color mode contract — the CLI seam delegates
// to the ui package (W18: ONE color-contract implementation for every
// screen). The --no-color alias is kept for muscle memory and wins over a
// conflicting --color — the explicit "off" is the safer reading of
// contradictory input.
func resolveColor(mode string, noColor bool, out io.Writer) (bool, error) {
	return ui.Resolve(mode, noColor, out)
}

// writerIsTerminal reports whether w is a character device (a TTY). A
// non-file writer (pipes, buffers, tests) is never a terminal.
func writerIsTerminal(w io.Writer) bool { return ui.WriterIsTerminal(w) }

func runCheck(cmd *cobra.Command, cfg *config.Config, targets []string, f checkFlags) error {
	p := newPaths(cfg)
	out := cmd.OutOrStdout()
	color, err := resolveColor(f.color, f.noColor, out)
	if err != nil {
		return err
	}
	opts := checker.Options{
		Targets:          targets,
		Countries:        splitCountries(f.countries),
		Limit:            f.limit,
		Attempts:         f.attempts,
		Timeout:          f.timeout,
		Concurrency:      f.concurrency,
		WithDead:         f.withDead,
		XrayBin:          config.ExpandHome(cfg.Activate.XrayBin),
		GeoBasePath:      p.geoBase,
		ProbeResultsPath: p.probeResults,
		NodesPath:        p.filtered,
		GeoTTL:           cfg.Geo.TTL.Duration,
		WorkDir:          p.workDir,
		Render: render.Config{
			TCPMaxSeg:      cfg.Render.TCPMaxSeg,
			TLSFingerprint: cfg.Render.TLSFingerprint,
		},
		Progress: cmd.ErrOrStderr(),
	}
	report, err := checker.Run(cmd.Context(), opts)
	if err != nil {
		return err
	}
	rendered := checker.RenderReport(report, checker.RenderOptions{Color: color, Top: f.top})
	_, _ = fmt.Fprint(out, rendered)
	if f.save != "" {
		path := f.save
		if !filepath.IsAbs(path) {
			path = filepath.Join(p.dataDir, path)
		}
		if err := writeReportJSON(path, report); err != nil {
			return fmt.Errorf("save report: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "report saved: %s\n", path)
	}
	return nil
}

// splitCountries parses the --countries list; empty input → nil (no filter).
func splitCountries(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// writeReportJSON writes the report atomically (temp + rename) so a reader
// never observes a half-written file.
func writeReportJSON(path string, report any) error {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".check-report-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
