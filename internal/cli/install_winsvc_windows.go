//go:build windows

package cli

import "assay/internal/install"

// newWinsvcScheduler is the production windows scheduler factory (the
// GOOS-split half install_cmd.go's seam var resolves to): the mgr-backed
// WinSvcScheduler with its pinned SCM surface.
//
//nolint:ireturn // the consumer-side lifecycle seam (go-design ruling)
func newWinsvcScheduler() scheduler {
	return install.NewProductionWinSvcScheduler()
}
