//go:build !windows

package cli

// newWinsvcScheduler on non-windows builds hands out the LOUD dead-path
// scheduler: the branch is gated by windowsHost() and never routes here —
// but a scheduler that refuses Available() with a windows-naming reason is
// the honest dead path, never a nil.
//
//nolint:ireturn // the consumer-side lifecycle seam (go-design ruling)
func newWinsvcScheduler() scheduler {
	return newRefusingWinSvcScheduler()
}
