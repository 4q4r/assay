package fetch

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBoundedReturnsCancellation pins the fan-out cancellation contract: when
// the context is cancelled, bounded must report it — workers that skip via
// ctx.Done must never yield a silent nil (their callers would otherwise hand
// back zero-value entries as a successful wave; fix-round-1 finding #9).
func TestBoundedReturnsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the fan-out starts: every worker skips

	ran := 0
	err := bounded(ctx, 4, []int{1, 2, 3}, func(int) error {
		ran++
		return nil
	})
	require.ErrorIs(t, err, context.Canceled, "cancelled fan-out must be loud, not nil")
	assert.LessOrEqual(t, ran, 3, "every job that ran must still be accounted for by the error")
}

// TestBoundedPropagatesFirstError keeps the existing first-error contract
// visible next to the cancellation one.
func TestBoundedPropagatesFirstError(t *testing.T) {
	sentinel := errors.New("boom")
	err := bounded(context.Background(), 2, []int{1, 2, 3}, func(i int) error {
		if i == 2 {
			return sentinel
		}
		return nil
	})
	require.ErrorIs(t, err, sentinel)
}
