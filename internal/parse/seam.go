// Allocation seam for the parse stage (allocation audit F3): test-scoped
// counters over the stage's full-body copies, full parses, and line-level
// pre-rejects. The instrument exists so a test can PIN the fused
// parse+filter pipeline's copy behavior — the pre-change tree pays 2-3
// full-body copies per fetched body plus one full parse per parsed link;
// the fused tree pays at most one (the base64 decode) plus a full parse
// per SURVIVING link and O(1) work per rejected line.
//
// Production runs with the seam disabled: the hot paths pay one nil-check
// per body and per link, nothing more. Tests install a Seam via WithSeam.

package parse

import "sync/atomic"

// Seam aggregates the F3 counting instrument. Every field is exact and
// deterministic for a given corpus — the assertions live in tests only.
type Seam struct {
	// LinesInvocations counts Lines entries (one per parsed body).
	LinesInvocations atomic.Int64
	// BodyCopies counts full-body string materializations: caller-side
	// string conversions (NoteBodyCopy), the ReplaceAll CRLF pass, and the
	// whole-body base64 decode.
	BodyCopies atomic.Int64
	// FullParses counts Link() invocations — the expensive per-link work
	// (url.Parse, Params map, SHA-256 identity key). The F3 target: one per
	// pre-reject SURVIVOR, not one per accepted-scheme line.
	FullParses atomic.Int64
	// PreRejects counts links rejected at the raw-line prefilter before any
	// per-link allocation ran.
	PreRejects atomic.Int64
}

var activeSeam atomic.Pointer[Seam]

// WithSeam runs fn with a fresh Seam installed and removes it afterwards.
// Not safe for concurrent parse calls — tests only.
func WithSeam(fn func(*Seam)) {
	s := &Seam{}
	activeSeam.Store(s)
	defer activeSeam.Store(nil)
	fn(s)
}

// seam returns the installed instrument or nil (production default).
func seam() *Seam { return activeSeam.Load() }

// NoteBodyCopy records one full-body string materialization made OUTSIDE
// this package (the pipeline's cached-body conversion at the Lines call
// site). It exists so the pre-change RED instrument counts the caller-side
// copy the fused pipeline removes; the call site disappears together with
// the conversion it counts.
func NoteBodyCopy() {
	if s := seam(); s != nil {
		s.BodyCopies.Add(1)
	}
}
