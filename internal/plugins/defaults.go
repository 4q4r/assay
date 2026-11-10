package plugins

import "embed"

// Defaults is the SINGLE source of truth for the built-in plugin set: the
// tracked sample template (the only plugin that ships in-repo — bring your
// own sources for everything else). It satisfies the go:embed glob and is
// compile-load-bearing: a zero-match glob is a build error. Whatever is
// embedded materializes into the plugins dir on first run (missing dir →
// write all; existing dir → never touched, owner-editable). The owner's
// local tree may carry additional untracked plugins in the same dir — embed
// reads disk, so they are embedded locally without being tracked.
//
//go:embed defaults/*.lua
var Defaults embed.FS
