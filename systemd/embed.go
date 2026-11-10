// Package systemd is the SINGLE source of truth for the assay systemd
// user unit: the .service file in this directory is a Go text template —
// `assay install` renders it (go:embed) into the user unit directory.
// There is no second copy of the unit content anywhere. Since W10 the unit
// is the watch DAEMON; the two W5 timer units are gone (their legacy names
// are cleaned up by install/uninstall for existing users).
package systemd

import "embed"

// Units carries the unit template from this directory.
//
//go:embed assay-watch.service
var Units embed.FS
