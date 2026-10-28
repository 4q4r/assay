package plugins

import "embed"

// Defaults is the SINGLE source of truth for the built-in plugin set: the
// four migrated D9 sources (matin, epodonios, radikal, haker — behavior
// parity with the former Go discovery) plus the StintikVPN reference plugin
// (network-API demo: data.json → subscriptions → nested fetches). They
// materialize into the plugins dir on first run (missing dir → write all;
// existing dir → never touched, owner-editable).
//
//go:embed defaults/*.lua
var Defaults embed.FS
