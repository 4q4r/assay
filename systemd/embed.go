// Package systemd is the SINGLE source of truth for the publicvpn systemd
// user units: the .service/.timer files in this directory are Go text
// templates — `publicvpn install` renders them (go:embed) into the user unit
// directory. There is no second copy of the unit content anywhere.
package systemd

import "embed"

// Units carries the four unit templates from this directory.
//
//go:embed public_vpn-refresh.service public_vpn-refresh.timer public_vpn-speedtest.service public_vpn-speedtest.timer
var Units embed.FS
