package platform

// CoreBinaryName returns the managed Xray-core binary's file name for goos
// (the §4.2 path table's "Managed core" row): "xray.exe" on windows (the
// upstream windows release assets ship xray.exe and the update pipeline
// stages it as such), "xray" everywhere else. This table is the single
// source of the name — Review Focus 5: every resolution, update, and
// uninstall path joins through it, never a bare "xray" literal.
func CoreBinaryName(goos string) string {
	if goos == "windows" {
		return "xray.exe"
	}
	return "xray"
}
