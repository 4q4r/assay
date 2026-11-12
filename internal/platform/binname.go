package platform

// CoreBinaryName returns the managed Xray-core binary's file name for goos
// (the §4.2 path table's "Managed core" row): "xray.exe" on windows (the
// upstream windows release assets ship xray.exe and the update pipeline
// stages it as such), "xray" everywhere else. This table is the single
// source of the name — Review Focus 5: every resolution, update, and
// uninstall path joins through it, never a bare "xray" literal.
func CoreBinaryName(goos string) string {
	if goos == windowsGOOS {
		return "xray.exe"
	}
	return "xray"
}

// AssayBinaryName returns assay's own installed-binary file name for goos
// (the §4.2 path table's "Installed binary" row): "assay.exe" on windows
// (a PE image needs its extension — SCM registration, CreateProcess and
// the copyBinary target all join through this table), "assay" elsewhere.
// The windows-service sibling of CoreBinaryName: one source of the name,
// never a bare literal at a join site.
func AssayBinaryName(goos string) string {
	if goos == windowsGOOS {
		return "assay.exe"
	}
	return "assay"
}
