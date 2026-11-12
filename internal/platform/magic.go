package platform

// ExecMagics returns every executable-format magic a binary for goos may
// start with — the self-update verifier's acceptance set (plan Consequence
// C, §5.7): ELF (\x7fELF) on unix, Mach-O (the 32-bit 0xfeedface and 64-bit
// 0xfeedfacf twins) on darwin, PE (the two-byte "MZ" DOS header) on
// windows. The first entry is the platform's canonical magic. Each magic
// must be ≤ 4 bytes: the verifier reads exactly 4 bytes per binary
// (verifyBinary), so a longer entry could never match.
func ExecMagics(goos string) [][]byte {
	switch goos {
	case "windows":
		return [][]byte{{'M', 'Z'}}
	case "darwin":
		return [][]byte{
			{0xcf, 0xfa, 0xed, 0xfe}, // 64-bit Mach-O (0xFEEDFACF little-endian)
			{0xce, 0xfa, 0xed, 0xfe}, // 32-bit Mach-O (0xFEEDFACE little-endian)
		}
	default:
		// linux and every other unix target: ELF.
		return [][]byte{{0x7f, 'E', 'L', 'F'}}
	}
}

// ExecMagic returns the primary executable magic for goos — the pinned
// single-slice accessor over ExecMagics.
func ExecMagic(goos string) []byte {
	return ExecMagics(goos)[0]
}

// ExecFormatName returns the human name of goos's executable format for
// verifier messages: "ELF", "Mach-O", or "PE".
func ExecFormatName(goos string) string {
	switch goos {
	case "windows":
		return "PE"
	case "darwin":
		return "Mach-O"
	default:
		return "ELF"
	}
}
