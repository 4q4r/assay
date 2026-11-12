package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSystemProfilePrefix pins the Windows SYSTEM-profile root table (plan
// §2.2.5): windows resolves <windir>\System32\config\systemprofile — the
// profile the LocalSystem service account owns, whose %LOCALAPPDATA% and
// os.UserHomeDir() answers all live under it. An empty windir falls back to
// the documented Windows root (C:\Windows). Every other GOOS has no SYSTEM
// profile — "" (the caller treats it as "the check cannot apply").
func TestSystemProfilePrefix(t *testing.T) {
	t.Run("windows resolves the systemprofile root under windir", func(t *testing.T) {
		got := SystemProfilePrefix("windows", `C:\Windows`)
		require.NotEmpty(t, got)
		assert.Equal(t, `C:\Windows\System32\config\systemprofile`, got)
	})
	t.Run("empty windir falls back to the documented Windows root", func(t *testing.T) {
		assert.Equal(t, `C:\Windows\System32\config\systemprofile`, SystemProfilePrefix("windows", ""))
	})
	t.Run("non-windows GOOS has no SYSTEM profile", func(t *testing.T) {
		assert.Empty(t, SystemProfilePrefix("linux", `C:\Windows`))
		assert.Empty(t, SystemProfilePrefix("darwin", `C:\Windows`))
	})
}

// TestUnderSystemProfile pins the prefix check that backs the §2.2.5
// fail-closed refusal: a service-context default data dir under the SYSTEM
// profile is refused before anything is created. Windows paths are
// case-insensitive and carry both separators — the check normalizes and
// compares case-insensitively, and refuses an exact-sibling prefix (a dir
// named systemprofile-extra must NOT match).
func TestUnderSystemProfile(t *testing.T) {
	profile := `C:\Windows\System32\config\systemprofile`
	t.Run("data dir directly under the profile matches", func(t *testing.T) {
		assert.True(t, UnderSystemProfile(profile+`\AppData\Local\assay`, profile))
	})
	t.Run("the profile dir itself matches", func(t *testing.T) {
		assert.True(t, UnderSystemProfile(profile, profile))
	})
	t.Run("a user profile dir does not match", func(t *testing.T) {
		assert.False(t, UnderSystemProfile(`C:\Users\u\AppData\Local\assay`, profile))
	})
	t.Run("case-insensitive", func(t *testing.T) {
		assert.True(t, UnderSystemProfile(`c:\windows\system32\config\systemprofile\appdata\local\assay`, profile))
	})
	t.Run("forward slashes normalize to backslashes", func(t *testing.T) {
		assert.True(t, UnderSystemProfile("C:/Windows/System32/config/systemprofile/AppData/Local/assay", profile))
	})
	t.Run("exact-prefix sibling is NOT under the profile", func(t *testing.T) {
		assert.False(t, UnderSystemProfile(profile+`-extra\assay`, profile))
	})
	t.Run("empty prefix never matches (check cannot apply)", func(t *testing.T) {
		assert.False(t, UnderSystemProfile(`C:\x\assay`, ""))
	})
	t.Run("empty path never matches", func(t *testing.T) {
		assert.False(t, UnderSystemProfile("", profile))
	})
}
