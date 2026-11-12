package install

// Portable shared test helpers for the install package. S4 extracted
// fakeExecutor from install_internal_test.go (`//go:build unix`) so the
// untagged suites that consume it (install_core, scheduler_impl) compile
// and run on the darwin/windows CI legs too. Everything here is
// OS-portable: recorded calls and temp dirs, no unix syscalls, no
// shell-script fixtures, no file-mode pins.

// fakeExecutor records every invocation; tests never execute systemctl.
type fakeExecutor struct {
	calls [][]string
	fail  error
}

func (f *fakeExecutor) Systemctl(args ...string) error {
	if f.fail != nil {
		return f.fail
	}
	f.calls = append(f.calls, args)
	return nil
}
