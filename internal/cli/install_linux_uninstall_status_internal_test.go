//go:build linux

package cli

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"assay/internal/install"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The linux uninstall/status scheduler routing (plan §3.3 + S3 review P2-2):
// `assay uninstall` routes to the HOLDER's scheduler for a non-systemd
// registration — the holder knows its own artifacts, so the install
// refusal's `assay uninstall` advice is literally true — and status renders
// the holding scheduler's state. A systemd holder (or an unregistered host)
// keeps the generic systemd paths byte-identical. The tests drive the CLI
// seam with fakes — the cobra layer never touches /proc, sv, rc-*, s6-*, or
// crontab.

// withLinuxHolder swaps the linux holder-routing seam and restores it after
// the test (sched == nil = the generic systemd path).
func withLinuxHolder(t *testing.T, sched scheduler) {
	t.Helper()
	oldHost, oldHolder := linuxHost, linuxHolderScheduler
	linuxHost = func() bool { return true }
	linuxHolderScheduler = func(string) scheduler { return sched }
	t.Cleanup(func() {
		linuxHost = oldHost
		linuxHolderScheduler = oldHolder
	})
}

// linuxRoutingFixture builds the config + paths the routing tests drive
// (the same wave-config shape the linux install tests use).
func linuxRoutingFixture(t *testing.T) (string, string) {
	t.Helper()
	home := t.TempDir()
	return writeWaveConfig(t, home, 8*time.Hour, 240*time.Hour), home
}

// TestUninstallLinuxRoutesToEachNonSystemdHolder pins the P2-2 routing per
// holder: runit, openrc, s6, and cron holders all reach THEIR scheduler's
// tested Uninstall with the managed-core data dir and the purge passthrough,
// while the generic systemd path stays untouched (zero systemctl calls).
func TestUninstallLinuxRoutesToEachNonSystemdHolder(t *testing.T) {
	for name, holder := range map[string]*fakeScheduler{
		install.SchedulerRunit:  {name: install.SchedulerRunit, uninstallRes: install.UninstallResult{DisabledUnits: []string{"assay-watch"}, RemovedUnits: []string{"assay-watch (service dir)"}}},
		install.SchedulerOpenRC: {name: install.SchedulerOpenRC, uninstallRes: install.UninstallResult{DisabledUnits: []string{"assay-watch"}, RemovedUnits: []string{"assay-watch"}}},
		install.SchedulerS6:     {name: install.SchedulerS6, uninstallRes: install.UninstallResult{DisabledUnits: []string{"assay-watch"}, RemovedUnits: []string{"assay-watch (service dir)"}}},
		install.SchedulerCron:   {name: install.SchedulerCron, uninstallRes: install.UninstallResult{RemovedUnits: []string{"crontab (@reboot assay-watch)"}}},
	} {
		t.Run(name, func(t *testing.T) {
			cfgPath, home := linuxRoutingFixture(t)
			ex := &fakeCtl{}
			withLinuxHolder(t, holder)
			buf := &bytes.Buffer{}
			require.NoError(t, runUninstall(buf, mustLoad(t, cfgPath), cfgPath, func() uninstallOptions {
				o := uninstallOptions{unitDir: filepath.Join(home, "units"), purge: true}
				o.exec = ex
				return o
			}()))
			// The holder's scheduler owned the teardown: the spec carries the
			// data dir (managed-core teardown) and the purge passthrough.
			assert.Equal(t, filepath.Join(home, "data"), holder.uninstallSpec.DataDir)
			assert.Equal(t, cfgPath, holder.uninstallSpec.PurgeConfigPath)
			assert.Equal(t, filepath.Join(home, "data"), holder.uninstallSpec.PurgeDataDir)
			assert.Empty(t, ex.calls, "the generic systemd path must stay untouched on the routed path")
			out := buf.String()
			assert.Contains(t, out, holder.uninstallRes.RemovedUnits[0], "the holder's teardown result renders")
			assert.NotContains(t, out, "user data kept", "--purge suppresses the keep line")
		})
	}
}

func TestUninstallLinuxSystemdHolderKeepsGenericPath(t *testing.T) {
	cfgPath, home := linuxRoutingFixture(t)
	ex := &fakeCtl{}
	withLinuxHolder(t, nil) // systemd holder / unregistered → the generic path
	buf := &bytes.Buffer{}
	require.NoError(t, runUninstall(buf, mustLoad(t, cfgPath), cfgPath, func() uninstallOptions {
		o := uninstallOptions{unitDir: filepath.Join(home, "units")}
		o.exec = ex
		return o
	}()))
	// The generic systemd teardown ran exactly as before (no units present:
	// every known unit reports absent; no purge → the keep line prints).
	out := buf.String()
	assert.Contains(t, out, "unit absent:      assay-watch.service (already clean)")
	assert.Contains(t, out, "user data kept")
	assert.Empty(t, ex.calls, "nothing to disable — no unit files exist in the fixture dir")
}

// TestStatusLinuxRendersHoldingSchedulerState pins the P2-2 status routing:
// the holding scheduler's Status note renders verbatim (the honest probe
// output — never a guess), next to the installed-binary line the generic
// section also carries. The systemd unit-dir inspection stays out.
func TestStatusLinuxRendersHoldingSchedulerState(t *testing.T) {
	_, home := linuxRoutingFixture(t)
	runit := &fakeScheduler{
		name: install.SchedulerRunit,
		status: install.SchedulerStatus{
			Active: true,
			Note:   "sv status: Run: 4242 900 — supervision: runsv restart-on-exit (1s backoff); logs unrotated",
		},
	}
	withLinuxHolder(t, runit)
	buf := &bytes.Buffer{}
	printInstallStatus(buf, nil, "", filepath.Join(home, "bin"), filepath.Join(home, "units"), false)
	out := buf.String()
	assert.Contains(t, out, "install:")
	assert.Contains(t, out, "binary:")
	assert.Contains(t, out, "runit — sv status: Run: 4242 900", "the holder's state renders under its name")
	assert.NotContains(t, out, "watch daemon not rendered", "the systemd unit-dir inspection stays out of the scheduler branch")
}

func TestStatusLinuxInactiveHolderRendersTheHonestNote(t *testing.T) {
	_, home := linuxRoutingFixture(t)
	cron := &fakeScheduler{
		name: install.SchedulerCron,
		status: install.SchedulerStatus{
			Active: false,
			Note:   "no @reboot assay-watch line in the user crontab (run `assay install`)",
		},
	}
	withLinuxHolder(t, cron)
	buf := &bytes.Buffer{}
	printInstallStatus(buf, nil, "", filepath.Join(home, "bin"), filepath.Join(home, "units"), false)
	assert.Contains(t, buf.String(), "no @reboot assay-watch line")
}

func TestStatusLinuxSystemdHolderKeepsGenericSection(t *testing.T) {
	_, home := linuxRoutingFixture(t)
	withLinuxHolder(t, nil) // systemd holder / unregistered → the generic section
	buf := &bytes.Buffer{}
	printInstallStatus(buf, nil, "", filepath.Join(home, "bin"), filepath.Join(home, "units"), false)
	assert.Contains(t, buf.String(), "watch daemon not rendered", "the generic section is byte-identical")
}

// TestLinuxHolderSchedulerBuildsTheHolderScheduler pins the production
// builder: each holder name constructs ITS scheduler wired to the scanned
// artifact location (runit/s6/openrc carry <dir>/assay-watch — the parent is
// the service dir / scandir / init dir; cron needs no location), and a
// systemd holder or an unknown name builds nothing (the generic path).
func TestLinuxHolderSchedulerBuildsTheHolderScheduler(t *testing.T) {
	s := newLinuxHolderScheduler(install.SchedulerRunit, "/home/u/service/assay-watch")
	rs, ok := s.(*install.RunitScheduler)
	require.True(t, ok)
	assert.Equal(t, "/home/u/service", rs.ServiceDir)

	s = newLinuxHolderScheduler(install.SchedulerOpenRC, "/home/u/.config/rc/init.d/assay-watch")
	osched, ok := s.(*install.OpenRCScheduler)
	require.True(t, ok)
	assert.Equal(t, "/home/u/.config/rc/init.d", osched.InitDir)

	s = newLinuxHolderScheduler(install.SchedulerS6, "/home/u/scandir/assay-watch")
	ssched, ok := s.(*install.S6Scheduler)
	require.True(t, ok)
	assert.Equal(t, "/home/u/scandir", ssched.ScanDir)

	s = newLinuxHolderScheduler(install.SchedulerCron, "user crontab (@reboot assay-watch)")
	_, ok = s.(*install.CronScheduler)
	require.True(t, ok, "the cron holder needs no location")

	assert.Nil(t, newLinuxHolderScheduler(install.SchedulerSystemd, "/units/assay-watch"),
		"the systemd holder keeps the generic path")
	assert.Nil(t, newLinuxHolderScheduler("", ""), "an unregistered host keeps the generic path")
	assert.Nil(t, newLinuxHolderScheduler("mystery", "/x"), "an unknown holder builds nothing")
}

// TestLinuxHolderSchedulerResolvesThroughTheProbe pins the production
// composition: the seam asks the probe for the holder and builds the
// holder's scheduler from the holder name + artifact location (the holder,
// NOT the detected scheduler — a runit registration is removed by the runit
// scheduler even when detection currently reports cron).
func TestLinuxHolderSchedulerResolvesThroughTheProbe(t *testing.T) {
	oldProbe := linuxSchedulerProbe
	linuxSchedulerProbe = func(string) (install.Scheduler, string, string) {
		return &fakeScheduler{name: install.SchedulerCron}, install.SchedulerRunit, "/home/u/service/assay-watch"
	}
	t.Cleanup(func() { linuxSchedulerProbe = oldProbe })

	s := linuxHolderScheduler("/units")
	rs, ok := s.(*install.RunitScheduler)
	require.True(t, ok, "the HOLDER's scheduler is built, not the detected one")
	assert.Equal(t, "/home/u/service", rs.ServiceDir)

	linuxSchedulerProbe = func(string) (install.Scheduler, string, string) {
		return &fakeScheduler{name: install.SchedulerSystemd}, install.SchedulerSystemd, "/units/assay-watch"
	}
	assert.Nil(t, linuxHolderScheduler("/units"), "a systemd holder keeps the generic path")

	linuxSchedulerProbe = func(string) (install.Scheduler, string, string) {
		return &fakeScheduler{name: install.SchedulerForeground}, "", ""
	}
	assert.Nil(t, linuxHolderScheduler("/units"), "an unregistered host keeps the generic path")
}
