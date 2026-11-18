package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mustDuration parses a Go duration string for table literals.
func mustDuration(t *testing.T, s string) time.Duration {
	t.Helper()
	d, err := time.ParseDuration(s)
	require.NoError(t, err, "parse %q", s)
	return d
}

// TestParseByteSize pins the memory_gate_min_avail value grammar: a
// non-negative number with an optional binary unit suffix (Ki/Mi/Gi/Ti/Pi/Ei,
// 1024-based, optional trailing "B"), a bare "B", or no suffix (bytes).
// Decimal SI units (KB/MB/GB) are deliberately NOT accepted — the knob gates
// real host memory bytes, and a decimal/binary unit mix-up would gate on a
// lie. Everything else fails loud (structural check, parse-and-warn loader
// discipline: bad VALUES refuse the load, missing keys take the defaults).
func TestParseByteSize(t *testing.T) {
	const gib = uint64(1) << 30
	tests := []struct {
		in   string
		want uint64
	}{
		{in: "1.5Gi", want: gib / 2 * 3},    // the knob default form
		{in: "1.5GiB", want: gib / 2 * 3},   // optional trailing B
		{in: " 1.5Gi ", want: gib / 2 * 3},  // surrounding space tolerated
		{in: "512Mi", want: 512 << 20},      // Mi
		{in: "64Ki", want: 64 << 10},        // Ki
		{in: "2Ti", want: 2 << 40},          // Ti
		{in: "1Pi", want: 1 << 50},          // Pi
		{in: "4096", want: 4096},            // bare = bytes
		{in: "4096B", want: 4096},           // explicit bytes
		{in: "0", want: 0},                  // zero = the default-means-unset anchor
		{in: "0Gi", want: 0},                // zero with a unit
		{in: "0.25Gi", want: (1 << 30) / 4}, // fractional mantissa
		{in: "1073741824", want: 1 << 30},   // large bare value
	}
	for _, tt := range tests {
		got, err := parseByteSize(tt.in)
		require.NoError(t, err, "parse %q", tt.in)
		require.Equal(t, tt.want, got, "parse %q", tt.in)
	}
}

func TestParseByteSizeErrors(t *testing.T) {
	for _, in := range []string{
		"", "   ", "Gi", "1.5", "-1Gi", "1.5 KB", "1.5GB", "1.5MB", "abc", "1Xi", "1.5GI", "1.5 gib",
		"18446744073709551616", // overflows uint64
	} {
		_, err := parseByteSize(in)
		require.Error(t, err, "parse %q must fail loud", in)
	}
}

// TestByteSizeMarshalRoundTrip pins the TOML round trip: whatever a file
// carries, re-encoding the decoded value must parse back to the same bytes.
func TestByteSizeMarshalRoundTrip(t *testing.T) {
	for _, in := range []string{"1.5Gi", "512Mi", "64Ki", "4096", "0"} {
		v, err := parseByteSize(in)
		require.NoError(t, err, "parse %q", in)
		b := ByteSize{Bytes: v}
		text, err := b.MarshalText()
		require.NoError(t, err, "marshal %q", in)
		back, err := parseByteSize(string(text))
		require.NoError(t, err, "re-parse %q from %q", in, string(text))
		require.Equal(t, v, back, "round trip %q", in)
	}
}

// TestMaintainMemoryGateDefaults pins the knob resolution: absent (nil) →
// the defaults verbatim (floor 1.5Gi, max wait 30m); an explicit zero floor
// means unset (the W6 zero-means-default convention, never "off"); an
// explicit max_wait "0s" STAYS 0 = the gate is disabled entirely (the same
// schedule-level escape hatch as speedtest_interval).
func TestMaintainMemoryGateDefaults(t *testing.T) {
	tests := []struct {
		name        string
		minAvail    *ByteSize
		maxWait     *Duration
		wantFloor   uint64
		wantMaxWait time.Duration
	}{
		{
			name:        "absent → defaults verbatim",
			wantFloor:   DefaultMemoryGateMinAvail,
			wantMaxWait: DefaultMemoryGateMaxWait,
		},
		{
			name:        "explicit zero floor → default (zero means unset)",
			minAvail:    &ByteSize{},
			wantFloor:   DefaultMemoryGateMinAvail,
			wantMaxWait: DefaultMemoryGateMaxWait,
		},
		{
			name:        "explicit values stay verbatim",
			minAvail:    &ByteSize{Bytes: 2 << 30},
			maxWait:     &Duration{Duration: mustDuration(t, "45m")},
			wantFloor:   2 << 30,
			wantMaxWait: mustDuration(t, "45m"),
		},
		{
			name:        "explicit 0s max_wait stays 0 = gate disabled",
			maxWait:     &Duration{},
			wantFloor:   DefaultMemoryGateMinAvail,
			wantMaxWait: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MaintainConfig{MemoryGateMinAvail: tt.minAvail, MemoryGateMaxWait: tt.maxWait}
			applyMaintainDefaults(&m)
			require.NotNil(t, m.MemoryGateMinAvail, "floor must materialize")
			require.Equal(t, tt.wantFloor, m.MemoryGateMinAvail.Bytes)
			require.NotNil(t, m.MemoryGateMaxWait, "max wait must materialize")
			require.Equal(t, tt.wantMaxWait, m.MemoryGateMaxWait.Duration)
		})
	}
}

// TestValidateMaintainMemoryGateNegative pins the structural check: a
// negative memory_gate_max_wait is sign-invalid, loud, named.
func TestValidateMaintainMemoryGateNegative(t *testing.T) {
	valid := func() MaintainConfig {
		return MaintainConfig{
			PruneDeadAfter:     Duration{Duration: 48 * time.Hour},
			RefreshInterval:    Duration{Duration: time.Hour}, // above the 5m floor
			StatsTimeout:       Duration{Duration: 10 * time.Second},
			MemoryGateMinAvail: &ByteSize{Bytes: 1 << 30},
			MemoryGateMaxWait:  &Duration{Duration: 30 * time.Minute},
		}
	}
	negative := valid()
	negative.MemoryGateMaxWait = &Duration{Duration: -1}
	err := validateMaintain(negative)
	require.Error(t, err)
	require.Contains(t, err.Error(), "memory_gate_max_wait", "error must name the knob")
	require.NoError(t, validateMaintain(valid()))
	disabled := valid()
	disabled.MemoryGateMaxWait = &Duration{} // explicit "0s" = the gate disabled — valid
	require.NoError(t, validateMaintain(disabled))
}
