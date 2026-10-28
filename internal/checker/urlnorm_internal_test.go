package checker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeTarget(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		url  string
		host string
	}{
		{"bare domain gets https", "nyaa.si", "https://nyaa.si", "nyaa.si"},
		{"bare domain with path", "nyaa.si/torrents", "https://nyaa.si/torrents", "nyaa.si"},
		{"https url unchanged", "https://nyaa.si/", "https://nyaa.si/", "nyaa.si"},
		{"http url kept", "http://example.com/a?b=1", "http://example.com/a?b=1", "example.com"},
		{"scheme and host lowercased", " HTTPS://NYAA.SI/Page ", "https://nyaa.si/Page", "nyaa.si"},
		{"default port dropped", "https://nyaa.si:443/t", "https://nyaa.si/t", "nyaa.si"},
		{"explicit port kept", "http://example.com:8080/", "http://example.com:8080/", "example.com"},
		{"query preserved", "example.com?q=site:check", "https://example.com?q=site:check", "example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeTarget(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.url, got.URL)
			require.Equal(t, tc.host, got.Host)
		})
	}
}

func TestNormalizeTargetRejects(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"", "   ", "ftp://example.com", "https://", "://nope", "not a url\x00"} {
		_, err := NormalizeTarget(raw)
		require.Error(t, err, "input %q must be rejected", raw)
	}
}
