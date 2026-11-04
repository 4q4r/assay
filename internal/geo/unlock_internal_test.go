package geo

import (
	"testing"
	"time"

	"public_vpn/internal/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mkStatus(checkedAt string) *model.MediaUnlockStatus {
	return &model.MediaUnlockStatus{CheckedAt: checkedAt}
}

// TestFreshUnlock boundaries: the 7-day window is judged against CheckedAt
// alone (the hot LRU lease is a separate, much shorter freshness).
func TestFreshUnlock(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second) // RFC3339 has second precision
	stamp := func(offset time.Duration) string {
		return now.Add(offset).Format(time.RFC3339)
	}
	tests := []struct {
		name      string
		checkedAt string
		want      bool
	}{
		{"fresh", stamp(-24 * time.Hour), true},
		{"exactly at TTL", stamp(-UnlockTTL), true},
		{"past TTL", stamp(-UnlockTTL - time.Second), false},
		{"within future skew", stamp(time.Second), true},
		{"too far in the future", stamp(5 * time.Minute), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := freshUnlock(mkStatus(tc.checkedAt), now)
			assert.Equal(t, tc.want, got)
		})
	}
	assert.False(t, freshUnlock(nil, now), "nil verdict = unchecked")
	assert.False(t, freshUnlock(mkStatus(""), now), "empty CheckedAt = never probed")
	assert.False(t, freshUnlock(mkStatus("not-a-time"), now), "unparsable = stale")
}

// TestDefaultUnlockEndpoints pins the production probe URL set (the Phase-1
// wire contract; the test seam overrides these, never the semantics).
func TestDefaultUnlockEndpoints(t *testing.T) {
	ep := defaultUnlockEndpoints()
	require.Equal(t, "https://chatgpt.com/cdn-cgi/trace", ep.ChatGPCTrace)
	require.Equal(t, "https://api.openai.com/compliance/cookie_requirements", ep.ChatGPTCompliance)
	assert.Equal(t, "https://www.netflix.com/title/81280792", ep.NetflixTitleA)
	assert.Equal(t, "https://www.netflix.com/title/70143836", ep.NetflixTitleB)
	assert.Equal(t, "https://www.youtube.com/premium", ep.YouTubePremium)
	assert.Equal(t, "https://www.tiktok.com/", ep.TikTokHome)
	assert.Equal(t, "https://www.tiktok.com/explore", ep.TikTokExplore)
	assert.Equal(t, "https://disney.api.edge.bamgrid.com/devices", ep.DisneyDevices)
	assert.Equal(t, "https://disney.api.edge.bamgrid.com/token", ep.DisneyAuth)
	assert.Equal(t, "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql", ep.DisneyGraphQL)
	assert.Equal(t, "https://ipinfo.io/widget/demo/", ep.IPInfoWidget)
}
