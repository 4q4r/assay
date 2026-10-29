package checker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDownloadWindowCountsBytes pins the probe speedtest primitive (W14):
// a GET through the tunnel counts the bytes received within the time window.
// A window that expires mid-stream is a NORMAL measurement end (bytes so
// far, no error) — a throughput sample never needs the whole file.
func TestDownloadWindowCountsBytes(t *testing.T) {
	payload := strings.Repeat("x", 128*1024) // 128 KB
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer site.Close()

	socks := newSocksServerForward(t, site.Listener.Addr().String()) // raw host:port relay
	tc := NewTunnelClient(socks.addr(), 5*time.Second)

	got, elapsed, err := tc.DownloadWindow(context.Background(), site.URL, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, int64(len(payload)), got, "a file smaller than the window is downloaded whole")
	assert.Positive(t, elapsed, "elapsed is the measured sample window")
}

// TestDownloadWindowExpiresMidStream pins the window semantics: an endless
// stream and a short window end WITHOUT error, returning the bytes received
// so far — the caller computes bytes/time from exactly this sample.
func TestDownloadWindowExpiresMidStream(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		assert.True(t, ok)
		chunk := strings.Repeat("y", 16*1024)
		for {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
			flusher.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer site.Close()

	socks := newSocksServerForward(t, site.Listener.Addr().String()) // raw host:port relay
	tc := NewTunnelClient(socks.addr(), 2*time.Second)

	got, elapsed, err := tc.DownloadWindow(context.Background(), site.URL, 150*time.Millisecond)
	require.NoError(t, err, "window expiry is a normal measurement end, never an error")
	assert.Positive(t, got, "bytes received inside the window are the sample")
	assert.LessOrEqual(t, elapsed, 2*time.Second, "the window bounds the download")
}

// TestDownloadWindowMustBePositive pins the structural guard: a non-positive
// window would measure nothing — it fails loud instead.
func TestDownloadWindowMustBePositive(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer site.Close()
	socks := newSocksServerForward(t, site.URL)
	tc := NewTunnelClient(socks.addr(), time.Second)
	_, _, err := tc.DownloadWindow(context.Background(), site.URL, 0)
	require.Error(t, err)
	assert.ErrorIs(t, err, errDownloadWindow)
}

// TestDownloadWindowTransportFailureIsLoud pins the failure path: when the
// tunnel cannot carry the request at all, the caller gets an error (and zero
// bytes) — a silent 0 B/s sample would masquerade as a measured dead node.
func TestDownloadWindowTransportFailureIsLoud(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer site.Close()
	tc := NewTunnelClient("127.0.0.1:1", 2*time.Second) // port 1: nothing listens, CONNECT fails

	_, _, err := tc.DownloadWindow(context.Background(), site.URL, time.Second)
	require.Error(t, err)
}
