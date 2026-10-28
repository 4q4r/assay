package checker

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyHTTPStatuses(t *testing.T) {
	t.Parallel()
	body := []byte("<html><body>the real nyaa page, plenty of content to push it over the tiny-body threshold...</body></html>")
	body = append(body, make([]byte, tinyBodyLimit)...)
	cases := []struct {
		name   string
		status int
		body   []byte
		want   Verdict
	}{
		{"200 ok", 200, body, VerdictSuccess},
		{"204 no content", 204, nil, VerdictSuccess},
		{"301 redirect", 301, nil, VerdictSuccess},
		{"404 reachable-but-missing", 404, []byte("not found"), VerdictSuccess},
		{"403 geo-block", 403, body, VerdictBlockedHTTP},
		{"451 legal-block", 451, body, VerdictBlockedHTTP},
		{"429 rate-limit", 429, body, VerdictBlockedHTTP},
		{"500 server", 500, body, VerdictBlockedHTTP},
		{"503 maintenance-or-block", 503, body, VerdictBlockedHTTP},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Classify(tc.status, tc.body)
			require.Equal(t, tc.want, got.Verdict)
		})
	}
}

func TestClassifyBlockpageSignatures(t *testing.T) {
	t.Parallel()
	for _, sig := range []string{
		"Access Denied",
		"ATTENTION REQUIRED",
		"Just a moment...",
		"One more step",
		"unusual traffic from your computer",
		"You have been blocked",
		"request unsuccessful. Error code",
		"error code: 1015",
		"error code: 1020",
		"доступ ограничен",
	} {
		got := Classify(200, []byte("<html>"+sig+"</html>"))
		require.Equal(t, VerdictBlockedPage, got.Verdict, "signature %q must classify blocked-page", sig)
		require.NotEmpty(t, got.Signature)
	}
	// Same signatures inside a large body do NOT flag: a big body means the
	// real page rendered (nyaa.si is behind Cloudflare and mentions it).
	large := append([]byte("<html>padding "), make([]byte, tinyBodyLimit+1)...)
	large = append(large, []byte("attention required by the page footer")...)
	got := Classify(200, large)
	require.Equal(t, VerdictSuccess, got.Verdict)
}

func TestVerdictFor(t *testing.T) {
	t.Parallel()
	canceled := fmt.Errorf(`Get "https://nyaa.si": %w`, context.Canceled)
	cases := []struct {
		name      string
		err       error
		connected bool // httptrace: the tunnel CONNECT already completed
		want      Verdict
	}{
		{"our deadline", staticError("context deadline exceeded"), false, VerdictTimeout},
		{`client timeout`, staticError(`Get "https://nyaa.si": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`), true, VerdictTimeout},
		{"dns", staticError("socks connect tcp 127.0.0.1:18500->nyaa.si:443: lookup nyaa.si: no such host"), false, VerdictDNSFail},
		{"refused pre-connect", staticError("connect: connection refused"), false, VerdictDialFail},
		{"dial timeout pre-connect", staticError("connect: connection timed out"), false, VerdictDialFail},
		{"dial i/o timeout pre-connect", staticError("read tcp 127.0.0.1:1->1.2.3.4:443: i/o timeout"), false, VerdictDialFail},
		{"reset", staticError("connection reset by peer"), false, VerdictDialFail},
		{"eof", staticError("EOF"), false, VerdictDialFail},
		{"no route", staticError("no route to host"), false, VerdictDialFail},
		// Post-connect stalls are NOT dial failures: the node connected fine,
		// the response stalled. The old string-only mapping called every i/o
		// timeout a dial-fail (reviewer finding I2).
		{"read timeout post-connect", staticError("read tcp 127.0.0.1:1->1.2.3.4:443: i/o timeout"), true, VerdictReadTimeout},
		{"stalled headers post-connect", staticError("connect: connection timed out"), true, VerdictReadTimeout},
		// Ctrl-C / context abort is the operator, never a timeout.
		{"canceled", canceled, false, VerdictCanceled},
		{"canceled post-connect", context.Canceled, true, VerdictCanceled},
		{"unknown", staticError("proxy: unknown authentication method"), false, VerdictError},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, verdictFor(tc.err, tc.connected), "%s: error %q", tc.name, tc.err)
	}
}

type staticError string

func (e staticError) Error() string { return string(e) }
