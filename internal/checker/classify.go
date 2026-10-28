package checker

import (
	"context"
	"errors"
	"strings"
)

// tinyBodyLimit bounds the "tiny body" heuristic: a blockpage masquerading as
// 2xx is tiny (denial stubs are a few hundred bytes); the real page for the
// target is not. Signatures only flag bodies at or below this size.
const tinyBodyLimit = 2048

// blockSignatures are known block/denial page markers (case-insensitive
// substrings), ordered from most to least specific. The list is deliberately
// conservative: a marker inside a large real page must NOT flag it (nyaa.si
// itself sits behind Cloudflare and can legitimately mention it).
var blockSignatures = []string{
	"error code: 1015",                 // Cloudflare rate-limit ban page
	"error code: 1020",                 // Cloudflare Access-rule block page
	"request unsuccessful. error code", // Imperva/Incapsula
	"access to this page has been denied",
	"you have been blocked",
	"attention required",
	"unusual traffic",
	"just a moment",
	"one more step",
	"access denied",
	"доступ ограничен",
	"доступ запрещён",
}

// Classification is the outcome of Classify.
type Classification struct {
	Verdict   Verdict
	Signature string // the matched blockpage signature, if any
}

// Classify maps one HTTP answer onto a verdict:
//   - 2xx/3xx (and other 4xx: 404/401 mean the site answered — reachable)
//     are success, UNLESS a tiny body carries a blockpage signature;
//   - 403/451/429/5xx are blocked-http (never silently success).
func Classify(status int, body []byte) Classification {
	if status >= 500 || status == 403 || status == 451 || status == 429 {
		return Classification{Verdict: VerdictBlockedHTTP}
	}
	if len(body) <= tinyBodyLimit {
		lower := strings.ToLower(string(body))
		for _, sig := range blockSignatures {
			if strings.Contains(lower, sig) {
				return Classification{Verdict: VerdictBlockedPage, Signature: sig}
			}
		}
	}
	return Classification{Verdict: VerdictSuccess}
}

// verdictFor maps a transport-level error onto a verdict class, honoring the
// httptrace phase. The classes are diagnostic, not exact: they separate the
// actionable groups (node cannot resolve the target / node egress failed /
// response stalled / our deadline / operator abort) with an "error" catch-all
// that is never silently hidden.
//
// The timeout family splits honestly by phase: an i/o timeout BEFORE the
// tunnel connected is a dial failure (the node's egress never came up); the
// same timeout AFTER connect is a stalled response READ — the node connected
// fine, so "dial-fail" would misdiagnose it. A canceled context is the
// operator (Ctrl-C), never a timeout of any kind.
func verdictFor(err error, connected bool) Verdict {
	if err == nil {
		return VerdictSuccess
	}
	if errors.Is(err, context.Canceled) {
		return VerdictCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return VerdictTimeout
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "context deadline exceeded"),
		strings.Contains(msg, "client.timeout exceeded"):
		return VerdictTimeout
	case strings.Contains(msg, "no such host"),
		strings.Contains(msg, "lookup "),
		strings.Contains(msg, "dns"):
		return VerdictDNSFail
	case strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "connection timed out"):
		if connected {
			return VerdictReadTimeout
		}
		return VerdictDialFail
	case strings.Contains(msg, "refused"),
		strings.Contains(msg, "unreachable"),
		strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "general failure"),
		strings.Contains(msg, "reset by peer"),
		strings.Contains(msg, "eof"),
		strings.Contains(msg, "broken pipe"):
		return VerdictDialFail
	default:
		return VerdictError
	}
}
