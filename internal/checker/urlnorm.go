package checker

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// NormalizeTarget turns user input into a checked Target. Bare domains get
// https://; scheme and host are lowercased; an explicit default port
// (https:443 / http:80) is dropped. Anything that is not an http(s) URL with
// a host after normalization is rejected loud.
func NormalizeTarget(raw string) (Target, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Target{}, errors.New("check: empty target")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return Target{}, fmt.Errorf("check: target %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Target{}, fmt.Errorf("check: target %q: scheme %q is not http/https", raw, u.Scheme)
	}
	if u.Host == "" {
		return Target{}, fmt.Errorf("check: target %q: no host", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
	}
	return Target{URL: u.String(), Host: u.Hostname()}, nil
}
