package lockfile

import (
	"fmt"
	"net/url"
	"strings"
)

// PublicHosts are well-known public registry / CDN hostnames. Resolutions to
// these hosts indicate the lockfile is pulling from the public internet rather
// than an internal proxy.
var PublicHosts = map[string]struct{}{
	"registry.npmjs.org":               {},
	"registry.npmjs.com":               {},
	"registry.yarnpkg.com":             {},
	"pypi.org":                         {},
	"pypi.python.org":                  {},
	"files.pythonhosted.org":           {},
	"repo.packagist.org":               {},
	"packagist.org":                    {},
	"proxy.golang.org":                 {},
	"sum.golang.org":                   {},
	"index.crates.io":                  {},
	"static.crates.io":                 {},
	"repo1.maven.org":                  {},
	"central.maven.org":                {},
	"repo.maven.apache.org":            {},
	"rubygems.org":                     {},
	"index.rubygems.org":               {},
	"center.conan.io":                  {},
	"docker.io":                        {},
	"registry-1.docker.io":             {},
	"production.cloudflare.docker.com": {},
}

// skipURLPrefixes are resolution schemes that never go through a package registry.
var skipURLPrefixes = []string{
	"file:", "link:", "workspace:", "portal:",
	"git:", "git+", "github:", "gitlab:", "bitbucket:", "gist:",
	"ssh:", "hg+", "bzr+", "svn+",
}

// Host extracts the lowercase hostname from a resolution URL.
// Returns ("", false) when the value is not an auditable registry URL.
func Host(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	lower := strings.ToLower(raw)
	for _, p := range skipURLPrefixes {
		if strings.HasPrefix(lower, p) {
			return "", false
		}
	}
	// Bare paths / relative refs are not registry resolutions.
	if !strings.Contains(lower, "://") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	return host, true
}

// Violation reports whether a resolved URL violates source policy.
//
// Without expectedHosts, only known public registry hosts are flagged.
// With expectedHosts, any host not in that set is flagged (after skip filters).
func Violation(raw string, expectedHosts []string) (host string, public bool, ok bool) {
	host, auditable := Host(raw)
	if !auditable {
		return "", false, false
	}
	_, isPublic := PublicHosts[host]
	if len(expectedHosts) == 0 {
		if !isPublic {
			return host, false, false
		}
		return host, true, true
	}
	for _, want := range expectedHosts {
		if host == normalizeHost(want) {
			return host, isPublic, false
		}
	}
	return host, isPublic, true
}

// NormalizeHosts parses --expected-host values into lowercase hostnames.
func NormalizeHosts(raw []string) ([]string, error) {
	var out []string
	seen := make(map[string]struct{})
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		h := normalizeHost(r)
		if h == "" {
			return nil, &HostError{Value: r}
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out, nil
}

// HostError is an invalid --expected-host value.
type HostError struct{ Value string }

func (e *HostError) Error() string {
	return fmt.Sprintf("invalid registry host %q", e.Value)
}

func normalizeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
