// Package npm checks package-name existence on the public npm registry.
package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/omni-line/omni-audit/internal/registry"
)

// DefaultBaseURL is the public npm registry.
const DefaultBaseURL = "https://registry.npmjs.org"

// Uppercase is accepted because legacy packages (e.g. JSONStream) still use it.
var nameRe = regexp.MustCompile(`(?i)^(?:@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$`)

var scopeRe = regexp.MustCompile(`(?i)^[a-z0-9~][a-z0-9._~-]*$`)

const maxNameLen = 214

// Client checks package existence on the npm registry.
type Client struct {
	BaseURL string
	Prober  *registry.Prober
}

// New returns a Client for the public npm registry.
func New(p *registry.Prober) *Client {
	return &Client{BaseURL: DefaultBaseURL, Prober: p}
}

// ValidName reports whether name is a syntactically valid npm package name.
func ValidName(name string) bool {
	return len(name) <= maxNameLen && nameRe.MatchString(name)
}

// Scope returns the npm scope (without '@') for a scoped package name.
func Scope(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if !strings.HasPrefix(name, "@") {
		return "", false
	}
	i := strings.IndexByte(name, '/')
	if i <= 1 {
		return "", false
	}
	scope := name[1:i]
	if !scopeRe.MatchString(scope) {
		return "", false
	}
	return scope, true
}

// Exists implements registry.Checker.
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	if !ValidName(name) {
		return registry.Unknown, registry.InvalidNameError("npm", name)
	}
	// Scoped packages are requested as /@scope%2Fname.
	return c.Prober.Probe(ctx, strings.TrimRight(c.BaseURL, "/")+"/"+url.PathEscape(name))
}

// ScopeExists reports whether any package is published under @scope/.
//
// Uses the unauthenticated search index (text=@scope/). A miss is treated as
// NotFound only when the response is well-formed and empty after filtering
// to packages whose names start with @scope/; otherwise Unknown so callers
// do not silently treat an index lag or parse error as an unclaimed scope.
func (c *Client) ScopeExists(ctx context.Context, scope string) (registry.Status, error) {
	scope = strings.TrimSpace(scope)
	if !scopeRe.MatchString(scope) {
		return registry.Unknown, registry.InvalidNameError("npm", "@"+scope)
	}
	prefix := "@" + strings.ToLower(scope) + "/"
	q := url.Values{"text": {"@" + scope + "/"}, "size": {"20"}}
	rawURL := strings.TrimRight(c.BaseURL, "/") + "/-/v1/search?" + q.Encode()
	body, st, err := c.Prober.Fetch(ctx, rawURL)
	if err != nil || st != registry.Exists {
		if st == registry.NotFound {
			// Search endpoint should not 404; treat as unknown.
			return registry.Unknown, fmt.Errorf("npm scope search: unexpected HTTP status")
		}
		return registry.Unknown, err
	}
	var resp struct {
		Objects []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return registry.Unknown, fmt.Errorf("npm scope search: decode: %w", err)
	}
	for _, o := range resp.Objects {
		if strings.HasPrefix(strings.ToLower(o.Package.Name), prefix) {
			return registry.Exists, nil
		}
	}
	return registry.NotFound, nil
}

// PackageURL returns the human-facing page for name on npmjs.com.
func PackageURL(name string) string {
	return "https://www.npmjs.com/package/" + name
}
