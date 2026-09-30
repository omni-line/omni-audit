// Package npm checks package-name existence on the public npm registry.
package npm

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/omni-line/omni-audit/internal/registry"
)

// DefaultBaseURL is the public npm registry.
const DefaultBaseURL = "https://registry.npmjs.org"

// Uppercase is accepted because legacy packages (e.g. JSONStream) still use it.
var nameRe = regexp.MustCompile(`(?i)^(?:@[a-z0-9~][a-z0-9._~-]*/)?[a-z0-9~][a-z0-9._~-]*$`)

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

// Exists implements registry.Checker.
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	if !ValidName(name) {
		return registry.Unknown, registry.InvalidNameError("npm", name)
	}
	// Scoped packages are requested as /@scope%2Fname.
	return c.Prober.Probe(ctx, strings.TrimRight(c.BaseURL, "/")+"/"+url.PathEscape(name))
}

// PackageURL returns the human-facing page for name on npmjs.com.
func PackageURL(name string) string {
	return "https://www.npmjs.com/package/" + name
}
