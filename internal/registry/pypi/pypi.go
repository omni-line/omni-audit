// Package pypi checks project-name existence on the Python Package Index.
package pypi

import (
	"context"
	"regexp"
	"strings"

	"github.com/omni-line/omni-audit/internal/registry"
)

// DefaultBaseURL is the public PyPI instance.
const DefaultBaseURL = "https://pypi.org"

var (
	// nameRe is the PEP 508 project-name grammar.
	nameRe = regexp.MustCompile(`(?i)^([a-z0-9]|[a-z0-9][a-z0-9._-]*[a-z0-9])$`)
	sepRe  = regexp.MustCompile(`[-_.]+`)
)

// Client checks project existence on PyPI.
type Client struct {
	BaseURL string
	Prober  *registry.Prober
}

// New returns a Client for public PyPI.
func New(p *registry.Prober) *Client {
	return &Client{BaseURL: DefaultBaseURL, Prober: p}
}

// Normalize applies PEP 503 normalization: lowercase, runs of -_. become "-".
func Normalize(name string) string {
	return sepRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

// ValidName reports whether name is a valid PEP 508 project name.
func ValidName(name string) bool {
	return nameRe.MatchString(name)
}

// Exists implements registry.Checker.
//
// Primary check is /pypi/<name>/json. Projects that are registered but have
// no releases (or whose releases were all deleted) return 404 from the JSON
// API while still appearing on the Simple API (/simple/<name>/, PEP 503).
// Those names are owned, so a JSON 404 falls back to the Simple index.
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	if !ValidName(name) {
		return registry.Unknown, registry.InvalidNameError("pypi", name)
	}
	norm := Normalize(name)
	base := strings.TrimRight(c.BaseURL, "/")
	st, err := c.Prober.Probe(ctx, base+"/pypi/"+norm+"/json")
	if err != nil || st != registry.NotFound {
		return st, err
	}
	return c.Prober.Probe(ctx, base+"/simple/"+norm+"/")
}

// PackageURL returns the human-facing page for name on pypi.org.
func PackageURL(name string) string {
	return "https://pypi.org/project/" + Normalize(name) + "/"
}
