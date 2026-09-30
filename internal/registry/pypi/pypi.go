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

// Exists implements registry.Checker using /pypi/<name>/json.
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	if !ValidName(name) {
		return registry.Unknown, registry.InvalidNameError("pypi", name)
	}
	return c.Prober.Probe(ctx, strings.TrimRight(c.BaseURL, "/")+"/pypi/"+Normalize(name)+"/json")
}

// PackageURL returns the human-facing page for name on pypi.org.
func PackageURL(name string) string {
	return "https://pypi.org/project/" + Normalize(name) + "/"
}
