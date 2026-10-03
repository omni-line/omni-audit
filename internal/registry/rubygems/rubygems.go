// Package rubygems checks gem-name existence on the public RubyGems index.
package rubygems

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/omni-line/omni-audit/internal/registry"
)

// DefaultBaseURL is the public RubyGems host.
const DefaultBaseURL = "https://rubygems.org"

// RubyGems allows letters, digits, underscore, dash, and dot; names must
// include a letter and may not begin with ., -, or _. Cap length so junk
// never reaches the network.
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

const maxNameLen = 64

// Client checks gem existence on RubyGems.
type Client struct {
	BaseURL string
	Prober  *registry.Prober
}

// New returns a Client for public RubyGems.
func New(p *registry.Prober) *Client {
	return &Client{BaseURL: DefaultBaseURL, Prober: p}
}

// Normalize lowercases a gem name; RubyGems treats names case-insensitively.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ValidName reports whether name is a syntactically valid RubyGems gem name.
func ValidName(name string) bool {
	if len(name) == 0 || len(name) > maxNameLen || !nameRe.MatchString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

// Exists implements registry.Checker.
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	if !ValidName(name) {
		return registry.Unknown, registry.InvalidNameError("rubygems", name)
	}
	norm := Normalize(name)
	return c.Prober.Probe(ctx, strings.TrimRight(c.BaseURL, "/")+"/api/v1/gems/"+url.PathEscape(norm)+".json")
}

// PackageURL returns the human-facing page for name on rubygems.org.
func PackageURL(name string) string {
	return "https://rubygems.org/gems/" + Normalize(name)
}
