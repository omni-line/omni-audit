// Package cratesio checks crate-name existence on crates.io.
package cratesio

import (
	"context"
	"strings"
	"unicode"

	"github.com/omni-line/omni-audit/internal/registry"
)

// DefaultBaseURL is the public crates.io registry.
const DefaultBaseURL = "https://crates.io"

const maxNameLen = 64

// Client checks crate existence on crates.io.
type Client struct {
	BaseURL string
	Prober  *registry.Prober
}

// New returns a Client for public crates.io.
func New(p *registry.Prober) *Client {
	return &Client{BaseURL: DefaultBaseURL, Prober: p}
}

// Normalize lowercases name; crates.io treats names case-insensitively.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ValidName reports whether name is a valid crates.io crate name:
// ASCII alphanumeric, '-' or '_'; starts with a letter; max 64 characters.
func ValidName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxNameLen {
		return false
	}
	for i, r := range name {
		if r > unicode.MaxASCII {
			return false
		}
		if i == 0 {
			if r < 'A' || (r > 'Z' && r < 'a') || r > 'z' {
				return false
			}
			continue
		}
		switch {
		case r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// Exists implements registry.Checker using /api/v1/crates/<name>.
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	name = Normalize(name)
	if !ValidName(name) {
		return registry.Unknown, registry.InvalidNameError("cargo", name)
	}
	return c.Prober.Probe(ctx, strings.TrimRight(c.BaseURL, "/")+"/api/v1/crates/"+name)
}

// PackageURL returns the human-facing page for name on crates.io.
func PackageURL(name string) string {
	return "https://crates.io/crates/" + Normalize(name)
}
