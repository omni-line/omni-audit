// Package goproxy checks module-path existence on proxy.golang.org.
package goproxy

import (
	"context"
	"strings"
	"unicode"

	"github.com/omni-line/omni-audit/internal/registry"
)

// DefaultBaseURL is the public Go module proxy.
const DefaultBaseURL = "https://proxy.golang.org"

const maxPathLen = 1024

// Client checks module existence on the Go module proxy.
type Client struct {
	BaseURL string
	Prober  *registry.Prober
}

// New returns a Client for the public Go module proxy.
func New(p *registry.Prober) *Client {
	return &Client{BaseURL: DefaultBaseURL, Prober: p}
}

// EscapePath encodes a module path for the module proxy (A–Z → !a–!z).
func EscapePath(path string) (string, bool) {
	var b strings.Builder
	b.Grow(len(path) + 8)
	for i := 0; i < len(path); i++ {
		c := path[i]
		if 'A' <= c && c <= 'Z' {
			b.WriteByte('!')
			b.WriteByte(c + 'a' - 'A')
			continue
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

// ValidName reports whether name is a plausible public Go module path.
// The first path element must contain a dot (a domain), matching what the
// public proxy will accept for confusion-relevant modules.
func ValidName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxPathLen {
		return false
	}
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "//") {
		return false
	}
	parts := strings.Split(name, "/")
	if !strings.Contains(parts[0], ".") {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
		if strings.HasPrefix(part, ".") {
			return false
		}
		for _, r := range part {
			if !validPathRune(r) {
				return false
			}
		}
	}
	return true
}

func validPathRune(r rune) bool {
	if r > unicode.MaxASCII {
		return false
	}
	switch {
	case r >= 'A' && r <= 'Z',
		r >= 'a' && r <= 'z',
		r >= '0' && r <= '9':
		return true
	}
	switch r {
	case '-', '.', '_', '~', '+':
		return true
	default:
		return false
	}
}

// Exists implements registry.Checker using /<module>/@v/list.
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	if !ValidName(name) {
		return registry.Unknown, registry.InvalidNameError("go", name)
	}
	escaped, _ := EscapePath(name)
	return c.Prober.Probe(ctx, strings.TrimRight(c.BaseURL, "/")+"/"+escaped+"/@v/list")
}

// PackageURL returns the pkg.go.dev page for the module path.
func PackageURL(name string) string {
	return "https://pkg.go.dev/" + name
}
