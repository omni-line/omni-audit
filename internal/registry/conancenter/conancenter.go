// Package conancenter checks package-name existence on ConanCenter.
package conancenter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/omni-line/omni-audit/internal/registry"
)

// DefaultBaseURL is the ConanCenter v2 Artifactory remote.
const DefaultBaseURL = "https://center2.conan.io"

// nameRe is Conan's package-name grammar (2–101 chars, lowercase).
// See https://docs.conan.io/2/reference/conanfile/attributes.html#name
var nameRe = regexp.MustCompile(`^[a-z0-9_][a-z0-9_+.-]{1,100}$`)

// Client checks package existence on ConanCenter.
type Client struct {
	BaseURL string
	Prober  *registry.Prober
}

// New returns a Client for public ConanCenter.
func New(p *registry.Prober) *Client {
	return &Client{BaseURL: DefaultBaseURL, Prober: p}
}

// Normalize lowercases name; Conan package names are lowercase.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ValidName reports whether name is a valid Conan package name.
func ValidName(name string) bool {
	return nameRe.MatchString(Normalize(name))
}

// Exists implements registry.Checker.
//
// ConanCenter's search endpoint always returns HTTP 200, including for
// unknown names (empty results) and substring matches. Existence is
// therefore decided by parsing {"results":[...]} and looking for an
// exact package-name match (segment before the first '/').
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	name = Normalize(name)
	if !nameRe.MatchString(name) {
		return registry.Unknown, registry.InvalidNameError("conan", name)
	}
	rawURL := strings.TrimRight(c.BaseURL, "/") + "/v2/conans/search?q=" + url.QueryEscape(name)
	body, st, err := c.Prober.Fetch(ctx, rawURL)
	if err != nil || st != registry.Exists {
		return st, err
	}
	var parsed struct {
		Results []string `json:"results"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return registry.Unknown, fmt.Errorf("conancenter search: %w", err)
	}
	for _, r := range parsed.Results {
		pkg := r
		if i := strings.IndexByte(r, '/'); i >= 0 {
			pkg = r[:i]
		}
		if Normalize(pkg) == name {
			return registry.Exists, nil
		}
	}
	return registry.NotFound, nil
}

// PackageURL returns the human-facing ConanCenter recipe page for name.
func PackageURL(name string) string {
	return "https://conan.io/center/recipes/" + Normalize(name)
}
