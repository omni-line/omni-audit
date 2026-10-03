// Package packagist checks package-name existence on Packagist (Composer).
package packagist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/omni-line/omni-audit/internal/registry"
)

// DefaultBaseURL is the Packagist metadata mirror (Composer v2 API).
const DefaultBaseURL = "https://repo.packagist.org"

// DefaultListURL is the Packagist website API (vendor package lists).
const DefaultListURL = "https://packagist.org"

// nameRe is Composer's own package-name pattern (see composer/schema.json).
var nameRe = regexp.MustCompile(`^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$`)

var vendorRe = regexp.MustCompile(`^[a-z0-9]([_.-]?[a-z0-9]+)*$`)

// Client checks package existence on Packagist.
type Client struct {
	BaseURL string
	ListURL string
	Prober  *registry.Prober
}

// New returns a Client for public Packagist.
func New(p *registry.Prober) *Client {
	return &Client{BaseURL: DefaultBaseURL, ListURL: DefaultListURL, Prober: p}
}

// Normalize lowercases name; Composer package names are case-insensitive.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ValidName reports whether name is a valid vendor/package Composer name.
func ValidName(name string) bool {
	return nameRe.MatchString(Normalize(name))
}

// Vendor returns the Packagist vendor for a vendor/package name.
func Vendor(name string) (string, bool) {
	name = Normalize(name)
	i := strings.IndexByte(name, '/')
	if i <= 0 || i == len(name)-1 {
		return "", false
	}
	vendor := name[:i]
	if !vendorRe.MatchString(vendor) {
		return "", false
	}
	return vendor, true
}

// Exists implements registry.Checker.
//
// Tagged releases live at /p2/<name>.json and dev branches at
// /p2/<name>~dev.json; a package with only dev branches is still claimed.
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	name = Normalize(name)
	if !nameRe.MatchString(name) {
		return registry.Unknown, registry.InvalidNameError("composer", name)
	}
	base := strings.TrimRight(c.BaseURL, "/") + "/p2/" + name
	st, err := c.Prober.Probe(ctx, base+".json")
	if err != nil || st != registry.NotFound {
		return st, err
	}
	return c.Prober.Probe(ctx, base+"~dev.json")
}

// VendorExists reports whether Packagist lists any package under vendor.
func (c *Client) VendorExists(ctx context.Context, vendor string) (registry.Status, error) {
	vendor = Normalize(vendor)
	if !vendorRe.MatchString(vendor) {
		return registry.Unknown, registry.InvalidNameError("composer", vendor)
	}
	listBase := c.ListURL
	if listBase == "" {
		listBase = DefaultListURL
	}
	rawURL := strings.TrimRight(listBase, "/") + "/packages/list.json?vendor=" + url.QueryEscape(vendor)
	body, st, err := c.Prober.Fetch(ctx, rawURL)
	if err != nil || st != registry.Exists {
		if st == registry.NotFound {
			return registry.NotFound, nil
		}
		return registry.Unknown, err
	}
	var resp struct {
		PackageNames []string `json:"packageNames"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return registry.Unknown, fmt.Errorf("packagist vendor list: decode: %w", err)
	}
	if len(resp.PackageNames) > 0 {
		return registry.Exists, nil
	}
	return registry.NotFound, nil
}

// PackageURL returns the human-facing page for name on packagist.org.
func PackageURL(name string) string {
	return "https://packagist.org/packages/" + Normalize(name)
}
