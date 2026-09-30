package packagist

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/omni-line/omni-audit/internal/registry"
)

const defaultBase = "https://repo.packagist.org"

// Client checks package existence on Packagist.
type Client struct {
	HTTP    *http.Client
	BaseURL string
	UA      string
}

// New returns a Client with sensible defaults.
func New(httpClient *http.Client, userAgent string) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &Client{HTTP: httpClient, BaseURL: defaultBase, UA: userAgent}
}

// Exists implements registry.Checker.
// Packagist package names are vendor/package.
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	name = strings.ToLower(name)
	if !strings.Contains(name, "/") {
		return registry.Unknown, fmt.Errorf("invalid composer package name %q", name)
	}
	base := strings.TrimRight(c.BaseURL, "/")
	reqURL := base + "/p2/" + name + ".json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return registry.Unknown, err
	}
	if c.UA != "" {
		req.Header.Set("User-Agent", c.UA)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return registry.Unknown, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return registry.Exists, nil
	case http.StatusNotFound:
		return registry.NotFound, nil
	default:
		return registry.Unknown, fmt.Errorf("packagist: unexpected status %d for %s", resp.StatusCode, name)
	}
}
