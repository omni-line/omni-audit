package npm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/omni-line/omni-audit/internal/registry"
)

const defaultBase = "https://registry.npmjs.org"

// Client checks package existence on the npm public registry.
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
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	// Scoped packages: @scope/name → /@scope%2Fname
	enc := url.PathEscape(name)
	reqURL := base + "/" + enc

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
		return registry.Unknown, fmt.Errorf("npm registry: unexpected status %d for %s", resp.StatusCode, name)
	}
}
