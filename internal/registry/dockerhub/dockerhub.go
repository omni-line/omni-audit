// Package dockerhub checks repository existence on Docker Hub.
package dockerhub

import (
	"context"
	"regexp"
	"strings"

	"github.com/omni-line/omni-audit/internal/registry"
)

// DefaultBaseURL is the public Docker Hub API host.
const DefaultBaseURL = "https://hub.docker.com"

// nameRe matches a Hub repository path namespace/name with Hub-allowed chars.
// Namespaces and names are lowercase alphanumerics with . _ - separators.
var nameRe = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

// Client checks repository existence on Docker Hub.
type Client struct {
	BaseURL string
	Prober  *registry.Prober
}

// New returns a Client for public Docker Hub.
func New(p *registry.Prober) *Client {
	return &Client{BaseURL: DefaultBaseURL, Prober: p}
}

// Normalize lowercases a Hub repository path.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ValidName reports whether name is a syntactically valid Hub namespace/name.
func ValidName(name string) bool {
	return nameRe.MatchString(Normalize(name))
}

// Exists implements registry.Checker.
//
// Hub repository metadata lives at /v2/repositories/<namespace>/<name>/.
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	name = Normalize(name)
	if !nameRe.MatchString(name) {
		return registry.Unknown, registry.InvalidNameError("docker", name)
	}
	ns, repo, ok := splitName(name)
	if !ok {
		return registry.Unknown, registry.InvalidNameError("docker", name)
	}
	url := strings.TrimRight(c.BaseURL, "/") + "/v2/repositories/" + ns + "/" + repo + "/"
	return c.Prober.Probe(ctx, url)
}

// PackageURL returns the human-facing Hub page for namespace/name.
func PackageURL(name string) string {
	name = Normalize(name)
	ns, repo, ok := splitName(name)
	if !ok {
		return ""
	}
	return "https://hub.docker.com/r/" + ns + "/" + repo
}

func splitName(name string) (namespace, repo string, ok bool) {
	i := strings.IndexByte(name, '/')
	if i <= 0 || i == len(name)-1 || strings.Count(name, "/") != 1 {
		return "", "", false
	}
	return name[:i], name[i+1:], true
}
