// Package mavencentral checks coordinate existence on Maven Central (repo1).
package mavencentral

import (
	"context"
	"strings"
	"unicode"

	"github.com/omni-line/omni-audit/internal/registry"
)

// DefaultBaseURL is the public Maven Central repository.
const DefaultBaseURL = "https://repo1.maven.org/maven2"

// Client checks package existence on Maven Central.
type Client struct {
	BaseURL string
	Prober  *registry.Prober
}

// New returns a Client for public Maven Central.
func New(p *registry.Prober) *Client {
	return &Client{BaseURL: DefaultBaseURL, Prober: p}
}

// Normalize returns name trimmed of surrounding whitespace.
// Maven coordinates are case-sensitive; case is preserved.
func Normalize(name string) string {
	return strings.TrimSpace(name)
}

// ValidName reports whether name is a valid groupId:artifactId coordinate.
func ValidName(name string) bool {
	name = Normalize(name)
	groupID, artifactID, ok := splitCoord(name)
	if !ok {
		return false
	}
	return validCoordPart(groupID) && validCoordPart(artifactID)
}

func splitCoord(name string) (groupID, artifactID string, ok bool) {
	i := strings.IndexByte(name, ':')
	if i <= 0 || i != strings.LastIndexByte(name, ':') {
		return "", "", false
	}
	groupID = name[:i]
	artifactID = name[i+1:]
	if groupID == "" || artifactID == "" {
		return "", "", false
	}
	return groupID, artifactID, true
}

func validCoordPart(s string) bool {
	if s == "" || strings.Contains(s, "..") {
		return false
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// Exists implements registry.Checker by probing maven-metadata.xml.
func (c *Client) Exists(ctx context.Context, name string) (registry.Status, error) {
	name = Normalize(name)
	if !ValidName(name) {
		return registry.Unknown, registry.InvalidNameError("maven", name)
	}
	groupID, artifactID, _ := splitCoord(name)
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	url := strings.TrimRight(c.BaseURL, "/") + "/" + groupPath + "/" + artifactID + "/maven-metadata.xml"
	return c.Prober.Probe(ctx, url)
}

// PackageURL returns the Sonatype Central page for the coordinate.
func PackageURL(name string) string {
	name = Normalize(name)
	groupID, artifactID, ok := splitCoord(name)
	if !ok {
		return ""
	}
	return "https://central.sonatype.com/artifact/" + groupID + "/" + artifactID
}
