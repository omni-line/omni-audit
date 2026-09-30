// Package npm parses package.json dependency declarations.
package npm

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
)

// Groups are the package.json sections scanned, in reporting order.
var Groups = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

// Specs with these prefixes never resolve through the public registry.
var nonRegistryPrefixes = []string{
	"file:", "link:", "workspace:", "portal:",
	"git:", "git+", "github:", "gitlab:", "bitbucket:", "gist:",
	"http:", "https:",
	"./", "../", "/", "~/",
}

// Parse returns registry-resolved dependencies from package.json bytes.
//
// Local and VCS specs (file:, workspace:, git URLs, "user/repo" shorthand,
// tarball URLs) are dropped because they cannot be hijacked on the registry.
// Aliases ("x": "npm:real-pkg@^1") are reported under the real package name.
func Parse(data []byte) ([]manifest.Dependency, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}
	seen := make(map[string]struct{})
	var out []manifest.Dependency
	for _, group := range Groups {
		section, ok := raw[group]
		if !ok || string(section) == "null" {
			continue
		}
		var deps map[string]string
		if err := json.Unmarshal(section, &deps); err != nil {
			return nil, fmt.Errorf("parse package.json %s: %w", group, err)
		}
		for _, key := range sortedKeys(deps) {
			name, version, ok := resolve(key, deps[key])
			if !ok || name == "" {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, manifest.Dependency{
				Name:    name,
				Version: version,
				Group:   group,
				Line:    manifest.JSONKeyLine(data, group, key),
			})
		}
	}
	return out, nil
}

// resolve maps a dependency entry to the registry package it installs.
func resolve(key, spec string) (name, version string, ok bool) {
	spec = strings.TrimSpace(spec)
	lower := strings.ToLower(spec)
	if strings.HasPrefix(lower, "npm:") {
		target := spec[len("npm:"):]
		if at := strings.LastIndex(target, "@"); at > 0 {
			return target[:at], target[at+1:], true
		}
		return target, "", true
	}
	for _, p := range nonRegistryPrefixes {
		if strings.HasPrefix(lower, p) {
			return "", "", false
		}
	}
	// "user/repo#ref" GitHub shorthand, bare paths, and tarballs.
	if strings.Contains(spec, "/") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar.gz") {
		return "", "", false
	}
	return key, spec, true
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
