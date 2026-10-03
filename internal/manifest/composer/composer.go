// Package composer parses composer.json dependency declarations.
package composer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
)

// Groups are the composer.json sections scanned, in reporting order.
var Groups = []string{"require", "require-dev"}

// Parse returns Packagist-resolvable dependencies from composer.json bytes.
//
// Platform packages (php, ext-*, lib-*, composer-plugin-api, ...) are
// skipped: every real Composer package is vendor/name, platform ones never are.
func Parse(data []byte) ([]manifest.Dependency, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse composer.json: %w", err)
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
			return nil, fmt.Errorf("parse composer.json %s: %w", group, err)
		}
		names := make([]string, 0, len(deps))
		for name := range deps {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if !strings.Contains(name, "/") {
				continue
			}
			key := strings.ToLower(name)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, manifest.Dependency{
				Name:    name,
				Version: deps[name],
				Group:   group,
				Line:    manifest.JSONKeyLine(data, group, name),
			})
		}
	}
	return out, nil
}

// Normalize lowercases vendor/package.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// Split returns vendor and package leaf for vendor/name.
func Split(name string) (namespace, leaf string) {
	name = Normalize(name)
	i := strings.IndexByte(name, '/')
	if i <= 0 || i == len(name)-1 {
		return "", name
	}
	return name[:i], name[i+1:]
}
