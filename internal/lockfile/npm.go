package lockfile

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
)

// ParseNPM extracts resolved URLs from package-lock.json / npm-shrinkwrap.json
// (lockfileVersion 1, 2, and 3).
func ParseNPM(data []byte) ([]Resolved, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}

	seen := make(map[string]struct{})
	var out []Resolved

	if packages, ok := raw["packages"]; ok && string(packages) != "null" {
		var pkgs map[string]npmPkg
		if err := json.Unmarshal(packages, &pkgs); err != nil {
			return nil, fmt.Errorf("package-lock.json packages: %w", err)
		}
		// Deterministic: iterate keys sorted via map then sort names at end — collect then sort.
		keys := make([]string, 0, len(pkgs))
		for k := range pkgs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if key == "" {
				continue // root project
			}
			p := pkgs[key]
			if strings.TrimSpace(p.Resolved) == "" {
				continue
			}
			name := npmLockName(key, p.Name)
			if name == "" {
				continue
			}
			dupKey := name + "@" + p.Version + "\x00" + p.Resolved
			if _, dup := seen[dupKey]; dup {
				continue
			}
			seen[dupKey] = struct{}{}
			out = append(out, Resolved{
				Name:    name,
				Version: p.Version,
				URL:     p.Resolved,
				Line:    manifest.JSONKeyLine(data, key, "resolved"),
			})
		}
		return out, nil
	}

	if deps, ok := raw["dependencies"]; ok && string(deps) != "null" {
		var tree map[string]npmV1Dep
		if err := json.Unmarshal(deps, &tree); err != nil {
			return nil, fmt.Errorf("package-lock.json dependencies: %w", err)
		}
		walkNPMV1(data, tree, seen, &out)
	}
	return out, nil
}

type npmPkg struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
}

type npmV1Dep struct {
	Version      string              `json:"version"`
	Resolved     string              `json:"resolved"`
	Dependencies map[string]npmV1Dep `json:"dependencies"`
}

func walkNPMV1(data []byte, tree map[string]npmV1Dep, seen map[string]struct{}, out *[]Resolved) {
	names := make([]string, 0, len(tree))
	for n := range tree {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		d := tree[name]
		if strings.TrimSpace(d.Resolved) != "" {
			dupKey := name + "@" + d.Version + "\x00" + d.Resolved
			if _, dup := seen[dupKey]; !dup {
				seen[dupKey] = struct{}{}
				*out = append(*out, Resolved{
					Name:    name,
					Version: d.Version,
					URL:     d.Resolved,
					Line:    manifest.JSONKeyLine(data, name, "resolved"),
				})
			}
		}
		if len(d.Dependencies) > 0 {
			walkNPMV1(data, d.Dependencies, seen, out)
		}
	}
}

func npmLockName(pathKey, explicit string) string {
	if explicit != "" {
		return explicit
	}
	const prefix = "node_modules/"
	key := pathKey
	for {
		i := strings.LastIndex(key, prefix)
		if i < 0 {
			break
		}
		key = key[i+len(prefix):]
	}
	return key
}
