package npm

import (
	"encoding/json"
	"fmt"
	"os"
)

type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// Dependency is a declared npm package.
type Dependency struct {
	Name    string
	Version string
}

// ParseFile reads package.json and returns declared dependencies.
func ParseFile(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses package.json bytes.
func Parse(data []byte) ([]Dependency, error) {
	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}
	seen := make(map[string]struct{})
	var out []Dependency
	add := func(m map[string]string) {
		for name, ver := range m {
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, Dependency{Name: name, Version: ver})
		}
	}
	add(pkg.Dependencies)
	add(pkg.DevDependencies)
	add(pkg.OptionalDependencies)
	add(pkg.PeerDependencies)
	return out, nil
}
