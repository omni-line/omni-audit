package composer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// Dependency is a declared Composer package.
type Dependency struct {
	Name    string
	Version string
}

// ParseFile reads composer.json and returns package dependencies (skips php / ext-*).
func ParseFile(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses composer.json bytes.
func Parse(data []byte) ([]Dependency, error) {
	var c composerJSON
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse composer.json: %w", err)
	}
	seen := make(map[string]struct{})
	var out []Dependency
	add := func(m map[string]string) {
		for name, ver := range m {
			if name == "" || skipPlatform(name) {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, Dependency{Name: name, Version: ver})
		}
	}
	add(c.Require)
	add(c.RequireDev)
	return out, nil
}

func skipPlatform(name string) bool {
	lower := strings.ToLower(name)
	if lower == "php" {
		return true
	}
	if strings.HasPrefix(lower, "ext-") {
		return true
	}
	if strings.HasPrefix(lower, "lib-") {
		return true
	}
	return false
}
