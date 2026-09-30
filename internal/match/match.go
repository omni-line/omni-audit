package match

import (
	"path"
	"strings"
)

// Matcher matches package names against glob patterns (path.Match semantics).
type Matcher struct {
	patterns []string
}

// New builds a Matcher from patterns. Empty patterns match nothing.
func New(patterns ...string) *Matcher {
	var cleaned []string
	for _, p := range patterns {
		for _, part := range strings.Split(p, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				cleaned = append(cleaned, part)
			}
		}
	}
	return &Matcher{patterns: cleaned}
}

// Match reports whether name matches any pattern.
func (m *Matcher) Match(name string) bool {
	if m == nil {
		return false
	}
	for _, p := range m.patterns {
		ok, err := path.Match(p, name)
		if err == nil && ok {
			return true
		}
		// Also allow trailing /* style against exact org prefix for npm scopes.
		if strings.HasSuffix(p, "/*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
	}
	return false
}

// Empty reports whether there are no patterns.
func (m *Matcher) Empty() bool {
	return m == nil || len(m.patterns) == 0
}
