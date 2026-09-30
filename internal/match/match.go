// Package match implements the glob allowlists used by --safe-namespace,
// --ignore, and --exclude.
package match

import (
	"fmt"
	"path"
	"strings"
)

// Matcher matches names against glob patterns (path.Match semantics). A
// pattern ending in "/*" also matches anything below that prefix.
type Matcher struct {
	patterns []string
}

// New builds a Matcher from patterns, splitting comma-separated values.
// Empty patterns match nothing. Malformed patterns never match; use Compile
// to reject them.
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

// Compile is like New but returns an error for malformed patterns.
func Compile(patterns ...string) (*Matcher, error) {
	m := New(patterns...)
	for _, p := range m.patterns {
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p, err)
		}
	}
	return m, nil
}

// Match reports whether name matches any pattern.
func (m *Matcher) Match(name string) bool {
	if m == nil {
		return false
	}
	for _, p := range m.patterns {
		if ok, err := path.Match(p, name); err == nil && ok {
			return true
		}
		if strings.HasSuffix(p, "/*") && strings.HasPrefix(name, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}

// Empty reports whether there are no patterns.
func (m *Matcher) Empty() bool {
	return m == nil || len(m.patterns) == 0
}
