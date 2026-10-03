// Package rubygems parses Gemfile and *.gemspec dependency declarations.
package rubygems

import (
	"regexp"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
	regruby "github.com/omni-line/omni-audit/internal/registry/rubygems"
)

var (
	// gem 'name' / gem "name" with optional trailing args on the same line.
	// Go's regexp has no backreferences, so single- and double-quoted forms
	// are alternated explicitly.
	gemLineRe = regexp.MustCompile(`(?i)^\s*gem\s+(?:'([^']+)'|"([^"]+)")\s*(?:,(.*))?$`)
	// Non-registry sources: symbol keys (:git =>), label keys (git:), or string keys.
	skipOptRe = regexp.MustCompile(`(?i)(?:^|[,{\s])(?::(?:git|path|github|gist|bitbucket)\s*(?:=>|:)|(?:git|path|github|gist|bitbucket)\s*:|['"](?:git|path|github|gist|bitbucket)['"]\s*(?:=>|:))\s*`)
	// add_dependency / add_runtime_dependency / add_development_dependency "name"
	gemspecDepRe = regexp.MustCompile(`(?i)\b(add_(?:runtime_)?dependency|add_development_dependency)\s*\(?\s*(?:'([^']+)'|"([^"]+)")`)
)

// ParseGemfile extracts gem declarations from a Bundler Gemfile.
// Gems with :git, :path, :github, :gist, or :bitbucket options (symbol or
// string keys) are skipped — they do not resolve through rubygems.org.
func ParseGemfile(data []byte) ([]manifest.Dependency, error) {
	c := newCollector()
	lines := strings.Split(string(data), "\n")
	for i, raw := range lines {
		line := stripRubyComment(strings.TrimRight(raw, "\r"))
		m := gemLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		if name == "" {
			name = m[2]
		}
		rest := strings.TrimSpace(m[3])
		if skipOptRe.MatchString(rest) {
			continue
		}
		version := ""
		if v, _, ok := readQuoted(rest); ok {
			version = v
		}
		c.add(name, version, "gem", i+1)
	}
	return c.out, nil
}

// ParseGemspec extracts add_*_dependency calls from a Ruby gemspec.
func ParseGemspec(data []byte) ([]manifest.Dependency, error) {
	c := newCollector()
	text := string(data)
	for _, loc := range gemspecDepRe.FindAllStringSubmatchIndex(text, -1) {
		method := text[loc[2]:loc[3]]
		name := ""
		if loc[4] >= 0 {
			name = text[loc[4]:loc[5]]
		} else {
			name = text[loc[6]:loc[7]]
		}
		line := strings.Count(text[:loc[0]], "\n") + 1
		c.add(name, "", method, line)
	}
	return c.out, nil
}

type collector struct {
	seen map[string]struct{}
	out  []manifest.Dependency
}

func newCollector() *collector {
	return &collector{seen: make(map[string]struct{}), out: []manifest.Dependency{}}
}

func (c *collector) add(name, version, group string, line int) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	key := regruby.Normalize(name)
	if _, dup := c.seen[key]; dup {
		return
	}
	c.seen[key] = struct{}{}
	c.out = append(c.out, manifest.Dependency{
		Name:    name,
		Version: version,
		Group:   group,
		Line:    line,
	})
}

// stripRubyComment removes a # comment that is not inside a single- or
// double-quoted string.
func stripRubyComment(line string) string {
	inQuote := byte(0)
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case inQuote != 0:
			if ch == '\\' && i+1 < len(line) {
				i++
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
		case ch == '\'' || ch == '"':
			inQuote = ch
		case ch == '#':
			return line[:i]
		}
	}
	return line
}

// readQuoted reads a leading '...' or "..." string from s.
func readQuoted(s string) (val, rest string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", s, false
	}
	q := s[0]
	if q != '\'' && q != '"' {
		return "", s, false
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		if ch == q {
			return b.String(), strings.TrimSpace(s[i+1:]), true
		}
		b.WriteByte(ch)
	}
	return "", s, false
}
