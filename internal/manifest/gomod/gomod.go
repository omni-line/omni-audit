// Package gomod parses require directives from go.mod files.
package gomod

import (
	"bufio"
	"strings"
	"unicode"

	"github.com/omni-line/omni-audit/internal/manifest"
)

// Parse extracts module paths from require directives in go.mod bytes.
// exclude / replace / retract / toolchain / go / module lines are ignored.
// Local and VCS replace targets never appear here — only require paths.
func Parse(data []byte) ([]manifest.Dependency, error) {
	seen := make(map[string]struct{})
	var out []manifest.Dependency

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	inRequire := false

	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		line := stripComment(raw)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if inRequire {
			if trimmed == ")" {
				inRequire = false
				continue
			}
			path, ver, ok := parseRequireEntry(trimmed)
			if !ok {
				continue
			}
			if _, dup := seen[path]; dup {
				continue
			}
			seen[path] = struct{}{}
			out = append(out, manifest.Dependency{
				Name:    path,
				Version: ver,
				Group:   "require",
				Line:    lineNo,
			})
			continue
		}

		lower := strings.ToLower(trimmed)
		switch {
		case lower == "require (":
			inRequire = true
		case strings.HasPrefix(lower, "require "):
			rest := strings.TrimSpace(trimmed[len("require"):])
			if rest == "(" {
				inRequire = true
				continue
			}
			path, ver, ok := parseRequireEntry(rest)
			if !ok {
				continue
			}
			if _, dup := seen[path]; dup {
				continue
			}
			seen[path] = struct{}{}
			out = append(out, manifest.Dependency{
				Name:    path,
				Version: ver,
				Group:   "require",
				Line:    lineNo,
			})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []manifest.Dependency{}
	}
	return out, nil
}

func stripComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && c == '/' && i+1 < len(line) && line[i+1] == '/' {
			return line[:i]
		}
	}
	return line
}

func parseRequireEntry(s string) (path, version string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "(" || s == ")" {
		return "", "", false
	}
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return "", "", false
	}
	path = fields[0]
	version = fields[1]
	// Reject accidental exclude/replace leftovers if somehow inside require.
	if path == "=>" || version == "=>" {
		return "", "", false
	}
	if !looksLikeModulePath(path) {
		return "", "", false
	}
	return path, version, true
}

func looksLikeModulePath(p string) bool {
	if p == "" || strings.Contains(p, "://") {
		return false
	}
	for _, r := range p {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}
