// Package cargo parses dependency declarations from Cargo.toml.
package cargo

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/registry/cratesio"
)

// TOML table headers, including trailing comments.
var tableRe = regexp.MustCompile(`(?m)^[ \t]*\[[ \t]*([^\[\]\r\n]+?)[ \t]*\][ \t]*(?:#.*)?\r?$`)

// Parse extracts crate dependencies from Cargo.toml bytes.
//
// Tables considered: [dependencies], [dev-dependencies], [build-dependencies],
// and [target.'.'.{dependencies,dev-dependencies,build-dependencies}].
// Path, git, and workspace = true dependencies are skipped (they do not
// resolve through crates.io). Renames via package = "..." use the real crate
// name. Results are deduped by normalized crate name.
func Parse(data []byte) ([]manifest.Dependency, error) {
	text := string(data)
	c := newCollector()
	for _, sec := range splitTOMLSections(text) {
		if !isDepTable(sec.name) {
			continue
		}
		parseDepEntries(text, sec, c)
	}
	if c.out == nil {
		c.out = []manifest.Dependency{}
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
	if name == "" || !cratesio.ValidName(name) {
		return
	}
	key := cratesio.Normalize(name)
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

type tomlSection struct {
	name       string
	start, end int
}

func splitTOMLSections(text string) []tomlSection {
	locs := tableRe.FindAllStringSubmatchIndex(text, -1)
	out := make([]tomlSection, 0, len(locs))
	for i, loc := range locs {
		end := len(text)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		raw := text[loc[2]:loc[3]]
		name := strings.ReplaceAll(raw, `"`, "")
		name = strings.ReplaceAll(name, `'`, "")
		name = strings.ReplaceAll(name, " ", "")
		out = append(out, tomlSection{name: name, start: loc[1], end: end})
	}
	return out
}

func isDepTable(name string) bool {
	switch name {
	case "dependencies", "dev-dependencies", "build-dependencies":
		return true
	}
	if !strings.HasPrefix(name, "target.") {
		return false
	}
	for _, suf := range []string{".dependencies", ".dev-dependencies", ".build-dependencies"} {
		if strings.HasSuffix(name, suf) && len(name) > len("target.")+len(suf) {
			return true
		}
	}
	return false
}

// parseDepEntries reads name = "version" and name = { ... } entries in sec.
func parseDepEntries(text string, sec tomlSection, c *collector) {
	body := text[sec.start:sec.end]
	i := 0
	for i < len(body) {
		for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' || body[i] == '\n') {
			i++
		}
		if i >= len(body) {
			return
		}
		if body[i] == '#' {
			for i < len(body) && body[i] != '\n' {
				i++
			}
			continue
		}

		keyStart := sec.start + i
		key, next, ok := readTOMLKey(body, i)
		if !ok {
			// Skip rest of line on parse failure.
			for i < len(body) && body[i] != '\n' {
				i++
			}
			continue
		}
		i = next
		for i < len(body) && (body[i] == ' ' || body[i] == '\t') {
			i++
		}
		if i >= len(body) || body[i] != '=' {
			for i < len(body) && body[i] != '\n' {
				i++
			}
			continue
		}
		i++
		for i < len(body) && (body[i] == ' ' || body[i] == '\t') {
			i++
		}
		if i >= len(body) {
			return
		}

		line := strings.Count(text[:keyStart], "\n") + 1
		switch body[i] {
		case '"', '\'':
			ver, end, ok := readTOMLString(body, i)
			if !ok {
				for i < len(body) && body[i] != '\n' {
					i++
				}
				continue
			}
			c.add(key, ver, sec.name, line)
			i = end + 1
		case '{':
			fields, end, ok := readInlineTable(body, i)
			if !ok {
				for i < len(body) && body[i] != '\n' {
					i++
				}
				continue
			}
			i = end + 1
			if fields.skip {
				continue
			}
			name := key
			if fields.packageName != "" {
				name = fields.packageName
			}
			if fields.version == "" {
				continue
			}
			c.add(name, fields.version, sec.name, line)
		default:
			for i < len(body) && body[i] != '\n' {
				i++
			}
		}
	}
}

type inlineFields struct {
	version     string
	packageName string
	skip        bool
}

// readInlineTable parses { ... } starting at body[open] == '{'.
// Sets skip when path, git, or workspace = true is present.
func readInlineTable(body string, open int) (inlineFields, int, bool) {
	var f inlineFields
	if open >= len(body) || body[open] != '{' {
		return f, 0, false
	}
	i := open + 1
	for i < len(body) {
		for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' || body[i] == '\n' || body[i] == ',') {
			i++
		}
		if i >= len(body) {
			return f, 0, false
		}
		if body[i] == '#' {
			for i < len(body) && body[i] != '\n' {
				i++
			}
			continue
		}
		if body[i] == '}' {
			return f, i, true
		}

		key, next, ok := readTOMLKey(body, i)
		if !ok {
			return f, 0, false
		}
		i = next
		for i < len(body) && (body[i] == ' ' || body[i] == '\t') {
			i++
		}
		if i >= len(body) || body[i] != '=' {
			return f, 0, false
		}
		i++
		for i < len(body) && (body[i] == ' ' || body[i] == '\t') {
			i++
		}
		if i >= len(body) {
			return f, 0, false
		}

		switch body[i] {
		case '"', '\'':
			val, end, ok := readTOMLString(body, i)
			if !ok {
				return f, 0, false
			}
			i = end + 1
			switch key {
			case "version":
				f.version = val
			case "package":
				f.packageName = val
			case "path", "git":
				f.skip = true
			}
		case 't', 'f': // true / false
			word, end := readBareWord(body, i)
			i = end
			if key == "workspace" && word == "true" {
				f.skip = true
			}
		case '[':
			end, ok := skipBracketValue(body, i)
			if !ok {
				return f, 0, false
			}
			i = end
		case '{':
			_, end, ok := readInlineTable(body, i)
			if !ok {
				return f, 0, false
			}
			i = end + 1
		default:
			_, end := readBareWord(body, i)
			i = end
		}
	}
	return f, 0, false
}

func readTOMLKey(s string, start int) (string, int, bool) {
	if start >= len(s) {
		return "", 0, false
	}
	if s[start] == '"' || s[start] == '\'' {
		key, end, ok := readTOMLString(s, start)
		if !ok {
			return "", 0, false
		}
		return key, end + 1, true
	}
	i := start
	for i < len(s) {
		r := rune(s[i])
		if r > unicode.MaxASCII {
			break
		}
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			i++
			continue
		}
		break
	}
	if i == start {
		return "", 0, false
	}
	return s[start:i], i, true
}

// readTOMLString reads a single-line basic ("...") or literal ('...') string
// starting at s[start]. Returns the value and the closing quote index.
func readTOMLString(s string, start int) (string, int, bool) {
	if start >= len(s) {
		return "", 0, false
	}
	quote := s[start]
	if quote != '"' && quote != '\'' {
		return "", 0, false
	}
	var b strings.Builder
	for i := start + 1; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\n':
			return "", 0, false
		case ch == '\\' && quote == '"' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case ch == quote:
			return b.String(), i, true
		default:
			b.WriteByte(ch)
		}
	}
	return "", 0, false
}

func readBareWord(s string, start int) (string, int) {
	i := start
	for i < len(s) {
		ch := s[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' {
			i++
			continue
		}
		break
	}
	return s[start:i], i
}

func skipBracketValue(s string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case '"', '\'':
			_, end, ok := readTOMLString(s, i)
			if !ok {
				return 0, false
			}
			i = end
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}
	return 0, false
}
