// Package pypi parses requirements files and pyproject.toml dependency
// declarations.
package pypi

import (
	"regexp"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
	regpypi "github.com/omni-line/omni-audit/internal/registry/pypi"
)

var (
	reqNameRe = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(.*)$`)
	// TOML table headers, including [[array.tables]] and trailing comments.
	tableRe = regexp.MustCompile(`(?m)^[ \t]*\[\[?[ \t]*([^\[\]\r\n]+?)[ \t]*\]\]?[ \t]*(?:#.*)?\r?$`)
	// Array-valued keys: `name = [`.
	arrayKeyRe = regexp.MustCompile(`(?m)^[ \t]*["']?([A-Za-z0-9_.-]+)["']?[ \t]*=[ \t]*\[`)
)

// Requirements lines that install from somewhere other than the index.
var nonIndexPrefixes = []string{"git+", "hg+", "svn+", "bzr+", ".", "/", "~"}

var archiveSuffixes = []string{".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2"}

// ParseRequirements parses pip requirements-file bytes.
func ParseRequirements(data []byte) ([]manifest.Dependency, error) {
	c := newCollector()
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := strings.TrimRight(lines[i], "\r")
		for strings.HasSuffix(line, `\`) && i+1 < len(lines) {
			i++
			line = strings.TrimSuffix(line, `\`) + strings.TrimRight(lines[i], "\r")
		}
		line = strings.TrimSpace(stripComment(line))
		if line == "" || strings.HasPrefix(line, "-") {
			// Blank, or an option such as -r, -c, -e, --index-url.
			continue
		}
		c.add(line, "", lineNo)
	}
	return c.out, nil
}

// stripComment removes a pip comment: '#' at line start or after whitespace.
func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

// ParsePyProject extracts PEP 621 [project] dependencies and
// optional-dependencies, plus PEP 735 [dependency-groups].
func ParsePyProject(data []byte) ([]manifest.Dependency, error) {
	text := string(data)
	c := newCollector()
	for _, sec := range splitTOMLSections(text) {
		switch sec.name {
		case "project":
			for _, arr := range findArrays(text, sec) {
				if arr.key == "dependencies" {
					c.addAll(text, arr, "dependencies")
				}
			}
		case "project.optional-dependencies":
			for _, arr := range findArrays(text, sec) {
				c.addAll(text, arr, "optional-dependencies."+arr.key)
			}
		case "dependency-groups":
			for _, arr := range findArrays(text, sec) {
				c.addAll(text, arr, "dependency-groups."+arr.key)
			}
		}
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

func (c *collector) addAll(text string, arr tomlArray, group string) {
	for _, it := range arr.items {
		c.add(it.value, group, strings.Count(text[:it.offset], "\n")+1)
	}
}

// add parses one PEP 508 requirement string.
func (c *collector) add(req, group string, line int) {
	if i := strings.IndexByte(req, ';'); i >= 0 {
		req = req[:i] // environment marker
	}
	req = strings.TrimSpace(req)
	lower := strings.ToLower(req)
	if req == "" || strings.Contains(req, "://") {
		return
	}
	for _, p := range nonIndexPrefixes {
		if strings.HasPrefix(lower, p) {
			return
		}
	}
	for _, s := range archiveSuffixes {
		if strings.HasSuffix(lower, s) {
			return
		}
	}
	m := reqNameRe.FindStringSubmatch(req)
	if m == nil {
		return
	}
	name, version := m[1], strings.TrimSpace(m[2])
	if strings.HasPrefix(version, "@") {
		return // PEP 508 direct reference: name @ url
	}
	if strings.EqualFold(name, "python") {
		return
	}
	key := regpypi.Normalize(name)
	if _, dup := c.seen[key]; dup {
		return
	}
	c.seen[key] = struct{}{}
	c.out = append(c.out, manifest.Dependency{Name: name, Version: version, Group: group, Line: line})
}

type tomlSection struct {
	name       string
	start, end int // body byte range within the document
}

func splitTOMLSections(text string) []tomlSection {
	locs := tableRe.FindAllStringSubmatchIndex(text, -1)
	out := make([]tomlSection, 0, len(locs))
	for i, loc := range locs {
		end := len(text)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		name := strings.ReplaceAll(text[loc[2]:loc[3]], `"`, "")
		name = strings.ReplaceAll(name, " ", "")
		out = append(out, tomlSection{name: name, start: loc[1], end: end})
	}
	return out
}

type tomlItem struct {
	value  string
	offset int
}

type tomlArray struct {
	key   string
	items []tomlItem
}

// findArrays returns every `key = [ ... ]` string array directly in sec.
func findArrays(text string, sec tomlSection) []tomlArray {
	body := text[sec.start:sec.end]
	var out []tomlArray
	for _, loc := range arrayKeyRe.FindAllStringSubmatchIndex(body, -1) {
		open := sec.start + loc[1] - 1 // index of '['
		items, ok := readStringArray(text, open)
		if ok {
			out = append(out, tomlArray{key: body[loc[2]:loc[3]], items: items})
		}
	}
	return out
}

// readStringArray reads the TOML array starting at text[open] == '['. Only
// strings directly inside the outer array are returned; strings in nested
// arrays or inline tables (e.g. {include-group = "dev"}) and comments are
// ignored.
func readStringArray(text string, open int) ([]tomlItem, bool) {
	depth, braces := 0, 0
	var items []tomlItem
	for i := open; i < len(text); i++ {
		switch ch := text[i]; ch {
		case '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return items, true
			}
		case '{':
			braces++
		case '}':
			braces--
		case '"', '\'':
			val, end, ok := readTOMLString(text, i)
			if !ok {
				return nil, false
			}
			if depth == 1 && braces == 0 {
				items = append(items, tomlItem{value: val, offset: i})
			}
			i = end
		}
	}
	return nil, false
}

// readTOMLString reads a single-line basic ("...") or literal ('...') string
// starting at text[start]. It returns the value and the closing quote index.
func readTOMLString(text string, start int) (string, int, bool) {
	quote := text[start]
	var b strings.Builder
	for i := start + 1; i < len(text); i++ {
		ch := text[i]
		switch {
		case ch == '\n':
			return "", 0, false
		case ch == '\\' && quote == '"' && i+1 < len(text):
			i++
			b.WriteByte(text[i])
		case ch == quote:
			return b.String(), i, true
		default:
			b.WriteByte(ch)
		}
	}
	return "", 0, false
}
