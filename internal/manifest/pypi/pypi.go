package pypi

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// Dependency is a declared Python package.
type Dependency struct {
	Name    string
	Version string
}

var (
	reqNameRe = regexp.MustCompile(`(?i)^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$`)
	markerRe  = regexp.MustCompile(`\s*;.*$`)
	tableRe   = regexp.MustCompile(`(?m)^\s*\[([^\]]+)\]\s*$`)
)

// ParseRequirementsFile reads a requirements.txt-style file.
func ParseRequirementsFile(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRequirements(data)
}

// ParseRequirements parses requirements.txt bytes.
func ParseRequirements(data []byte) ([]Dependency, error) {
	seen := make(map[string]struct{})
	var out []Dependency
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "git+") || strings.HasPrefix(lower, "hg+") ||
			strings.HasPrefix(lower, "svn+") || strings.HasPrefix(lower, "bzr+") ||
			strings.Contains(line, "://") {
			continue
		}
		line = markerRe.ReplaceAllString(line, "")
		line = strings.TrimSpace(line)
		name, ver, ok := splitRequirement(line)
		if !ok {
			continue
		}
		key := normalizeName(name)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Dependency{Name: name, Version: ver})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func splitRequirement(line string) (name, version string, ok bool) {
	m := reqNameRe.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	name = m[1]
	rest := strings.TrimSpace(m[2])
	if strings.HasPrefix(rest, "@") {
		return "", "", false
	}
	return name, rest, true
}

// ParsePyProjectFile reads project dependencies from pyproject.toml.
func ParsePyProjectFile(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePyProject(data)
}

// ParsePyProject extracts PEP 621 [project] dependencies and optional-dependencies.
func ParsePyProject(data []byte) ([]Dependency, error) {
	text := string(data)
	seen := make(map[string]struct{})
	var out []Dependency

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		raw = strings.Trim(raw, `"'`)
		raw = markerRe.ReplaceAllString(raw, "")
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		name, ver, ok := splitRequirement(raw)
		if !ok {
			return
		}
		// Skip python version constraints mistakenly listed as deps.
		if strings.EqualFold(name, "python") {
			return
		}
		key := normalizeName(name)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Dependency{Name: name, Version: ver})
	}

	sections := splitTOMLSections(text)
	if body, ok := sections["project"]; ok {
		for _, item := range findNamedStringArray(body, "dependencies") {
			add(item)
		}
	}
	if body, ok := sections["project.optional-dependencies"]; ok {
		for _, arr := range findAllStringArrays(body) {
			for _, item := range arr {
				add(item)
			}
		}
	}

	if out == nil {
		out = []Dependency{}
	}
	return out, nil
}

func splitTOMLSections(text string) map[string]string {
	out := make(map[string]string)
	locs := tableRe.FindAllStringSubmatchIndex(text, -1)
	if len(locs) == 0 {
		return out
	}
	for i, loc := range locs {
		name := text[loc[2]:loc[3]]
		start := loc[1]
		end := len(text)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out[name] = text[start:end]
	}
	return out
}

func findNamedStringArray(body, key string) []string {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=\s*\[`)
	loc := re.FindStringIndex(body)
	if loc == nil {
		return nil
	}
	idx := strings.Index(body[loc[0]:], "[")
	if idx < 0 {
		return nil
	}
	items, ok := readStringArray(body[loc[0]+idx:])
	if !ok {
		return nil
	}
	return items
}

func findAllStringArrays(body string) [][]string {
	var out [][]string
	re := regexp.MustCompile(`(?m)^\s*[A-Za-z0-9_-]+\s*=\s*\[`)
	locs := re.FindAllStringIndex(body, -1)
	for _, loc := range locs {
		idx := strings.Index(body[loc[0]:loc[1]], "[")
		if idx < 0 {
			continue
		}
		items, ok := readStringArray(body[loc[0]+idx:])
		if ok {
			out = append(out, items)
		}
	}
	return out
}

func readStringArray(s string) ([]string, bool) {
	if !strings.HasPrefix(s, "[") {
		return nil, false
	}
	depth := 0
	inStr := false
	var quote rune
	escape := false
	var cur strings.Builder
	var items []string
	for _, r := range s {
		if inStr {
			if escape {
				cur.WriteRune(r)
				escape = false
				continue
			}
			if r == '\\' {
				escape = true
				continue
			}
			if r == quote {
				inStr = false
				items = append(items, cur.String())
				cur.Reset()
				continue
			}
			cur.WriteRune(r)
			continue
		}
		switch r {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return items, true
			}
		case '"', '\'':
			inStr = true
			quote = r
		}
	}
	return nil, false
}

func normalizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	return name
}
