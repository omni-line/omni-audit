package lockfile

import (
	"bufio"
	"bytes"
	"strings"
)

// ParseYarn extracts resolved URLs from a classic Yarn lockfile (yarn.lock v1).
// Yarn Berry (YAML) lockfiles without "resolved" lines yield no entries.
func ParseYarn(data []byte) ([]Resolved, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	// Allow long integrity lines.
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	var (
		out        []Resolved
		names      []string
		version    string
		lineNo     int
		headerLine int
	)
	flush := func(resolved string, resolvedLine int) {
		if resolved == "" || len(names) == 0 {
			return
		}
		for _, name := range names {
			out = append(out, Resolved{
				Name:    name,
				Version: version,
				URL:     resolved,
				Line:    resolvedLine,
			})
		}
	}

	var resolved string
	var resolvedLine int
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// New entry: not indented and ends with ':'
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
			flush(resolved, resolvedLine)
			names = yarnEntryNames(strings.TrimSuffix(trimmed, ":"))
			version = ""
			resolved = ""
			resolvedLine = 0
			headerLine = lineNo
			_ = headerLine
			continue
		}
		key, val, ok := yarnField(trimmed)
		if !ok {
			continue
		}
		switch key {
		case "version":
			version = unquoteYarn(val)
		case "resolved":
			resolved = unquoteYarn(val)
			// Strip yarn's optional "#hash" suffix from the URL.
			if i := strings.Index(resolved, "#"); i > 0 {
				resolved = resolved[:i]
			}
			resolvedLine = lineNo
		}
	}
	flush(resolved, resolvedLine)
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func yarnEntryNames(header string) []string {
	parts := strings.Split(header, ",")
	var names []string
	seen := make(map[string]struct{})
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = unquoteYarn(p)
		name := yarnPackageName(p)
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

// yarnPackageName strips version selectors from "lodash@^4.17.21" / "@scope/pkg@1.0.0".
func yarnPackageName(spec string) string {
	if spec == "" {
		return ""
	}
	if strings.HasPrefix(spec, "@") {
		// @scope/name@version — split on last @ after the scope slash.
		slash := strings.Index(spec, "/")
		if slash < 0 {
			return spec
		}
		rest := spec[slash+1:]
		if at := strings.Index(rest, "@"); at >= 0 {
			return spec[:slash+1+at]
		}
		return spec
	}
	if at := strings.Index(spec, "@"); at > 0 {
		return spec[:at]
	}
	return spec
}

func yarnField(line string) (key, val string, ok bool) {
	i := strings.IndexAny(line, " \t")
	if i <= 0 {
		return "", "", false
	}
	return line[:i], strings.TrimSpace(line[i+1:]), true
}

func unquoteYarn(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
