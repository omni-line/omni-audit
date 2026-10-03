package lockfile

import (
	"bufio"
	"bytes"
	"strings"
)

// defaultPyPISource is assumed when a poetry.lock package has no [package.source].
const defaultPyPISource = "https://pypi.org/simple"

// ParsePoetry extracts source URLs from poetry.lock (TOML subset).
// Packages without an explicit source are treated as resolving from PyPI.
func ParsePoetry(data []byte) ([]Resolved, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	var (
		out      []Resolved
		inPkg    bool
		inSrc    bool
		name     string
		version  string
		srcURL   string
		nameLine int
		lineNo   int
		hasSrc   bool
	)
	flush := func() {
		if !inPkg || name == "" {
			return
		}
		url := srcURL
		if !hasSrc || url == "" {
			url = defaultPyPISource
		}
		out = append(out, Resolved{
			Name:    name,
			Version: version,
			URL:     url,
			Line:    nameLine,
		})
	}

	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "[[package]]" {
			flush()
			inPkg, inSrc = true, false
			name, version, srcURL = "", "", ""
			nameLine, hasSrc = 0, false
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			if trimmed == "[package.source]" && inPkg {
				inSrc = true
				hasSrc = true
				continue
			}
			// Leaving the package / source table.
			if inSrc && trimmed != "[package.source]" {
				inSrc = false
			}
			if strings.HasPrefix(trimmed, "[[") && trimmed != "[[package]]" {
				flush()
				inPkg, inSrc = false, false
			}
			if strings.HasPrefix(trimmed, "[metadata") {
				flush()
				inPkg, inSrc = false, false
			}
			continue
		}
		if !inPkg {
			continue
		}
		key, val, ok := tomlKeyVal(trimmed)
		if !ok {
			continue
		}
		if inSrc {
			if key == "url" {
				srcURL = val
			}
			continue
		}
		switch key {
		case "name":
			name = val
			nameLine = lineNo
		case "version":
			version = val
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func tomlKeyVal(line string) (key, val string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	val = strings.TrimSpace(line[i+1:])
	if len(val) >= 2 && val[0] == '"' {
		if end := strings.LastIndexByte(val[1:], '"'); end >= 0 {
			return key, val[1 : 1+end], true
		}
	}
	if len(val) >= 2 && val[0] == '\'' {
		if end := strings.LastIndexByte(val[1:], '\''); end >= 0 {
			return key, val[1 : 1+end], true
		}
	}
	return key, val, true
}
