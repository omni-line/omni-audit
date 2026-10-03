// Package docker parses Dockerfile FROM instructions and Compose image: lines
// into Docker Hub repository identities.
package docker

import (
	"bufio"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
)

// ParseDockerfile extracts Hub repository names from FROM instructions.
func ParseDockerfile(data []byte) ([]manifest.Dependency, error) {
	return parseLines(data, parseFROM)
}

// ParseCompose extracts Hub repository names from image: keys in Compose YAML.
// It uses a simple line scan (no YAML library): good enough for typical files.
func ParseCompose(data []byte) ([]manifest.Dependency, error) {
	return parseLines(data, parseImageLine)
}

type lineParser func(line string) (name, version, group string, ok bool)

func parseLines(data []byte, parse lineParser) ([]manifest.Dependency, error) {
	seen := make(map[string]struct{})
	out := []manifest.Dependency{}

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		name, version, group, ok := parse(sc.Text())
		if !ok || name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, manifest.Dependency{
			Name:    name,
			Version: version,
			Group:   group,
			Line:    lineNo,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseFROM handles "FROM [--flag=val ...] image [AS stage]".
func parseFROM(raw string) (name, version, group string, ok bool) {
	line := strings.TrimSpace(stripDockerfileComment(raw))
	if line == "" {
		return "", "", "", false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
		return "", "", "", false
	}
	i := 1
	for i < len(fields) && strings.HasPrefix(fields[i], "--") {
		i++
	}
	if i >= len(fields) {
		return "", "", "", false
	}
	ref := fields[i]
	hub, ver, ok := HubRepository(ref)
	if !ok {
		return "", "", "", false
	}
	return hub, ver, "FROM", true
}

func stripDockerfileComment(line string) string {
	inQuote := false
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuote {
			if c == quote {
				inQuote = false
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = true
			quote = c
			continue
		}
		if c == '#' {
			return line[:i]
		}
	}
	return line
}

// parseImageLine finds a top-level-ish "image:" value on a single YAML line.
func parseImageLine(raw string) (name, version, group string, ok bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", "", false
	}
	// Drop trailing YAML comments outside quotes.
	line = stripYAMLComment(line)
	lower := strings.ToLower(line)
	const key = "image:"
	idx := strings.Index(lower, key)
	if idx < 0 {
		return "", "", "", false
	}
	// Require image: at the start of the (trimmed) key, allowing leading "- ".
	prefix := strings.TrimSpace(line[:idx])
	if prefix != "" && prefix != "-" {
		return "", "", "", false
	}
	val := strings.TrimSpace(line[idx+len(key):])
	val = unquote(val)
	if val == "" || isVariableOnly(val) {
		return "", "", "", false
	}
	hub, ver, ok := HubRepository(val)
	if !ok {
		return "", "", "", false
	}
	return hub, ver, "image", true
}

func stripYAMLComment(line string) string {
	inQuote := false
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuote {
			if c == quote {
				inQuote = false
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = true
			quote = c
			continue
		}
		if c == '#' {
			return strings.TrimSpace(line[:i])
		}
	}
	return line
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// isVariableOnly reports Compose refs that are only a substitution with no
// concrete repository path (e.g. ${IMG}, $IMAGE).
func isVariableOnly(ref string) bool {
	s := strings.TrimSpace(ref)
	if s == "" {
		return true
	}
	// Strip digest/tag noise before judging.
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 && !strings.Contains(s, "/") {
		// official:tag — keep name side for the check below
		s = s[:i]
	} else if i := strings.LastIndexByte(s, ':'); i >= 0 {
		// namespace/name:tag — tag after last path segment
		if j := strings.LastIndexByte(s, '/'); j < i {
			s = s[:i]
		}
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") && !strings.Contains(s[2:len(s)-1], "}") {
		return true
	}
	if len(s) > 1 && s[0] == '$' {
		rest := s[1:]
		if !strings.ContainsAny(rest, "/:{}") {
			return true
		}
	}
	return false
}

// HubRepository maps an image reference to a Docker Hub repository path
// (namespace/name) and an optional tag. Non-Hub registries and scratch are
// skipped (ok=false).
//
//	nginx                  → library/nginx
//	nginx:1.25             → library/nginx
//	bitnami/nginx:latest   → bitnami/nginx
//	docker.io/library/nginx → library/nginx
//	ghcr.io/foo/bar        → skip
func HubRepository(ref string) (hub, tag string, ok bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", "", false
	}
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	if ref == "" {
		return "", "", false
	}

	path, tag := splitNameTag(ref)
	path = strings.ToLower(path)
	if path == "" || isVariableOnly(path) {
		return "", "", false
	}

	parts := strings.Split(path, "/")
	if len(parts) >= 1 && isRegistryHost(parts[0]) {
		if parts[0] != "docker.io" {
			return "", "", false
		}
		parts = parts[1:]
		if len(parts) == 0 {
			return "", "", false
		}
	}

	var name string
	switch len(parts) {
	case 1:
		if parts[0] == "scratch" {
			return "", "", false
		}
		name = "library/" + parts[0]
	default:
		// Hub identity is namespace/name; ignore extra path segments (rare).
		name = parts[0] + "/" + parts[1]
		if name == "library/scratch" {
			return "", "", false
		}
	}
	return name, tag, true
}

// splitNameTag separates an optional tag. Registry hosts with ports are not
// present here — callers strip those refs before calling HubRepository, and
// isRegistryHost runs on the first path segment of the full ref.
func splitNameTag(ref string) (name, tag string) {
	// Tag is after the last ':' that follows the last '/', or the only ':'
	// when there is no '/'.
	slash := strings.LastIndexByte(ref, '/')
	colon := strings.LastIndexByte(ref, ':')
	if colon < 0 || colon < slash {
		return ref, ""
	}
	return ref[:colon], ref[colon+1:]
}

// isRegistryHost reports whether a path segment looks like a registry host
// (contains '.' or ':'), e.g. ghcr.io, localhost:5000.
func isRegistryHost(seg string) bool {
	return strings.Contains(seg, ".") || strings.Contains(seg, ":")
}
