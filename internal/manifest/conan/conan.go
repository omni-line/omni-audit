// Package conan parses dependency declarations from conanfile.txt.
//
// conanfile.py is intentionally not supported: evaluating a Python recipe
// is out of scope for a static scanner.
package conan

import (
	"bufio"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
)

// Groups are the conanfile.txt sections scanned for dependencies.
// build_requires is accepted as a Conan 1.x alias of tool_requires.
var Groups = []string{"requires", "tool_requires", "build_requires"}

var tracked = map[string]struct{}{
	"requires":       {},
	"tool_requires":  {},
	"build_requires": {},
}

// Parse returns ConanCenter-resolvable dependencies from conanfile.txt bytes.
//
// Only [requires], [tool_requires], and [build_requires] are read. Each
// reference contributes the package name (segment before the first '/') and
// an optional version (the rest). Blank lines and '#' comment lines are
// skipped. Dependencies are deduped by package name (case-insensitive);
// the first occurrence wins.
func Parse(data []byte) ([]manifest.Dependency, error) {
	seen := make(map[string]struct{})
	var out []manifest.Dependency

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	section := ""

	for sc.Scan() {
		lineNo++
		trimmed := strings.TrimSpace(sc.Text())
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			continue
		}

		if _, ok := tracked[section]; !ok {
			continue
		}

		name, version := splitRef(trimmed)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, manifest.Dependency{
			Name:    name,
			Version: version,
			Group:   section,
			Line:    lineNo,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []manifest.Dependency{}
	}
	return out, nil
}

// splitRef splits "pkg/1.2.3@user/channel#rrev" into name and version.
// A bare "pkg" (no '/') yields an empty version.
func splitRef(ref string) (name, version string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", ""
	}
	i := strings.IndexByte(ref, '/')
	if i < 0 {
		return ref, ""
	}
	return ref[:i], ref[i+1:]
}
