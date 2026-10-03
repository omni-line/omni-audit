// Package lockfile parses package manager lockfiles and extracts resolved
// download URLs for source / shadow-registry auditing.
package lockfile

import (
	"fmt"
	"path"
	"strings"
)

// Resolved is a dependency with a concrete resolution URL from a lockfile.
type Resolved struct {
	// Name is the package name as recorded in the lockfile.
	Name string
	// Version is the locked version, verbatim; may be empty.
	Version string
	// URL is the resolved download / registry URL.
	URL string
	// Line is the 1-based line of the resolution, or 0 when unknown.
	Line int
}

// Kind describes a supported lockfile format.
type Kind struct {
	// Ecosystem is the stable ecosystem id (npm, composer, pypi, …).
	Ecosystem string
	// IsLockfile reports whether rel (slash-separated) is this kind of lockfile.
	IsLockfile func(rel string) bool
	// Parse extracts resolved dependencies from lockfile bytes.
	Parse func(data []byte) ([]Resolved, error)
}

// Default returns the lockfile kinds audited by omni-audit.
func Default() []Kind {
	return []Kind{
		{
			Ecosystem: "npm",
			IsLockfile: func(rel string) bool {
				base := path.Base(rel)
				return strings.EqualFold(base, "package-lock.json") ||
					strings.EqualFold(base, "npm-shrinkwrap.json")
			},
			Parse: ParseNPM,
		},
		{
			Ecosystem: "npm",
			IsLockfile: func(rel string) bool {
				return strings.EqualFold(path.Base(rel), "yarn.lock")
			},
			Parse: ParseYarn,
		},
		{
			Ecosystem: "pypi",
			IsLockfile: func(rel string) bool {
				return strings.EqualFold(path.Base(rel), "poetry.lock")
			},
			Parse: ParsePoetry,
		},
		{
			Ecosystem: "composer",
			IsLockfile: func(rel string) bool {
				return strings.EqualFold(path.Base(rel), "composer.lock")
			},
			Parse: ParseComposer,
		},
	}
}

// Classify returns the ecosystem name for a lockfile path, or "" if unsupported.
// When multiple kinds match, the first in Default wins.
func Classify(kinds []Kind, rel string) string {
	for _, k := range kinds {
		if k.IsLockfile(rel) {
			return k.Ecosystem
		}
	}
	return ""
}

// ParseFile parses a lockfile using the first matching kind.
func ParseFile(kinds []Kind, rel string, data []byte) ([]Resolved, error) {
	for _, k := range kinds {
		if k.IsLockfile(rel) {
			deps, err := k.Parse(data)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", path.Base(rel), err)
			}
			return deps, nil
		}
	}
	return nil, fmt.Errorf("unsupported lockfile %q", rel)
}
