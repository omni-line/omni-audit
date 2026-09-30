package ecosystem

import (
	"path"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/pypi"
	"github.com/omni-line/omni-audit/internal/registry"
	regpypi "github.com/omni-line/omni-audit/internal/registry/pypi"
)

// PyPI is requirements files and pyproject.toml checked against PyPI.
func PyPI(c registry.Checker) Ecosystem {
	return Ecosystem{
		Name:       "pypi",
		Registry:   "pypi.org",
		IsManifest: isPythonManifest,
		Parse: func(rel string, data []byte) ([]manifest.Dependency, error) {
			if strings.EqualFold(path.Base(rel), "pyproject.toml") {
				return pypi.ParsePyProject(data)
			}
			return pypi.ParseRequirements(data)
		},
		Normalize:  regpypi.Normalize,
		PackageURL: regpypi.PackageURL,
		Remediation: "Reserve the name on PyPI, and install internal packages with --index-url " +
			"pointing at your private index (--extra-index-url lets the public index win).",
		Checker: c,
	}
}

// isPythonManifest matches pyproject.toml, requirements*.txt, and *.txt files
// inside a requirements/ directory.
func isPythonManifest(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	if base == "pyproject.toml" {
		return true
	}
	if !strings.HasSuffix(base, ".txt") {
		return false
	}
	if strings.HasPrefix(base, "requirements") {
		return true
	}
	return strings.EqualFold(path.Base(path.Dir(rel)), "requirements")
}
