package ecosystem

import (
	"path"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/gomod"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/goproxy"
)

// Go is go.mod checked against the public Go module proxy.
func Go(c registry.Checker) Ecosystem {
	return Ecosystem{
		Name:     "go",
		Registry: "proxy.golang.org",
		IsManifest: func(rel string) bool {
			return strings.EqualFold(path.Base(rel), "go.mod")
		},
		Parse: func(_ string, data []byte) ([]manifest.Dependency, error) {
			return gomod.Parse(data)
		},
		Normalize:  gomod.Normalize,
		PackageURL: goproxy.PackageURL,
		Remediation: "Keep private modules under a domain you control, set GOPRIVATE so the " +
			"public proxy is never asked, and publish a go-import meta tag for vanity paths.",
		Checker: c,
	}
}
