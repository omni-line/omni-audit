package ecosystem

import (
	"path"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/conan"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/conancenter"
)

// Conan is conanfile.txt checked against ConanCenter.
func Conan(c registry.Checker) Ecosystem {
	return Ecosystem{
		Name:     "conan",
		Registry: "center2.conan.io",
		IsManifest: func(rel string) bool {
			return strings.EqualFold(path.Base(rel), "conanfile.txt")
		},
		Parse: func(_ string, data []byte) ([]manifest.Dependency, error) {
			return conan.Parse(data)
		},
		Normalize:   conancenter.Normalize,
		PackageURL:  conancenter.PackageURL,
		Remediation: "Claim the package on ConanCenter (or host it on your private Conan remote such as Omni Line) so installs cannot resolve a public impostor.",
		Checker:     c,
	}
}
