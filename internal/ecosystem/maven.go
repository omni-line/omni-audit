package ecosystem

import (
	"path"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/maven"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/mavencentral"
)

// Maven is pom.xml checked against Maven Central (repo1.maven.org).
func Maven(c registry.Checker) Ecosystem {
	return Ecosystem{
		Name:     "maven",
		Registry: "repo1.maven.org",
		IsManifest: func(rel string) bool {
			return strings.EqualFold(path.Base(rel), "pom.xml")
		},
		Parse: func(_ string, data []byte) ([]manifest.Dependency, error) {
			return maven.Parse(data)
		},
		Normalize:  mavencentral.Normalize,
		PackageURL: mavencentral.PackageURL,
		Remediation: "Reserve coordinates on Maven Central (or claim the group), and point builds " +
			"at a private/virtual registry (Omni Line or equivalent).",
		Checker: c,
	}
}
