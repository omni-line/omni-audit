package ecosystem

import (
	"path"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/rubygems"
	"github.com/omni-line/omni-audit/internal/registry"
	regruby "github.com/omni-line/omni-audit/internal/registry/rubygems"
)

// RubyGems is Gemfile / *.gemspec checked against rubygems.org.
func RubyGems(c registry.Checker) Ecosystem {
	return Ecosystem{
		Name:     "rubygems",
		Registry: "rubygems.org",
		IsManifest: func(rel string) bool {
			base := path.Base(rel)
			if strings.EqualFold(base, "Gemfile") {
				return true
			}
			return strings.HasSuffix(strings.ToLower(base), ".gemspec")
		},
		Parse: func(rel string, data []byte) ([]manifest.Dependency, error) {
			if strings.EqualFold(path.Base(rel), "Gemfile") {
				return rubygems.ParseGemfile(data)
			}
			return rubygems.ParseGemspec(data)
		},
		Normalize:  regruby.Normalize,
		PackageURL: regruby.PackageURL,
		Remediation: "Claim the name on rubygems.org, and configure Bundler to use your " +
			"private source (Omni Line or equivalent).",
		Checker: c,
	}
}
