package ecosystem

import (
	"path"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/cargo"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/cratesio"
)

// Cargo is Cargo.toml checked against crates.io.
func Cargo(c registry.Checker) Ecosystem {
	return Ecosystem{
		Name:     "cargo",
		Registry: "crates.io",
		IsManifest: func(rel string) bool {
			return strings.EqualFold(path.Base(rel), "Cargo.toml")
		},
		Parse: func(_ string, data []byte) ([]manifest.Dependency, error) {
			return cargo.Parse(data)
		},
		Normalize:  cratesio.Normalize,
		PackageURL: cratesio.PackageURL,
		Remediation: "Claim the crate name on crates.io, and point Cargo at your private registry " +
			"(e.g. Omni Line) via .cargo/config.toml.",
		Checker: c,
	}
}
