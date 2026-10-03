package ecosystem

import (
	"context"
	"path"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/composer"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/packagist"
)

// Composer is composer.json checked against Packagist.
func Composer(c registry.Checker) Ecosystem {
	eco := Ecosystem{
		Name:     "composer",
		Registry: "packagist.org",
		IsManifest: func(rel string) bool {
			return strings.EqualFold(path.Base(rel), "composer.json")
		},
		Parse: func(_ string, data []byte) ([]manifest.Dependency, error) {
			return composer.Parse(data)
		},
		Normalize:     packagist.Normalize,
		PeerNamespace: composer.Split,
		PackageURL:    packagist.PackageURL,
		Remediation: "Register the vendor name on Packagist so nobody else can publish under it, " +
			"and declare your private repository in composer.json \"repositories\".",
		Checker: c,
	}
	if client, ok := c.(*packagist.Client); ok {
		eco.Namespace = packagist.Vendor
		eco.NamespaceChecker = registry.CheckerFunc(func(ctx context.Context, ns string) (registry.Status, error) {
			return client.VendorExists(ctx, ns)
		})
	}
	return eco
}
