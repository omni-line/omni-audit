package ecosystem

import (
	"context"
	"path"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/npm"
	"github.com/omni-line/omni-audit/internal/registry"
	regnpm "github.com/omni-line/omni-audit/internal/registry/npm"
)

// NPM is package.json checked against the npm registry.
func NPM(c registry.Checker) Ecosystem {
	eco := Ecosystem{
		Name:     "npm",
		Registry: "registry.npmjs.org",
		IsManifest: func(rel string) bool {
			return strings.EqualFold(path.Base(rel), "package.json")
		},
		Parse: func(_ string, data []byte) ([]manifest.Dependency, error) {
			return npm.Parse(data)
		},
		PackageURL: regnpm.PackageURL,
		Remediation: "Claim the name (or its @scope as an npm organization) on npmjs.com, " +
			"and map internal scopes to your private registry in .npmrc.",
		Checker: c,
	}
	if client, ok := c.(*regnpm.Client); ok {
		eco.Namespace = regnpm.Scope
		eco.NamespaceChecker = registry.CheckerFunc(func(ctx context.Context, ns string) (registry.Status, error) {
			return client.ScopeExists(ctx, ns)
		})
	}
	return eco
}
