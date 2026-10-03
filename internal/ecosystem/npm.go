package ecosystem

import (
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
		Normalize:     npm.Normalize,
		PeerNamespace: npm.Split,
		Implied:       impliedNPM,
		PackageURL:    regnpm.PackageURL,
		Remediation: "Claim the name (or its @scope as an npm organization) on npmjs.com, " +
			"and map internal scopes to your private registry in .npmrc.",
		Checker: c,
	}
	if ns, ok := c.(registry.Namespaced); ok {
		eco.Namespace = ns.PackageNamespace
		eco.NamespaceChecker = registry.CheckerFunc(ns.NamespaceExists)
	}
	return eco
}

// impliedNPM trusts DefinitelyTyped packages for popular libraries.
// DefinitelyTyped encodes "@scope/pkg" as "@types/scope__pkg".
func impliedNPM(key string, popular func(string) bool) bool {
	scope, leaf := npm.Split(key)
	if scope != "@types" {
		return false
	}
	if s, p, ok := strings.Cut(leaf, "__"); ok {
		return popular("@" + s + "/" + p)
	}
	return popular(leaf)
}
