// Package ecosystem binds a manifest format to its public registry.
//
// Adding an ecosystem means writing a manifest parser under internal/manifest,
// a registry client under internal/registry, and one constructor in this
// package that is listed in Default. Discovery, scanning, and reporting are
// ecosystem-agnostic.
package ecosystem

import (
	"errors"
	"fmt"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/conancenter"
	"github.com/omni-line/omni-audit/internal/registry/cratesio"
	"github.com/omni-line/omni-audit/internal/registry/dockerhub"
	"github.com/omni-line/omni-audit/internal/registry/goproxy"
	"github.com/omni-line/omni-audit/internal/registry/mavencentral"
	regnpm "github.com/omni-line/omni-audit/internal/registry/npm"
	"github.com/omni-line/omni-audit/internal/registry/packagist"
	regpypi "github.com/omni-line/omni-audit/internal/registry/pypi"
	regruby "github.com/omni-line/omni-audit/internal/registry/rubygems"
)

// Ecosystem describes one package ecosystem end to end.
type Ecosystem struct {
	// Name is the stable identifier used in reports ("npm", "composer", ...).
	Name string
	// Registry is a human label for the public registry host.
	Registry string
	// IsManifest reports whether rel (slash-separated, relative to the scan
	// root) is a manifest this ecosystem can parse.
	IsManifest func(rel string) bool
	// Parse extracts dependencies; rel lets one ecosystem handle several
	// manifest formats.
	Parse func(rel string, data []byte) ([]manifest.Dependency, error)
	// Normalize maps a name to its registry identity, used to dedupe checks.
	Normalize func(name string) string
	// PackageURL returns the public web page for a package name.
	PackageURL func(name string) string
	// Namespace extracts the scope/vendor from a package name when the
	// ecosystem has namespace-level ownership (npm scopes, Packagist vendors).
	Namespace func(name string) (ns string, ok bool)
	// NamespaceChecker reports whether a namespace is claimed. Optional;
	// when set with Namespace, findings get severity from ownership.
	NamespaceChecker registry.Checker
	// Remediation is short, vendor-neutral advice for an unclaimed name.
	Remediation string
	// Checker queries the public registry.
	Checker registry.Checker
}

// Validate reports missing required fields.
func (e Ecosystem) Validate() error {
	var missing []string
	if e.Name == "" {
		missing = append(missing, "Name")
	}
	if e.IsManifest == nil {
		missing = append(missing, "IsManifest")
	}
	if e.Parse == nil {
		missing = append(missing, "Parse")
	}
	if e.Checker == nil {
		missing = append(missing, "Checker")
	}
	if len(missing) > 0 {
		return fmt.Errorf("ecosystem %q: missing %v", e.Name, missing)
	}
	return nil
}

// Key returns the identity used to dedupe registry checks.
func (e Ecosystem) Key(name string) string {
	if e.Normalize == nil {
		return name
	}
	return e.Normalize(name)
}

// URL returns the public page for name, or "" if unknown.
func (e Ecosystem) URL(name string) string {
	if e.PackageURL == nil {
		return ""
	}
	return e.PackageURL(name)
}

// Default returns every supported ecosystem backed by its public registry.
func Default(p *registry.Prober) []Ecosystem {
	npmClient := regnpm.New(p)
	packagistClient := packagist.New(p)
	return []Ecosystem{
		NPM(npmClient),
		Composer(packagistClient),
		PyPI(regpypi.New(p)),
		Go(goproxy.New(p)),
		Cargo(cratesio.New(p)),
		RubyGems(regruby.New(p)),
		Maven(mavencentral.New(p)),
		Conan(conancenter.New(p)),
		Docker(dockerhub.New(p)),
	}
}

// ValidateAll checks a set of ecosystems for missing fields and duplicate names.
func ValidateAll(ecosystems []Ecosystem) error {
	if len(ecosystems) == 0 {
		return errors.New("no ecosystems configured")
	}
	seen := make(map[string]struct{}, len(ecosystems))
	for _, e := range ecosystems {
		if err := e.Validate(); err != nil {
			return err
		}
		if _, dup := seen[e.Name]; dup {
			return fmt.Errorf("ecosystem %q registered twice", e.Name)
		}
		seen[e.Name] = struct{}{}
	}
	return nil
}
