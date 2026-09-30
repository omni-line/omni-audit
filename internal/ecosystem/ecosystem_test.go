package ecosystem_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/registry"
)

func TestDefaultEcosystemsAreValid(t *testing.T) {
	ecos := ecosystem.Default(registry.NewProber(nil, "test"))
	if err := ecosystem.ValidateAll(ecos); err != nil {
		t.Fatal(err)
	}
	for _, e := range ecos {
		if e.Registry == "" || e.Remediation == "" || e.PackageURL == nil {
			t.Errorf("%s: missing reporting metadata", e.Name)
		}
	}
}

func TestValidateAllRejectsDuplicatesAndGaps(t *testing.T) {
	npm := ecosystem.NPM(registry.CheckerFunc(nil))
	if err := ecosystem.ValidateAll([]ecosystem.Ecosystem{npm, npm}); err == nil {
		t.Error("expected duplicate error")
	}
	broken := npm
	broken.Parse = nil
	if err := ecosystem.ValidateAll([]ecosystem.Ecosystem{broken}); err == nil {
		t.Error("expected missing-field error")
	}
	if err := ecosystem.ValidateAll(nil); err == nil {
		t.Error("expected error for empty set")
	}
}

func TestManifestDetection(t *testing.T) {
	var checker registry.CheckerFunc
	cases := []struct {
		eco  ecosystem.Ecosystem
		rel  string
		want bool
	}{
		{ecosystem.NPM(checker), "apps/web/package.json", true},
		{ecosystem.NPM(checker), "package-lock.json", false},
		{ecosystem.Composer(checker), "composer.json", true},
		{ecosystem.Composer(checker), "composer.lock", false},
		{ecosystem.PyPI(checker), "pyproject.toml", true},
		{ecosystem.PyPI(checker), "requirements.txt", true},
		{ecosystem.PyPI(checker), "requirements-dev.txt", true},
		{ecosystem.PyPI(checker), "requirements/base.txt", true},
		{ecosystem.PyPI(checker), "docs/notes.txt", false},
		{ecosystem.PyPI(checker), "setup.cfg", false},
		{ecosystem.Go(checker), "go.mod", true},
		{ecosystem.Go(checker), "pkg/go.mod", true},
		{ecosystem.Go(checker), "go.sum", false},
	}
	for _, tc := range cases {
		if got := tc.eco.IsManifest(tc.rel); got != tc.want {
			t.Errorf("%s.IsManifest(%q)=%v want %v", tc.eco.Name, tc.rel, got, tc.want)
		}
	}
}
