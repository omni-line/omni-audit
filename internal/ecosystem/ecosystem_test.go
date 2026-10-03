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
	want := []string{"npm", "composer", "pypi", "go", "cargo", "rubygems", "maven", "conan", "docker"}
	if len(ecos) != len(want) {
		t.Fatalf("got %d ecosystems, want %d", len(ecos), len(want))
	}
	for i, e := range ecos {
		if e.Name != want[i] {
			t.Errorf("ecosystem[%d]=%q want %q", i, e.Name, want[i])
		}
		if e.Registry == "" || e.Remediation == "" || e.PackageURL == nil {
			t.Errorf("%s: missing reporting metadata", e.Name)
		}
	}
	if ecos[0].Namespace == nil || ecos[0].NamespaceChecker == nil {
		t.Error("npm should have namespace ownership checks")
	}
	if ecos[1].Namespace == nil || ecos[1].NamespaceChecker == nil {
		t.Error("composer should have namespace ownership checks")
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
		{ecosystem.Cargo(checker), "Cargo.toml", true},
		{ecosystem.Cargo(checker), "src/Cargo.toml", true},
		{ecosystem.Cargo(checker), "Cargo.lock", false},
		{ecosystem.RubyGems(checker), "Gemfile", true},
		{ecosystem.RubyGems(checker), "foo.gemspec", true},
		{ecosystem.RubyGems(checker), "Gemfile.lock", false},
		{ecosystem.Maven(checker), "pom.xml", true},
		{ecosystem.Maven(checker), "module/pom.xml", true},
		{ecosystem.Conan(checker), "conanfile.txt", true},
		{ecosystem.Conan(checker), "conanfile.py", false},
		{ecosystem.Docker(checker), "Dockerfile", true},
		{ecosystem.Docker(checker), "Dockerfile.prod", true},
		{ecosystem.Docker(checker), "compose.yaml", true},
		{ecosystem.Docker(checker), "docker-compose.yml", true},
		{ecosystem.Docker(checker), "README.md", false},
	}
	for _, tc := range cases {
		if got := tc.eco.IsManifest(tc.rel); got != tc.want {
			t.Errorf("%s.IsManifest(%q)=%v want %v", tc.eco.Name, tc.rel, got, tc.want)
		}
	}
}
