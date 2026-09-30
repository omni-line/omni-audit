package pypi_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest/pypi"
)

func TestParseRequirements(t *testing.T) {
	data := []byte(`
# comment
requests>=2.28
Flask[async]==2.3.0
acme_internal==1.0.0 ; python_version >= "3.9"
-r other.txt
--index-url https://example.com
git+https://github.com/x/y.git
`)
	deps, err := pypi.ParseRequirements(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range deps {
		got[d.Name] = d.Version
	}
	if got["requests"] != ">=2.28" || got["Flask"] != "==2.3.0" || got["acme_internal"] != "==1.0.0" {
		t.Fatalf("unexpected deps: %#v", got)
	}
	if len(deps) != 3 {
		t.Fatalf("len=%d want 3", len(deps))
	}
}

func TestParsePyProject(t *testing.T) {
	data := []byte(`
[project]
name = "demo"
dependencies = [
  "requests>=2.0",
  "acme-private==0.1.0",
]

[project.optional-dependencies]
dev = [
  "pytest>=7",
]
`)
	deps, err := pypi.ParsePyProject(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range deps {
		got[d.Name] = true
	}
	for _, name := range []string{"requests", "acme-private", "pytest"} {
		if !got[name] {
			t.Fatalf("missing %s in %#v", name, got)
		}
	}
	if len(deps) != 3 {
		t.Fatalf("len=%d want 3", len(deps))
	}
}
