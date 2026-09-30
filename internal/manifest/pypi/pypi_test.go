package pypi_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/pypi"
)

func TestParseRequirements(t *testing.T) {
	data := []byte(`
# comment
requests>=2.28
Flask[async]==2.3.0  # pinned for prod
acme_internal==1.0.0 ; python_version >= "3.9"
-r other.txt
-e .
--index-url https://example.com
git+https://github.com/x/y.git
pkg @ https://example.com/pkg.whl
./local/pkg
dist/thing-1.0-py3-none-any.whl
long-name \
    >=1.0,<2
ACME.Internal==2.0
`)
	deps, err := pypi.ParseRequirements(data)
	if err != nil {
		t.Fatal(err)
	}
	got := index(deps)
	want := map[string]struct {
		version string
		line    int
	}{
		"requests":      {">=2.28", 3},
		"Flask":         {"==2.3.0", 4},
		"acme_internal": {"==1.0.0", 5},
		"long-name":     {">=1.0,<2", 13},
	}
	for name, w := range want {
		d, ok := got[name]
		if !ok || d.Version != w.version || d.Line != w.line {
			t.Errorf("%s = %+v, want version=%q line=%d", name, d, w.version, w.line)
		}
	}
	if len(deps) != len(want) {
		t.Fatalf("len=%d want %d (ACME.Internal dedupes with acme_internal): %#v", len(deps), len(want), got)
	}
}

func TestParsePyProject(t *testing.T) {
	data := []byte(`
[project]
name = "demo"
dependencies = [
  "requests>=2.0",
  # "commented-out>=1",
  'acme-private==0.1.0',
]

[project.optional-dependencies]
dev = [
  "pytest>=7",
]
docs = ["sphinx"]

[dependency-groups]
test = [
  "coverage",
  {include-group = "lint"},
]

[[tool.custom.entries]]
dependencies = ["not-a-dep"]

[tool.other] # trailing comment
dependencies = ["also-not-a-dep"]
`)
	deps, err := pypi.ParsePyProject(data)
	if err != nil {
		t.Fatal(err)
	}
	got := index(deps)
	want := map[string]struct {
		group string
		line  int
	}{
		"requests":     {"dependencies", 5},
		"acme-private": {"dependencies", 7},
		"pytest":       {"optional-dependencies.dev", 12},
		"sphinx":       {"optional-dependencies.docs", 14},
		"coverage":     {"dependency-groups.test", 18},
	}
	for name, w := range want {
		d, ok := got[name]
		if !ok || d.Group != w.group || d.Line != w.line {
			t.Errorf("%s = %+v, want group=%q line=%d", name, d, w.group, w.line)
		}
	}
	if len(deps) != len(want) {
		t.Fatalf("len=%d want %d: %#v", len(deps), len(want), got)
	}
}

func index(deps []manifest.Dependency) map[string]manifest.Dependency {
	m := make(map[string]manifest.Dependency, len(deps))
	for _, d := range deps {
		m[d.Name] = d
	}
	return m
}
