package npm_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/npm"
)

func TestParse(t *testing.T) {
	data := []byte(`{
  "dependencies": {
    "lodash": "1.0.0",
    "@acme/x": "2.0.0"
  },
  "devDependencies": {"lodash": "2.0.0", "typescript": "5.0.0"},
  "peerDependencies": {"react": "18"},
  "optionalDependencies": {"fsevents": "1"}
}`)
	deps, err := npm.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	got := index(deps)
	if got["lodash"].Version != "1.0.0" || got["lodash"].Group != "dependencies" {
		t.Fatalf("lodash = %+v, want first-seen 1.0.0 in dependencies", got["lodash"])
	}
	if got["lodash"].Line != 3 || got["@acme/x"].Line != 4 {
		t.Fatalf("lines: lodash=%d @acme/x=%d", got["lodash"].Line, got["@acme/x"].Line)
	}
	if got["typescript"].Group != "devDependencies" || got["typescript"].Line != 6 {
		t.Fatalf("typescript = %+v", got["typescript"])
	}
	for _, name := range []string{"react", "fsevents"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("missing dependency %s", name)
		}
	}
	if len(deps) != 5 {
		t.Fatalf("len=%d want 5", len(deps))
	}
}

func TestParseSkipsNonRegistrySpecsAndResolvesAliases(t *testing.T) {
	data := []byte(`{"dependencies": {
		"local-lib": "file:../lib",
		"ws-pkg": "workspace:*",
		"linked": "link:../linked",
		"from-git": "git+https://github.com/x/y.git",
		"gh-short": "acme/repo#main",
		"gh-proto": "github:acme/repo",
		"tarball": "https://example.com/x.tgz",
		"rel": "./vendor/pkg",
		"my-alias": "npm:@acme/real-pkg@^1.2.0",
		"plain-alias": "npm:other",
		"ranged": ">=1.0.0 <2",
		"tagged": "latest"
	}}`)
	deps, err := npm.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	got := index(deps)
	for _, skipped := range []string{"local-lib", "ws-pkg", "linked", "from-git", "gh-short", "gh-proto", "tarball", "rel", "my-alias", "plain-alias"} {
		if _, ok := got[skipped]; ok {
			t.Errorf("%s should not be reported under its local key", skipped)
		}
	}
	if d, ok := got["@acme/real-pkg"]; !ok || d.Version != "^1.2.0" {
		t.Errorf("alias target missing or wrong: %+v", d)
	}
	for _, name := range []string{"other", "ranged", "tagged"} {
		if _, ok := got[name]; !ok {
			t.Errorf("missing %s", name)
		}
	}
}

func TestParseRejectsInvalidJSON(t *testing.T) {
	if _, err := npm.Parse([]byte(`{"dependencies": [`)); err == nil {
		t.Fatal("expected error")
	}
	if _, err := npm.Parse([]byte(`{"dependencies": {"x": 1}}`)); err == nil {
		t.Fatal("expected error for non-string version")
	}
}

func index(deps []manifest.Dependency) map[string]manifest.Dependency {
	m := make(map[string]manifest.Dependency, len(deps))
	for _, d := range deps {
		m[d.Name] = d
	}
	return m
}
