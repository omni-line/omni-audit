package cargo_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/cargo"
)

func TestParse(t *testing.T) {
	data := []byte(`
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1", features = ["full"] }
# comment
local = { path = "../local" }
fromgit = { git = "https://github.com/foo/bar" }
ws = { workspace = true }
renamed = { package = "real-crate", version = "0.2" }
path_rename = { package = "other-crate", path = "../other" }
"quoted-name" = "0.3"

[dev-dependencies]
pretty_assertions = "1.4"

[build-dependencies]
cc = { version = "1.0" }

[target.'cfg(windows)'.dependencies]
winapi = "0.3"

[target.x86_64-unknown-linux-gnu.dev-dependencies]
linux-dev = "0.1"

[dependencies]
serde = "2.0" # duplicate; first wins

[profile.release]
lto = true
`)
	deps, err := cargo.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	got := index(deps)
	want := map[string]struct {
		version string
		group   string
		line    int
	}{
		"serde":             {"1.0", "dependencies", 7},
		"tokio":             {"1", "dependencies", 8},
		"real-crate":        {"0.2", "dependencies", 13},
		"quoted-name":       {"0.3", "dependencies", 15},
		"pretty_assertions": {"1.4", "dev-dependencies", 18},
		"cc":                {"1.0", "build-dependencies", 21},
		"winapi":            {"0.3", "target.cfg(windows).dependencies", 24},
		"linux-dev":         {"0.1", "target.x86_64-unknown-linux-gnu.dev-dependencies", 27},
	}
	for name, w := range want {
		d, ok := got[name]
		if !ok || d.Version != w.version || d.Group != w.group || d.Line != w.line {
			t.Errorf("%s = %+v, want version=%q group=%q line=%d", name, d, w.version, w.group, w.line)
		}
	}
	for _, skip := range []string{"local", "fromgit", "ws", "other-crate", "path_rename"} {
		if _, ok := got[skip]; ok {
			t.Errorf("should skip %s", skip)
		}
	}
	if len(deps) != len(want) {
		t.Fatalf("len=%d want %d: %#v", len(deps), len(want), got)
	}
}

func TestParseMultilineInline(t *testing.T) {
	data := []byte(`
[dependencies]
foo = {
  version = "1.2",
  features = ["a", "b"],
}
bar = {
  path = "../bar",
  version = "0.1",
}
`)
	deps, err := cargo.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	got := index(deps)
	if d, ok := got["foo"]; !ok || d.Version != "1.2" {
		t.Fatalf("foo: %+v", got)
	}
	if _, ok := got["bar"]; ok {
		t.Fatal("path dep must be skipped even with version")
	}
	if len(deps) != 1 {
		t.Fatalf("len=%d: %#v", len(deps), deps)
	}
}

func TestParseEmpty(t *testing.T) {
	deps, err := cargo.Parse([]byte("[package]\nname = \"x\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 0 {
		t.Fatalf("want empty, got %#v", deps)
	}
}

func TestParseBuildTarget(t *testing.T) {
	data := []byte(`
[target.'cfg(unix)'.build-dependencies]
pkg-config = "0.3"
`)
	deps, err := cargo.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "pkg-config" || deps[0].Group != "target.cfg(unix).build-dependencies" {
		t.Fatalf("got %#v", deps)
	}
}

func index(deps []manifest.Dependency) map[string]manifest.Dependency {
	out := make(map[string]manifest.Dependency, len(deps))
	for _, d := range deps {
		out[d.Name] = d
	}
	return out
}
