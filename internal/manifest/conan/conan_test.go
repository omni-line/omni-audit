package conan_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest/conan"
)

func TestParseSections(t *testing.T) {
	data := []byte(`
[requires]
zlib/1.2.13
openssl/3.1.0@user/stable
# skipped comment
acme-private/0.1.0

[options]
zlib/*:shared=True

[tool_requires]
cmake/3.25.0

[build_requires]
ninja/1.11.0
zlib/1.2.11

[generators]
CMakeDeps
`)
	deps, err := conan.Parse(data)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	groups := map[string]string{}
	lines := map[string]int{}
	for _, d := range deps {
		got[d.Name] = d.Version
		groups[d.Name] = d.Group
		lines[d.Name] = d.Line
	}

	if got["zlib"] != "1.2.13" {
		t.Fatalf("zlib: want first occurrence version, got %#v", got)
	}
	if groups["zlib"] != "requires" {
		t.Fatalf("zlib group: %#v", groups)
	}
	if got["openssl"] != "3.1.0@user/stable" {
		t.Fatalf("openssl: %#v", got)
	}
	if got["acme-private"] != "0.1.0" {
		t.Fatalf("acme-private: %#v", got)
	}
	if got["cmake"] != "3.25.0" || groups["cmake"] != "tool_requires" {
		t.Fatalf("cmake: version=%q group=%q", got["cmake"], groups["cmake"])
	}
	if got["ninja"] != "1.11.0" || groups["ninja"] != "build_requires" {
		t.Fatalf("ninja: version=%q group=%q", got["ninja"], groups["ninja"])
	}
	if len(deps) != 5 {
		t.Fatalf("len=%d want 5 (dedupe zlib): %#v", len(deps), deps)
	}
	if lines["zlib"] != 3 || lines["cmake"] == 0 {
		t.Fatalf("lines: %#v", lines)
	}
}

func TestParseBareNameAndRevision(t *testing.T) {
	data := []byte(`[requires]
mylib
other/1.0.0#rrev
`)
	deps, err := conan.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("len=%d want 2: %#v", len(deps), deps)
	}
	if deps[0].Name != "mylib" || deps[0].Version != "" {
		t.Fatalf("bare: %#v", deps[0])
	}
	if deps[1].Name != "other" || deps[1].Version != "1.0.0#rrev" {
		t.Fatalf("revision: %#v", deps[1])
	}
}

func TestParseEmpty(t *testing.T) {
	deps, err := conan.Parse([]byte("[options]\nzlib/*:shared=True\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 0 {
		t.Fatalf("want empty, got %#v", deps)
	}
}

func TestParseCaseInsensitiveSectionAndDedupe(t *testing.T) {
	data := []byte(`[Requires]
Zlib/1.2.13

[TOOL_REQUIRES]
zlib/9.9.9
`)
	deps, err := conan.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("len=%d want 1: %#v", len(deps), deps)
	}
	if deps[0].Name != "Zlib" || deps[0].Version != "1.2.13" {
		t.Fatalf("got %#v", deps[0])
	}
}
