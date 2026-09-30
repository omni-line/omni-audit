package gomod_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest/gomod"
)

func TestParseRequire(t *testing.T) {
	data := []byte(`
module example.com/app

go 1.22

require github.com/stretchr/testify v1.9.0

require (
	github.com/google/uuid v1.6.0 // indirect
	example.com/Internal/SDK v0.1.0
)

exclude github.com/bad/thing v1.0.0

replace example.com/Internal/SDK => ../sdk
`)
	deps, err := gomod.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	lines := map[string]int{}
	for _, d := range deps {
		got[d.Name] = d.Version
		lines[d.Name] = d.Line
		if d.Group != "require" {
			t.Errorf("%s: group=%q", d.Name, d.Group)
		}
	}
	if got["github.com/stretchr/testify"] != "v1.9.0" {
		t.Fatalf("testify: %#v", got)
	}
	if got["github.com/google/uuid"] != "v1.6.0" {
		t.Fatalf("uuid: %#v", got)
	}
	if got["example.com/Internal/SDK"] != "v0.1.0" {
		t.Fatalf("internal: %#v", got)
	}
	if _, ok := got["github.com/bad/thing"]; ok {
		t.Fatal("exclude must not produce a dependency")
	}
	if len(deps) != 3 {
		t.Fatalf("len=%d want 3: %#v", len(deps), deps)
	}
	if lines["github.com/stretchr/testify"] == 0 {
		t.Fatal("expected line for single-line require")
	}
}

func TestParseEmpty(t *testing.T) {
	deps, err := gomod.Parse([]byte("module example.com/x\n\ngo 1.21\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 0 {
		t.Fatalf("want empty, got %#v", deps)
	}
}
