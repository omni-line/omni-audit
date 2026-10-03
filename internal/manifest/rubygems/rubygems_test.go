package rubygems_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/rubygems"
)

func TestParseGemfile(t *testing.T) {
	data := []byte(`
source "https://rubygems.org"

gem "rails", "~> 7.0"
gem 'nokogiri'
gem "puma", ">= 5.0", require: false
# gem "commented"
gem 'acme_internal'
gem "ACME_Internal", "~> 2.0"
gem "from_git", git: "https://github.com/acme/from_git.git"
gem "from_path", :path => "../from_path"
gem 'from_github', github: "acme/from_github"
gem "from_gist", "gist" => "deadbeef"
gem 'from_bb', :bitbucket => "acme/from_bb"
gem "sidekiq", group: :production
`)
	deps, err := rubygems.ParseGemfile(data)
	if err != nil {
		t.Fatal(err)
	}
	got := index(deps)
	want := map[string]struct {
		version string
		group   string
		line    int
	}{
		"rails":         {"~> 7.0", "gem", 4},
		"nokogiri":      {"", "gem", 5},
		"puma":          {">= 5.0", "gem", 6},
		"acme_internal": {"", "gem", 8},
		"sidekiq":       {"", "gem", 15},
	}
	for name, w := range want {
		d, ok := got[name]
		if !ok || d.Version != w.version || d.Group != w.group || d.Line != w.line {
			t.Errorf("%s = %+v, want version=%q group=%q line=%d", name, d, w.version, w.group, w.line)
		}
	}
	if len(deps) != len(want) {
		t.Fatalf("len=%d want %d (skipped git/path; ACME_Internal dedupes): %#v", len(deps), len(want), got)
	}
}

func TestParseGemspec(t *testing.T) {
	data := []byte(`
Gem::Specification.new do |spec|
  spec.name = "demo"
  spec.add_dependency "rails", "~> 7.0"
  spec.add_runtime_dependency 'nokogiri'
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_dependency "RAILS" # dedupe with rails
end
`)
	deps, err := rubygems.ParseGemspec(data)
	if err != nil {
		t.Fatal(err)
	}
	got := index(deps)
	want := map[string]struct {
		group string
		line  int
	}{
		"rails":    {"add_dependency", 4},
		"nokogiri": {"add_runtime_dependency", 5},
		"rspec":    {"add_development_dependency", 6},
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
