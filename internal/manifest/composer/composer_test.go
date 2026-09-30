package composer_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest/composer"
)

func TestParseSkipsPlatform(t *testing.T) {
	data := []byte(`{
	"require": {
		"php": "^8.2",
		"ext-json": "*",
		"lib-curl": "*",
		"composer-plugin-api": "^2.0",
		"php-64bit": "*",
		"monolog/monolog": "^3.0",
		"acme/private": "1.0"
	},
	"require-dev": {
		"phpunit/phpunit": "^10",
		"Monolog/Monolog": "^3.0"
	}
}`)
	deps, err := composer.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	groups := map[string]string{}
	for _, d := range deps {
		got[d.Name] = d.Line
		groups[d.Name] = d.Group
	}
	for _, platform := range []string{"php", "ext-json", "lib-curl", "composer-plugin-api", "php-64bit"} {
		if _, ok := got[platform]; ok {
			t.Fatalf("platform dep %s should be skipped: %#v", platform, got)
		}
	}
	if len(deps) != 3 {
		t.Fatalf("len=%d want 3 (case-insensitive dedupe): %#v", len(deps), got)
	}
	if got["acme/private"] != 9 || got["phpunit/phpunit"] != 12 {
		t.Fatalf("lines: %#v", got)
	}
	if groups["phpunit/phpunit"] != "require-dev" {
		t.Fatalf("groups: %#v", groups)
	}
}
