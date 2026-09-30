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
			"monolog/monolog": "^3.0",
			"acme/private": "1.0"
		},
		"require-dev": {
			"phpunit/phpunit": "^10"
		}
	}`)
	deps, err := composer.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range deps {
		got[d.Name] = true
	}
	if got["php"] || got["ext-json"] || got["lib-curl"] {
		t.Fatalf("platform deps should be skipped: %#v", got)
	}
	if !got["monolog/monolog"] || !got["acme/private"] || !got["phpunit/phpunit"] {
		t.Fatalf("missing packages: %#v", got)
	}
	if len(deps) != 3 {
		t.Fatalf("len=%d want 3", len(deps))
	}
}
