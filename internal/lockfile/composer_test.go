package lockfile_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/lockfile"
)

func TestParseComposer(t *testing.T) {
	data := []byte(`{
  "packages": [
    {
      "name": "monolog/monolog",
      "version": "3.0.0",
      "dist": {
        "type": "zip",
        "url": "https://api.github.com/repos/Seldaek/monolog/zipball/abc"
      }
    },
    {
      "name": "acme/sdk",
      "version": "1.0.0",
      "dist": {
        "url": "https://repo.packagist.org/p2/acme/sdk/acme-sdk-1.0.0.zip"
      }
    }
  ],
  "packages-dev": []
}`)
	deps, err := lockfile.ParseComposer(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("got %d: %+v", len(deps), deps)
	}
	byName := map[string]lockfile.Resolved{}
	for _, d := range deps {
		byName[d.Name] = d
	}
	_, _, bad := lockfile.Violation(byName["monolog/monolog"].URL, nil)
	if bad {
		t.Fatal("github dist should not flag without expected-host")
	}
	_, public, bad := lockfile.Violation(byName["acme/sdk"].URL, nil)
	if !bad || !public {
		t.Fatalf("packagist should flag: %+v", byName["acme/sdk"])
	}
}
