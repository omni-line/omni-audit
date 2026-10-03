package lockfile_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/lockfile"
)

func TestParseNPMLockV3(t *testing.T) {
	data := []byte(`{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "app",
      "dependencies": { "lodash": "^4.17.21", "@acme/util": "1.0.0" }
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-abc"
    },
    "node_modules/@acme/util": {
      "version": "1.0.0",
      "resolved": "https://registry.mycompany.com/@acme/util/-/util-1.0.0.tgz",
      "integrity": "sha512-def"
    }
  }
}`)
	deps, err := lockfile.ParseNPM(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("got %d deps: %+v", len(deps), deps)
	}
	byName := map[string]lockfile.Resolved{}
	for _, d := range deps {
		byName[d.Name] = d
	}
	if byName["lodash"].URL == "" || byName["@acme/util"].Version != "1.0.0" {
		t.Fatalf("unexpected: %+v", byName)
	}
}

func TestParseNPMLockV1(t *testing.T) {
	data := []byte(`{
  "lockfileVersion": 1,
  "dependencies": {
    "ms": {
      "version": "2.1.3",
      "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz",
      "integrity": "sha512-x",
      "dependencies": {
        "nested": {
          "version": "1.0.0",
          "resolved": "https://registry.yarnpkg.com/nested/-/nested-1.0.0.tgz"
        }
      }
    }
  }
}`)
	deps, err := lockfile.ParseNPM(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("got %d: %+v", len(deps), deps)
	}
}

func TestHostPolicy(t *testing.T) {
	host, public, bad := lockfile.Violation("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", nil)
	if !bad || !public || host != "registry.npmjs.org" {
		t.Fatalf("public host: host=%s public=%v bad=%v", host, public, bad)
	}
	_, _, bad = lockfile.Violation("https://registry.mycompany.com/lodash.tgz", nil)
	if bad {
		t.Fatal("private host without expected list should not flag")
	}
	host, _, bad = lockfile.Violation("https://registry.npmjs.org/x.tgz", []string{"registry.mycompany.com"})
	if !bad || host != "registry.npmjs.org" {
		t.Fatalf("expected-host miss: host=%s bad=%v", host, bad)
	}
	_, _, bad = lockfile.Violation("https://registry.mycompany.com/x.tgz", []string{"registry.mycompany.com"})
	if bad {
		t.Fatal("expected host should pass")
	}
	_, _, bad = lockfile.Violation("file:../local", nil)
	if bad {
		t.Fatal("file: should skip")
	}

	hosts, err := lockfile.NormalizeHosts([]string{"https://Registry.MyCompany.com/npm/", "registry.mycompany.com"})
	if err != nil || len(hosts) != 1 || hosts[0] != "registry.mycompany.com" {
		t.Fatalf("normalize: %v %v", hosts, err)
	}
}
