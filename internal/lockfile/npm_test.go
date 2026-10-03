package lockfile_test

import (
	"fmt"
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

func TestParseNPMLockV1DepthLimit(t *testing.T) {
	// Build a chain deeper than maxNPMV1Depth (64); only depths 0..64 appear.
	const depth = 80
	node := ""
	for i := depth - 1; i >= 0; i-- {
		name := fmt.Sprintf("p%d", i)
		resolved := fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-1.0.0.tgz", name, name)
		if node == "" {
			node = fmt.Sprintf(`"%s":{"version":"1.0.0","resolved":%q}`, name, resolved)
		} else {
			node = fmt.Sprintf(`"%s":{"version":"1.0.0","resolved":%q,"dependencies":{%s}}`, name, resolved, node)
		}
	}
	data := []byte(`{"lockfileVersion":1,"dependencies":{` + node + `}}`)
	deps, err := lockfile.ParseNPM(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 65 {
		t.Fatalf("got %d deps want 65 (depth-capped)", len(deps))
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

func TestRedactURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{
			"https://npm:s3cret@registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
			"https://npm:xxxxx@registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
		},
		{
			"https://TOKEN@registry.npmjs.org/pkg.tgz",
			"https://xxxxx@registry.npmjs.org/pkg.tgz",
		},
		{
			"https://registry.npmjs.org/pkg.tgz?token=abc&other=1",
			"https://registry.npmjs.org/pkg.tgz?other=1&token=xxxxx",
		},
		{
			"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
			"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
		},
		{"not a url", "not a url"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := lockfile.RedactURL(tc.in); got != tc.want {
			t.Errorf("RedactURL(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
	// Host policy still matches when credentials are present.
	host, _, bad := lockfile.Violation("https://user:pass@registry.npmjs.org/x.tgz", nil)
	if !bad || host != "registry.npmjs.org" {
		t.Fatalf("violation with userinfo: host=%s bad=%v", host, bad)
	}
}
