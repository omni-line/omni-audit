package lockfile_test

import (
	"strings"
	"testing"

	"github.com/omni-line/omni-audit/internal/lockfile"
)

func TestDefaultClassify(t *testing.T) {
	kinds := lockfile.Default()
	if len(kinds) < 4 {
		t.Fatalf("kinds=%d", len(kinds))
	}
	cases := []struct {
		rel  string
		want string
	}{
		{"package-lock.json", "npm"},
		{"npm-shrinkwrap.json", "npm"},
		{"subdir/yarn.lock", "npm"},
		{"poetry.lock", "pypi"},
		{"composer.lock", "composer"},
		{"Cargo.lock", ""},
		{"go.sum", ""},
		{"package.json", ""},
	}
	for _, tc := range cases {
		if got := lockfile.Classify(kinds, tc.rel); got != tc.want {
			t.Errorf("Classify(%q)=%q want %q", tc.rel, got, tc.want)
		}
	}
}

func TestParseFileNPM(t *testing.T) {
	kinds := lockfile.Default()
	data := []byte(`{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {},
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    }
  }
}`)
	deps, err := lockfile.ParseFile(kinds, "package-lock.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "lodash" {
		t.Fatalf("deps=%+v", deps)
	}

	deps, err = lockfile.ParseFile(kinds, "npm-shrinkwrap.json", data)
	if err != nil || len(deps) != 1 {
		t.Fatalf("shrinkwrap: deps=%+v err=%v", deps, err)
	}
}

func TestParseFileUnsupported(t *testing.T) {
	_, err := lockfile.ParseFile(lockfile.Default(), "Cargo.lock", []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("err=%v", err)
	}
}

func TestParseFileWrapsParseError(t *testing.T) {
	_, err := lockfile.ParseFile(lockfile.Default(), "composer.lock", []byte("not-json"))
	if err == nil || !strings.Contains(err.Error(), "parse composer.lock") {
		t.Fatalf("err=%v", err)
	}
}
