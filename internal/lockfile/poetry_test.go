package lockfile_test

import (
	"strings"
	"testing"

	"github.com/omni-line/omni-audit/internal/lockfile"
)

func TestParsePoetry(t *testing.T) {
	data := []byte(`
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"
files = [
    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:abc"},
]

[[package]]
name = "internal-sdk"
version = "1.0.0"
description = ""
optional = false
python-versions = "*"
files = []

[package.source]
type = "legacy"
url = "https://pypi.mycompany.com/simple"
reference = "company"

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "abc"
`)
	deps, err := lockfile.ParsePoetry(data)
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
	if !strings.Contains(byName["requests"].URL, "pypi.org") {
		t.Fatalf("default source: %+v", byName["requests"])
	}
	if byName["internal-sdk"].URL != "https://pypi.mycompany.com/simple" {
		t.Fatalf("private source: %+v", byName["internal-sdk"])
	}
}
