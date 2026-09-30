package discover_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/omni-line/omni-audit/internal/discover"
	"github.com/omni-line/omni-audit/internal/match"
)

func classify(rel string) string {
	switch filepath.Base(rel) {
	case "package.json":
		return "npm"
	case "composer.json":
		return "composer"
	}
	if strings.HasSuffix(rel, ".txt") || strings.HasSuffix(rel, ".toml") {
		return "pypi"
	}
	return ""
}

func TestWalkSkipsJunkDirs(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{}`)
	mustWrite(t, filepath.Join(root, "composer.json"), `{}`)
	mustWrite(t, filepath.Join(root, "requirements.txt"), "requests\n")
	mustWrite(t, filepath.Join(root, "node_modules", "pkg", "package.json"), `{}`)
	mustWrite(t, filepath.Join(root, "vendor", "x", "composer.json"), `{}`)
	mustWrite(t, filepath.Join(root, ".venv", "lib", "requirements.txt"), "x\n")
	mustWrite(t, filepath.Join(root, "apps", "web", "package.json"), `{}`)

	res, err := discover.Walk(root, discover.Options{Classify: classify})
	if err != nil {
		t.Fatal(err)
	}
	got := rels(res)
	want := []string{"apps/web/package.json", "composer.json", "package.json", "requirements.txt"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, m := range res.Manifests {
		if !strings.HasPrefix(m.Path, root) {
			t.Fatalf("path %q should be reachable from cwd", m.Path)
		}
	}
}

func TestWalkExclude(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{}`)
	mustWrite(t, filepath.Join(root, "testdata", "package.json"), `{}`)
	mustWrite(t, filepath.Join(root, "apps", "legacy", "package.json"), `{}`)
	mustWrite(t, filepath.Join(root, "apps", "web", "fixtures", "package.json"), `{}`)
	mustWrite(t, filepath.Join(root, "apps", "web", "package.json"), `{}`)

	res, err := discover.Walk(root, discover.Options{
		Classify: classify,
		Exclude:  match.New("testdata", "apps/legacy", "apps/*/fixtures"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(rels(res), ","); got != "apps/web/package.json,package.json" {
		t.Fatalf("got %s", got)
	}
}

func TestWalkRootNamedLikeSkipDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "build")
	mustWrite(t, filepath.Join(root, "package.json"), `{}`)

	res, err := discover.Walk(root, discover.Options{Classify: classify})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Manifests) != 1 {
		t.Fatalf("explicit root named build should be scanned: %+v", res)
	}
}

func TestWalkSingleFileRoot(t *testing.T) {
	file := filepath.Join(t.TempDir(), "package.json")
	mustWrite(t, file, `{}`)
	res, err := discover.Walk(file, discover.Options{Classify: classify})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Manifests) != 1 || res.Manifests[0].Rel != "package.json" {
		t.Fatalf("got %+v", res.Manifests)
	}
}

func TestWalkMissingRoot(t *testing.T) {
	if _, err := discover.Walk(filepath.Join(t.TempDir(), "nope"), discover.Options{Classify: classify}); err == nil {
		t.Fatal("expected error")
	}
}

func TestWalkRejectsSymlinkOutsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	outside := filepath.Join(t.TempDir(), "secrets.txt")
	mustWrite(t, outside, "TOKEN\n")
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "inner.txt"), "requests\n")
	if err := os.Symlink(outside, filepath.Join(root, "requirements.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "inner.txt"), filepath.Join(root, "requirements-dev.txt")); err != nil {
		t.Fatal(err)
	}

	res, err := discover.Walk(root, discover.Options{Classify: func(rel string) string {
		if strings.HasPrefix(rel, "requirements") {
			return "pypi"
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(rels(res), ","); got != "requirements-dev.txt" {
		t.Fatalf("got %s", got)
	}
	if len(res.Problems) != 1 || !errors.Is(res.Problems[0].Err, discover.ErrOutsideRoot) {
		t.Fatalf("problems: %+v", res.Problems)
	}
}

func rels(res discover.Result) []string {
	out := make([]string, 0, len(res.Manifests))
	for _, m := range res.Manifests {
		out = append(out, m.Rel)
	}
	sort.Strings(out)
	return out
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
