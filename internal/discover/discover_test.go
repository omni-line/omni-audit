package discover_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/omni-line/omni-audit/internal/discover"
)

func TestWalkSkipsJunkDirs(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{}`)
	mustWrite(t, filepath.Join(root, "composer.json"), `{}`)
	mustWrite(t, filepath.Join(root, "requirements.txt"), "requests\n")
	mustWrite(t, filepath.Join(root, "pyproject.toml"), "[project]\n")
	mustWrite(t, filepath.Join(root, "requirements-dev.txt"), "pytest\n")
	mustWrite(t, filepath.Join(root, "node_modules", "pkg", "package.json"), `{}`)
	mustWrite(t, filepath.Join(root, "vendor", "x", "composer.json"), `{}`)
	mustWrite(t, filepath.Join(root, ".venv", "lib", "requirements.txt"), "x\n")
	mustWrite(t, filepath.Join(root, "apps", "web", "package.json"), `{}`)

	ms, err := discover.Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 6 {
		t.Fatalf("got %d manifests, want 6: %#v", len(ms), ms)
	}
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
