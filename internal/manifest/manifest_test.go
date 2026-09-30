package manifest_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest"
)

func TestReadFileStripsBOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	if err := os.WriteFile(path, []byte("\xEF\xBB\xBF{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := manifest.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{}" {
		t.Fatalf("got %q", data)
	}
}

func TestReadFileRejectsOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(manifest.MaxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := manifest.ReadFile(path); !errors.Is(err, manifest.ErrTooLarge) {
		t.Fatalf("err=%v want ErrTooLarge", err)
	}
}

func TestJSONKeyLine(t *testing.T) {
	data := []byte("{\n  \"name\": \"dependencies\",\n  \"dependencies\": {\n    \"lodash\" : \"1\"\n  }\n}")
	if got := manifest.JSONKeyLine(data, "dependencies", "lodash"); got != 4 {
		t.Fatalf("line=%d want 4", got)
	}
	if got := manifest.JSONKeyLine(data, "devDependencies", "lodash"); got != 0 {
		t.Fatalf("line=%d want 0", got)
	}
}
