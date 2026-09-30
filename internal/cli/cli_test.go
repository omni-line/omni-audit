package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/omni-line/omni-audit/internal/cli"
)

func TestVersion(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := cli.Run([]string{"--version"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit=%d err=%s", code, errBuf.String())
	}
	if strings.TrimSpace(out.String()) == "" {
		t.Fatal("expected version output")
	}
}

func TestFlagsAfterPath(t *testing.T) {
	root := t.TempDir()
	var out, errBuf bytes.Buffer
	code := cli.Run([]string{root, "--format", "json", "--no-marketing", "--fail-on", "none"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit=%d err=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"findings"`) {
		t.Fatalf("expected json: %s", out.String())
	}
	if strings.Contains(out.String(), `"sponsor"`) {
		t.Fatal("sponsor should be omitted with --no-marketing")
	}
}

func TestEmptyTree(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "README"), "x")
	var out, errBuf bytes.Buffer
	code := cli.Run([]string{root, "-q", "--no-marketing"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit=%d err=%s", code, errBuf.String())
	}
}

func TestHelp(t *testing.T) {
	var out, errBuf bytes.Buffer
	_ = cli.Run([]string{"-h"}, &out, &errBuf)
	if !strings.Contains(errBuf.String(), "Usage:") {
		t.Fatalf("expected usage: %s", errBuf.String())
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
