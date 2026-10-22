package cli_test

import (
	"bytes"
	"encoding/json"
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
	code := cli.Run([]string{root, "--format", "json", "--no-marketing", "--fail-on", "none", "--exclude", "testdata"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit=%d err=%s", code, errBuf.String())
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	if _, ok := doc["findings"]; !ok {
		t.Fatalf("expected findings: %s", out.String())
	}
	if _, ok := doc["sponsor"]; ok {
		t.Fatal("sponsor should be omitted with --no-marketing")
	}
}

func TestSARIFFormat(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := cli.Run([]string{t.TempDir(), "--format=sarif"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit=%d err=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"version": "2.1.0"`) {
		t.Fatalf("expected sarif: %s", out.String())
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

func TestBadManifestStrict(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), "{broken")
	var out, errBuf bytes.Buffer
	if code := cli.Run([]string{root, "--no-marketing"}, &out, &errBuf); code != 0 {
		t.Fatalf("lenient exit=%d err=%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "package.json") {
		t.Fatalf("expected warning: %s", errBuf.String())
	}
	out.Reset()
	errBuf.Reset()
	if code := cli.Run([]string{root, "--no-marketing", "--strict"}, &out, &errBuf); code != 2 {
		t.Fatalf("strict exit=%d want 2", code)
	}
}

func TestHelp(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := cli.Run([]string{"-h"}, &out, &errBuf); code != 0 {
		t.Fatalf("help exit=%d", code)
	}
	for _, want := range []string{"Usage:", "-exclude", "-strict", "sarif"} {
		if !strings.Contains(errBuf.String(), want) {
			t.Fatalf("usage missing %q: %s", want, errBuf.String())
		}
	}
}

func TestInvalidArguments(t *testing.T) {
	cases := [][]string{
		{"--format", "xml"},
		{"--fail-on", "sometimes"},
		{"--color", "rainbow"},
		{"--concurrency", "0"},
		{"--concurrency", "100000"},
		{"--retries", "-1"},
		{"--timeout", "0s"},
		{"--ignore", "@acme/["},
		{"--format"},
		{"--unknown-flag"},
		{"a", "b"},
	}
	for _, args := range cases {
		var out, errBuf bytes.Buffer
		if code := cli.Run(args, &out, &errBuf); code != 2 {
			t.Errorf("%v: exit=%d want 2 (stderr=%s)", args, code, errBuf.String())
		}
	}
}

func TestMissingRoot(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := cli.Run([]string{filepath.Join(t.TempDir(), "nope")}, &out, &errBuf); code != 2 {
		t.Fatalf("exit=%d want 2", code)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMaliciousCheckAndOptOut(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/@oku-ui/presence": {"version": "0.6.2", "resolved": "https://registry.npmjs.org/@oku-ui/presence/-/presence-0.6.2.tgz"}
  }
}`)
	base := []string{root, "--format", "json", "--no-marketing", "--no-typosquat", "--expected-host", "registry.npmjs.org"}

	var out, errBuf bytes.Buffer
	if code := cli.Run(base, &out, &errBuf); code != 1 {
		t.Fatalf("exit=%d, want 1 (malicious finding); err=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"reason": "malicious"`) || !strings.Contains(out.String(), "MAL-2025-191265") {
		t.Fatalf("expected a malicious finding: %s", out.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := cli.Run(append(base, "--no-malicious"), &out, &errBuf); code != 0 {
		t.Fatalf("--no-malicious: exit=%d out=%s err=%s", code, out.String(), errBuf.String())
	}
}

func TestRegistryConfigAuditAndOptOut(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".npmrc"), "//npm.acme.corp/:_authToken=not-a-real-token\n")
	base := []string{root, "--format", "json", "--no-marketing"}

	var out, errBuf bytes.Buffer
	if code := cli.Run(base, &out, &errBuf); code != 1 {
		t.Fatalf("exit=%d, want 1; err=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"reason": "registry_config"`) || !strings.Contains(out.String(), `"kind": "plaintext_credential"`) ||
		strings.Contains(out.String(), "not-a-real-token") {
		t.Fatalf("expected a redacted registry_config finding: %s", out.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := cli.Run(append(base, "--no-registry-config"), &out, &errBuf); code != 0 {
		t.Fatalf("--no-registry-config: exit=%d out=%s err=%s", code, out.String(), errBuf.String())
	}
}
