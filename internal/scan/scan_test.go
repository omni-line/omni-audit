package scan_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/match"
	"github.com/omni-line/omni-audit/internal/registry"
	regnpm "github.com/omni-line/omni-audit/internal/registry/npm"
	"github.com/omni-line/omni-audit/internal/registry/packagist"
	regpypi "github.com/omni-line/omni-audit/internal/registry/pypi"
	"github.com/omni-line/omni-audit/internal/scan"
)

func TestRunFindsUnclaimed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lodash", "/p2/monolog/monolog.json", "/pypi/requests/json":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{
  "dependencies": {
    "lodash": "4.0.0",
    "@acme/internal": "1.0.0"
  }
}`)
	mustWrite(t, filepath.Join(root, "composer.json"), `{
		"require": {
			"php": "^8.2",
			"monolog/monolog": "^3.0",
			"acme/private": "^1.0"
		}
	}`)
	mustWrite(t, filepath.Join(root, "requirements.txt"), "requests>=2.0\nacme-private==1.0.0\n")

	p := registry.NewProber(srv.Client(), "test")
	npmClient := regnpm.New(p)
	npmClient.BaseURL = srv.URL
	packClient := packagist.New(p)
	packClient.BaseURL = srv.URL
	pypiClient := regpypi.New(p)
	pypiClient.BaseURL = srv.URL
	ecos := []ecosystem.Ecosystem{
		ecosystem.NPM(npmClient),
		ecosystem.Composer(packClient),
		ecosystem.PyPI(pypiClient),
	}

	res, err := scan.Run(context.Background(), root, scan.Options{Ecosystems: ecos})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Findings != 3 {
		t.Fatalf("findings=%d want 3: %+v", res.Stats.Findings, res.Findings)
	}
	first := res.Findings[0]
	if first.Manifest != filepath.Join(root, "composer.json") || first.Package != "acme/private" {
		t.Fatalf("findings should be sorted by manifest: %+v", res.Findings)
	}
	npmFinding := res.Findings[1]
	if npmFinding.Line != 4 || npmFinding.Group != "dependencies" ||
		npmFinding.URL != "https://www.npmjs.com/package/@acme/internal" || npmFinding.Remediation == "" {
		t.Fatalf("npm finding lacks detail: %+v", npmFinding)
	}

	res2, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems:     ecos,
		SafeNamespaces: match.New("@acme/*", "acme/*"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Stats.Findings != 1 || res2.Stats.Skipped != 2 {
		t.Fatalf("findings=%d skipped=%d: %+v", res2.Stats.Findings, res2.Stats.Skipped, res2.Findings)
	}

	res3, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems: ecos,
		Ignore:     match.New("@acme/*", "acme/*", "acme-*"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res3.Stats.Findings != 0 || res3.Stats.Skipped != 3 {
		t.Fatalf("findings=%d skipped=%d", res3.Stats.Findings, res3.Stats.Skipped)
	}
}

// countingChecker records how often each name is checked.
type countingChecker struct {
	mu     sync.Mutex
	calls  map[string]int
	status registry.Status
	err    error
}

func (c *countingChecker) Exists(_ context.Context, name string) (registry.Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	c.calls[name]++
	return c.status, c.err
}

func TestRunDedupesRegistryChecksAcrossManifests(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"a", "b", "c"} {
		mustWrite(t, filepath.Join(root, dir, "requirements.txt"), "Acme_Internal==1\nshared\n")
	}
	mustWrite(t, filepath.Join(root, "d", "requirements.txt"), "acme.internal\n")

	checker := &countingChecker{status: registry.NotFound}
	res, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems: []ecosystem.Ecosystem{ecosystem.PyPI(checker)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(checker.calls) != 2 {
		t.Fatalf("expected 2 distinct checks, got %v", checker.calls)
	}
	for name, n := range checker.calls {
		if n != 1 {
			t.Fatalf("%s checked %d times", name, n)
		}
	}
	if res.Stats.Packages != 7 || res.Stats.UniquePackages != 2 || res.Stats.Findings != 7 {
		t.Fatalf("stats: %+v", res.Stats)
	}
}

func TestRunAllowlistMatchesNormalizedName(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "requirements.txt"), "Acme_Internal==1\n")

	checker := &countingChecker{status: registry.NotFound}
	res, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems: []ecosystem.Ecosystem{ecosystem.PyPI(checker)},
		Ignore:     match.New("acme-*"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Skipped != 1 || len(checker.calls) != 0 {
		t.Fatalf("stats=%+v calls=%v", res.Stats, checker.calls)
	}
}

func TestRunBadManifestIsWarningNotFatal(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "broken", "package.json"), `{not json`)
	mustWrite(t, filepath.Join(root, "ok", "package.json"), `{"dependencies": {"acme-x": "1"}}`)

	checker := &countingChecker{status: registry.NotFound}
	res, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems: []ecosystem.Ecosystem{ecosystem.NPM(checker)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Findings != 1 || res.Stats.Errors != 1 || res.Complete() {
		t.Fatalf("stats=%+v warnings=%+v", res.Stats, res.Warnings)
	}
	if w := res.Warnings[0]; w.Kind != scan.WarnManifest || w.Ecosystem != "npm" {
		t.Fatalf("warning: %+v", w)
	}
}

func TestRunRegistryFailureIsWarning(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"dependencies": {"x": "1"}}`)

	checker := &countingChecker{status: registry.Unknown, err: errors.New("boom")}
	res, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems: []ecosystem.Ecosystem{ecosystem.NPM(checker)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Findings != 0 || len(res.Warnings) != 1 || res.Warnings[0].Kind != scan.WarnRegistry {
		t.Fatalf("res=%+v", res)
	}
}

func TestRunCancelledContext(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"dependencies": {"x": "1", "y": "1"}}`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checker := &countingChecker{status: registry.NotFound}
	res, err := scan.Run(ctx, root, scan.Options{
		Ecosystems: []ecosystem.Ecosystem{ecosystem.NPM(checker)},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	// Unchecked names must never be reported as claimed or unclaimed.
	if res.Stats.Findings != 0 {
		t.Fatalf("cancelled scan reported findings: %+v", res.Findings)
	}
}

func TestRunRequiresEcosystems(t *testing.T) {
	if _, err := scan.Run(context.Background(), t.TempDir(), scan.Options{}); err == nil {
		t.Fatal("expected error")
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
