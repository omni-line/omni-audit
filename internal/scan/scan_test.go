package scan_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/omni-line/omni-audit/internal/match"
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
			_, _ = w.Write([]byte(`{}`))
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

	npmClient := regnpm.New(srv.Client(), "test")
	npmClient.BaseURL = srv.URL
	packClient := packagist.New(srv.Client(), "test")
	packClient.BaseURL = srv.URL
	pypiClient := regpypi.New(srv.Client(), "test")
	pypiClient.BaseURL = srv.URL

	res, err := scan.Run(context.Background(), root, scan.Options{
		NPM:      npmClient,
		Composer: packClient,
		PyPI:     pypiClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Findings != 3 {
		t.Fatalf("findings=%d want 3: %+v", res.Stats.Findings, res.Findings)
	}

	res2, err := scan.Run(context.Background(), root, scan.Options{
		NPM:            npmClient,
		Composer:       packClient,
		PyPI:           pypiClient,
		SafeNamespaces: match.New("@acme/*", "acme/*", "acme-*"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Stats.Findings != 0 {
		t.Fatalf("with safe-namespace findings=%d want 0: %+v", res2.Stats.Findings, res2.Findings)
	}
	if res2.Stats.Skipped != 3 {
		t.Fatalf("skipped=%d want 3", res2.Stats.Skipped)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
