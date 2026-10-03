package scan_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/lockfile"
	"github.com/omni-line/omni-audit/internal/registry"
	regnpm "github.com/omni-line/omni-audit/internal/registry/npm"
	"github.com/omni-line/omni-audit/internal/scan"
)

func TestRunFlagsShadowRegistry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{
  "dependencies": { "lodash": "4.17.21" }
}`)
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app" },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    },
    "node_modules/@acme/util": {
      "version": "1.0.0",
      "resolved": "https://npm.mycompany.com/@acme/util/-/util-1.0.0.tgz"
    }
  }
}`)

	p := registry.NewProber(srv.Client(), "test")
	npmClient := regnpm.New(p)
	npmClient.BaseURL = srv.URL
	ecos := []ecosystem.Ecosystem{ecosystem.NPM(npmClient)}

	res, err := scan.Run(context.Background(), root, scan.Options{Ecosystems: ecos})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Lockfiles != 1 || res.Stats.ResolvedPackages != 2 {
		t.Fatalf("stats: %+v", res.Stats)
	}
	var shadow int
	for _, f := range res.Findings {
		if f.Reason == scan.ReasonShadowRegistry {
			shadow++
			if f.Package != "lodash" || f.Registry != "registry.npmjs.org" || f.ResolvedURL == "" {
				t.Fatalf("shadow finding: %+v", f)
			}
		}
	}
	if shadow != 1 {
		t.Fatalf("shadow=%d findings=%+v", shadow, res.Findings)
	}

	res2, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems:    ecos,
		ExpectedHosts: []string{"npm.mycompany.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	shadow = 0
	for _, f := range res2.Findings {
		if f.Reason == scan.ReasonShadowRegistry {
			shadow++
		}
	}
	if shadow != 1 {
		t.Fatalf("with expected-host shadow=%d want 1: %+v", shadow, res2.Findings)
	}

	res3, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems: ecos,
		Lockfiles:  []lockfile.Kind{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res3.Findings {
		if f.Reason == scan.ReasonShadowRegistry {
			t.Fatalf("empty Lockfiles should disable source audit: %+v", res3.Findings)
		}
	}
	if res3.Stats.Lockfiles != 0 {
		t.Fatalf("lockfiles=%d", res3.Stats.Lockfiles)
	}
}
