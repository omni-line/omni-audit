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
	"github.com/omni-line/omni-audit/internal/registry/packagist"
	regpypi "github.com/omni-line/omni-audit/internal/registry/pypi"
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

	res, err := scan.Run(context.Background(), root, scan.Options{Ecosystems: ecos, NoTyposquat: true})
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
		NoTyposquat:   true,
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
		NoTyposquat: true,
		Ecosystems:  ecos,
		Lockfiles:   []lockfile.Kind{},
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

func TestRunFlagsShadowRegistryYarnPoetryComposer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"dependencies":{"lodash":"4.17.21"}}`)
	mustWrite(t, filepath.Join(root, "yarn.lock"), `# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abcdef"
  integrity sha512-abc
`)
	mustWrite(t, filepath.Join(root, "pyproject.toml"), `[project]
name = "app"
dependencies = ["requests>=2.0"]
`)
	mustWrite(t, filepath.Join(root, "poetry.lock"), `
[[package]]
name = "requests"
version = "2.31.0"
description = ""
optional = false
python-versions = "*"
files = []

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "abc"
`)
	mustWrite(t, filepath.Join(root, "composer.json"), `{"require":{"acme/sdk":"^1.0"}}`)
	mustWrite(t, filepath.Join(root, "composer.lock"), `{
  "packages": [
    {
      "name": "acme/sdk",
      "version": "1.0.0",
      "dist": {
        "url": "https://repo.packagist.org/p2/acme/sdk/acme-sdk-1.0.0.zip"
      }
    }
  ],
  "packages-dev": []
}`)

	p := registry.NewProber(srv.Client(), "test")
	npmClient := regnpm.New(p)
	npmClient.BaseURL = srv.URL
	packClient := packagist.New(p)
	packClient.BaseURL = srv.URL
	packClient.ListURL = srv.URL
	pypiClient := regpypi.New(p)
	pypiClient.BaseURL = srv.URL

	res, err := scan.Run(context.Background(), root, scan.Options{
		NoTyposquat: true,
		Ecosystems: []ecosystem.Ecosystem{
			ecosystem.NPM(npmClient),
			ecosystem.Composer(packClient),
			ecosystem.PyPI(pypiClient),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Lockfiles != 3 {
		t.Fatalf("lockfiles=%d want 3: stats=%+v", res.Stats.Lockfiles, res.Stats)
	}
	byPkg := map[string]scan.Finding{}
	for _, f := range res.Findings {
		if f.Reason == scan.ReasonShadowRegistry {
			byPkg[f.Package] = f
		}
	}
	for _, want := range []string{"lodash", "requests", "acme/sdk"} {
		if _, ok := byPkg[want]; !ok {
			t.Fatalf("missing shadow for %s: %+v", want, res.Findings)
		}
	}
	if byPkg["lodash"].Registry != "registry.yarnpkg.com" {
		t.Fatalf("yarn host: %+v", byPkg["lodash"])
	}
	if byPkg["requests"].Registry != "pypi.org" {
		t.Fatalf("poetry host: %+v", byPkg["requests"])
	}
	if byPkg["acme/sdk"].Registry != "repo.packagist.org" {
		t.Fatalf("composer host: %+v", byPkg["acme/sdk"])
	}
}

func TestRunRedactsLockfileCredentials(t *testing.T) {
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
      "resolved": "https://npm:s3cret-token@registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    }
  }
}`)

	p := registry.NewProber(srv.Client(), "test")
	npmClient := regnpm.New(p)
	npmClient.BaseURL = srv.URL
	res, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems:  []ecosystem.Ecosystem{ecosystem.NPM(npmClient)},
		NoTyposquat: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range res.Findings {
		if f.Reason != scan.ReasonShadowRegistry {
			continue
		}
		found = true
		if f.ResolvedURL != "https://npm:xxxxx@registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" {
			t.Fatalf("ResolvedURL=%q", f.ResolvedURL)
		}
		if f.URL != f.ResolvedURL {
			t.Fatalf("URL=%q ResolvedURL=%q", f.URL, f.ResolvedURL)
		}
	}
	if !found {
		t.Fatalf("no shadow finding: %+v", res.Findings)
	}
}
