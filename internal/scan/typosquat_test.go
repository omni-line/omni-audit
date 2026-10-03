package scan_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/lockfile"
	"github.com/omni-line/omni-audit/internal/match"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/scan"
)

// existsAll reports every name as present so only typosquat findings are asserted.
type existsAll struct{}

func (existsAll) Exists(context.Context, string) (registry.Status, error) {
	return registry.Exists, nil
}

func typoEcosystems() []ecosystem.Ecosystem {
	c := existsAll{}
	// Prober is unused because every Checker is replaced below.
	ecos := ecosystem.Default(registry.NewProber(registry.NewHTTPClient(registry.DefaultTimeout, 1), "test"))
	for i := range ecos {
		ecos[i].Checker = c
		ecos[i].NamespaceChecker = c
	}
	return ecos
}

func TestClassicTypos(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	res, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems:  typoEcosystems(),
		MaxDistance: 2,
		Lockfiles:   []lockfile.Kind{},
		// Isolate typosquat fixtures from other testdata trees.
		Exclude: mustCompile(t, "composer", "go", "mixed", "npm", "pypi"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]scan.Finding{}
	for _, f := range res.Findings {
		if f.Reason != scan.ReasonTyposquat {
			continue
		}
		got[f.Package] = f
	}
	want := map[string]struct {
		sug  string
		sev  string
		kind string
	}{
		"crossenv":                          {"cross-env", scan.SeverityCritical, scan.KindPopular},
		"react-domm":                        {"react-dom", scan.SeverityCritical, scan.KindPopular},
		"reqeusts":                          {"requests", scan.SeverityCritical, scan.KindPopular},
		"@acme/authh":                       {"@acme/auth", scan.SeverityHigh, scan.KindScopePeer},
		"monologg/monolog":                  {"monolog/monolog", scan.SeverityCritical, scan.KindPopular},
		"github.com/gin-gonic/ginn":         {"github.com/gin-gonic/gin", scan.SeverityCritical, scan.KindPopular},
		"serdee":                            {"serde", scan.SeverityCritical, scan.KindPopular},
		"org.apache.commons:commons-langg3": {"org.apache.commons:commons-lang3", scan.SeverityCritical, scan.KindPopular},
		"railss":                            {"rails", scan.SeverityCritical, scan.KindPopular},
		"library/nginxg":                    {"nginx", scan.SeverityCritical, scan.KindPopular},
		"openssll":                          {"openssl", scan.SeverityCritical, scan.KindPopular},
	}
	for pkg, w := range want {
		f, ok := got[pkg]
		if !ok {
			t.Errorf("missing finding for %q; got %v", pkg, keys(got))
			continue
		}
		if f.Severity != w.sev || f.Kind != w.kind {
			t.Errorf("%s: severity=%s kind=%s want %s/%s", pkg, f.Severity, f.Kind, w.sev, w.kind)
		}
		if len(f.Suggestions) == 0 || f.Suggestions[0] != w.sug {
			t.Errorf("%s: suggestions=%v want %q", pkg, f.Suggestions, w.sug)
		}
		if f.Message == "" || f.Technique == "" || f.Line == 0 {
			t.Errorf("%s: missing detail: %+v", pkg, f)
		}
	}
	for _, exact := range []string{"lodash", "requests", "@acme/auth", "urllib3", "monolog/monolog", "serde", "rails", "nginx", "openssl"} {
		if _, ok := got[exact]; ok {
			t.Errorf("exact package %q should not be a finding", exact)
		}
	}
}

func TestTyposquatAllowAndIgnore(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "npm-typos")
	ignore, err := match.Compile("crossenv")
	if err != nil {
		t.Fatal(err)
	}
	res, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems: typoEcosystems(),
		Lockfiles:  []lockfile.Kind{},
		Ignore:     ignore,
		Allow:      map[string]struct{}{"react-domm": {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.Reason != scan.ReasonTyposquat {
			continue
		}
		if f.Package == "crossenv" || f.Package == "react-domm" {
			t.Errorf("unexpected finding %q", f.Package)
		}
	}
}

func TestNoTyposquatFlag(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "npm-typos")
	res, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems:  typoEcosystems(),
		Lockfiles:   []lockfile.Kind{},
		NoTyposquat: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.Reason == scan.ReasonTyposquat {
			t.Fatalf("unexpected typosquat finding with NoTyposquat: %+v", f)
		}
	}
}

func mustCompile(t *testing.T, patterns ...string) *match.Matcher {
	t.Helper()
	m, err := match.Compile(patterns...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func keys(m map[string]scan.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
