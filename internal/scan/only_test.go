package scan_test

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/scan"
)

// writeOnlyFixture writes an npm project whose one dependency is unclaimed
// on the (fake) registry and whose lockfile resolves a known malicious
// version from the public registry.
func writeOnlyFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{
  "dependencies": { "@oku-ui/presence": "0.6.2" }
}`)
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app" },
    "node_modules/@oku-ui/presence": {
      "version": "0.6.2",
      "resolved": "https://registry.npmjs.org/@oku-ui/presence/-/presence-0.6.2.tgz"
    }
  }
}`)
	return root
}

func reasons(res *scan.Result) map[string]int {
	out := map[string]int{}
	for _, f := range res.Findings {
		out[f.Reason]++
	}
	return out
}

func TestRunNoUnclaimedMakesNoRegistryRequests(t *testing.T) {
	root := writeOnlyFixture(t)
	checker := &countingChecker{status: registry.NotFound}
	res, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems:  []ecosystem.Ecosystem{ecosystem.NPM(checker)},
		NoUnclaimed: true,
		NoTyposquat: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(checker.calls) != 0 {
		t.Fatalf("registry checked with NoUnclaimed: %v", checker.calls)
	}
	got := reasons(res)
	if got[scan.ReasonUnclaimed] != 0 || got[scan.ReasonMalicious] == 0 || got[scan.ReasonShadowRegistry] == 0 {
		t.Fatalf("reasons = %v", got)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", res.Warnings)
	}
	want := []string{scan.ReasonMalicious, scan.ReasonShadowRegistry, scan.ReasonConfig}
	if !reflect.DeepEqual(res.Checks, want) {
		t.Fatalf("checks = %v, want %v", res.Checks, want)
	}
}

// NoSources drops shadow-registry findings but still reads lockfiles, so
// a malicious locked version is reported.
func TestRunNoSourcesKeepsLockfileMalicious(t *testing.T) {
	root := writeOnlyFixture(t)
	res, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems:  []ecosystem.Ecosystem{ecosystem.NPM(&countingChecker{status: registry.Exists})},
		NoSources:   true,
		NoTyposquat: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := reasons(res)
	if got[scan.ReasonShadowRegistry] != 0 || got[scan.ReasonMalicious] == 0 {
		t.Fatalf("reasons = %v", got)
	}
	if res.Stats.Lockfiles != 1 || res.Stats.ResolvedPackages != 1 {
		t.Fatalf("stats: %+v", res.Stats)
	}
}
