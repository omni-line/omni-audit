package scan_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/omni-line/mal-check/pkg/maldb"
	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/scan"
)

// npmjs accepts lockfile resolutions from the public npm registry, so the
// shadow-registry audit stays quiet in these tests.
var npmjs = []string{"registry.npmjs.org"}

// claimed reports every name as registered, so only malicious findings remain.
type claimed struct{}

func (claimed) Exists(context.Context, string) (registry.Status, error) { return registry.Exists, nil }

func testMalDB(t *testing.T) *maldb.DB {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	for _, r := range []maldb.Record{
		{ID: "MAL-1", Ecosystem: maldb.NPM, Name: "evil", All: true, Campaign: "tea-xyz-token-farming"},
		{ID: "MAL-2", Ecosystem: maldb.NPM, Name: "hijacked", Versions: []string{"2.0.1"}},
		{ID: "MAL-3", Ecosystem: maldb.PyPI, Name: "bad-pkg", Versions: []string{"1.0.0"}},
	} {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := maldb.Load(bytes.NewReader(buf.Bytes()), maldb.Meta{})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestRunFindsMaliciousPackages(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{
  "dependencies": {
    "evil": "^1.0.0",
    "hijacked": "^2.0.0",
    "lodash": "4.17.21"
  }
}`)
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/hijacked": {"version": "2.0.1", "resolved": "https://registry.npmjs.org/hijacked/-/hijacked-2.0.1.tgz"},
    "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}
  }
}`)
	mustWrite(t, filepath.Join(root, "requirements.txt"), "Bad_Pkg>=0.9\nbad-pkg==1.1.0\n")

	ecos := []ecosystem.Ecosystem{ecosystem.NPM(claimed{}), ecosystem.PyPI(claimed{})}
	res, err := scan.Run(context.Background(), root, scan.Options{Ecosystems: ecos, NoTyposquat: true, ExpectedHosts: npmjs, Malicious: testMalDB(t)})
	if err != nil {
		t.Fatal(err)
	}

	type got struct{ pkg, version, sev, manifest string }
	var mal []got
	for _, f := range res.Findings {
		if f.Reason != scan.ReasonMalicious {
			t.Errorf("unexpected non-malicious finding: %+v", f)
			continue
		}
		mal = append(mal, got{f.Package, f.Version, f.Severity, filepath.Base(f.Manifest)})
	}
	want := []got{
		// locked to the malicious version: the lockfile wins over package.json
		{"hijacked", "2.0.1", scan.SeverityCritical, "package-lock.json"},
		// every version is malicious, so a declared range is too
		{"evil", "^1.0.0", scan.SeverityCritical, "package.json"},
		// version-specific advisory, unpinned requirement
		{"Bad_Pkg", ">=0.9", scan.SeverityHigh, "requirements.txt"},
	}
	// bad-pkg==1.1.0 is a pinned clean version: not reported.
	if len(mal) != len(want) {
		t.Fatalf("malicious findings = %+v, want %+v", mal, want)
	}
	for _, w := range want {
		found := false
		for _, g := range mal {
			found = found || g == w
		}
		if !found {
			t.Errorf("missing %+v in %+v", w, mal)
		}
	}
	for _, f := range res.Findings {
		if f.Package == "evil" && (f.Campaign != "tea-xyz-token-farming" || f.URL != maldb.URL("MAL-1") || len(f.IDs) != 1) {
			t.Errorf("evil finding lacks detail: %+v", f)
		}
	}

	off, err := scan.Run(context.Background(), root, scan.Options{Ecosystems: ecos, NoTyposquat: true, ExpectedHosts: npmjs, NoMalicious: true, Malicious: testMalDB(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(off.Findings) != 0 {
		t.Errorf("--no-malicious still reported: %+v", off.Findings)
	}
}

// The embedded snapshot is used when no database is passed.
func TestRunMaliciousDefaultSnapshot(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/@oku-ui/presence": {"version": "0.6.2", "resolved": "https://registry.npmjs.org/@oku-ui/presence/-/presence-0.6.2.tgz"}
  }
}`)
	res, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems: []ecosystem.Ecosystem{ecosystem.NPM(claimed{})}, NoTyposquat: true, ExpectedHosts: npmjs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Reason != scan.ReasonMalicious || res.Findings[0].IDs[0] != "MAL-2025-191265" {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

// Registries take malware down, so a malicious name often reads as
// unclaimed; the malicious finding replaces the unclaimed one.
func TestMaliciousSupersedesUnclaimed(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "requirements.txt"), "bad-pkg>=0.9\nother-gone>=1\n")
	ecos := []ecosystem.Ecosystem{ecosystem.PyPI(unclaimed{})}
	res, err := scan.Run(context.Background(), root, scan.Options{Ecosystems: ecos, NoTyposquat: true, Malicious: testMalDB(t)})
	if err != nil {
		t.Fatal(err)
	}
	var reasons []string
	for _, f := range res.Findings {
		reasons = append(reasons, f.Package+":"+f.Reason)
	}
	if len(reasons) != 2 || reasons[0] != "bad-pkg:malicious" || reasons[1] != "other-gone:unclaimed" {
		t.Fatalf("findings = %v", reasons)
	}
}

// unclaimed reports every name as missing from the registry.
type unclaimed struct{}

func (unclaimed) Exists(context.Context, string) (registry.Status, error) {
	return registry.NotFound, nil
}
