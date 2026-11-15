package scan_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/scan"
)

func TestParseBaselineShapes(t *testing.T) {
	fromList, err := scan.ParseBaseline([]byte(`{"fingerprints":["aaa", "", "bbb"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(fromList) != 2 {
		t.Fatalf("list=%v", fromList)
	}

	f := scan.Finding{Ecosystem: "npm", Package: "left-pad", Manifest: "package.json", Reason: scan.ReasonUnclaimed}
	fp := scan.Fingerprint(f)
	raw := []byte(`{"findings":[{"fingerprint":"` + fp + `"}]}`)
	fromReport, err := scan.ParseBaseline(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fromReport[fp]; !ok {
		t.Fatalf("missing %s in %v", fp, fromReport)
	}

	if _, err := scan.ParseBaseline([]byte(`{"findings":[{"package":"left-pad"}]}`)); err == nil {
		t.Fatal("expected missing fingerprint error")
	}
	if _, err := scan.ParseBaseline([]byte(`{"sponsor":{}}`)); err == nil {
		t.Fatal("expected shape error")
	}
	empty, err := scan.ParseBaseline([]byte(`{"findings":[]}`))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty report: %v %v", empty, err)
	}
}

func TestApplyBaseline(t *testing.T) {
	keep := scan.Finding{Ecosystem: "npm", Package: "kept", Manifest: "package.json", Reason: scan.ReasonUnclaimed}
	drop := scan.Finding{Ecosystem: "npm", Package: "drop", Manifest: "package.json", Reason: scan.ReasonUnclaimed}
	res := &scan.Result{
		Findings: []scan.Finding{keep, drop},
		Stats:    scan.Stats{Findings: 2},
	}
	scan.ApplyBaseline(res, map[string]struct{}{scan.Fingerprint(drop): {}})
	if len(res.Findings) != 1 || res.Findings[0].Package != "kept" {
		t.Fatalf("findings=%+v", res.Findings)
	}
	if res.Stats.Findings != 1 || res.Stats.Suppressed != 1 {
		t.Fatalf("stats=%+v", res.Stats)
	}
}
