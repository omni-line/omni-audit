package scan_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/scan"
)

func TestRenameActionsOnlyUnambiguous(t *testing.T) {
	got := scan.RenameActions([]scan.Finding{
		{Ecosystem: "npm", Reason: scan.ReasonTyposquat, Package: "crossenv", Distance: 1, Suggestions: []string{"cross-env"}},
		{Ecosystem: "npm", Reason: scan.ReasonTyposquat, Package: "crossenv", Distance: 1, Suggestions: []string{"cross-env"}},
		{Ecosystem: "pypi", Reason: scan.ReasonTyposquat, Package: "reqeusts", Distance: 2, Suggestions: []string{"requests"}},
		{Ecosystem: "npm", Reason: scan.ReasonTyposquat, Package: "lodahs", Distance: 1, Suggestions: []string{"lodash", "loda"}},
		{Ecosystem: "npm", Reason: scan.ReasonUnclaimed, Package: "x", Distance: 1, Suggestions: []string{"y"}},
	})
	if len(got) != 1 || got[0].Package != "crossenv" || got[0].Replacement != "cross-env" || got[0].Ecosystem != "npm" {
		t.Fatalf("actions=%+v", got)
	}
}

func TestDecideHonorsMinSeverity(t *testing.T) {
	res := &scan.Result{Findings: []scan.Finding{{Severity: scan.SeverityLow, Reason: scan.ReasonUnclaimed}}}
	if scan.Decide(res, scan.SeverityHigh) != scan.DecisionAllow {
		t.Fatal("low finding should not block a high gate")
	}
	if scan.Decide(res, scan.SeverityLow) != scan.DecisionBlock {
		t.Fatal("low finding blocks a low gate")
	}
	incomplete := &scan.Result{Warnings: []scan.Warning{{Message: "timeout"}}}
	if scan.Decide(incomplete, "") != scan.DecisionUnknown {
		t.Fatal("incomplete without findings is unknown")
	}
	if scan.Decide(nil, "") != scan.DecisionUnknown {
		t.Fatal("nil is unknown")
	}
}

func TestFingerprintStableAndDistinct(t *testing.T) {
	a := scan.Finding{Ecosystem: "npm", Package: "left-pad", Manifest: "package.json", Reason: scan.ReasonUnclaimed}
	again := scan.Finding{Ecosystem: "npm", Package: "left-pad", Manifest: "package.json", Reason: scan.ReasonUnclaimed}
	b := a
	b.Reason = scan.ReasonTyposquat
	if scan.Fingerprint(a) == "" || scan.Fingerprint(a) != scan.Fingerprint(again) {
		t.Fatal("fingerprint should be stable")
	}
	if scan.Fingerprint(a) == scan.Fingerprint(b) {
		t.Fatal("reason is part of the fingerprint")
	}
	if scan.RuleID(scan.ReasonUnclaimed) != scan.RuleUnclaimed || scan.RuleID(scan.ReasonShadowRegistry) != scan.RuleShadowRegistry || scan.RuleID(scan.ReasonTyposquat) != scan.RuleTyposquat || scan.RuleID(scan.ReasonInstallHook) != scan.RuleInstallHook {
		t.Fatal("rule ids drifted")
	}
	if scan.ReportPath("") != "" {
		t.Fatal("name checks have no manifest path")
	}
}
