package scan_test

import (
	"context"
	"errors"
	"testing"

	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/match"
	"github.com/omni-line/omni-audit/internal/registry"
	regnpm "github.com/omni-line/omni-audit/internal/registry/npm"
	"github.com/omni-line/omni-audit/internal/scan"
)

func TestCheckUnclaimedAndClaimed(t *testing.T) {
	missing := &countingChecker{status: registry.NotFound}
	res, err := scan.Check(context.Background(), ecosystem.PyPI(missing), []string{"acme-private"}, scan.Options{NoTyposquat: true, NoMalicious: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Reason != scan.ReasonUnclaimed || res.Findings[0].Package != "acme-private" {
		t.Fatalf("findings: %+v", res.Findings)
	}
	if scan.Decide(res, "") != scan.DecisionBlock {
		t.Fatalf("decision=%s", scan.Decide(res, ""))
	}
	if len(missing.calls) != 1 {
		t.Fatalf("calls=%v", missing.calls)
	}

	present := &countingChecker{status: registry.Exists}
	res, err = scan.Check(context.Background(), ecosystem.PyPI(present), []string{"requests", "requests"}, scan.Options{NoTyposquat: true, NoMalicious: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || !res.Complete() {
		t.Fatalf("expected a clean check: %+v %+v", res.Findings, res.Warnings)
	}
	if scan.Decide(res, "") != scan.DecisionAllow {
		t.Fatalf("decision=%s", scan.Decide(res, ""))
	}
	if present.calls["requests"] != 1 {
		t.Fatalf("dedupe failed: %v", present.calls)
	}
	if res.Stats.Packages != 2 || res.Stats.UniquePackages != 1 {
		t.Fatalf("stats=%+v", res.Stats)
	}
}

func TestCheckUnknownIsNotAllow(t *testing.T) {
	checker := &countingChecker{status: registry.Unknown, err: errors.New("timeout")}
	res, err := scan.Check(context.Background(), ecosystem.PyPI(checker), []string{"requests"}, scan.Options{NoTyposquat: true, NoMalicious: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete() || len(res.Findings) != 0 {
		t.Fatalf("result=%+v warnings=%+v", res.Findings, res.Warnings)
	}
	if res.Warnings[0].Kind != scan.WarnRegistry {
		t.Fatalf("warning=%+v", res.Warnings[0])
	}
	if scan.Decide(res, "") != scan.DecisionUnknown {
		t.Fatalf("decision=%s", scan.Decide(res, ""))
	}
}

func TestCheckInvalidName(t *testing.T) {
	eco := ecosystem.NPM(regnpm.New(registry.NewProber(registry.NewHTTPClient(registry.DefaultTimeout, 1), "test")))
	_, err := scan.Check(context.Background(), eco, []string{"not a name"}, scan.Options{NoTyposquat: true, NoMalicious: true})
	if !errors.Is(err, registry.ErrInvalidName) {
		t.Fatalf("err=%v", err)
	}
}

func TestCheckIgnoreSkipsRegistry(t *testing.T) {
	checker := &countingChecker{status: registry.NotFound}
	res, err := scan.Check(context.Background(), ecosystem.PyPI(checker), []string{"acme-private"}, scan.Options{
		NoTyposquat: true,
		NoMalicious: true,
		Ignore:      match.New("acme-*"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(checker.calls) != 0 || res.Stats.Skipped != 1 || len(res.Findings) != 0 {
		t.Fatalf("stats=%+v calls=%v", res.Stats, checker.calls)
	}
	if scan.Decide(res, "") != scan.DecisionAllow {
		t.Fatalf("decision=%s", scan.Decide(res, ""))
	}
}

type nsStatus struct {
	pkg registry.Status
	ns  registry.Status
}

func (c nsStatus) Exists(context.Context, string) (registry.Status, error) {
	return c.pkg, nil
}

func (c nsStatus) PackageNamespace(name string) (string, bool) {
	return regnpm.Scope(name)
}

func (c nsStatus) NamespaceExists(context.Context, string) (registry.Status, error) {
	return c.ns, nil
}

func TestCheckUnclaimedScopeIsCritical(t *testing.T) {
	eco := ecosystem.NPM(nsStatus{pkg: registry.NotFound, ns: registry.NotFound})
	res, err := scan.Check(context.Background(), eco, []string{"@acme/internal-utils"}, scan.Options{NoTyposquat: true, NoMalicious: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings=%+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != scan.SeverityCritical || f.NamespaceStatus != scan.NamespaceUnclaimed || f.Namespace != "acme" {
		t.Fatalf("finding=%+v", f)
	}
}

func TestCheckTyposquatRename(t *testing.T) {
	eco := ecosystem.NPM(existsAll{})
	res, err := scan.Check(context.Background(), eco, []string{"crossenv"}, scan.Options{MaxDistance: 2, NoMalicious: true})
	if err != nil {
		t.Fatal(err)
	}
	var typo *scan.Finding
	for i := range res.Findings {
		if res.Findings[i].Reason == scan.ReasonTyposquat {
			typo = &res.Findings[i]
			break
		}
	}
	if typo == nil {
		t.Fatalf("expected a typosquat, got %+v", res.Findings)
	}
	if typo.Distance != 1 || len(typo.Suggestions) != 1 || typo.Suggestions[0] != "cross-env" {
		t.Fatalf("typo=%+v", typo)
	}
	actions := scan.RenameActions(res.Findings)
	if len(actions) != 1 || actions[0].Type != scan.ActionRename || actions[0].Replacement != "cross-env" || actions[0].Confidence != scan.ConfidenceHigh {
		t.Fatalf("actions=%+v", actions)
	}
	if scan.Decide(res, "") != scan.DecisionBlock {
		t.Fatalf("decision=%s", scan.Decide(res, ""))
	}
}

func TestCheckMalicious(t *testing.T) {
	eco := ecosystem.NPM(existsAll{})
	res, err := scan.Check(context.Background(), eco, []string{"evil"}, scan.Options{
		NoTyposquat: true,
		Malicious:   testMalDB(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Reason != scan.ReasonMalicious || res.Findings[0].Severity != scan.SeverityCritical {
		t.Fatalf("findings=%+v", res.Findings)
	}
	if scan.Decide(res, "") != scan.DecisionBlock {
		t.Fatalf("decision=%s", scan.Decide(res, ""))
	}
	if actions := scan.RenameActions(res.Findings); len(actions) != 0 {
		t.Fatalf("malware has no rename: %+v", actions)
	}
}
