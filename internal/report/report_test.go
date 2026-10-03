package report_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/omni-line/omni-audit/internal/report"
	"github.com/omni-line/omni-audit/internal/scan"
)

func write(t *testing.T, res *scan.Result, opts report.Options) (string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	if opts.Version == "" {
		opts.Version = "0.1.0"
	}
	if opts.Color == "" {
		opts.Color = report.ColorNever
	}
	if err := report.Write(&out, &errBuf, res, opts); err != nil {
		t.Fatal(err)
	}
	return out.String(), errBuf.String()
}

func oneFinding() *scan.Result {
	return &scan.Result{
		Findings: []scan.Finding{{
			Ecosystem:   "npm",
			Package:     "@acme/secret-pkg",
			Version:     "1.0.0",
			Manifest:    "apps/web/package.json",
			Line:        12,
			Group:       "devDependencies",
			Reason:      scan.ReasonUnclaimed,
			Registry:    "registry.npmjs.org",
			URL:         "https://www.npmjs.com/package/@acme/secret-pkg",
			Remediation: "Claim the scope.",
		}},
		Stats: scan.Stats{Manifests: 1, Packages: 3, UniquePackages: 3, Findings: 1, DurationMS: 1234},
	}
}

func TestTextIncludesMarketing(t *testing.T) {
	res := &scan.Result{Stats: scan.Stats{Manifests: 1, Packages: 1}}
	text, _ := write(t, res, report.Options{
		Format:      report.FormatText,
		ForceMarket: true,
		StdoutIsTTY: true,
		StderrIsTTY: true,
	})
	for _, want := range []string{
		"omni-audit v0.1.0",
		"one registry for every package",
		"https://omniline.app",
		"omniline.app/docs",
		"Kept clean",
		"safe place for your supply chain",
		"✓ No unclaimed package names found.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
}

func TestHeaderDoesNotDoubleVPrefix(t *testing.T) {
	text, _ := write(t, &scan.Result{}, report.Options{Format: report.FormatText, ForceMarket: true, Version: "v1.2.3"})
	if strings.Contains(text, "vv1.2.3") || !strings.Contains(text, "v1.2.3") {
		t.Fatalf("bad header: %s", text)
	}
}

func TestTextFindingDetails(t *testing.T) {
	text, errText := write(t, oneFinding(), report.Options{
		Format:      report.FormatText,
		NoMarketing: true,
		StdoutIsTTY: true,
		StderrIsTTY: true,
	})
	all := text + errText
	if strings.Contains(all, "omniline.app") || strings.Contains(all, "Omni Line") {
		t.Fatalf("marketing should be suppressed: %s", all)
	}
	for _, want := range []string{
		"✗ 1 unclaimed package name found",
		"SEVERITY", "ECOSYSTEM", "PACKAGE", "LOCATION",
		"@acme/secret-pkg",
		"apps/web/package.json:12",
		"devDependencies",
		"How to fix",
		"Claim the scope.",
		"Scanned 1 manifest · 3 packages · 1 finding · 0 skipped · 0 errors in 1.2s",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "https://www.npmjs.com") {
		t.Error("package URL should only be shown with --verbose")
	}

	verbose, _ := write(t, oneFinding(), report.Options{Format: report.FormatText, NoMarketing: true, Verbose: true})
	if !strings.Contains(verbose, "https://www.npmjs.com/package/@acme/secret-pkg") {
		t.Errorf("verbose should show package URL:\n%s", verbose)
	}
}

func TestTextTableAligned(t *testing.T) {
	res := oneFinding()
	res.Findings = append(res.Findings, scan.Finding{
		Ecosystem: "composer", Package: "a/b", Manifest: "composer.json", Reason: scan.ReasonUnclaimed,
	})
	text, _ := write(t, res, report.Options{Format: report.FormatText, NoMarketing: true, Quiet: true})
	lines := strings.Split(strings.Trim(text, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("quiet should print only the table, got:\n%s", text)
	}
	col := strings.Index(lines[0], "PACKAGE")
	for _, l := range lines[1:] {
		if l[col-2:col] != "  " || l[col] == ' ' {
			t.Fatalf("PACKAGE column misaligned at %d:\n%s", col, text)
		}
	}
}

func TestQuietSuppressesMarketing(t *testing.T) {
	text, errText := write(t, &scan.Result{}, report.Options{
		Format:      report.FormatText,
		Quiet:       true,
		ForceMarket: true,
		StdoutIsTTY: true,
		StderrIsTTY: true,
	})
	if strings.Contains(text+errText, "omniline.app") {
		t.Fatal("quiet should suppress marketing")
	}
}

func TestTextSanitizesUntrustedValues(t *testing.T) {
	res := oneFinding()
	res.Findings[0].Package = "evil\x1b]52;c;cGF5bG9hZA==\x07pkg\u202e"
	res.Warnings = []scan.Warning{{Kind: scan.WarnManifest, Manifest: "x\x1b[2Jy", Message: "bad\rline"}}
	text, errText := write(t, res, report.Options{Format: report.FormatText, NoMarketing: true})
	all := text + errText
	if strings.ContainsAny(all, "\x1b\x07\r\u202e") {
		t.Fatalf("control characters leaked: %q", all)
	}
	if !strings.Contains(all, `evil\u001b]52`) || !strings.Contains(all, `\u202e`) {
		t.Fatalf("expected escaped form: %q", all)
	}
}

func TestIncompleteScanIsNotReportedClean(t *testing.T) {
	res := &scan.Result{
		Warnings: []scan.Warning{{Kind: scan.WarnRegistry, Ecosystem: "npm", Package: "x", Manifest: "package.json", Message: "timeout"}},
		Stats:    scan.Stats{Manifests: 1, Packages: 1, Errors: 1},
	}
	text, errText := write(t, res, report.Options{Format: report.FormatText, NoMarketing: true})
	if strings.Contains(text, "✓") || !strings.Contains(text, "incomplete") {
		t.Fatalf("incomplete scan shown as clean:\n%s", text)
	}
	if !strings.Contains(errText, "registry npm x (package.json): timeout") {
		t.Fatalf("warning missing on stderr:\n%s", errText)
	}
}

func TestWarningsTruncatedWithoutVerbose(t *testing.T) {
	res := &scan.Result{Stats: scan.Stats{Manifests: 1}}
	for i := 0; i < 25; i++ {
		res.Warnings = append(res.Warnings, scan.Warning{Kind: scan.WarnRegistry, Package: fmt.Sprintf("p%d", i), Message: "x"})
	}
	_, errText := write(t, res, report.Options{Format: report.FormatText, NoMarketing: true})
	if !strings.Contains(errText, "and 15 more") {
		t.Fatalf("expected truncation:\n%s", errText)
	}
	_, errText = write(t, res, report.Options{Format: report.FormatText, NoMarketing: true, Verbose: true})
	if strings.Contains(errText, "more") || !strings.Contains(errText, "p24") {
		t.Fatalf("verbose should show all:\n%s", errText)
	}
}

func TestNoManifestsMessage(t *testing.T) {
	text, _ := write(t, &scan.Result{}, report.Options{Format: report.FormatText, NoMarketing: true})
	if !strings.Contains(text, "No supported dependency manifests found") {
		t.Fatalf("got:\n%s", text)
	}
}

func TestJSONDocument(t *testing.T) {
	out, _ := write(t, oneFinding(), report.Options{Format: report.FormatJSON})
	var doc report.JSONDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != report.SchemaVersion || !doc.Complete {
		t.Fatalf("doc header: %+v", doc)
	}
	if doc.Sponsor == nil || doc.Sponsor.URL != "https://omniline.app" || doc.Sponsor.DocsURL != "https://omniline.app/docs" {
		t.Fatalf("expected sponsor: %+v", doc.Sponsor)
	}
	f := doc.Findings[0]
	if f.Line != 12 || f.Group != "devDependencies" || f.URL == "" || f.Reason != "unclaimed" {
		t.Fatalf("finding: %+v", f)
	}

	// Stable fields used by CI must stay present.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"findings", "stats", "sponsor", "version"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("missing top-level %q", k)
		}
	}

	out, _ = write(t, &scan.Result{}, report.Options{Format: report.FormatJSON, NoMarketing: true})
	doc = report.JSONDocument{}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Sponsor != nil || doc.Findings == nil {
		t.Fatalf("sponsor should be omitted and findings an empty array: %s", out)
	}
}

func TestSARIF(t *testing.T) {
	res := oneFinding()
	res.Warnings = []scan.Warning{{Kind: scan.WarnRegistry, Ecosystem: "npm", Package: "x", Manifest: "package.json", Message: "timeout"}}
	out, _ := write(t, res, report.Options{Format: report.FormatSARIF, Version: "v0.3.0"})
	if strings.Contains(out, "omniline.app") {
		t.Fatal("SARIF must not contain marketing")
	}

	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Invocations []struct {
				ExecutionSuccessful bool              `json:"executionSuccessful"`
				Notifications       []json.RawMessage `json:"toolExecutionNotifications"`
			} `json:"invocations"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc.Runs[0]
	if doc.Version != "2.1.0" || run.Tool.Driver.Name != "omni-audit" || run.Tool.Driver.Version != "0.3.0" {
		t.Fatalf("header: %+v", doc)
	}
	if len(run.Results) != 1 || run.Results[0].RuleID != run.Tool.Driver.Rules[0].ID || run.Results[0].Level != "error" {
		t.Fatalf("results: %+v", run.Results)
	}
	loc := run.Results[0].Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "apps/web/package.json" || loc.Region.StartLine != 12 {
		t.Fatalf("location: %+v", loc)
	}
	if len(run.Results[0].PartialFingerprints) == 0 {
		t.Fatal("missing fingerprint")
	}
	if run.Invocations[0].ExecutionSuccessful || len(run.Invocations[0].Notifications) != 1 {
		t.Fatalf("invocation: %+v", run.Invocations[0])
	}
}

func TestSharpCTAOnFindings(t *testing.T) {
	text, _ := write(t, oneFinding(), report.Options{
		Format:      report.FormatText,
		Version:     "dev",
		ForceMarket: true,
	})
	for _, want := range []string{"Unclaimed names can be published", "Prevent confusion at install time", "One UI, one API, your infrastructure"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestMarketingGoesToStderrWhenStdoutPiped(t *testing.T) {
	out, errText := write(t, oneFinding(), report.Options{Format: report.FormatText, StderrIsTTY: true})
	if strings.Contains(out, "omniline.app") || !strings.Contains(errText, "omniline.app") {
		t.Fatalf("stdout=%q stderr=%q", out, errText)
	}
}

func TestColorModes(t *testing.T) {
	out, _ := write(t, oneFinding(), report.Options{Format: report.FormatText, NoMarketing: true, Color: report.ColorAlways})
	if !strings.Contains(out, "\033[") {
		t.Fatalf("expected ANSI codes with --color always: %q", out)
	}
	out, _ = write(t, oneFinding(), report.Options{Format: report.FormatText, ForceMarket: true, StdoutIsTTY: true, Color: report.ColorNever})
	if strings.Contains(out, "\033[") {
		t.Fatalf("did not expect ANSI with --color never: %q", out)
	}
}

func TestExitCode(t *testing.T) {
	clean := &scan.Result{}
	incomplete := &scan.Result{Warnings: []scan.Warning{{Message: "x"}}}
	findings := oneFinding()
	both := oneFinding()
	both.Warnings = incomplete.Warnings

	cases := []struct {
		name   string
		res    *scan.Result
		policy report.Policy
		want   int
	}{
		{"clean", clean, report.Policy{FailOnFindings: true, Strict: true}, report.ExitOK},
		{"findings", findings, report.Policy{FailOnFindings: true}, report.ExitFindings},
		{"findings fail-on none", findings, report.Policy{}, report.ExitOK},
		{"incomplete lenient", incomplete, report.Policy{FailOnFindings: true}, report.ExitOK},
		{"incomplete strict", incomplete, report.Policy{FailOnFindings: true, Strict: true}, report.ExitError},
		{"findings win over incomplete", both, report.Policy{FailOnFindings: true, Strict: true}, report.ExitFindings},
		{"min-severity filters low", &scan.Result{Findings: []scan.Finding{{Severity: scan.SeverityLow, Package: "x"}}}, report.Policy{FailOnFindings: true, MinSeverity: scan.SeverityHigh}, report.ExitOK},
		{"min-severity keeps critical", &scan.Result{Findings: []scan.Finding{{Severity: scan.SeverityCritical, Package: "x"}}}, report.Policy{FailOnFindings: true, MinSeverity: scan.SeverityHigh}, report.ExitFindings},
		{"nil", nil, report.Policy{}, report.ExitError},
	}
	for _, tc := range cases {
		if got := report.ExitCode(tc.res, tc.policy); got != tc.want {
			t.Errorf("%s: exit=%d want %d", tc.name, got, tc.want)
		}
	}
}

func TestParseFormat(t *testing.T) {
	for _, f := range []string{"text", "json", "sarif"} {
		if _, err := report.ParseFormat(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if _, err := report.ParseFormat("xml"); err == nil {
		t.Error("expected error")
	}
}
