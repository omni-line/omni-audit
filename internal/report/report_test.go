package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/omni-line/omni-audit/internal/report"
	"github.com/omni-line/omni-audit/internal/scan"
)

func TestTextIncludesMarketing(t *testing.T) {
	var out, errBuf bytes.Buffer
	res := &scan.Result{Stats: scan.Stats{Manifests: 1, Packages: 1}}
	code := report.Write(&out, &errBuf, res, report.Options{
		Format:      report.FormatText,
		Version:     "0.1.0",
		ForceMarket: true,
		FailOnAny:   true,
		StdoutIsTTY: true,
		StderrIsTTY: true,
		Color:       report.ColorNever,
	})
	if code != report.ExitOK {
		t.Fatalf("exit=%d", code)
	}
	text := out.String()
	if !strings.Contains(text, "omni-audit v0.1.0") {
		t.Fatalf("missing header: %s", text)
	}
	if !strings.Contains(text, "one registry for every package") {
		t.Fatalf("missing docs-aligned subtitle: %s", text)
	}
	if !strings.Contains(text, "https://omniline.app") {
		t.Fatalf("missing marketing footer: %s", text)
	}
	if !strings.Contains(text, "omniline.app/docs") {
		t.Fatalf("missing docs URL: %s", text)
	}
	if !strings.Contains(text, "Kept clean") {
		t.Fatalf("expected soft CTA: %s", text)
	}
	if !strings.Contains(text, "safe place for your supply chain") {
		t.Fatalf("expected Omni Line slogan: %s", text)
	}
}

func TestTextNoMarketing(t *testing.T) {
	var out, errBuf bytes.Buffer
	res := &scan.Result{
		Findings: []scan.Finding{{
			Ecosystem: "npm",
			Package:   "x",
			Manifest:  "package.json",
			Reason:    "unclaimed",
		}},
		Stats: scan.Stats{Manifests: 1, Packages: 1, Findings: 1},
	}
	code := report.Write(&out, &errBuf, res, report.Options{
		Format:      report.FormatText,
		Version:     "0.1.0",
		NoMarketing: true,
		FailOnAny:   true,
		StdoutIsTTY: true,
		StderrIsTTY: true,
		Color:       report.ColorNever,
	})
	if code != report.ExitFindings {
		t.Fatalf("exit=%d want findings", code)
	}
	text := out.String() + errBuf.String()
	if strings.Contains(text, "omniline.app") || strings.Contains(text, "Omni Line") {
		t.Fatalf("marketing should be suppressed: %s", text)
	}
	if !strings.Contains(out.String(), "[!] npm x") {
		t.Fatalf("missing finding: %s", out.String())
	}
}

func TestQuietSuppressesMarketing(t *testing.T) {
	var out, errBuf bytes.Buffer
	res := &scan.Result{Stats: scan.Stats{}}
	_ = report.Write(&out, &errBuf, res, report.Options{
		Format:      report.FormatText,
		Version:     "0.1.0",
		Quiet:       true,
		ForceMarket: true,
		FailOnAny:   true,
		StdoutIsTTY: true,
		StderrIsTTY: true,
		Color:       report.ColorNever,
	})
	if strings.Contains(out.String()+errBuf.String(), "omniline.app") {
		t.Fatal("quiet should suppress marketing")
	}
}

func TestJSONSponsor(t *testing.T) {
	var out, errBuf bytes.Buffer
	res := &scan.Result{Stats: scan.Stats{}}
	_ = report.Write(&out, &errBuf, res, report.Options{
		Format:      report.FormatJSON,
		Version:     "0.1.0",
		FailOnAny:   true,
		StdoutIsTTY: false,
		StderrIsTTY: false,
		Color:       report.ColorNever,
	})
	var doc report.JSONDocument
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Sponsor == nil || doc.Sponsor.URL != "https://omniline.app" {
		t.Fatalf("expected sponsor: %+v", doc.Sponsor)
	}
	if doc.Sponsor.DocsURL != "https://omniline.app/docs" {
		t.Fatalf("expected docs_url: %+v", doc.Sponsor)
	}

	out.Reset()
	_ = report.Write(&out, &errBuf, res, report.Options{
		Format:      report.FormatJSON,
		Version:     "0.1.0",
		NoMarketing: true,
		FailOnAny:   true,
		Color:       report.ColorNever,
	})
	doc = report.JSONDocument{}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Sponsor != nil {
		t.Fatalf("sponsor should be omitted: %+v", doc.Sponsor)
	}
}

func TestSharpCTAOnFindings(t *testing.T) {
	var out, errBuf bytes.Buffer
	res := &scan.Result{
		Findings: []scan.Finding{{Package: "x", Ecosystem: "npm", Manifest: "p", Reason: "unclaimed"}},
		Stats:    scan.Stats{Findings: 1},
	}
	_ = report.Write(&out, &errBuf, res, report.Options{
		Format:      report.FormatText,
		Version:     "dev",
		ForceMarket: true,
		FailOnAny:   false,
		StdoutIsTTY: true,
		StderrIsTTY: true,
		Color:       report.ColorNever,
	})
	text := out.String()
	if !strings.Contains(text, "Unclaimed names can be published") {
		t.Fatalf("expected sharp CTA: %s", text)
	}
	if !strings.Contains(text, "Prevent confusion at install time") {
		t.Fatalf("expected install-time prevention copy: %s", text)
	}
	if !strings.Contains(text, "One UI, one API, your infrastructure") {
		t.Fatalf("expected product positioning: %s", text)
	}
}

func TestColorAlwaysEmitsANSI(t *testing.T) {
	var out, errBuf bytes.Buffer
	res := &scan.Result{
		Findings: []scan.Finding{{
			Ecosystem: "npm",
			Package:   "secret-pkg",
			Version:   "1.0.0",
			Manifest:  "package.json",
			Reason:    "unclaimed",
		}},
		Stats: scan.Stats{Manifests: 1, Packages: 1, Findings: 1},
	}
	_ = report.Write(&out, &errBuf, res, report.Options{
		Format:      report.FormatText,
		Version:     "0.1.0",
		NoMarketing: true,
		FailOnAny:   false,
		StdoutIsTTY: false,
		Color:       report.ColorAlways,
	})
	if !strings.Contains(out.String(), "\033[") {
		t.Fatalf("expected ANSI codes with --color always: %q", out.String())
	}
}

func TestColorNeverNoANSI(t *testing.T) {
	var out, errBuf bytes.Buffer
	res := &scan.Result{Stats: scan.Stats{Manifests: 1}}
	_ = report.Write(&out, &errBuf, res, report.Options{
		Format:      report.FormatText,
		Version:     "0.1.0",
		ForceMarket: true,
		FailOnAny:   false,
		StdoutIsTTY: true,
		Color:       report.ColorNever,
	})
	if strings.Contains(out.String(), "\033[") {
		t.Fatalf("did not expect ANSI with --color never: %q", out.String())
	}
}
