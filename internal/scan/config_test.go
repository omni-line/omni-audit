package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/regconfig"
	"github.com/omni-line/omni-audit/internal/scan"
)

func TestRunAuditsRegistryConfig(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "registry-config")
	opts := scan.Options{
		Ecosystems:  []ecosystem.Ecosystem{ecosystem.NPM(claimed{}), ecosystem.PyPI(claimed{})},
		NoTyposquat: true, NoMalicious: true,
	}
	res, err := scan.Run(context.Background(), root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.ConfigFiles != 13 {
		t.Errorf("config files = %d, want 13", res.Stats.ConfigFiles)
	}
	var got []string
	for _, f := range res.Findings {
		if f.Reason != scan.ReasonConfig {
			t.Errorf("unexpected finding: %+v", f)
			continue
		}
		if f.Kind != f.Group || f.Remediation == "" || f.Message == "" {
			t.Errorf("finding lacks detail: %+v", f)
		}
		got = append(got, filepath.Base(f.Manifest)+":"+f.Kind+":"+f.Severity)
	}
	sort.Strings(got)
	for _, want := range []string{
		".npmrc:plaintext_credential:high",
		"Dockerfile:extra_index:high",
		"Dockerfile:unsafe_index_strategy:high",
		"Gemfile:multiple_global_sources:high",
		"composer.json:non_canonical_repository:high",
		"auth.json:plaintext_credential:high",
		"config.toml:insecure_transport:medium",
		"settings.xml:plaintext_credential:high",
	} {
		if !contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if len(got) != 26 {
		t.Errorf("config findings = %d, want 26:\n%s", len(got), strings.Join(got, "\n"))
	}

	opts.NoConfig = true
	off, err := scan.Run(context.Background(), root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(off.Findings) != 0 || off.Stats.ConfigFiles != 0 {
		t.Errorf("--no-registry-config still audited: %+v", off.Findings)
	}

	opts.NoConfig = false
	opts.ConfigFiles = []regconfig.File{}
	if none, _ := scan.Run(context.Background(), root, opts); len(none.Findings) != 0 {
		t.Errorf("empty ConfigFiles still audited: %+v", none.Findings)
	}
}

// A setting reported twice on one line (flag and env var) is one finding.
func TestConfigFindingsDeduplicated(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "Dockerfile"), "RUN PIP_EXTRA_INDEX_URL=https://pypi.acme.corp/simple pip install --extra-index-url https://pypi.acme.corp/simple x\n")
	res, err := scan.Run(context.Background(), root, scan.Options{Ecosystems: []ecosystem.Ecosystem{ecosystem.PyPI(claimed{})}, NoTyposquat: true, NoMalicious: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Kind != regconfig.RiskExtraIndex {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Credentials in files that .gitignore excludes are local settings, not
// leaks; other risks in them are still reported.
func TestConfigCredentialsInIgnoredFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".gitignore"), "# local\n!keep.json\nbuild/\n/auth.json\n**/.npmrc\n")
	mustWrite(t, filepath.Join(root, "auth.json"), `{"bearer": {"repo.acme.corp": "not-a-real-token"}}`)
	if err := os.MkdirAll(filepath.Join(root, "web", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "web", ".gitignore"), "pip.*\n")
	mustWrite(t, filepath.Join(root, "web", "deep", ".npmrc"), "//npm.acme.corp/:_authToken=not-a-real-token\nstrict-ssl=false\n")
	mustWrite(t, filepath.Join(root, "web", "deep", "pip.conf"), "[global]\nindex-url = https://u:not-a-real-password@pypi.acme.corp/simple\n")
	mustWrite(t, filepath.Join(root, "web", "auth.json"), `{"bearer": {"repo.acme.corp": "not-a-real-token"}}`)

	res, err := scan.Run(context.Background(), root, scan.Options{
		Ecosystems: []ecosystem.Ecosystem{ecosystem.PyPI(claimed{})}, NoTyposquat: true, NoMalicious: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range res.Findings {
		rel, _ := filepath.Rel(root, f.Manifest)
		got = append(got, filepath.ToSlash(rel)+":"+f.Kind)
	}
	sort.Strings(got)
	want := "web/auth.json:plaintext_credential web/deep/.npmrc:insecure_transport"
	if strings.Join(got, " ") != want {
		t.Fatalf("findings = %v, want %s", got, want)
	}
}
