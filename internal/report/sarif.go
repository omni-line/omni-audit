package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/omni-line/omni-audit/internal/scan"
)

// SARIF 2.1.0 output for GitHub code scanning and other SAST dashboards.
// Only the subset of the schema that omni-audit populates is modeled.

const (
	sarifSchema        = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifRuleUnclaimed = "OA001"
	sarifRuleShadow    = "OA002"
	sarifRuleTyposquat = "OA003"
	sarifRuleMalicious = "OA004"
	sarifRuleRegConfig = "OA005"
	toolInfoURI        = "https://github.com/omni-line/omni-audit"
	fingerprintK       = "omniAudit/v1"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      sarifText       `json:"fullDescription"`
	Help                 sarifText       `json:"help"`
	HelpURI              string          `json:"helpUri"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           map[string]any  `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func writeSARIF(w io.Writer, res *scan.Result, opts Options) error {
	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "omni-audit",
				Version:        strings.TrimPrefix(opts.Version, "v"),
				InformationURI: toolInfoURI,
				Rules:          []sarifRule{unclaimedRule(), shadowRule(), typosquatRule(), maliciousRule(), configRule()},
			}},
			Invocations: []sarifInvocation{invocation(res)},
			Results:     make([]sarifResult, 0, len(res.Findings)),
		}},
	}
	for _, f := range res.Findings {
		log.Runs[0].Results = append(log.Runs[0].Results, sarifFinding(f))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("encode sarif: %w", err)
	}
	return nil
}

func unclaimedRule() sarifRule {
	return sarifRule{
		ID:   sarifRuleUnclaimed,
		Name: "UnclaimedPackageName",
		ShortDescription: sarifText{
			Text: "Dependency name is unclaimed on its public registry",
		},
		FullDescription: sarifText{
			Text: "The dependency is not registered on the public registry for its ecosystem. " +
				"Anyone can publish a package with this name; a build that resolves it from the " +
				"public registry instead of your private source would install that code (dependency confusion).",
		},
		Help: sarifText{
			Text: "Claim the name (or its scope/vendor) on the public registry, and configure your " +
				"package manager so internal names resolve only from your private registry.",
		},
		HelpURI:              toolInfoURI + "#readme",
		DefaultConfiguration: sarifRuleConfig{Level: "error"},
		Properties: map[string]any{
			"tags":              []string{"security", "supply-chain", "dependency-confusion"},
			"security-severity": "8.1",
			"precision":         "high",
		},
	}
}

func shadowRule() sarifRule {
	return sarifRule{
		ID:   sarifRuleShadow,
		Name: "UnexpectedPackageSource",
		ShortDescription: sarifText{
			Text: "Lockfile dependency resolves outside the expected registry proxy",
		},
		FullDescription: sarifText{
			Text: "A lockfile records a resolution URL on a public or unexpected registry host. " +
				"Installs that follow this URL bypass the internal registry proxy and its " +
				"security controls (shadow registry / broken proxy configuration).",
		},
		Help: sarifText{
			Text: "Configure the package manager to use your internal registry proxy, regenerate " +
				"the lockfile so resolved URLs use that host, or adopt Omni Line Virtual Registries.",
		},
		HelpURI:              toolInfoURI + "#readme",
		DefaultConfiguration: sarifRuleConfig{Level: "error"},
		Properties: map[string]any{
			"tags":              []string{"security", "supply-chain", "shadow-registry"},
			"security-severity": "7.5",
			"precision":         "high",
		},
	}
}

func typosquatRule() sarifRule {
	return sarifRule{
		ID:   sarifRuleTyposquat,
		Name: "TyposquatPackageName",
		ShortDescription: sarifText{
			Text: "Dependency name is a near-miss of a popular package",
		},
		FullDescription: sarifText{
			Text: "The dependency name is 1–2 edits away from a high-download package (or a " +
				"peer in the same namespace). Attackers publish near-miss names so a typo in a " +
				"manifest installs malware.",
		},
		Help: sarifText{
			Text: "Confirm the package name is intentional. If it is a typo, correct it to the " +
				"suggested package. Proxy public registries and allow-list approved externals.",
		},
		HelpURI:              toolInfoURI + "#readme",
		DefaultConfiguration: sarifRuleConfig{Level: "error"},
		Properties: map[string]any{
			"tags":              []string{"security", "supply-chain", "typosquat"},
			"security-severity": "8.1",
			"precision":         "high",
		},
	}
}

func maliciousRule() sarifRule {
	return sarifRule{
		ID:   sarifRuleMalicious,
		Name: "KnownMaliciousPackage",
		ShortDescription: sarifText{
			Text: "Dependency was published to a public registry as malware",
		},
		FullDescription: sarifText{
			Text: "The dependency matches an OpenSSF malicious-packages (MAL-) advisory for this " +
				"name, at this version or at every version. Malicious packages typically run " +
				"their payload in install scripts, so any machine that installed it may be compromised.",
		},
		Help: sarifText{
			Text: scan.RemediationMalicious,
		},
		HelpURI:              toolInfoURI + "#readme",
		DefaultConfiguration: sarifRuleConfig{Level: "error"},
		Properties: map[string]any{
			"tags":              []string{"security", "supply-chain", "malware"},
			"security-severity": "9.8",
			"precision":         "very-high",
		},
	}
}

func configRule() sarifRule {
	return sarifRule{
		ID:   sarifRuleRegConfig,
		Name: "RiskyRegistryConfiguration",
		ShortDescription: sarifText{
			Text: "Package-manager configuration enables dependency confusion, leaks a credential, or disables TLS",
		},
		FullDescription: sarifText{
			Text: "A configuration file (.npmrc, .yarnrc.yml, pip.conf, requirements, pyproject.toml, " +
				"Pipfile, composer.json, auth.json, Gemfile, .cargo/config.toml, settings.xml, or a " +
				"build script) merges public and internal indexes, makes a repository non-canonical, " +
				"stores a registry credential in plain text, or reaches a registry without verified TLS.",
		},
		Help: sarifText{
			Text: "Use one registry URL that serves internal and public packages, keep credentials in " +
				"environment variables or user-level config, and use HTTPS with certificate checks.",
		},
		HelpURI:              toolInfoURI + "#readme",
		DefaultConfiguration: sarifRuleConfig{Level: "error"},
		Properties: map[string]any{
			"tags":              []string{"security", "supply-chain", "dependency-confusion", "configuration"},
			"security-severity": "7.5",
			"precision":         "high",
		},
	}
}

func invocation(res *scan.Result) sarifInvocation {
	inv := sarifInvocation{ExecutionSuccessful: res.Complete()}
	for _, wn := range res.Warnings {
		msg := wn.Message
		if wn.Package != "" {
			msg = fmt.Sprintf("%s %s (%s): %s", wn.Ecosystem, wn.Package, wn.Manifest, wn.Message)
		} else if wn.Manifest != "" {
			msg = fmt.Sprintf("%s: %s", wn.Manifest, wn.Message)
		}
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sarifNotification{
			Level:   "warning",
			Message: sarifText{Text: msg},
		})
	}
	return inv
}

func sarifFinding(f scan.Finding) sarifResult {
	uri := sarifURI(f.Manifest)
	ruleID := sarifRuleUnclaimed
	msg := fmt.Sprintf("%s package %q is not registered on %s. Anyone can publish it.", f.Ecosystem, f.Package, registryLabel(f))
	switch f.Reason {
	case scan.ReasonShadowRegistry:
		ruleID = sarifRuleShadow
		msg = fmt.Sprintf("%s package %q resolves from %s instead of your expected registry proxy.", f.Ecosystem, f.Package, registryLabel(f))
		if f.ResolvedURL != "" {
			msg += " Resolved URL: " + f.ResolvedURL + "."
		}
	case scan.ReasonMalicious:
		ruleID = sarifRuleMalicious
		msg = f.Message + "."
	case scan.ReasonConfig:
		ruleID = sarifRuleRegConfig
		msg = fmt.Sprintf("%s setting %q: %s.", f.Ecosystem, f.Package, f.Message)
	case scan.ReasonTyposquat:
		ruleID = sarifRuleTyposquat
		switch {
		case f.Message != "":
			msg = f.Message + "."
		case len(f.Suggestions) > 0:
			msg = fmt.Sprintf("%s package %q looks like a typosquat of %q.", f.Ecosystem, f.Package, f.Suggestions[0])
		default:
			msg = fmt.Sprintf("%s package %q looks like a typosquat of a popular package.", f.Ecosystem, f.Package)
		}
	}
	if f.Remediation != "" {
		msg += " " + f.Remediation
	}
	loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}}
	if f.Line > 0 {
		loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
	}
	fp := f.Ecosystem + "\x00" + f.Package + "\x00" + uri + "\x00" + f.Reason
	if f.ResolvedURL != "" {
		fp += "\x00" + f.ResolvedURL
	}
	if f.Kind != "" {
		fp += "\x00" + f.Kind
	}
	sum := sha256.Sum256([]byte(fp))
	props := map[string]string{"ecosystem": f.Ecosystem, "package": f.Package, "reason": f.Reason}
	if f.Version != "" {
		props["version"] = f.Version
	}
	if f.Group != "" {
		props["group"] = f.Group
	}
	if f.ResolvedURL != "" {
		props["resolved_url"] = f.ResolvedURL
	}
	if f.Kind != "" {
		props["kind"] = f.Kind
	}
	if f.Technique != "" {
		props["technique"] = f.Technique
	}
	if len(f.Suggestions) > 0 {
		props["suggestion"] = f.Suggestions[0]
	}
	sev := f.Severity
	if sev == "" {
		sev = scan.SeverityHigh
	}
	props["severity"] = sev
	if len(f.IDs) > 0 {
		props["ids"] = strings.Join(f.IDs, ", ")
	}
	if f.Campaign != "" {
		props["campaign"] = f.Campaign
	}
	if f.Namespace != "" {
		props["namespace"] = f.Namespace
	}
	if f.NamespaceStatus != "" {
		props["namespace_status"] = f.NamespaceStatus
	}
	level, secSev := sarifSeverity(sev)
	props["security-severity"] = secSev
	return sarifResult{
		RuleID:              ruleID,
		Level:               level,
		Message:             sarifText{Text: msg},
		Locations:           []sarifLocation{loc},
		PartialFingerprints: map[string]string{fingerprintK: hex.EncodeToString(sum[:16])},
		Properties:          props,
	}
}

func sarifSeverity(sev string) (level, securitySeverity string) {
	switch sev {
	case scan.SeverityCritical:
		return "error", "9.0"
	case scan.SeverityMedium:
		return "warning", "5.5"
	case scan.SeverityLow:
		return "warning", "3.1"
	default:
		return "error", "8.1"
	}
}

func registryLabel(f scan.Finding) string {
	if f.Registry != "" {
		return f.Registry
	}
	return "the public registry"
}

// sarifURI returns a slash-separated path, relative to the working directory
// when possible, as code-scanning uploads expect repository-relative URIs.
func sarifURI(p string) string {
	if filepath.IsAbs(p) {
		if wd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(rel, "..") {
				p = rel
			}
		}
	}
	return strings.TrimPrefix(filepath.ToSlash(filepath.Clean(p)), "./")
}
