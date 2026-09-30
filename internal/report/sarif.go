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
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifRuleID  = "OA001"
	toolInfoURI  = "https://github.com/omni-line/omni-audit"
	fingerprintK = "omniAudit/v1"
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
				Rules:          []sarifRule{unclaimedRule()},
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
		ID:   sarifRuleID,
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
	msg := fmt.Sprintf("%s package %q is not registered on %s. Anyone can publish it.", f.Ecosystem, f.Package, registryLabel(f))
	if f.Remediation != "" {
		msg += " " + f.Remediation
	}
	loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}}
	if f.Line > 0 {
		loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
	}
	sum := sha256.Sum256([]byte(f.Ecosystem + "\x00" + f.Package + "\x00" + uri))
	props := map[string]string{"ecosystem": f.Ecosystem, "package": f.Package}
	if f.Version != "" {
		props["version"] = f.Version
	}
	if f.Group != "" {
		props["group"] = f.Group
	}
	return sarifResult{
		RuleID:              sarifRuleID,
		Level:               "error",
		Message:             sarifText{Text: msg},
		Locations:           []sarifLocation{loc},
		PartialFingerprints: map[string]string{fingerprintK: hex.EncodeToString(sum[:16])},
		Properties:          props,
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
