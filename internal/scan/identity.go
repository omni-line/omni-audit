package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// RuleID returns the stable rule identifier for a finding reason.
// Unknown reasons use the unclaimed rule, matching SARIF output.
func RuleID(reason string) string {
	switch reason {
	case ReasonShadowRegistry:
		return RuleShadowRegistry
	case ReasonTyposquat:
		return RuleTyposquat
	case ReasonMalicious:
		return RuleMalicious
	case ReasonConfig:
		return RuleConfig
	case ReasonInstallHook:
		return RuleInstallHook
	default:
		return RuleUnclaimed
	}
}

// ReportPath is the slash-separated path used in SARIF locations and
// fingerprints. Absolute paths inside the working directory become relative.
// An empty path stays empty (name checks have no manifest).
func ReportPath(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		if wd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(rel, "..") {
				p = rel
			}
		}
	}
	return strings.TrimPrefix(filepath.ToSlash(filepath.Clean(p)), "./")
}

// Fingerprint is the stable identity of a finding, shared by JSON and SARIF.
// It ignores version and line so a baseline still matches after a constraint
// bump, and includes the resolved URL and typosquat kind when set.
func Fingerprint(f Finding) string {
	uri := ReportPath(f.Manifest)
	fp := f.Ecosystem + "\x00" + f.Package + "\x00" + uri + "\x00" + f.Reason
	if f.ResolvedURL != "" {
		fp += "\x00" + f.ResolvedURL
	}
	if f.Kind != "" {
		fp += "\x00" + f.Kind
	}
	sum := sha256.Sum256([]byte(fp))
	return hex.EncodeToString(sum[:16])
}
