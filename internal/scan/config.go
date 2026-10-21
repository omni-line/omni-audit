package scan

import (
	"strconv"

	"github.com/omni-line/omni-audit/internal/discover"
	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/regconfig"
)

// WarnConfig marks a configuration file that could not be read.
const WarnConfig = "config"

// configSeverity ranks registry configuration risks. Settings that let a
// public package replace an internal one, and leaked credentials, are high;
// transport weaknesses are medium.
func configSeverity(risk string) string {
	if risk == regconfig.RiskInsecure {
		return SeverityMedium
	}
	return SeverityHigh
}

// auditConfig flags risky settings in package-manager configuration files
// (.npmrc, pip.conf, composer.json, Gemfile, …). Offline.
func auditConfig(root string, opts Options, res *Result) {
	files := opts.ConfigFiles
	if files == nil {
		files = regconfig.Default()
	}
	if opts.NoConfig || len(files) == 0 {
		return
	}
	walk, err := discover.Walk(root, discover.Options{
		Classify: func(rel string) string { return regconfig.Classify(files, rel) },
		Exclude:  opts.Exclude,
	})
	if err != nil {
		res.Warnings = append(res.Warnings, Warning{Kind: WarnConfig, Message: err.Error()})
		return
	}
	for _, p := range walk.Problems {
		res.Warnings = append(res.Warnings, Warning{Kind: WarnWalk, Manifest: p.Path, Message: p.Err.Error()})
	}
	res.Stats.ConfigFiles = len(walk.Manifests)
	for _, m := range walk.Manifests {
		data, err := manifest.ReadFile(m.Path)
		if err != nil {
			res.Warnings = append(res.Warnings, Warning{Kind: WarnConfig, Ecosystem: m.Ecosystem, Manifest: m.Path, Message: err.Error()})
			continue
		}
		issues := regconfig.AuditFile(files, m.Rel, data)
		seen := make(map[string]struct{})
		for _, is := range issues {
			// A token in an ignored file is a local setting, not a leak.
			if is.Risk == regconfig.RiskCredential && gitignored(root, m.Rel) {
				continue
			}
			key := is.Risk + "\x00" + is.URL + "\x00" + strconv.Itoa(is.Line)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			res.Findings = append(res.Findings, Finding{
				Ecosystem:   m.Ecosystem,
				Package:     is.Setting,
				Manifest:    m.Path,
				Line:        is.Line,
				Group:       is.Risk,
				Reason:      ReasonConfig,
				Severity:    configSeverity(is.Risk),
				URL:         is.URL,
				Remediation: regconfig.Remediation(is.Risk),
				Kind:        is.Risk,
				Message:     is.Message,
			})
		}
	}
}
