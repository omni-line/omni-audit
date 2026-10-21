package scan

import (
	"fmt"
	"strings"

	"github.com/omni-line/mal-check/pkg/maldb"
)

// RemediationMalicious is default guidance for known malicious packages.
const RemediationMalicious = "Remove the package, delete node_modules / virtualenvs / caches, and reinstall from a clean lockfile. If it was ever installed on a machine or in CI, treat that environment as compromised and rotate every secret it could read. Omni Line blocks MAL- packages at install time."

// lockedDep is one lockfile resolution, kept for the malicious-package audit.
type lockedDep struct {
	ecosystem string
	name      string
	version   string
	manifest  string
	line      int
}

// auditMalicious checks lockfile resolutions and declared dependencies
// against the embedded OpenSSF malicious-packages snapshot (MAL- advisories).
// Lockfile versions are exact; a declaration of a package that a lockfile
// already resolves is skipped, because the lockfile says what is installed.
// Clean versions of once-hijacked packages are not reported. Offline.
func auditMalicious(opts Options, occs []occurrence, locked []lockedDep) ([]Finding, error) {
	if opts.NoMalicious || (len(occs) == 0 && len(locked) == 0) {
		return nil, nil // nothing to check: skip loading the ~240k-record snapshot
	}
	db := opts.Malicious
	if db == nil {
		var err error
		if db, err = maldb.Default(); err != nil {
			return nil, fmt.Errorf("malicious-package database: %w", err)
		}
	}

	var out []Finding
	seen := make(map[string]struct{})
	add := func(f Finding) {
		k := f.Ecosystem + "\x00" + f.Package + "\x00" + f.Version + "\x00" + f.Manifest
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		out = append(out, f)
	}

	resolved := make(map[string]bool, len(locked))
	for _, l := range locked {
		resolved[l.ecosystem+"\x00"+maldb.Normalize(l.ecosystem, l.name)] = true
		if f, ok := maliciousFinding(db, l.ecosystem, l.name, l.version, true); ok {
			f.Manifest, f.Line, f.Group = l.manifest, l.line, "resolved"
			add(f)
		}
	}
	for _, o := range occs {
		if resolved[o.eco.Name+"\x00"+maldb.Normalize(o.eco.Name, o.dep.Name)] {
			continue
		}
		f, ok := maliciousFinding(db, o.eco.Name, o.dep.Name, o.dep.Version, exactVersion(o.dep.Version))
		if !ok {
			continue
		}
		f.Manifest, f.Line, f.Group = o.manifest, o.dep.Line, o.dep.Group
		add(f)
	}
	return out, nil
}

// supersedeUnclaimed drops unclaimed findings for declarations that are also
// known malicious packages. Registries take malware down, so its name often
// reads as unclaimed, and "reserve the name" is the wrong fix: remove it.
func supersedeUnclaimed(findings, malicious []Finding) []Finding {
	if len(malicious) == 0 {
		return findings
	}
	key := func(f Finding) string {
		return f.Ecosystem + "\x00" + f.Package + "\x00" + f.Manifest + "\x00" + fmt.Sprint(f.Line)
	}
	mal := make(map[string]struct{}, len(malicious))
	for _, f := range malicious {
		mal[key(f)] = struct{}{}
	}
	out := findings[:0]
	for _, f := range findings {
		if _, hit := mal[key(f)]; hit && f.Reason == ReasonUnclaimed {
			continue
		}
		out = append(out, f)
	}
	return out
}

// maliciousFinding folds every advisory for a package into one finding at
// the most severe verdict: critical when this version (or every version) is
// malicious, high when only some versions are and this one is not pinned.
func maliciousFinding(db *maldb.DB, ecosystem, name, version string, exact bool) (Finding, bool) {
	recs := db.Lookup(ecosystem, name)
	if len(recs) == 0 {
		return Finding{}, false
	}
	check := ""
	if exact {
		check = strings.TrimPrefix(strings.TrimSpace(version), "==")
	}
	best := maldb.Clean
	var lead *maldb.Record
	var ids []string
	for i := range recs {
		v := maldb.Check(recs[i], check)
		ids = append(ids, recs[i].ID)
		if lead == nil || v < best {
			best, lead = v, &recs[i]
		}
	}
	if best == maldb.Clean {
		return Finding{}, false
	}
	f := Finding{
		Ecosystem:   ecosystem,
		Package:     name,
		Version:     version,
		Reason:      ReasonMalicious,
		Severity:    SeverityCritical,
		URL:         maldb.URL(lead.ID),
		IDs:         ids,
		Remediation: RemediationMalicious,
		Message:     fmt.Sprintf("%s package %q is a known malicious package (%s)", ecosystem, name, strings.Join(ids, ", ")),
	}
	f.Campaign = lead.Campaign
	if best == maldb.Unknown {
		f.Severity = SeverityHigh
		f.Message = fmt.Sprintf("%s package %q has malicious versions (%s) and %q is not pinned to a known-clean one",
			ecosystem, name, strings.Join(ids, ", "), version)
	}
	return f, true
}

// exactVersion reports whether a declared version is one concrete version
// (1.2.3, v1.2.3, ==1.2.3) rather than a range.
func exactVersion(v string) bool {
	v = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "=="), "v")
	if v == "" || v[0] < '0' || v[0] > '9' {
		return false
	}
	return !strings.ContainsAny(v, " <>=^~*|,xX")
}
