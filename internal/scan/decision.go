package scan

// Decisions an agent can take from a check or an --agent report.
const (
	// DecisionAllow means every checked name is claimed and not a typosquat.
	DecisionAllow = "allow"
	// DecisionBlock means at least one finding is at or above the severity gate.
	DecisionBlock = "block"
	// DecisionUnknown means a lookup failed and nothing was blocked. Callers
	// must not treat that as a safe name.
	DecisionUnknown = "unknown"
)

// Action types.
const (
	ActionRename = "rename"
)

// Confidence values for an action an agent might apply on its own.
const (
	ConfidenceHigh = "high"
)

// Action is a machine-readable fix. A rename is emitted only when a typosquat
// has a single suggestion at edit distance 1, so the replacement is unambiguous.
type Action struct {
	Type        string `json:"type"`
	Ecosystem   string `json:"ecosystem"`
	Package     string `json:"package"`
	Replacement string `json:"replacement"`
	Confidence  string `json:"confidence"`
}

// Decide maps a result to allow, block, or unknown. minSeverity is the same
// gate as --min-severity; empty means low (any finding blocks). Findings below
// the gate do not block. Any warning (a failed registry lookup, an unreadable
// manifest) yields unknown when nothing blocks.
func Decide(res *Result, minSeverity string) string {
	if res == nil {
		return DecisionUnknown
	}
	if HasSeverity(res, minSeverity) {
		return DecisionBlock
	}
	if !res.Complete() {
		return DecisionUnknown
	}
	return DecisionAllow
}

// HasSeverity reports whether res contains a finding at or above minSeverity.
// An empty severity on a finding is treated as high. An empty minSeverity
// means low.
func HasSeverity(res *Result, minSeverity string) bool {
	if res == nil || len(res.Findings) == 0 {
		return false
	}
	if minSeverity == "" {
		minSeverity = SeverityLow
	}
	threshold := SeverityRank(minSeverity)
	for _, f := range res.Findings {
		sev := f.Severity
		if sev == "" {
			sev = SeverityHigh
		}
		if SeverityRank(sev) >= threshold {
			return true
		}
	}
	return false
}

// RenameActions returns one rename per unambiguous typosquat. Distance 2 and
// several equally close suggestions are left for a person to judge.
func RenameActions(findings []Finding) []Action {
	seen := map[string]struct{}{}
	var out []Action
	for _, f := range findings {
		if f.Reason != ReasonTyposquat || f.Distance != 1 || len(f.Suggestions) != 1 {
			continue
		}
		replacement := f.Suggestions[0]
		if replacement == "" || replacement == f.Package {
			continue
		}
		key := f.Ecosystem + "\x00" + f.Package + "\x00" + replacement
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Action{
			Type:        ActionRename,
			Ecosystem:   f.Ecosystem,
			Package:     f.Package,
			Replacement: replacement,
			Confidence:  ConfidenceHigh,
		})
	}
	return out
}
