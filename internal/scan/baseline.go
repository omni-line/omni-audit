package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Baseline file cap. A fingerprint list or a previous report fits well under this.
const maxBaselineSize = 32 << 20

// LoadBaseline reads a previous omni-audit JSON report (findings[].fingerprint)
// or a document of the form {"fingerprints": ["..."]}. The two shapes can be
// combined. An empty fingerprint list is valid and suppresses nothing.
func LoadBaseline(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	if len(data) > maxBaselineSize {
		return nil, errors.New("baseline exceeds 32 MiB limit")
	}
	return ParseBaseline(data)
}

// ParseBaseline decodes a baseline document.
func ParseBaseline(data []byte) (map[string]struct{}, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	_, hasFP := raw["fingerprints"]
	_, hasFindings := raw["findings"]
	if !hasFP && !hasFindings {
		return nil, errors.New("baseline must be an omni-audit JSON report or {\"fingerprints\": [...]}")
	}

	set := map[string]struct{}{}
	if hasFP {
		var list []string
		if err := json.Unmarshal(raw["fingerprints"], &list); err != nil {
			return nil, fmt.Errorf("baseline fingerprints: %w", err)
		}
		for _, fp := range list {
			if fp != "" {
				set[fp] = struct{}{}
			}
		}
	}
	if hasFindings {
		var list []struct {
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.Unmarshal(raw["findings"], &list); err != nil {
			return nil, fmt.Errorf("baseline findings: %w", err)
		}
		for _, f := range list {
			if f.Fingerprint == "" {
				return nil, errors.New("baseline findings are missing fingerprint; regenerate the report with this version of omni-audit")
			}
			set[f.Fingerprint] = struct{}{}
		}
	}
	return set, nil
}

// ApplyBaseline removes findings whose fingerprint is in set and records how
// many were hidden. Stats.Findings is updated to the remaining count.
func ApplyBaseline(res *Result, set map[string]struct{}) {
	if res == nil || len(set) == 0 || len(res.Findings) == 0 {
		return
	}
	kept := make([]Finding, 0, len(res.Findings))
	for _, f := range res.Findings {
		if _, ok := set[Fingerprint(f)]; ok {
			res.Stats.Suppressed++
			continue
		}
		kept = append(kept, f)
	}
	res.Findings = kept
	res.Stats.Findings = len(kept)
}
