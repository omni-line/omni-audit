package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/omni-line/omni-audit/internal/scan"
)

// SchemaVersion is bumped only for breaking changes to the JSON document.
// Adding fields is not a breaking change.
const SchemaVersion = 1

// JSONDocument is the machine-readable report.
type JSONDocument struct {
	SchemaVersion int            `json:"schema_version"`
	Version       string         `json:"version"`
	Complete      bool           `json:"complete"`
	Decision      string         `json:"decision,omitempty"`
	Checks        []string       `json:"checks,omitempty"`
	Findings      []scan.Finding `json:"findings"`
	// Actions is a pointer so an empty list still encodes as [] when a
	// decision is present. A nil pointer is omitted on ordinary tree scans.
	Actions  *[]scan.Action `json:"actions,omitempty"`
	Warnings []scan.Warning `json:"warnings,omitempty"`
	Stats    scan.Stats     `json:"stats"`
	Sponsor  *Sponsor       `json:"sponsor,omitempty"`
}

func writeJSON(w io.Writer, res *scan.Result, opts Options) error {
	doc := JSONDocument{
		SchemaVersion: SchemaVersion,
		Version:       opts.Version,
		Complete:      res.Complete(),
		Decision:      res.Decision,
		Checks:        res.Checks,
		Findings:      stampFindings(res.Findings),
		Warnings:      res.Warnings,
		Stats:         res.Stats,
	}
	if res.Decision != "" {
		doc.Decision = res.Decision
		actions := scan.RenameActions(res.Findings)
		if actions == nil {
			actions = []scan.Action{}
		}
		doc.Actions = &actions
	}
	if shouldShowMarketing(opts) {
		s := NewSponsor(len(res.Findings))
		doc.Sponsor = &s
	}
	enc := json.NewEncoder(w)
	if !opts.Compact {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

// stampFindings copies findings and fills the stable rule id and fingerprint.
func stampFindings(in []scan.Finding) []scan.Finding {
	if len(in) == 0 {
		return []scan.Finding{}
	}
	out := make([]scan.Finding, len(in))
	for i, f := range in {
		f.ID = scan.RuleID(f.Reason)
		f.Fingerprint = scan.Fingerprint(f)
		out[i] = f
	}
	return out
}
