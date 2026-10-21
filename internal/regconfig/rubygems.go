package regconfig

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// gemSource matches `source "url"` and `source("url")`, global or block.
	gemSource = regexp.MustCompile(`^\s*source\s*\(?\s*["']([^"']+)["']\s*\)?\s*(.*)$`)
	// gemBlock is the rest of a source line that opens a block.
	gemBlock = regexp.MustCompile(`^(do\b|\{)`)
)

// auditGemfile checks Gemfile sources. With several global sources Bundler
// may resolve any gem from any of them; internal gems belong in a
// `source "…" do … end` block.
func auditGemfile(data []byte) []Issue {
	var out []Issue
	var global []string
	for i, l := range lines(data) {
		m := gemSource.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		line := i + 1
		out = append(out, urlIssues("source", m[1], line)...)
		if gemBlock.MatchString(strings.TrimSpace(m[2])) {
			continue
		}
		global = append(global, m[1])
		if len(global) == 2 {
			out = append(out, Issue{Risk: RiskMultipleSources, Setting: "source", Line: line,
				Message: fmt.Sprintf("Gemfile declares more than one global source (%s, %s), so Bundler may install an internal gem name from the public source", global[0], global[1])})
		}
	}
	return out
}
