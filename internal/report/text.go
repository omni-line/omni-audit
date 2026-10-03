package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/omni-line/omni-audit/internal/scan"
)

// maxWarnings is how many warnings are printed without --verbose.
const maxWarnings = 10

func writeText(stdout, stderr io.Writer, res *scan.Result, opts Options) {
	c := NewPalette(opts.Color, opts.StdoutIsTTY)
	ec := NewPalette(opts.Color, opts.StderrIsTTY)
	showMarketing := shouldShowMarketing(opts)
	mw, mTTY := marketingWriter(stdout, stderr, opts)
	mc := NewPalette(opts.Color, mTTY)

	if showMarketing {
		fmt.Fprintln(mw, mc.BoldCyan(HeaderLine(opts.Version)))
		fmt.Fprintln(mw, mc.Dim(HeaderSubtitle()))
		fmt.Fprintln(mw)
	}

	unclaimed, shadow := splitFindings(res.Findings)
	if len(res.Findings) > 0 {
		if !opts.Quiet {
			writeFindingHeadlines(stdout, c, unclaimed, shadow)
			fmt.Fprintln(stdout)
		}
		writeFindingsTable(stdout, c, res.Findings, opts.Verbose)
		if !opts.Quiet {
			writeGuidance(stdout, c, unclaimed, shadow)
		}
	} else if !opts.Quiet {
		switch {
		case res.Stats.Manifests == 0 && res.Stats.Lockfiles == 0:
			fmt.Fprintln(stdout, c.BoldYellow("! No supported dependency manifests or lockfiles found."))
		case !res.Complete():
			fmt.Fprintln(stdout, c.BoldYellow("! No findings, but the scan is incomplete (see warnings)."))
		default:
			fmt.Fprintln(stdout, c.BoldGreen("✓ No unclaimed names or unexpected package sources found."))
		}
	}

	if opts.Quiet {
		return
	}

	writeWarnings(stderr, ec, res.Warnings, opts.Verbose)

	fmt.Fprintln(stdout)
	summary := summaryLine(res.Stats)
	if res.Stats.Findings > 0 {
		fmt.Fprintln(stdout, c.BoldYellow(summary))
	} else {
		fmt.Fprintln(stdout, c.Dim(summary))
	}

	if showMarketing {
		fmt.Fprintln(mw)
		fmt.Fprintln(mw, colorFooter(mc, len(unclaimed), len(shadow)))
	}
}

func writeFindingHeadlines(w io.Writer, c Palette, unclaimed, shadow []scan.Finding) {
	if len(unclaimed) > 0 {
		fmt.Fprintln(w, c.BoldRed(fmt.Sprintf("✗ %s found", plural(len(unclaimed), "unclaimed package name", "unclaimed package names"))))
	}
	if len(shadow) > 0 {
		fmt.Fprintln(w, c.BoldRed(fmt.Sprintf("✗ Audit failed: %s resolving outside your expected registry proxy",
			plural(len(shadow), "dependency", "dependencies"))))
	}
}

type column struct {
	header string
	style  func(string) string
}

func writeFindingsTable(w io.Writer, c Palette, findings []scan.Finding, verbose bool) {
	cols := []column{
		{"SEVERITY", severityStyle(c)},
		{"ECOSYSTEM", c.Yellow},
		{"PACKAGE", c.Bold},
		{"VERSION", c.Dim},
		{"LOCATION", c.Cyan},
		{"SECTION", c.Dim},
		{"REASON", c.Dim},
	}
	rows := make([][]string, len(findings))
	for i, f := range findings {
		version := f.Version
		if version == "" {
			version = "-"
		}
		loc := f.Manifest
		if f.Line > 0 {
			loc += ":" + strconv.Itoa(f.Line)
		}
		sev := f.Severity
		if sev == "" {
			sev = scan.SeverityHigh
		}
		reason := f.Reason
		if reason == "" {
			reason = "-"
		}
		section := f.Group
		if f.Reason == scan.ReasonShadowRegistry && f.Registry != "" {
			section = f.Registry
		}
		rows[i] = []string{clean(sev), clean(f.Ecosystem), clean(f.Package), clean(version), clean(loc), clean(section), clean(reason)}
	}

	widths := make([]int, len(cols))
	for i, col := range cols {
		widths[i] = utf8.RuneCountInString(col.header)
	}
	for _, row := range rows {
		for i, cell := range row {
			if n := utf8.RuneCountInString(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}

	line := func(cells []string, style func(i int, s string) string) string {
		var b strings.Builder
		b.WriteString("  ")
		for i, cell := range cells {
			if i > 0 {
				b.WriteString("  ")
			}
			pad := ""
			if i < len(cells)-1 {
				pad = strings.Repeat(" ", widths[i]-utf8.RuneCountInString(cell))
			}
			b.WriteString(style(i, cell))
			b.WriteString(pad)
		}
		return strings.TrimRight(b.String(), " ")
	}

	headers := make([]string, len(cols))
	for i, col := range cols {
		headers[i] = col.header
	}
	fmt.Fprintln(w, line(headers, func(_ int, s string) string { return c.Dim(s) }))
	for i, row := range rows {
		fmt.Fprintln(w, line(row, func(i int, s string) string { return cols[i].style(s) }))
		if verbose {
			u := findings[i].URL
			if findings[i].ResolvedURL != "" {
				u = findings[i].ResolvedURL
			}
			if u != "" {
				fmt.Fprintf(w, "  %s %s\n", c.Dim("↳"), c.Dim(clean(u)))
			}
		}
	}
}

func writeGuidance(w io.Writer, c Palette, unclaimed, shadow []scan.Finding) {
	if len(unclaimed) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Anyone can publish these names on the public registry. If a build resolves")
		fmt.Fprintln(w, "them there instead of your private source, it installs the publisher's code.")
	}
	if len(shadow) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "These installs bypass your internal registry proxy and its security controls.")
		fmt.Fprintln(w, "Lockfiles that embed public registry URLs pull directly from the internet.")
	}

	type advice struct{ eco, text string }
	var tips []advice
	seen := map[string]bool{}
	width := 0
	add := func(eco, text string) {
		key := eco + "\x00" + text
		if text == "" || seen[key] {
			return
		}
		seen[key] = true
		tips = append(tips, advice{clean(eco), text})
		if n := utf8.RuneCountInString(eco); n > width {
			width = n
		}
	}
	for _, f := range unclaimed {
		add(f.Ecosystem, f.Remediation)
	}
	if len(shadow) > 0 {
		add("sources", scan.RemediationShadow)
	}
	if len(tips) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.Bold("How to fix"))
	for _, t := range tips {
		fmt.Fprintf(w, "  %s  %s\n", c.Yellow(t.eco+strings.Repeat(" ", width-utf8.RuneCountInString(t.eco))), t.text)
	}
}

func writeWarnings(w io.Writer, c Palette, warnings []scan.Warning, verbose bool) {
	if len(warnings) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.BoldYellow(fmt.Sprintf("Warnings (%d) — results may be incomplete", len(warnings))))
	shown := warnings
	if !verbose && len(shown) > maxWarnings {
		shown = shown[:maxWarnings]
	}
	for _, wn := range shown {
		subject := clean(wn.Manifest)
		if wn.Package != "" {
			subject = fmt.Sprintf("%s %s (%s)", clean(wn.Ecosystem), clean(wn.Package), clean(wn.Manifest))
		}
		kind := wn.Kind
		if kind == "" {
			kind = "warn"
		}
		fmt.Fprintf(w, "  %s %s: %s\n", c.Yellow(kind), subject, clean(wn.Message))
	}
	if hidden := len(warnings) - len(shown); hidden > 0 {
		fmt.Fprintf(w, "  %s\n", c.Dim(fmt.Sprintf("… and %d more (use -v to show all)", hidden)))
	}
}

func summaryLine(s scan.Stats) string {
	packages := plural(s.Packages, "package", "packages")
	if s.UniquePackages > 0 && s.UniquePackages != s.Packages {
		packages += fmt.Sprintf(" (%d unique)", s.UniquePackages)
	}
	parts := []string{
		"Scanned " + plural(s.Manifests, "manifest", "manifests"),
	}
	if s.Lockfiles > 0 || s.ResolvedPackages > 0 {
		parts[0] += " · " + plural(s.Lockfiles, "lockfile", "lockfiles")
	}
	parts = append(parts,
		packages,
		plural(s.Findings, "finding", "findings"),
		fmt.Sprintf("%d skipped", s.Skipped),
		plural(s.Errors, "error", "errors"),
	)
	if s.ResolvedPackages > 0 {
		parts = []string{
			parts[0],
			packages,
			plural(s.ResolvedPackages, "resolved dep", "resolved deps"),
			plural(s.Findings, "finding", "findings"),
			fmt.Sprintf("%d skipped", s.Skipped),
			plural(s.Errors, "error", "errors"),
		}
	}
	line := strings.Join(parts, " · ")
	if s.DurationMS > 0 {
		line += " in " + formatDuration(time.Duration(s.DurationMS)*time.Millisecond)
	}
	return line
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func severityStyle(c Palette) func(string) string {
	return func(s string) string {
		switch s {
		case scan.SeverityCritical:
			return c.BoldRed(s)
		case scan.SeverityHigh:
			return c.BoldYellow(s)
		default:
			return c.Dim(s)
		}
	}
}

func splitFindings(findings []scan.Finding) (unclaimed, shadow []scan.Finding) {
	for _, f := range findings {
		switch f.Reason {
		case scan.ReasonShadowRegistry:
			shadow = append(shadow, f)
		default:
			unclaimed = append(unclaimed, f)
		}
	}
	return unclaimed, shadow
}

func colorFooter(c Palette, unclaimed, shadow int) string {
	plain := FooterText(unclaimed, shadow)
	if !c.Enabled() {
		return plain
	}
	lines := strings.Split(plain, "\n")
	out := make([]string, 0, len(lines))
	findingCount := unclaimed + shadow
	for i, line := range lines {
		switch {
		case i == 0 && strings.HasPrefix(line, "───"):
			out = append(out, c.Dim(line))
		case strings.Contains(line, "https://"):
			out = append(out, c.BoldCyan(line))
		case i == 1 && findingCount > 0:
			out = append(out, c.BoldYellow(line))
		case i == 1:
			out = append(out, c.Green(line))
		default:
			out = append(out, c.Dim(line))
		}
	}
	return strings.Join(out, "\n")
}
