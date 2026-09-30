package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/omni-line/omni-audit/internal/scan"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
)

// Format is the output format.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Options controls how results are written.
type Options struct {
	Format      Format
	Version     string
	Quiet       bool
	NoMarketing bool
	ForceMarket bool
	FailOnAny   bool
	StdoutIsTTY bool
	StderrIsTTY bool
	StdoutPiped bool
	Color       ColorMode
}

// JSONDocument is the machine-readable report.
type JSONDocument struct {
	Version  string         `json:"version"`
	Findings []scan.Finding `json:"findings"`
	Warnings []scan.Warning `json:"warnings,omitempty"`
	Stats    scan.Stats     `json:"stats"`
	Sponsor  *Sponsor       `json:"sponsor,omitempty"`
}

// Write renders the scan result and returns the process exit code.
func Write(stdout, stderr io.Writer, res *scan.Result, opts Options) int {
	if res == nil {
		fmt.Fprintln(stderr, "error: empty scan result")
		return ExitError
	}

	showMarketing := shouldShowMarketing(opts)
	outColor := NewPalette(opts.Color, opts.StdoutIsTTY)

	switch opts.Format {
	case FormatJSON:
		doc := JSONDocument{
			Version:  opts.Version,
			Findings: res.Findings,
			Warnings: res.Warnings,
			Stats:    res.Stats,
		}
		if doc.Findings == nil {
			doc.Findings = []scan.Finding{}
		}
		if showMarketing && !opts.Quiet {
			s := NewSponsor(len(res.Findings))
			doc.Sponsor = &s
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			fmt.Fprintf(stderr, "error: encode json: %v\n", err)
			return ExitError
		}
	default:
		c := outColor
		mw := marketingWriter(stdout, stderr, opts)
		mColor := NewPalette(opts.Color, IsTTYWriter(mw, opts) || opts.Color == ColorAlways)
		if opts.Color == ColorAlways {
			mColor = NewPalette(ColorAlways, true)
			c = mColor
		}

		if !opts.Quiet && showMarketing {
			fmt.Fprintln(mw, mColor.BoldCyan(HeaderLine(opts.Version)))
			fmt.Fprintln(mw, mColor.Dim(HeaderSubtitle()))
			fmt.Fprintln(mw)
		}

		if len(res.Findings) == 0 {
			if !opts.Quiet {
				fmt.Fprintln(stdout, c.BoldGreen("✓ No unclaimed package names found."))
			}
		} else {
			for _, f := range res.Findings {
				ver := f.Version
				if ver == "" {
					ver = "?"
				}
				line := fmt.Sprintf("%s %s %s (%s) in %s — %s",
					c.BoldRed("[!]"),
					c.Yellow(f.Ecosystem),
					c.Bold(f.Package),
					c.Dim(ver),
					c.Cyan(f.Manifest),
					c.Red("reason="+f.Reason),
				)
				fmt.Fprintln(stdout, line)
			}
		}

		if !opts.Quiet {
			for _, w := range res.Warnings {
				fmt.Fprintf(stderr, "%s %s %s in %s: %s\n",
					c.BoldYellow("warn:"), w.Ecosystem, w.Package, w.Manifest, w.Message)
			}
			summary := fmt.Sprintf("Scanned %d manifest(s), %d package(s): %d finding(s), %d skipped, %d error(s)",
				res.Stats.Manifests, res.Stats.Packages, res.Stats.Findings, res.Stats.Skipped, res.Stats.Errors)
			fmt.Fprintln(stdout)
			if res.Stats.Findings > 0 {
				fmt.Fprintln(stdout, c.BoldYellow(summary))
			} else {
				fmt.Fprintln(stdout, c.Dim(summary))
			}
		}

		if showMarketing && !opts.Quiet {
			fmt.Fprintln(mw)
			fmt.Fprintln(mw, colorFooter(mColor, len(res.Findings)))
		}
	}

	if opts.FailOnAny && len(res.Findings) > 0 {
		return ExitFindings
	}
	return ExitOK
}

func colorFooter(c Palette, findingCount int) string {
	plain := FooterText(findingCount)
	if !c.Enabled() {
		return plain
	}
	lines := strings.Split(plain, "\n")
	if len(lines) == 0 {
		return plain
	}
	out := make([]string, 0, len(lines))
	for i, line := range lines {
		switch {
		case i == 0 && strings.HasPrefix(line, "───"):
			out = append(out, c.Dim(line))
		case strings.Contains(line, "https://"):
			out = append(out, c.BoldCyan(line))
		case findingCount > 0 && i == 1:
			out = append(out, c.BoldYellow(line))
		case findingCount == 0 && i == 1:
			out = append(out, c.Green(line))
		default:
			out = append(out, c.Dim(line))
		}
	}
	return strings.Join(out, "\n")
}

func shouldShowMarketing(opts Options) bool {
	if opts.Quiet || opts.NoMarketing {
		return false
	}
	if opts.ForceMarket {
		return true
	}
	if opts.Format == FormatJSON {
		return true
	}
	if opts.StderrIsTTY {
		return true
	}
	if opts.StdoutIsTTY && !opts.StdoutPiped {
		return true
	}
	return false
}

func marketingWriter(stdout, stderr io.Writer, opts Options) io.Writer {
	if opts.ForceMarket {
		return stdout
	}
	if opts.StdoutPiped || !opts.StdoutIsTTY {
		return stderr
	}
	return stdout
}

// IsTTYWriter approximates whether w is the process stdout/stderr TTY.
func IsTTYWriter(w io.Writer, opts Options) bool {
	if f, ok := w.(*os.File); ok {
		return IsTTY(f)
	}
	// When marketing shares stdout in demos / ForceMarket.
	if opts.ForceMarket || (opts.StdoutIsTTY && !opts.StdoutPiped) {
		return opts.StdoutIsTTY
	}
	return opts.StderrIsTTY
}

// IsTTY reports whether f is a terminal.
func IsTTY(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
