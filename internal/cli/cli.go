package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/omni-line/omni-audit/internal/match"
	regnpm "github.com/omni-line/omni-audit/internal/registry/npm"
	"github.com/omni-line/omni-audit/internal/registry/packagist"
	"github.com/omni-line/omni-audit/internal/report"
	"github.com/omni-line/omni-audit/internal/scan"
	"github.com/omni-line/omni-audit/internal/version"
)

// stringList accumulates repeatable or comma-separated flag values.
type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

// Run executes the CLI and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("omni-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		format      = fs.String("format", "text", "output format: text|json")
		timeout     = fs.Duration("timeout", 5*time.Second, "per-request registry timeout")
		concurrency = fs.Int("concurrency", 16, "parallel registry checks")
		failOn      = fs.String("fail-on", "any", "when to exit 1: any|none")
		colorMode   = fs.String("color", "auto", "color output: auto|always|never")
		quiet       = fs.Bool("q", false, "findings only; suppress banner and marketing")
		quietLong   = fs.Bool("quiet", false, "alias for -q")
		noMarketing = fs.Bool("no-marketing", false, "hide Omni Line CTA / JSON sponsor")
		forceMarket = fs.Bool("marketing", false, "force marketing even when non-TTY")
		verbose     = fs.Bool("v", false, "verbose warnings")
		verboseLong = fs.Bool("verbose", false, "alias for -v")
		showVersion = fs.Bool("version", false, "print version and exit")
		safeNS      stringList
		ignore      stringList
	)
	fs.Var(&safeNS, "safe-namespace", "glob of known-safe namespaces (repeatable or comma-separated)")
	fs.Var(&ignore, "ignore", "package name globs to skip (repeatable or comma-separated)")

	fs.Usage = func() {
		fmt.Fprintf(stderr, `Usage: omni-audit [path] [flags]

Scan a project tree for dependency confusion risks (NPM and Composer).
Unclaimed names on public registries are reported as findings.

`)
		fs.PrintDefaults()
		fmt.Fprintf(stderr, `
Exit codes:
  0  no findings (or fail-on=none)
  1  findings reported
  2  usage or runtime error

Environment:
  OMNI_AUDIT_NO_MARKETING=1  same as --no-marketing
  NO_COLOR=1                 disable ANSI colors (also --color never)
  FORCE_COLOR=1              enable colors even when non-TTY
`)
	}

	flagArgs, positional, err := splitArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return report.ExitError
	}

	if err := fs.Parse(flagArgs); err != nil {
		return report.ExitError
	}

	if *showVersion {
		fmt.Fprintln(stdout, version.Version)
		return report.ExitOK
	}

	root := "."
	if len(positional) > 1 {
		fmt.Fprintln(stderr, "error: too many path arguments")
		fs.Usage()
		return report.ExitError
	}
	if len(positional) == 1 {
		root = positional[0]
	}

	quietMode := *quiet || *quietLong
	_ = *verbose || *verboseLong

	noMkt := *noMarketing || envTruthy("OMNI_AUDIT_NO_MARKETING")
	failAny := true
	switch strings.ToLower(*failOn) {
	case "any":
		failAny = true
	case "none":
		failAny = false
	default:
		fmt.Fprintf(stderr, "error: invalid --fail-on %q (want any|none)\n", *failOn)
		return report.ExitError
	}

	fmtName := report.Format(strings.ToLower(*format))
	if fmtName != report.FormatText && fmtName != report.FormatJSON {
		fmt.Fprintf(stderr, "error: invalid --format %q (want text|json)\n", *format)
		return report.ExitError
	}

	color, err := report.ParseColorMode(*colorMode)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return report.ExitError
	}

	stdoutFile, _ := stdout.(*os.File)
	stderrFile, _ := stderr.(*os.File)
	stdoutTTY := report.IsTTY(stdoutFile)
	stderrTTY := report.IsTTY(stderrFile)

	ua := fmt.Sprintf("omni-audit/%s (+https://github.com/omni-line/omni-audit)", version.Version)
	httpClient := &http.Client{Timeout: *timeout}

	ctx := context.Background()
	res, err := scan.Run(ctx, root, scan.Options{
		SafeNamespaces: match.New(safeNS...),
		Ignore:         match.New(ignore...),
		Concurrency:    *concurrency,
		NPM:            regnpm.New(httpClient, ua),
		Composer:       packagist.New(httpClient, ua),
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return report.ExitError
	}

	return report.Write(stdout, stderr, res, report.Options{
		Format:      fmtName,
		Version:     version.Version,
		Quiet:       quietMode,
		NoMarketing: noMkt,
		ForceMarket: *forceMarket,
		FailOnAny:   failAny,
		StdoutIsTTY: stdoutTTY,
		StderrIsTTY: stderrTTY,
		StdoutPiped: !stdoutTTY,
		Color:       color,
	})
}

// splitArgs allows `omni-audit [path] [flags]` by separating flags from one path.
func splitArgs(args []string) (flagArgs, positional []string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			// Flags that take a separate value (not -x=y / --x=y / boolean-looking).
			if !strings.Contains(a, "=") && takesValue(a) {
				if i+1 >= len(args) {
					return nil, nil, fmt.Errorf("flag %s requires a value", a)
				}
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	return flagArgs, positional, nil
}

func takesValue(flagName string) bool {
	name := strings.TrimLeft(flagName, "-")
	switch name {
	case "format", "timeout", "concurrency", "fail-on",
		"safe-namespace", "ignore", "color":
		return true
	default:
		return false
	}
}

func envTruthy(key string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
