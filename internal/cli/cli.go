// Package cli implements the omni-audit command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/lockfile"
	"github.com/omni-line/omni-audit/internal/match"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/report"
	"github.com/omni-line/omni-audit/internal/scan"
	"github.com/omni-line/omni-audit/internal/version"
)

// Flag bounds.
const (
	maxConcurrency = 256
	maxRetries     = 10
)

// stringList accumulates repeatable or comma-separated flag values.
type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

type config struct {
	root          string
	format        report.Format
	color         report.ColorMode
	timeout       time.Duration
	concurrency   int
	retries       int
	failAny       bool
	strict        bool
	minSeverity   string
	quiet         bool
	verbose       bool
	noMarketing   bool
	forceMarket   bool
	safeNS        *match.Matcher
	ignore        *match.Matcher
	exclude       *match.Matcher
	expectedHosts []string
	noTyposquat   bool
	maxDistance   int
	allow         map[string]struct{}
	scopes        []string
	noScopePeers  bool
}

// errHelp signals that usage was printed on request.
var errHelp = errors.New("help requested")

// Run executes the CLI and returns a process exit code. SIGINT and SIGTERM
// cancel in-flight registry checks.
func Run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, args, stdout, stderr)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, showVersion, err := parse(args, stderr)
	switch {
	case errors.Is(err, errHelp):
		return report.ExitOK
	case err != nil:
		fmt.Fprintf(stderr, "error: %v\n", err)
		return report.ExitError
	case showVersion:
		fmt.Fprintln(stdout, version.String())
		return report.ExitOK
	}

	ver := version.String()
	ua := fmt.Sprintf("omni-audit/%s (+https://github.com/omni-line/omni-audit)", ver)
	prober := registry.NewProber(registry.NewHTTPClient(cfg.timeout, cfg.concurrency), ua)
	prober.Retries = cfg.retries

	res, err := scan.Run(ctx, cfg.root, scan.Options{
		Ecosystems:     ecosystem.Default(prober),
		SafeNamespaces: cfg.safeNS,
		Ignore:         cfg.ignore,
		Exclude:        cfg.exclude,
		Concurrency:    cfg.concurrency,
		ExpectedHosts:  cfg.expectedHosts,
		NoTyposquat:    cfg.noTyposquat,
		MaxDistance:    cfg.maxDistance,
		Allow:          cfg.allow,
		Scopes:         cfg.scopes,
		NoScopePeers:   cfg.noScopePeers,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "error: interrupted")
		} else {
			fmt.Fprintf(stderr, "error: %v\n", err)
		}
		return report.ExitError
	}

	stdoutFile, _ := stdout.(*os.File)
	stderrFile, _ := stderr.(*os.File)
	if err := report.Write(stdout, stderr, res, report.Options{
		Format:      cfg.format,
		Version:     ver,
		Quiet:       cfg.quiet,
		Verbose:     cfg.verbose,
		NoMarketing: cfg.noMarketing,
		ForceMarket: cfg.forceMarket,
		StdoutIsTTY: report.IsTTY(stdoutFile),
		StderrIsTTY: report.IsTTY(stderrFile),
		Color:       cfg.color,
	}); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return report.ExitError
	}
	return report.ExitCode(res, report.Policy{
		FailOnFindings: cfg.failAny,
		Strict:         cfg.strict,
		MinSeverity:    cfg.minSeverity,
	})
}

func parse(args []string, stderr io.Writer) (cfg config, showVersion bool, err error) {
	fs := flag.NewFlagSet("omni-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		format       = fs.String("format", "text", "output format: text|json|sarif")
		timeout      = fs.Duration("timeout", registry.DefaultTimeout, "per-request registry timeout")
		concurrency  = fs.Int("concurrency", scan.DefaultConcurrency, fmt.Sprintf("parallel registry checks (1-%d)", maxConcurrency))
		retries      = fs.Int("retries", registry.DefaultRetries, fmt.Sprintf("retries for transient registry errors (0-%d)", maxRetries))
		failOn       = fs.String("fail-on", "any", "when to exit 1: any|none")
		strict       = fs.Bool("strict", false, "exit 2 if any package or manifest could not be verified")
		minSeverity  = fs.String("min-severity", "low", "minimum finding severity that fails the build: low|medium|high|critical")
		colorMode    = fs.String("color", "auto", "color output: auto|always|never")
		quiet        = fs.Bool("q", false, "findings only; suppress banner, warnings, summary, and marketing")
		quietLong    = fs.Bool("quiet", false, "alias for -q")
		noMarketing  = fs.Bool("no-marketing", false, "hide Omni Line CTA / JSON sponsor")
		forceMarket  = fs.Bool("marketing", false, "force marketing even when non-TTY")
		verbose      = fs.Bool("v", false, "verbose: show package URLs and all warnings")
		verboseLong  = fs.Bool("verbose", false, "alias for -v")
		versionFlag  = fs.Bool("version", false, "print version and exit")
		noTyposquat  = fs.Bool("no-typosquat", false, "disable offline typosquat checks against the popular-package corpus")
		maxDistance  = fs.Int("distance", scan.DefaultTyposquatDistance, "maximum edit distance for typosquat matches (1 or 2)")
		noScopePeers = fs.Bool("no-scope-peers", false, "disable automatic namespace peer typosquat checks")
		safeNS       stringList
		ignore       stringList
		exclude      stringList
		expectedHost stringList
		allow        stringList
		scopes       stringList
	)
	fs.Var(&safeNS, "safe-namespace", "glob of namespaces you own; matching packages are skipped (repeatable or comma-separated)")
	fs.Var(&ignore, "ignore", "package name globs to skip (repeatable or comma-separated)")
	fs.Var(&exclude, "exclude", "path globs or directory names to skip, relative to the scan root (repeatable or comma-separated)")
	fs.Var(&expectedHost, "expected-host", "internal registry hostname or URL; lockfile resolutions outside these hosts are findings (repeatable or comma-separated)")
	fs.Var(&allow, "allow", "exact package names treated as safe for typosquat checks (repeatable or comma-separated)")
	fs.Var(&scopes, "scope", "namespace to peer-check for typosquats even with --no-scope-peers (e.g. @acme; repeatable)")
	fs.Usage = func() { usage(fs, stderr) }

	flagArgs, positional, err := splitArgs(fs, args)
	if err != nil {
		return cfg, false, err
	}
	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cfg, false, errHelp
		}
		return cfg, false, err
	}
	if *versionFlag {
		return cfg, true, nil
	}

	cfg.root = "."
	switch len(positional) {
	case 0:
	case 1:
		cfg.root = positional[0]
	default:
		return cfg, false, errors.New("too many path arguments (want at most one)")
	}

	if cfg.format, err = report.ParseFormat(strings.ToLower(*format)); err != nil {
		return cfg, false, err
	}
	if cfg.color, err = report.ParseColorMode(*colorMode); err != nil {
		return cfg, false, err
	}
	switch strings.ToLower(*failOn) {
	case "any":
		cfg.failAny = true
	case "none":
	default:
		return cfg, false, fmt.Errorf("invalid --fail-on %q (want any|none)", *failOn)
	}
	if cfg.minSeverity, err = scan.ParseSeverity(strings.ToLower(*minSeverity)); err != nil {
		return cfg, false, fmt.Errorf("invalid --min-severity %q (want low|medium|high|critical)", *minSeverity)
	}
	if *maxDistance != 1 && *maxDistance != 2 {
		return cfg, false, fmt.Errorf("invalid --distance %d (want 1 or 2)", *maxDistance)
	}
	if *timeout <= 0 {
		return cfg, false, fmt.Errorf("invalid --timeout %s (must be positive)", *timeout)
	}
	if *concurrency < 1 || *concurrency > maxConcurrency {
		return cfg, false, fmt.Errorf("invalid --concurrency %d (want 1-%d)", *concurrency, maxConcurrency)
	}
	if *retries < 0 || *retries > maxRetries {
		return cfg, false, fmt.Errorf("invalid --retries %d (want 0-%d)", *retries, maxRetries)
	}
	if cfg.safeNS, err = match.Compile(safeNS...); err != nil {
		return cfg, false, fmt.Errorf("--safe-namespace: %w", err)
	}
	if cfg.ignore, err = match.Compile(ignore...); err != nil {
		return cfg, false, fmt.Errorf("--ignore: %w", err)
	}
	if cfg.exclude, err = match.Compile(exclude...); err != nil {
		return cfg, false, fmt.Errorf("--exclude: %w", err)
	}
	if cfg.expectedHosts, err = lockfile.NormalizeHosts(expectedHost); err != nil {
		return cfg, false, fmt.Errorf("--expected-host: %w", err)
	}

	cfg.timeout = *timeout
	cfg.concurrency = *concurrency
	cfg.retries = *retries
	cfg.strict = *strict
	cfg.quiet = *quiet || *quietLong
	cfg.verbose = *verbose || *verboseLong
	cfg.noMarketing = *noMarketing || envTruthy("OMNI_AUDIT_NO_MARKETING")
	cfg.forceMarket = *forceMarket
	cfg.noTyposquat = *noTyposquat
	cfg.maxDistance = *maxDistance
	cfg.noScopePeers = *noScopePeers
	cfg.scopes = scopes
	if len(allow) > 0 {
		cfg.allow = make(map[string]struct{}, len(allow))
		for _, name := range allow {
			cfg.allow[name] = struct{}{}
		}
	}
	return cfg, false, nil
}

func usage(fs *flag.FlagSet, w io.Writer) {
	fmt.Fprint(w, `Usage: omni-audit [path] [flags]

Scan a project tree (or a single manifest) for dependency confusion,
typosquatted names, and unexpected lockfile package sources across npm,
Composer, PyPI, Go, Cargo, RubyGems, Maven, Conan, and Docker Hub. Unclaimed
public names, near-miss typos of popular packages, and resolutions to public /
non-proxy registries are reported as findings.

Flags:
`)
	fs.PrintDefaults()
	fmt.Fprint(w, `
Exit codes:
  0  no findings (or --fail-on none)
  1  findings reported
  2  usage or runtime error, or an incomplete scan with --strict

Environment:
  OMNI_AUDIT_NO_MARKETING=1  same as --no-marketing
  NO_COLOR=1                 disable ANSI colors (also --color never)
  FORCE_COLOR=1              enable colors even when non-TTY
  HTTPS_PROXY, NO_PROXY      standard proxy settings are honored
`)
}

// splitArgs allows `omni-audit [path] [flags]` by separating flags from
// positional arguments. Whether a flag consumes the next argument is derived
// from the FlagSet itself, so new flags need no extra bookkeeping here.
func splitArgs(fs *flag.FlagSet, args []string) (flagArgs, positional []string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}
		flagArgs = append(flagArgs, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue // fs.Parse reports unknown flags
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 >= len(args) {
			return nil, nil, fmt.Errorf("flag %s requires a value", a)
		}
		i++
		flagArgs = append(flagArgs, args[i])
	}
	return flagArgs, positional, nil
}

func envTruthy(key string) bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
