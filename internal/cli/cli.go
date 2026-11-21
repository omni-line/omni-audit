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
	noUnclaimed   bool
	noSources     bool
	noTyposquat   bool
	noMalicious   bool
	noConfig      bool
	noInstallHook bool
	installed     bool
	maxDistance   int
	allow         map[string]struct{}
	scopes        []string
	noScopePeers  bool
	agent         bool
	compact       bool
	baseline      string
	check         bool
	ecosystem     string
	names         []string
}

// errHelp signals that usage was printed on request.
var errHelp = errors.New("help requested")

// Run executes the CLI and returns a process exit code. SIGINT and SIGTERM
// cancel in-flight registry checks. The first argument "check" selects name
// checks (`omni-audit check --ecosystem npm <package>`).
func Run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(args) > 0 && args[0] == "check" {
		return runCheck(ctx, args[1:], stdout, stderr)
	}
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
	prober := newProber(ver, cfg)
	res, err := scan.Run(ctx, cfg.root, scanOptions(cfg, prober))
	if err != nil {
		return fail(stderr, err)
	}
	if err := prepare(res, cfg); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return report.ExitError
	}
	if err := writeReport(stdout, stderr, res, ver, cfg); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return report.ExitError
	}
	return report.ExitCode(res, report.Policy{
		FailOnFindings: cfg.failAny,
		Strict:         cfg.strict,
		MinSeverity:    cfg.minSeverity,
	})
}

func newProber(ver string, cfg config) *registry.Prober {
	ua := fmt.Sprintf("omni-audit/%s (+https://github.com/omni-line/omni-audit)", ver)
	prober := registry.NewProber(registry.NewHTTPClient(cfg.timeout, cfg.concurrency), ua)
	prober.Retries = cfg.retries
	return prober
}

func scanOptions(cfg config, prober *registry.Prober) scan.Options {
	return scan.Options{
		Ecosystems:     ecosystem.Default(prober),
		SafeNamespaces: cfg.safeNS,
		Ignore:         cfg.ignore,
		Exclude:        cfg.exclude,
		Concurrency:    cfg.concurrency,
		ExpectedHosts:  cfg.expectedHosts,
		NoUnclaimed:    cfg.noUnclaimed,
		NoSources:      cfg.noSources,
		NoTyposquat:    cfg.noTyposquat,
		NoMalicious:    cfg.noMalicious,
		NoConfig:       cfg.noConfig,
		NoInstallHook:  cfg.noInstallHook,
		Installed:      cfg.installed,
		MaxDistance:    cfg.maxDistance,
		Allow:          cfg.allow,
		Scopes:         cfg.scopes,
		NoScopePeers:   cfg.noScopePeers,
	}
}

func prepare(res *scan.Result, cfg config) error {
	if cfg.baseline != "" {
		set, err := scan.LoadBaseline(cfg.baseline)
		if err != nil {
			return err
		}
		scan.ApplyBaseline(res, set)
	}
	if cfg.agent || cfg.check {
		res.Decision = scan.Decide(res, cfg.minSeverity)
	}
	return nil
}

func writeReport(stdout, stderr io.Writer, res *scan.Result, ver string, cfg config) error {
	stdoutFile, _ := stdout.(*os.File)
	stderrFile, _ := stderr.(*os.File)
	return report.Write(stdout, stderr, res, report.Options{
		Format:      cfg.format,
		Version:     ver,
		Quiet:       cfg.quiet,
		Verbose:     cfg.verbose,
		NoMarketing: cfg.noMarketing,
		ForceMarket: cfg.forceMarket,
		StdoutIsTTY: report.IsTTY(stdoutFile),
		StderrIsTTY: report.IsTTY(stderrFile),
		Color:       cfg.color,
		Compact:     cfg.compact,
	})
}

func fail(stderr io.Writer, err error) int {
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "error: interrupted")
	} else {
		fmt.Fprintf(stderr, "error: %v\n", err)
	}
	return report.ExitError
}

func parse(args []string, stderr io.Writer) (cfg config, showVersion bool, err error) {
	fs := flag.NewFlagSet("omni-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		format        = fs.String("format", "text", "output format: text|json|sarif")
		timeout       = fs.Duration("timeout", registry.DefaultTimeout, "per-request registry timeout")
		concurrency   = fs.Int("concurrency", scan.DefaultConcurrency, fmt.Sprintf("parallel registry checks (1-%d)", maxConcurrency))
		retries       = fs.Int("retries", registry.DefaultRetries, fmt.Sprintf("retries for transient registry errors (0-%d)", maxRetries))
		failOn        = fs.String("fail-on", "any", "when to exit 1: any|none")
		strict        = fs.Bool("strict", false, "exit 2 if any package or manifest could not be verified")
		minSeverity   = fs.String("min-severity", "low", "minimum finding severity that fails the build: low|medium|high|critical")
		colorMode     = fs.String("color", "auto", "color output: auto|always|never")
		quiet         = fs.Bool("q", false, "findings only; suppress banner, warnings, summary, and marketing")
		quietLong     = fs.Bool("quiet", false, "alias for -q")
		noMarketing   = fs.Bool("no-marketing", false, "hide Omni Line CTA / JSON sponsor")
		forceMarket   = fs.Bool("marketing", false, "force marketing even when non-TTY")
		verbose       = fs.Bool("v", false, "verbose: show package URLs and all warnings")
		verboseLong   = fs.Bool("verbose", false, "alias for -v")
		versionFlag   = fs.Bool("version", false, "print version and exit")
		noUnclaimed   = fs.Bool("no-unclaimed", false, "disable the public-registry checks for unclaimed names (the only check that uses the network)")
		noSources     = fs.Bool("no-sources", false, "disable the lockfile audit for resolutions outside the expected registry hosts")
		noTyposquat   = fs.Bool("no-typosquat", false, "disable offline typosquat checks against the popular-package corpus")
		noMalicious   = fs.Bool("no-malicious", false, "disable the offline known-malicious-package check (OpenSSF MAL- advisories)")
		noConfig      = fs.Bool("no-registry-config", false, "disable the offline audit of package-manager config files (.npmrc, pip.conf, composer.json, Gemfile, …)")
		noInstallHook = fs.Bool("no-install-hook", false, "disable the offline install-hook audit (lifecycle scripts, setup.py, .pth, and, with --installed, lockfile drift)")
		installed     = fs.Bool("installed", false, "also scan installed trees (node_modules, virtualenvs) for install hooks and npm lockfile drift")
		maxDistance   = fs.Int("distance", scan.DefaultTyposquatDistance, "maximum edit distance for typosquat matches (1 or 2)")
		noScopePeers  = fs.Bool("no-scope-peers", false, "disable automatic namespace peer typosquat checks")
		agent         = fs.Bool("agent", false, "compact JSON for agents: no marketing, with decision, actions, id, and fingerprint")
		baseline      = fs.String("baseline", "", "hide findings whose fingerprint is in this JSON report or {\"fingerprints\":[...]}")
		safeNS        stringList
		ignore        stringList
		exclude       stringList
		expectedHost  stringList
		allow         stringList
		scopes        stringList
		only          stringList
	)
	fs.Var(&safeNS, "safe-namespace", "glob of namespaces you own; matching packages are skipped (repeatable or comma-separated)")
	fs.Var(&ignore, "ignore", "package name globs to skip (repeatable or comma-separated)")
	fs.Var(&exclude, "exclude", "path globs or directory names to skip, relative to the scan root (repeatable or comma-separated)")
	fs.Var(&expectedHost, "expected-host", "internal registry hostname or URL; lockfile resolutions outside these hosts are findings (repeatable or comma-separated)")
	fs.Var(&allow, "allow", "exact package names treated as safe for typosquat checks (repeatable or comma-separated)")
	fs.Var(&only, "only", "run only these checks: "+strings.Join(checkNames, ",")+" (repeatable or comma-separated)")
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
	cfg.noUnclaimed = *noUnclaimed
	cfg.noSources = *noSources
	cfg.noTyposquat = *noTyposquat
	cfg.noMalicious = *noMalicious
	cfg.noConfig = *noConfig
	cfg.noInstallHook = *noInstallHook
	cfg.installed = *installed
	if len(only) > 0 {
		if cfg.noUnclaimed || cfg.noSources || cfg.noTyposquat || cfg.noMalicious || cfg.noConfig || cfg.noInstallHook {
			return cfg, false, errors.New("--only cannot be combined with --no-unclaimed, --no-sources, --no-typosquat, --no-malicious, --no-registry-config, or --no-install-hook")
		}
		if err := cfg.applyOnly(only); err != nil {
			return cfg, false, err
		}
	}
	cfg.maxDistance = *maxDistance
	cfg.noScopePeers = *noScopePeers
	cfg.scopes = scopes
	cfg.baseline = strings.TrimSpace(*baseline)
	if len(allow) > 0 {
		cfg.allow = make(map[string]struct{}, len(allow))
		for _, name := range allow {
			cfg.allow[name] = struct{}{}
		}
	}
	if err := applyAgent(fs, &cfg, *agent); err != nil {
		return cfg, false, err
	}
	return cfg, false, nil
}

func applyAgent(fs *flag.FlagSet, cfg *config, agent bool) error {
	if !agent {
		return nil
	}
	formatSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "format" {
			formatSet = true
		}
	})
	if formatSet && cfg.format != report.FormatJSON {
		return errors.New("--agent writes JSON; do not combine it with another --format")
	}
	cfg.agent = true
	cfg.format = report.FormatJSON
	cfg.compact = true
	cfg.noMarketing = true
	cfg.forceMarket = false
	cfg.color = report.ColorNever
	return nil
}

func usage(fs *flag.FlagSet, w io.Writer) {
	fmt.Fprint(w, `Usage:
  omni-audit [path] [flags]
  omni-audit check --ecosystem <name> <package> [package...] [flags]

Scan a project tree (or a single manifest) for dependency confusion,
typosquatted names, known malicious packages, unexpected lockfile package
sources, risky registry settings, and install-time payloads across npm,
Composer, PyPI, Go, Cargo, RubyGems, Maven, Conan, and Docker Hub. Unclaimed
public names, near-miss typos of popular packages, packages published as
malware (OpenSSF MAL- advisories, checked offline), resolutions to public /
non-proxy registries, config that merges public and internal indexes, stores
credentials in plain text, or disables TLS, and install scripts that download
a payload, decode and execute code, or read credentials are reported as
findings. --installed also scans node_modules and virtualenvs.

check looks up proposed package names without walking a tree. Use it before
adding a dependency. --agent prints a compact JSON decision (allow, block, or
unknown) and a rename action when a typosquat is unambiguous.

Flags:
`)
	fs.PrintDefaults()
	fmt.Fprint(w, `
Exit codes:
  0  no findings (or --fail-on none)
  1  findings reported
  2  usage or runtime error, an incomplete scan with --strict, or a failed check lookup

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

// checkNames are the --only values: the finding reasons, one per check.
var checkNames = []string{scan.ReasonUnclaimed, scan.ReasonShadowRegistry, scan.ReasonTyposquat, scan.ReasonMalicious, scan.ReasonConfig, scan.ReasonInstallHook}

// applyOnly disables every check not named in only.
func (cfg *config) applyOnly(only []string) error {
	on := map[string]bool{}
	for _, name := range only {
		name = strings.ToLower(strings.TrimSpace(name))
		known := false
		for _, c := range checkNames {
			known = known || name == c
		}
		if !known {
			return fmt.Errorf("invalid --only %q (want %s)", name, strings.Join(checkNames, "|"))
		}
		on[name] = true
	}
	cfg.noUnclaimed = !on[scan.ReasonUnclaimed]
	cfg.noSources = !on[scan.ReasonShadowRegistry]
	cfg.noTyposquat = !on[scan.ReasonTyposquat]
	cfg.noMalicious = !on[scan.ReasonMalicious]
	cfg.noConfig = !on[scan.ReasonConfig]
	cfg.noInstallHook = !on[scan.ReasonInstallHook]
	return nil
}
