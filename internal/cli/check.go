package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/match"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/report"
	"github.com/omni-line/omni-audit/internal/scan"
	"github.com/omni-line/omni-audit/internal/version"
)

func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, showVersion, err := parseCheck(args, stderr)
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
	ecos := ecosystem.Default(prober)
	eco, ok := ecosystem.Lookup(ecos, cfg.ecosystem)
	if !ok {
		fmt.Fprintf(stderr, "error: invalid --ecosystem %q (want %s)\n", cfg.ecosystem, ecosystem.NameList(ecos))
		return report.ExitError
	}

	opts := scanOptions(cfg, prober)
	opts.Ecosystems = nil
	res, err := scan.Check(ctx, eco, cfg.names, opts)
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
		UnknownFails:   true,
	})
}

func parseCheck(args []string, stderr io.Writer) (cfg config, showVersion bool, err error) {
	fs := flag.NewFlagSet("omni-audit check", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		ecoName      = fs.String("ecosystem", "", "package ecosystem: npm|composer|pypi|go|cargo|rubygems|maven|conan|docker")
		format       = fs.String("format", "text", "output format: text|json|sarif")
		timeout      = fs.Duration("timeout", registry.DefaultTimeout, "per-request registry timeout")
		concurrency  = fs.Int("concurrency", scan.DefaultConcurrency, fmt.Sprintf("parallel registry checks (1-%d)", maxConcurrency))
		retries      = fs.Int("retries", registry.DefaultRetries, fmt.Sprintf("retries for transient registry errors (0-%d)", maxRetries))
		failOn       = fs.String("fail-on", "any", "when to exit 1: any|none")
		strict       = fs.Bool("strict", false, "exit 2 if any package could not be verified")
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
		agent        = fs.Bool("agent", false, "compact JSON for agents: no marketing, with decision, actions, id, and fingerprint")
		baseline     = fs.String("baseline", "", "hide findings whose fingerprint is in this JSON report or {\"fingerprints\":[...]}")
		safeNS       stringList
		ignore       stringList
		allow        stringList
		scopes       stringList
	)
	fs.Var(&safeNS, "safe-namespace", "glob of namespaces you own; matching packages are skipped (repeatable or comma-separated)")
	fs.Var(&ignore, "ignore", "package name globs to skip (repeatable or comma-separated)")
	fs.Var(&allow, "allow", "exact package names treated as safe for typosquat checks (repeatable or comma-separated)")
	fs.Var(&scopes, "scope", "namespace to peer-check for typosquats even with --no-scope-peers (e.g. @acme; repeatable)")
	fs.Usage = func() { checkUsage(fs, stderr) }

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

	if strings.TrimSpace(*ecoName) == "" {
		return cfg, false, errors.New("missing --ecosystem")
	}
	if len(positional) == 0 {
		return cfg, false, errors.New("missing package name")
	}

	cfg.ecosystem = strings.ToLower(strings.TrimSpace(*ecoName))
	cfg.names = positional
	cfg.check = true

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

func checkUsage(fs *flag.FlagSet, w io.Writer) {
	fmt.Fprint(w, `Usage: omni-audit check --ecosystem <name> <package> [package...] [flags]

Look up proposed package names before adding them. No project tree is walked.
Each name is compared offline to the popular-package corpus and checked on
the public registry. Pass the package name, not a version spec (lodash, not
lodash@4).

  omni-audit check --ecosystem npm --agent crossenv
  omni-audit check --ecosystem pypi requests urllib3

Exit codes:
  0  allow — claimed names, no typosquat at or above --min-severity
  1  block — unclaimed name or typosquat
  2  unknown or usage error — the registry lookup failed, or the arguments are invalid

A failed lookup is never reported as a clean name. --fail-on none still exits
2 when the lookup fails.

Flags:
`)
	fs.PrintDefaults()
}
