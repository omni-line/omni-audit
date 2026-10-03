// Package scan orchestrates discovery, parsing, and registry checks.
package scan

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/omni-line/omni-audit/internal/discover"
	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/lockfile"
	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/match"
	"github.com/omni-line/omni-audit/internal/registry"
)

// Finding reasons.
const (
	// ReasonUnclaimed marks a name that does not exist on the public registry.
	ReasonUnclaimed = "unclaimed"
	// ReasonShadowRegistry marks a lockfile resolution outside the expected proxy.
	ReasonShadowRegistry = "shadow_registry"
	// ReasonTyposquat marks a name that is a near-miss of a popular package.
	ReasonTyposquat = "typosquat"
)

// Finding severities. Additive JSON fields; default for unscoped names is high.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Namespace ownership statuses on findings.
const (
	NamespaceClaimed   = "claimed"
	NamespaceUnclaimed = "unclaimed"
	NamespaceUnknown   = "unknown"
)

// Warning kinds.
const (
	WarnWalk      = "walk"      // a path could not be walked or was skipped
	WarnManifest  = "manifest"  // a manifest could not be read or parsed
	WarnRegistry  = "registry"  // a registry check failed; result unknown
	WarnNamespace = "namespace" // a namespace ownership check failed
	WarnLockfile  = "lockfile"  // a lockfile could not be read or parsed
)

// RemediationShadow is the default guidance for unexpected lockfile sources.
const RemediationShadow = "Point the package manager at your internal registry proxy and regenerate the lockfile so resolved URLs use that host. Omni Line Virtual Registries expose one URL that routes internal and external packages correctly."

// DefaultConcurrency is used when Options.Concurrency is not positive.
const DefaultConcurrency = 16

// Finding is a reportable audit risk (unclaimed name, unexpected source, or typosquat).
//
// ecosystem, package, version, manifest, and reason are part of the stable
// JSON schema; other fields are additive.
type Finding struct {
	Ecosystem       string   `json:"ecosystem"`
	Package         string   `json:"package"`
	Version         string   `json:"version,omitempty"`
	Manifest        string   `json:"manifest"`
	Line            int      `json:"line,omitempty"`
	Group           string   `json:"group,omitempty"`
	Reason          string   `json:"reason"`
	Severity        string   `json:"severity,omitempty"`
	Namespace       string   `json:"namespace,omitempty"`
	NamespaceStatus string   `json:"namespace_status,omitempty"`
	Registry        string   `json:"registry,omitempty"`
	URL             string   `json:"url,omitempty"`
	ResolvedURL     string   `json:"resolved_url,omitempty"`
	Remediation     string   `json:"remediation,omitempty"`
	Kind            string   `json:"kind,omitempty"`
	Distance        int      `json:"distance,omitempty"`
	Suggestions     []string `json:"suggestions,omitempty"`
	TargetRank      int      `json:"target_rank,omitempty"`
	Technique       string   `json:"technique,omitempty"`
	SuggestionURL   string   `json:"suggestion_url,omitempty"`
	Message         string   `json:"message,omitempty"`
}

// Warning is a non-fatal issue that may leave the scan incomplete.
type Warning struct {
	Kind      string `json:"kind,omitempty"`
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Manifest  string `json:"manifest"`
	Message   string `json:"message"`
}

// Stats summarizes a scan.
type Stats struct {
	// Manifests is the number of manifests discovered.
	Manifests int `json:"manifests"`
	// Lockfiles is the number of lockfiles discovered for source auditing.
	Lockfiles int `json:"lockfiles"`
	// Packages counts dependency declarations across all manifests.
	Packages int `json:"packages"`
	// ResolvedPackages counts lockfile resolutions inspected for source policy.
	ResolvedPackages int `json:"resolved_packages"`
	// UniquePackages is the number of distinct names checked on registries.
	UniquePackages int `json:"unique_packages"`
	Findings       int `json:"findings"`
	// Skipped counts declarations matched by --ignore or --safe-namespace.
	Skipped int `json:"skipped"`
	// Errors counts warnings (unreadable paths, bad manifests, failed checks).
	Errors     int   `json:"errors"`
	DurationMS int64 `json:"duration_ms"`
}

// Result is the full scan outcome.
type Result struct {
	Findings []Finding `json:"findings"`
	Warnings []Warning `json:"warnings,omitempty"`
	Stats    Stats     `json:"stats"`
}

// Complete reports whether every discovered manifest and package was verified.
func (r *Result) Complete() bool {
	return len(r.Warnings) == 0
}

// Options configures Run.
type Options struct {
	Ecosystems     []ecosystem.Ecosystem
	SafeNamespaces *match.Matcher
	Ignore         *match.Matcher
	Exclude        *match.Matcher
	Concurrency    int
	// ExpectedHosts are optional internal registry hostnames. When set, any
	// lockfile resolution whose host is not in this list is a finding.
	// When empty, only known public registry hosts are flagged.
	ExpectedHosts []string
	// Lockfiles overrides the default lockfile kinds; nil means lockfile.Default().
	// An empty non-nil slice disables lockfile source auditing.
	Lockfiles []lockfile.Kind
	// NoTyposquat disables offline popular-package / scope-peer typosquat checks.
	NoTyposquat bool
	// MaxDistance is the maximum edit distance for typosquat matches (1 or 2).
	MaxDistance int
	// Allow lists exact package names treated as safe for typosquat checks.
	Allow map[string]struct{}
	// Scopes are namespaces (npm "@org") to peer-check in addition to those
	// discovered automatically.
	Scopes []string
	// NoScopePeers disables automatic namespace peer typosquat checks
	// (explicit Scopes still apply).
	NoScopePeers bool
}

type checkKey struct{ ecosystem, name string }

type check struct {
	eco      *ecosystem.Ecosystem
	name     string
	manifest string // first manifest that declared it, for warnings
	status   registry.Status
	err      error
}

type nsKey struct{ ecosystem, ns string }

type nsCheck struct {
	eco    *ecosystem.Ecosystem
	ns     string
	status registry.Status
	err    error
}

type occurrence struct {
	key      checkKey
	eco      *ecosystem.Ecosystem
	dep      manifest.Dependency
	manifest string
}

var errNotChecked = errors.New("not checked: scan was cancelled")

// SeverityRank orders severities for sorting and --min-severity gating.
// Higher is more severe. Unknown values rank 0.
func SeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ParseSeverity validates a --min-severity value.
func ParseSeverity(s string) (string, error) {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return s, nil
	default:
		return "", errors.New(`invalid severity (want low|medium|high|critical)`)
	}
}

// Run discovers manifests and lockfiles under root, checks each distinct
// package name once against its public registry, audits lockfile resolution
// URLs for unexpected / public registry hosts, and (by default) compares
// declared names to an embedded popular-package corpus for typosquats.
// On cancellation it returns the partial result together with ctx.Err().
func Run(ctx context.Context, root string, opts Options) (*Result, error) {
	start := time.Now()
	if err := ecosystem.ValidateAll(opts.Ecosystems); err != nil {
		return nil, err
	}
	byName := make(map[string]*ecosystem.Ecosystem, len(opts.Ecosystems))
	for i := range opts.Ecosystems {
		byName[opts.Ecosystems[i].Name] = &opts.Ecosystems[i]
	}

	walk, err := discover.Walk(root, discover.Options{
		Classify: func(rel string) string {
			for i := range opts.Ecosystems {
				if opts.Ecosystems[i].IsManifest(rel) {
					return opts.Ecosystems[i].Name
				}
			}
			return ""
		},
		Exclude: opts.Exclude,
	})
	if err != nil {
		return nil, err
	}

	res := &Result{Findings: []Finding{}}
	res.Stats.Manifests = len(walk.Manifests)
	for _, p := range walk.Problems {
		res.Warnings = append(res.Warnings, Warning{Kind: WarnWalk, Manifest: p.Path, Message: p.Err.Error()})
	}

	checks := make(map[checkKey]*check)
	var ordered []*check
	nsChecks := make(map[nsKey]*nsCheck)
	var nsOrdered []*nsCheck
	var occs []occurrence
	for _, m := range walk.Manifests {
		eco := byName[m.Ecosystem]
		deps, err := parse(eco, m)
		if err != nil {
			res.Warnings = append(res.Warnings, Warning{
				Kind: WarnManifest, Ecosystem: eco.Name, Manifest: m.Path, Message: err.Error(),
			})
			continue
		}
		for _, d := range deps {
			res.Stats.Packages++
			key := checkKey{eco.Name, eco.Key(d.Name)}
			if allowlisted(opts, d.Name, key.name) {
				res.Stats.Skipped++
				continue
			}
			if _, ok := checks[key]; !ok {
				c := &check{eco: eco, name: d.Name, manifest: m.Path, status: registry.Unknown, err: errNotChecked}
				checks[key] = c
				ordered = append(ordered, c)
			}
			if eco.Namespace != nil && eco.NamespaceChecker != nil {
				if ns, ok := eco.Namespace(d.Name); ok {
					nk := nsKey{eco.Name, ns}
					if _, seen := nsChecks[nk]; !seen {
						nc := &nsCheck{eco: eco, ns: ns, status: registry.Unknown, err: errNotChecked}
						nsChecks[nk] = nc
						nsOrdered = append(nsOrdered, nc)
					}
				}
			}
			occs = append(occs, occurrence{key: key, eco: eco, dep: d, manifest: m.Path})
		}
	}
	res.Stats.UniquePackages = len(ordered)

	runChecks(ctx, ordered, opts.Concurrency)
	runNamespaceChecks(ctx, nsOrdered, opts.Concurrency)

	for _, o := range occs {
		if checks[o.key].status != registry.NotFound {
			continue
		}
		f := Finding{
			Ecosystem:   o.eco.Name,
			Package:     o.dep.Name,
			Version:     o.dep.Version,
			Manifest:    o.manifest,
			Line:        o.dep.Line,
			Group:       o.dep.Group,
			Reason:      ReasonUnclaimed,
			Severity:    SeverityHigh,
			Registry:    o.eco.Registry,
			URL:         lockfile.RedactURL(o.eco.URL(o.dep.Name)),
			Remediation: o.eco.Remediation,
		}
		if o.eco.Namespace != nil && o.eco.NamespaceChecker != nil {
			if ns, ok := o.eco.Namespace(o.dep.Name); ok {
				f.Namespace = ns
				nc := nsChecks[nsKey{o.eco.Name, ns}]
				switch {
				case nc == nil || nc.status == registry.Unknown:
					f.NamespaceStatus = NamespaceUnknown
					f.Severity = SeverityHigh
				case nc.status == registry.NotFound:
					f.NamespaceStatus = NamespaceUnclaimed
					f.Severity = SeverityCritical
				case nc.status == registry.Exists:
					f.NamespaceStatus = NamespaceClaimed
					f.Severity = SeverityLow
				}
			}
		}
		res.Findings = append(res.Findings, f)
	}
	for _, c := range ordered {
		if c.status != registry.Unknown {
			continue
		}
		msg := "registry check failed"
		if c.err != nil {
			msg = c.err.Error()
		}
		res.Warnings = append(res.Warnings, Warning{
			Kind: WarnRegistry, Ecosystem: c.eco.Name, Package: c.name, Manifest: c.manifest, Message: msg,
		})
	}
	for _, nc := range nsOrdered {
		if nc.status != registry.Unknown {
			continue
		}
		msg := "namespace ownership check failed; severity kept at high"
		if nc.err != nil {
			msg = nc.err.Error()
		}
		res.Warnings = append(res.Warnings, Warning{
			Kind: WarnNamespace, Ecosystem: nc.eco.Name, Package: nc.ns, Message: msg,
		})
	}

	auditLockfiles(root, opts, res)

	if typos, err := auditTyposquats(opts, occs); err != nil {
		return nil, err
	} else {
		res.Findings = append(res.Findings, typos...)
	}

	sortFindings(res.Findings)
	sortWarnings(res.Warnings)
	res.Stats.Findings = len(res.Findings)
	res.Stats.Errors = len(res.Warnings)
	res.Stats.DurationMS = time.Since(start).Milliseconds()
	return res, ctx.Err()
}

func parse(eco *ecosystem.Ecosystem, m discover.Manifest) ([]manifest.Dependency, error) {
	data, err := manifest.ReadFile(m.Path)
	if err != nil {
		return nil, err
	}
	return eco.Parse(m.Rel, data)
}

func auditLockfiles(root string, opts Options, res *Result) {
	kinds := opts.Lockfiles
	if kinds == nil {
		kinds = lockfile.Default()
	}
	if len(kinds) == 0 {
		return
	}

	walk, err := discover.Walk(root, discover.Options{
		Classify: func(rel string) string {
			return lockfile.Classify(kinds, rel)
		},
		Exclude: opts.Exclude,
	})
	if err != nil {
		res.Warnings = append(res.Warnings, Warning{Kind: WarnLockfile, Message: err.Error()})
		return
	}
	res.Stats.Lockfiles = len(walk.Manifests)
	for _, p := range walk.Problems {
		res.Warnings = append(res.Warnings, Warning{Kind: WarnWalk, Manifest: p.Path, Message: p.Err.Error()})
	}

	for _, m := range walk.Manifests {
		data, err := manifest.ReadFile(m.Path)
		if err != nil {
			res.Warnings = append(res.Warnings, Warning{
				Kind: WarnLockfile, Ecosystem: m.Ecosystem, Manifest: m.Path, Message: err.Error(),
			})
			continue
		}
		deps, err := lockfile.ParseFile(kinds, m.Rel, data)
		if err != nil {
			res.Warnings = append(res.Warnings, Warning{
				Kind: WarnLockfile, Ecosystem: m.Ecosystem, Manifest: m.Path, Message: err.Error(),
			})
			continue
		}
		for _, d := range deps {
			res.Stats.ResolvedPackages++
			if allowlisted(opts, d.Name, d.Name) {
				res.Stats.Skipped++
				continue
			}
			host, _, bad := lockfile.Violation(d.URL, opts.ExpectedHosts)
			if !bad {
				continue
			}
			safeURL := lockfile.RedactURL(d.URL)
			res.Findings = append(res.Findings, Finding{
				Ecosystem:   m.Ecosystem,
				Package:     d.Name,
				Version:     d.Version,
				Manifest:    m.Path,
				Line:        d.Line,
				Group:       "resolved",
				Reason:      ReasonShadowRegistry,
				Severity:    SeverityHigh,
				Registry:    host,
				URL:         safeURL,
				ResolvedURL: safeURL,
				Remediation: RemediationShadow,
			})
		}
	}
}

// allowlisted matches both the declared and the normalized name so that
// e.g. --ignore 'acme-*' also covers acme_internal on PyPI.
func allowlisted(opts Options, name, normalized string) bool {
	for _, m := range []*match.Matcher{opts.Ignore, opts.SafeNamespaces} {
		if m.Match(name) || (normalized != name && m.Match(normalized)) {
			return true
		}
	}
	return false
}

// runChecks resolves every check with a bounded worker pool. Each worker
// writes only to the check it received, and results are read after Wait.
func runChecks(ctx context.Context, checks []*check, workers int) {
	runPool(ctx, checks, workers, func(ctx context.Context, c *check) {
		st, err := c.eco.Checker.Exists(ctx, c.name)
		if err != nil {
			st = registry.Unknown
		}
		c.status, c.err = st, err
	})
}

func runNamespaceChecks(ctx context.Context, checks []*nsCheck, workers int) {
	runPool(ctx, checks, workers, func(ctx context.Context, c *nsCheck) {
		st, err := c.eco.NamespaceChecker.Exists(ctx, c.ns)
		if err != nil {
			st = registry.Unknown
		}
		c.status, c.err = st, err
	})
}

// runPool runs work over items with a bounded worker pool. Items not started
// before ctx cancellation are left untouched; in-flight work still runs until
// the checker returns or its own context ends.
func runPool[T any](ctx context.Context, items []T, workers int, work func(context.Context, T)) {
	if len(items) == 0 {
		return
	}
	if workers <= 0 {
		workers = DefaultConcurrency
	}
	if workers > len(items) {
		workers = len(items)
	}

	jobs := make(chan T)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					continue
				}
				work(ctx, item)
			}
		}()
	}

feed:
	for _, item := range items {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- item:
		}
	}
	close(jobs)
	wg.Wait()
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := SeverityRank(a.Severity), SeverityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.Manifest != b.Manifest {
			return a.Manifest < b.Manifest
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		return a.Package < b.Package
	})
}

func sortWarnings(ws []Warning) {
	sort.SliceStable(ws, func(i, j int) bool {
		a, b := ws[i], ws[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Manifest != b.Manifest {
			return a.Manifest < b.Manifest
		}
		return a.Package < b.Package
	})
}
