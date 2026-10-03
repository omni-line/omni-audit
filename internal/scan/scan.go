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
	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/match"
	"github.com/omni-line/omni-audit/internal/registry"
)

// ReasonUnclaimed marks a name that does not exist on the public registry.
const ReasonUnclaimed = "unclaimed"

// Finding severities. Additive JSON fields; default for unscoped names is high.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
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
)

// DefaultConcurrency is used when Options.Concurrency is not positive.
const DefaultConcurrency = 16

// Finding is a reportable dependency confusion risk.
//
// ecosystem, package, version, manifest, and reason are part of the stable
// JSON schema; other fields are additive.
type Finding struct {
	Ecosystem       string `json:"ecosystem"`
	Package         string `json:"package"`
	Version         string `json:"version,omitempty"`
	Manifest        string `json:"manifest"`
	Line            int    `json:"line,omitempty"`
	Group           string `json:"group,omitempty"`
	Reason          string `json:"reason"`
	Severity        string `json:"severity,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	NamespaceStatus string `json:"namespace_status,omitempty"`
	Registry        string `json:"registry,omitempty"`
	URL             string `json:"url,omitempty"`
	Remediation     string `json:"remediation,omitempty"`
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
	// Packages counts dependency declarations across all manifests.
	Packages int `json:"packages"`
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
		return 3
	case SeverityHigh:
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
	case SeverityCritical, SeverityHigh, SeverityLow:
		return s, nil
	default:
		return "", errors.New(`invalid severity (want low|high|critical)`)
	}
}

// Run discovers manifests under root and checks each distinct package name
// once against its public registry. On cancellation it returns the partial
// result together with ctx.Err().
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
			URL:         o.eco.URL(o.dep.Name),
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
	if len(checks) == 0 {
		return
	}
	if workers <= 0 {
		workers = DefaultConcurrency
	}
	if workers > len(checks) {
		workers = len(checks)
	}

	jobs := make(chan *check)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				if ctx.Err() != nil {
					continue // leave as Unknown / errNotChecked
				}
				st, err := c.eco.Checker.Exists(ctx, c.name)
				if err != nil {
					st = registry.Unknown
				}
				c.status, c.err = st, err
			}
		}()
	}

feed:
	for _, c := range checks {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- c:
		}
	}
	close(jobs)
	wg.Wait()
}

func runNamespaceChecks(ctx context.Context, checks []*nsCheck, workers int) {
	if len(checks) == 0 {
		return
	}
	if workers <= 0 {
		workers = DefaultConcurrency
	}
	if workers > len(checks) {
		workers = len(checks)
	}

	jobs := make(chan *nsCheck)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				if ctx.Err() != nil {
					continue
				}
				st, err := c.eco.NamespaceChecker.Exists(ctx, c.ns)
				if err != nil {
					st = registry.Unknown
				}
				c.status, c.err = st, err
			}
		}()
	}

feed:
	for _, c := range checks {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- c:
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
