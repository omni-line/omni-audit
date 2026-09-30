package scan

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/omni-line/omni-audit/internal/discover"
	"github.com/omni-line/omni-audit/internal/manifest/composer"
	"github.com/omni-line/omni-audit/internal/manifest/npm"
	"github.com/omni-line/omni-audit/internal/manifest/pypi"
	"github.com/omni-line/omni-audit/internal/match"
	"github.com/omni-line/omni-audit/internal/registry"
)

// Finding is a reportable dependency confusion risk.
type Finding struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version,omitempty"`
	Manifest  string `json:"manifest"`
	Reason    string `json:"reason"`
}

// Warning is a non-fatal scan issue (e.g. network error).
type Warning struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Manifest  string `json:"manifest"`
	Message   string `json:"message"`
}

// Stats summarizes a scan.
type Stats struct {
	Manifests int `json:"manifests"`
	Packages  int `json:"packages"`
	Findings  int `json:"findings"`
	Skipped   int `json:"skipped"`
	Errors    int `json:"errors"`
}

// Result is the full scan outcome.
type Result struct {
	Findings []Finding `json:"findings"`
	Warnings []Warning `json:"warnings,omitempty"`
	Stats    Stats     `json:"stats"`
}

// Options configures a Scanner.
type Options struct {
	SafeNamespaces *match.Matcher
	Ignore         *match.Matcher
	Concurrency    int
	NPM            registry.Checker
	Composer       registry.Checker
	PyPI           registry.Checker
}

type job struct {
	ecosystem string
	name      string
	version   string
	manifest  string
	checker   registry.Checker
}

type outcome struct {
	finding *Finding
	warning *Warning
	skipped bool
}

// Run discovers manifests under root and checks public registries.
func Run(ctx context.Context, root string, opts Options) (*Result, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 16
	}
	if opts.NPM == nil || opts.Composer == nil || opts.PyPI == nil {
		return nil, fmt.Errorf("npm, composer, and pypi registry checkers are required")
	}

	manifests, err := discover.Walk(root)
	if err != nil {
		return nil, err
	}

	var jobs []job
	for _, m := range manifests {
		switch m.Ecosystem {
		case "npm":
			deps, err := npm.ParseFile(m.Path)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", m.Path, err)
			}
			for _, d := range deps {
				jobs = append(jobs, job{
					ecosystem: "npm",
					name:      d.Name,
					version:   d.Version,
					manifest:  m.Path,
					checker:   opts.NPM,
				})
			}
		case "composer":
			deps, err := composer.ParseFile(m.Path)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", m.Path, err)
			}
			for _, d := range deps {
				jobs = append(jobs, job{
					ecosystem: "composer",
					name:      d.Name,
					version:   d.Version,
					manifest:  m.Path,
					checker:   opts.Composer,
				})
			}
		case "pypi":
			deps, err := parsePythonManifest(m.Path)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", m.Path, err)
			}
			for _, d := range deps {
				jobs = append(jobs, job{
					ecosystem: "pypi",
					name:      d.Name,
					version:   d.Version,
					manifest:  m.Path,
					checker:   opts.PyPI,
				})
			}
		}
	}

	res := &Result{
		Stats: Stats{
			Manifests: len(manifests),
			Packages:  len(jobs),
		},
	}

	if len(jobs) == 0 {
		return res, nil
	}

	jobsCh := make(chan job)
	outCh := make(chan outcome)
	var wg sync.WaitGroup

	workers := opts.Concurrency
	if workers > len(jobs) {
		workers = len(jobs)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobsCh {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if (opts.Ignore != nil && opts.Ignore.Match(j.name)) ||
					(opts.SafeNamespaces != nil && opts.SafeNamespaces.Match(j.name)) {
					outCh <- outcome{skipped: true}
					continue
				}

				st, err := j.checker.Exists(ctx, j.name)
				if err != nil || st == registry.Unknown {
					msg := "registry check failed"
					if err != nil {
						msg = err.Error()
					}
					outCh <- outcome{warning: &Warning{
						Ecosystem: j.ecosystem,
						Package:   j.name,
						Manifest:  j.manifest,
						Message:   msg,
					}}
					continue
				}
				if st == registry.NotFound {
					outCh <- outcome{finding: &Finding{
						Ecosystem: j.ecosystem,
						Package:   j.name,
						Version:   j.version,
						Manifest:  j.manifest,
						Reason:    "unclaimed",
					}}
					continue
				}
				outCh <- outcome{}
			}
		}()
	}

	go func() {
		defer close(jobsCh)
		for _, j := range jobs {
			select {
			case <-ctx.Done():
				return
			case jobsCh <- j:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(outCh)
	}()

	for o := range outCh {
		if o.skipped {
			res.Stats.Skipped++
			continue
		}
		if o.warning != nil {
			res.Warnings = append(res.Warnings, *o.warning)
			res.Stats.Errors++
			continue
		}
		if o.finding != nil {
			res.Findings = append(res.Findings, *o.finding)
		}
	}
	res.Stats.Findings = len(res.Findings)

	if err := ctx.Err(); err != nil {
		return res, err
	}
	return res, nil
}

func parsePythonManifest(path string) ([]pypi.Dependency, error) {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == "pyproject.toml":
		return pypi.ParsePyProjectFile(path)
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return pypi.ParseRequirementsFile(path)
	default:
		return pypi.ParseRequirementsFile(path)
	}
}
