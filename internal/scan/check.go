package scan

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/registry"
)

// Check verifies proposed package names for one ecosystem. It does not walk a
// tree and does not audit lockfiles. Each name is compared to the embedded
// popular-package corpus and looked up on the public registry.
//
// An invalid name (one the registry would never accept) is returned as an
// error and is not sent over the network. A failed lookup is a warning; the
// caller decides allow, block, or unknown from the result.
func Check(ctx context.Context, eco ecosystem.Ecosystem, names []string, opts Options) (*Result, error) {
	start := time.Now()
	if err := eco.Validate(); err != nil {
		return nil, err
	}
	names, err := cleanNames(names)
	if err != nil {
		return nil, err
	}

	res := &Result{Findings: []Finding{}, Checks: nameCheckReasons(opts)}
	ecoPtr := &eco
	checks := make(map[checkKey]*check)
	var ordered []*check
	nsChecks := make(map[nsKey]*nsCheck)
	var nsOrdered []*nsCheck
	var occs []occurrence

	for _, name := range names {
		res.Stats.Packages++
		key := checkKey{eco.Name, eco.Key(name)}
		if allowlisted(opts, name, key.name) {
			res.Stats.Skipped++
			continue
		}
		if _, ok := checks[key]; ok {
			continue
		}
		c := &check{eco: ecoPtr, name: name, status: registry.Unknown, err: errNotChecked}
		checks[key] = c
		ordered = append(ordered, c)
		if eco.Namespace != nil && eco.NamespaceChecker != nil {
			if ns, ok := eco.Namespace(name); ok {
				nk := nsKey{eco.Name, ns}
				if _, seen := nsChecks[nk]; !seen {
					nc := &nsCheck{eco: ecoPtr, ns: ns, status: registry.Unknown, err: errNotChecked}
					nsChecks[nk] = nc
					nsOrdered = append(nsOrdered, nc)
				}
			}
		}
		occs = append(occs, occurrence{
			key: key,
			eco: ecoPtr,
			dep: manifest.Dependency{Name: name},
		})
	}
	res.Stats.UniquePackages = len(ordered)
	if opts.NoUnclaimed {
		ordered, nsOrdered = nil, nil
	}

	runChecks(ctx, ordered, opts.Concurrency)
	runNamespaceChecks(ctx, nsOrdered, opts.Concurrency)

	for _, c := range ordered {
		if errors.Is(c.err, registry.ErrInvalidName) {
			return nil, c.err
		}
	}

	addUnclaimed(res, occs, checks, nsChecks)
	addRegistryWarnings(res, ordered)
	addNamespaceWarnings(res, nsOrdered)

	typos, err := auditTyposquats(opts, occs)
	if err != nil {
		return nil, err
	}
	res.Findings = append(res.Findings, typos...)
	mal, err := auditMalicious(opts, occs, nil)
	if err != nil {
		return nil, err
	}
	res.Findings = append(supersedeUnclaimed(res.Findings, mal), mal...)

	finish(res, start)
	return res, ctx.Err()
}

// nameCheckReasons lists the checks a name lookup actually runs. Shadow
// registry and registry-config audits need a tree, so they are omitted.
func nameCheckReasons(opts Options) []string {
	out := []string{}
	for _, reason := range enabledChecks(opts) {
		if reason == ReasonShadowRegistry || reason == ReasonConfig {
			continue
		}
		out = append(out, reason)
	}
	return out
}

func cleanNames(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, errors.New("missing package name")
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, errors.New("empty package name")
		}
		out = append(out, name)
	}
	return out, nil
}
