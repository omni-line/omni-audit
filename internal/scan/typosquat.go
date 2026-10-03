package scan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/omni-line/omni-audit/internal/corpus"
	"github.com/omni-line/omni-audit/internal/distance"
	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/lockfile"
	"github.com/omni-line/omni-audit/internal/manifest"
)

// Typosquat finding kinds.
const (
	KindPopular   = "popular"
	KindScopePeer = "scope-peer"
)

// DefaultTyposquatDistance is the default maximum edit distance flagged.
const DefaultTyposquatDistance = 2

const maxSuggestions = 3

// RemediationTyposquat is default guidance for near-miss package names.
const RemediationTyposquat = "Confirm the package name is intentional. If it is a typo, correct it to the suggested popular package. Proxy public registries through Omni Line and allow-list approved externals so unknown near-miss names never resolve."

type typoDecl struct {
	eco *ecosystem.Ecosystem
	dep manifest.Dependency
	key string
	rel string
}

type popularHit struct {
	dist    int
	targets []string
}

type typoScanner struct {
	opts     Options
	corpora  map[string]*corpus.Set
	popular  map[string]popularHit
	reported map[string]struct{}
	out      []Finding
}

// auditTyposquats compares declared dependency names to popular-package
// corpora and to namespace peers. It is offline and uses the embedded corpus.
func auditTyposquats(opts Options, occs []occurrence) ([]Finding, error) {
	if opts.NoTyposquat {
		return nil, nil
	}
	maxDist := opts.MaxDistance
	if maxDist <= 0 {
		maxDist = DefaultTyposquatDistance
	}
	if maxDist > 2 {
		maxDist = 2
	}
	opts.MaxDistance = maxDist

	s := &typoScanner{
		opts:     opts,
		corpora:  map[string]*corpus.Set{},
		popular:  map[string]popularHit{},
		reported: map[string]struct{}{},
	}

	decls := make([]typoDecl, 0, len(occs))
	for _, o := range occs {
		decls = append(decls, typoDecl{
			eco: o.eco,
			dep: o.dep,
			key: o.eco.TypoKey(o.dep.Name),
			rel: o.manifest,
		})
		if _, ok := s.corpora[o.eco.Name]; ok {
			continue
		}
		set, err := corpus.Load(o.eco.Name, o.eco.TypoKey)
		if err != nil {
			return nil, fmt.Errorf("typosquat corpus %s: %w", o.eco.Name, err)
		}
		s.corpora[o.eco.Name] = set
	}
	for _, d := range decls {
		if allowedExact(opts, d.dep.Name, d.key) {
			continue
		}
		s.checkPopular(d)
	}
	s.checkPeers(decls)
	return s.out, nil
}

func allowedExact(opts Options, name, key string) bool {
	if allowlisted(opts, name, key) {
		return true
	}
	if opts.Allow != nil {
		if _, ok := opts.Allow[name]; ok {
			return true
		}
		if _, ok := opts.Allow[key]; ok {
			return true
		}
	}
	return false
}

func (s *typoScanner) checkPopular(d typoDecl) {
	set := s.corpora[d.eco.Name]
	if set == nil {
		return
	}
	if set.Contains(d.key) || (d.eco.Implied != nil && d.eco.Implied(d.key, set.Contains)) {
		return
	}
	memo := d.eco.Name + "\x00" + d.key
	hit, ok := s.popular[memo]
	if !ok {
		hit = nearest(set, d.key, s.opts.MaxDistance)
		s.popular[memo] = hit
	}
	if len(hit.targets) == 0 {
		return
	}
	display := make([]string, len(hit.targets))
	for i, t := range hit.targets {
		display[i] = set.Display(t)
	}
	var targetRank int
	if r, ok := set.Rank(hit.targets[0]); ok {
		targetRank = r
	}
	s.add(d, KindPopular, hit.dist, distance.Classify(d.key, hit.targets[0]), display, targetRank)
}

func nearest(set *corpus.Set, key string, maxDist int) popularHit {
	best := popularHit{dist: maxDist + 1}
	seen := map[string]struct{}{}
	set.Candidates(key, maxDist, func(c string) {
		if _, dup := seen[c]; dup {
			return
		}
		seen[c] = struct{}{}
		limit := typoBudget(key, c, maxDist)
		if limit == 0 {
			return
		}
		d, ok := distance.Within(key, c, limit)
		if !ok || d == 0 {
			return
		}
		if d < best.dist {
			best.dist = d
			best.targets = best.targets[:0]
		}
		if d == best.dist {
			best.targets = append(best.targets, c)
		}
	})
	sort.Slice(best.targets, func(i, j int) bool {
		ri, oki := set.Rank(best.targets[i])
		rj, okj := set.Rank(best.targets[j])
		switch {
		case oki && okj && ri != rj:
			return ri < rj
		case oki != okj:
			return oki
		default:
			return best.targets[i] < best.targets[j]
		}
	})
	if len(best.targets) > maxSuggestions {
		best.targets = best.targets[:maxSuggestions]
	}
	return best
}

func typoBudget(a, b string, maxDist int) int {
	n := len(distance.StripSeparators(a))
	if m := len(distance.StripSeparators(b)); m < n {
		n = m
	}
	switch {
	case n < 3:
		return 0
	case n < 5 && maxDist > 1:
		return 1
	default:
		return maxDist
	}
}

type peerHit struct {
	dist  int
	goods []string
}

func (s *typoScanner) checkPeers(decls []typoDecl) {
	wanted := map[string]struct{}{}
	for _, sc := range s.opts.Scopes {
		if sc = strings.TrimSpace(sc); sc != "" {
			wanted[strings.ToLower(sc)] = struct{}{}
		}
	}
	type group struct {
		eco   *ecosystem.Ecosystem
		names map[string][]typoDecl
	}
	groups := map[string]*group{}
	for _, d := range decls {
		if d.eco.PeerNamespace == nil {
			continue
		}
		ns, _ := d.eco.PeerNamespace(d.key)
		if ns == "" {
			continue
		}
		if _, ok := wanted[ns]; !ok && s.opts.NoScopePeers {
			continue
		}
		gk := d.eco.Name + "\x00" + ns
		g := groups[gk]
		if g == nil {
			g = &group{eco: d.eco, names: map[string][]typoDecl{}}
			groups[gk] = g
		}
		g.names[d.key] = append(g.names[d.key], d)
	}

	for _, g := range groups {
		names := make([]string, 0, len(g.names))
		for n := range g.names {
			names = append(names, n)
		}
		sort.Strings(names)
		set := s.corpora[g.eco.Name]
		hits := map[string]*peerHit{}
		for i := 0; i < len(names); i++ {
			for j := i + 1; j < len(names); j++ {
				a, b := names[i], names[j]
				_, aLeaf := g.eco.PeerNamespace(a)
				_, bLeaf := g.eco.PeerNamespace(b)
				if isSiblingFamily(aLeaf, bLeaf) {
					continue
				}
				limit := typoBudget(aLeaf, bLeaf, s.opts.MaxDistance)
				if limit == 0 {
					continue
				}
				d, ok := distance.Within(aLeaf, bLeaf, limit)
				if !ok || d == 0 {
					continue
				}
				typo, good := pickTypo(a, aLeaf, b, bLeaf, set)
				h := hits[typo]
				if h == nil || d < h.dist {
					h = &peerHit{dist: d}
					hits[typo] = h
				}
				if d == h.dist && len(h.goods) < maxSuggestions {
					h.goods = append(h.goods, good)
				}
			}
		}
		for typo, h := range hits {
			_, tLeaf := g.eco.PeerNamespace(typo)
			_, gLeaf := g.eco.PeerNamespace(h.goods[0])
			tech := distance.Classify(tLeaf, gLeaf)
			for _, d := range g.names[typo] {
				s.add(d, KindScopePeer, h.dist, tech, h.goods, 0)
			}
		}
	}
}

func isSiblingFamily(a, b string) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	if a == "" || len(b) < len(a)+2 {
		return false
	}
	isSep := func(c byte) bool { return c == '-' || c == '_' || c == '.' }
	return (strings.HasPrefix(b, a) && isSep(b[len(a)])) ||
		(strings.HasSuffix(b, a) && isSep(b[len(b)-len(a)-1]))
}

func pickTypo(a, aLeaf, b, bLeaf string, set *corpus.Set) (typo, good string) {
	aPop, bPop := set.Contains(a), set.Contains(b)
	switch {
	case aPop && !bPop:
		return b, a
	case bPop && !aPop:
		return a, b
	case len(aLeaf) != len(bLeaf):
		if len(aLeaf) > len(bLeaf) {
			return a, b
		}
		return b, a
	case a > b:
		return a, b
	default:
		return b, a
	}
}

func (s *typoScanner) add(d typoDecl, kind string, dist int, tech distance.Technique, targets []string, targetRank int) {
	key := strings.Join([]string{d.eco.Name, d.rel, d.key, kind}, "\x00")
	if _, dup := s.reported[key]; dup {
		return
	}
	s.reported[key] = struct{}{}
	f := Finding{
		Ecosystem:   d.eco.Name,
		Package:     d.dep.Name,
		Version:     d.dep.Version,
		Manifest:    d.rel,
		Line:        d.dep.Line,
		Group:       d.dep.Group,
		Reason:      ReasonTyposquat,
		Severity:    typosquatSeverity(kind, dist),
		Kind:        kind,
		Distance:    dist,
		Suggestions: targets,
		TargetRank:  targetRank,
		Technique:   string(tech),
		Registry:    d.eco.Registry,
		URL:         lockfile.RedactURL(d.eco.URL(d.dep.Name)),
		Remediation: RemediationTyposquat,
	}
	if len(targets) > 0 {
		// Prefer the corpus display form for URLs when it differs from the key.
		suggest := targets[0]
		f.SuggestionURL = lockfile.RedactURL(d.eco.URL(suggest))
		if f.SuggestionURL == "" {
			f.SuggestionURL = lockfile.RedactURL(d.eco.URL(d.eco.TypoKey(suggest)))
		}
		f.Message = typosquatMessage(f)
	}
	s.out = append(s.out, f)
}

func typosquatSeverity(kind string, dist int) string {
	switch {
	case kind == KindPopular && dist <= 1:
		return SeverityCritical
	case kind == KindPopular, dist <= 1:
		return SeverityHigh
	default:
		return SeverityMedium
	}
}

func typosquatMessage(f Finding) string {
	what := "a popular " + f.Ecosystem + " package"
	if f.Kind == KindScopePeer {
		what = "a package in the same namespace"
	}
	edits := "edit"
	if f.Distance != 1 {
		edits = "edits"
	}
	msg := fmt.Sprintf("%q is %d %s away from %s, %q", f.Package, f.Distance, edits, what, f.Suggestions[0])
	if f.Technique != "" {
		msg += " (" + distance.Technique(f.Technique).Describe() + ")"
	}
	return msg
}
