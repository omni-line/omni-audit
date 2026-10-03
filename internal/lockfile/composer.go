package lockfile

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/omni-line/omni-audit/internal/manifest"
)

// ParseComposer extracts dist/source URLs from composer.lock.
func ParseComposer(data []byte) ([]Resolved, error) {
	var raw struct {
		Packages    []composerPkg `json:"packages"`
		PackagesDev []composerPkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("composer.lock: %w", err)
	}

	seen := make(map[string]struct{})
	var out []Resolved
	appendPkgs := func(pkgs []composerPkg, group string) {
		// Stable order by name.
		idxs := make([]int, len(pkgs))
		for i := range pkgs {
			idxs[i] = i
		}
		sort.SliceStable(idxs, func(i, j int) bool {
			return pkgs[idxs[i]].Name < pkgs[idxs[j]].Name
		})
		for _, i := range idxs {
			p := pkgs[i]
			if p.Name == "" {
				continue
			}
			url := p.Dist.URL
			if url == "" {
				url = p.Source.URL
			}
			if url == "" {
				continue
			}
			dupKey := p.Name + "\x00" + url
			if _, dup := seen[dupKey]; dup {
				continue
			}
			seen[dupKey] = struct{}{}
			out = append(out, Resolved{
				Name:    p.Name,
				Version: p.Version,
				URL:     url,
				Line:    manifest.JSONKeyLine(data, group, p.Name),
			})
		}
	}
	appendPkgs(raw.Packages, "packages")
	appendPkgs(raw.PackagesDev, "packages-dev")
	return out, nil
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		URL string `json:"url"`
	} `json:"dist"`
	Source struct {
		URL string `json:"url"`
	} `json:"source"`
}
