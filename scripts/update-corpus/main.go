// Command update-corpus refreshes embedded popular-package snapshots.
//
// Each ecosystem is one entry in sources. Adding a registry means adding a
// source with a fetch function; the output file name (<name>.json.gz) must
// match ecosystem.Ecosystem.Name.
//
// Snapshots are written as [{"name","rank"}, ...] sorted alphabetically by
// name so monthly refresh diffs stay reviewable. Rank is the 1-based position
// in the upstream popularity ordering (preserved before the alphabetical sort).
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	pypiURL      = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
	npmRankURL   = "https://github.com/LeoDog896/npm-rank/releases/download/latest/raw.json"
	packagistURL = "https://packagist.org/explore/popular.json"
	ecosysteBase = "https://packages.ecosyste.ms/api/v1/registries"

	defaultLimit = 10000
	npmLimit     = 25000
	maxBodyBytes = 256 << 20
	userAgent    = "omni-audit-update-corpus (+https://github.com/omni-line/omni-audit)"
	orderedBy    = "downloads"
	minNames     = 100
	perPage      = 100
)

type source struct {
	name     string
	url      string
	limit    int
	fetch    func(ctx context.Context, c *http.Client, limit int) ([]string, error)
	fallback func() []string
	must     []string
}

var sources = []source{
	{
		name: "npm", url: ecosysteBase + "/npmjs.org/packages?sort=downloads&order=desc",
		limit: npmLimit, fetch: fetchEcosyste("npmjs.org", "downloads"),
		fallback: npmSeed, must: []string{"react-dom", "cross-env", "lodash", "express", "axios", "typescript", "pg-boss"},
	},
	{
		name: "pypi", url: pypiURL, limit: defaultLimit, fetch: fetchPyPI,
		must: []string{"requests"},
	},
	{
		name: "composer", url: packagistURL, limit: defaultLimit, fetch: fetchPackagist,
		must: []string{"monolog/monolog", "symfony/symfony", "laravel/framework"},
	},
	{
		name: "go", url: ecosysteBase + "/proxy.golang.org/packages?sort=dependent_repos_count&order=desc",
		limit: defaultLimit, fetch: fetchEcosyste("proxy.golang.org", "dependent_repos_count"),
		must: []string{"github.com/gin-gonic/gin", "github.com/stretchr/testify", "golang.org/x/sys"},
	},
	{
		name: "cargo", url: ecosysteBase + "/crates.io/packages?sort=downloads&order=desc",
		limit: defaultLimit, fetch: fetchEcosyste("crates.io", "downloads"),
		must: []string{"serde", "tokio", "clap", "anyhow"},
	},
	{
		name: "maven", url: ecosysteBase + "/repo1.maven.org/packages?sort=dependent_repos_count&order=desc",
		limit: defaultLimit, fetch: fetchEcosyste("repo1.maven.org", "dependent_repos_count"),
		must: []string{"junit:junit", "com.google.guava:guava", "org.apache.commons:commons-lang3"},
	},
	{
		name: "rubygems", url: ecosysteBase + "/rubygems.org/packages?sort=downloads&order=desc",
		limit: defaultLimit, fetch: fetchEcosyste("rubygems.org", "downloads"),
		must: []string{"rails", "sidekiq", "rake", "bundler"},
	},
	{
		name: "docker", url: ecosysteBase + "/hub.docker.com/packages?sort=dependent_repos_count&order=desc",
		limit: defaultLimit, fetch: fetchEcosyste("hub.docker.com", "dependent_repos_count"),
		fallback: dockerSeed, must: []string{"nginx", "redis", "postgres", "alpine", "ubuntu", "node", "python"},
	},
	{
		name: "conan", url: "seeded ConanCenter popular recipes",
		limit: defaultLimit, fetch: nil, fallback: conanSeed,
		must: []string{"openssl", "zlib", "boost", "fmt", "nlohmann_json"},
	},
}

type entry struct {
	Name string `json:"name"`
	Rank int    `json:"rank"`
}

type ecoMeta struct {
	Count     int    `json:"count"`
	Source    string `json:"source"`
	OrderedBy string `json:"ordered_by"`
}

type meta struct {
	Ecosystems  map[string]ecoMeta `json:"ecosystems"`
	GeneratedAt string             `json:"generated_at"`
}

func main() {
	outDir := flag.String("out", "internal/corpus", "output directory")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	err := run(ctx, *outDir)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	m := meta{Ecosystems: map[string]ecoMeta{}, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, src := range sources {
		limit := src.limit
		if limit <= 0 {
			limit = defaultLimit
		}
		var names []string
		var err error
		origin := src.url
		if src.fetch != nil {
			names, err = src.fetch(ctx, client, limit)
			if err == nil && len(names) < minNames {
				err = fmt.Errorf("only %d names returned (want >= %d)", len(names), minNames)
			}
		} else {
			err = errors.New("no fetch configured")
		}
		if err != nil {
			if src.fallback == nil {
				return fmt.Errorf("%s: %w", src.name, err)
			}
			fmt.Fprintf(os.Stderr, "warning: %s fetch failed (%v); using seed list\n", src.name, err)
			names = src.fallback()
			origin = "seeded top " + src.name + " packages (scripts/update-corpus fallback)"
		}
		names = appendUnique(names, src.must...)
		if len(names) > limit {
			names = names[:limit]
		}
		entries := rankedEntries(names)
		if err := writeGzipJSON(filepath.Join(outDir, src.name+".json.gz"), entries); err != nil {
			return err
		}
		m.Ecosystems[src.name] = ecoMeta{Count: len(entries), Source: origin, OrderedBy: orderedBy}
		fmt.Fprintf(os.Stderr, "%s: %d packages\n", src.name, len(entries))
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "meta.json"), append(raw, '\n'), 0o644)
}

func getJSON(ctx context.Context, c *http.Client, rawURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxBodyBytes {
		return errors.New("response exceeds size limit")
	}
	return json.Unmarshal(body, v)
}

func fetchPyPI(ctx context.Context, c *http.Client, limit int) ([]string, error) {
	var payload struct {
		Rows []struct {
			Project string `json:"project"`
		} `json:"rows"`
	}
	if err := getJSON(ctx, c, pypiURL, &payload); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(payload.Rows))
	for _, row := range payload.Rows {
		names = append(names, row.Project)
	}
	return topUnique(names, limit), nil
}

func fetchPackagist(ctx context.Context, c *http.Client, limit int) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	next := packagistURL + "?per_page=100"
	for next != "" && len(out) < limit {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var payload struct {
			Packages []struct {
				Name string `json:"name"`
			} `json:"packages"`
			Next string `json:"next"`
		}
		if err := getJSON(ctx, c, next, &payload); err != nil {
			return nil, err
		}
		for _, p := range payload.Packages {
			if p.Name == "" {
				continue
			}
			if _, ok := seen[p.Name]; ok {
				continue
			}
			seen[p.Name] = struct{}{}
			out = append(out, p.Name)
			if len(out) >= limit {
				break
			}
		}
		next = payload.Next
		time.Sleep(50 * time.Millisecond)
	}
	return out, nil
}

func fetchEcosyste(registry, sortKey string) func(context.Context, *http.Client, int) ([]string, error) {
	return func(ctx context.Context, c *http.Client, limit int) ([]string, error) {
		seen := map[string]struct{}{}
		var out []string
		for page := 1; len(out) < limit; page++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			u := fmt.Sprintf("%s/%s/packages?sort=%s&order=desc&per_page=%d&page=%d",
				ecosysteBase, url.PathEscape(registry), url.QueryEscape(sortKey), perPage, page)
			var rows []struct {
				Name string `json:"name"`
			}
			if err := getJSON(ctx, c, u, &rows); err != nil {
				return nil, err
			}
			if len(rows) == 0 {
				break
			}
			for _, row := range rows {
				n := row.Name
				if registry == "hub.docker.com" {
					n = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(n), "library/"))
				}
				if n == "" {
					continue
				}
				if _, ok := seen[n]; ok {
					continue
				}
				seen[n] = struct{}{}
				out = append(out, n)
				if len(out) >= limit {
					break
				}
			}
			if len(rows) < perPage {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if registry == "npmjs.org" && len(out) < 1000 {
			extra, err := fetchNPMRank(ctx, c, limit)
			if err == nil {
				out = appendUnique(out, extra...)
			}
		}
		return out, nil
	}
}

func fetchNPMRank(ctx context.Context, c *http.Client, limit int) ([]string, error) {
	var rows []struct {
		Name string `json:"name"`
	}
	if err := getJSON(ctx, c, npmRankURL, &rows); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, row.Name)
	}
	return topUnique(names, limit), nil
}

func topUnique(names []string, limit int) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, limit)
	for _, n := range names {
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
		if len(out) == limit {
			break
		}
	}
	return out
}

func appendUnique(names []string, extra ...string) []string {
	seen := make(map[string]struct{}, len(names))
	for _, n := range names {
		seen[n] = struct{}{}
	}
	for _, n := range extra {
		if n == "" {
			continue
		}
		if _, ok := seen[n]; !ok {
			names = append(names, n)
			seen[n] = struct{}{}
		}
	}
	return names
}

func rankedEntries(names []string) []entry {
	entries := make([]entry, 0, len(names))
	for i, n := range names {
		if n == "" {
			continue
		}
		entries = append(entries, entry{Name: n, Rank: i + 1})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	return entries
}

func writeGzipJSON(path string, entries []entry) error {
	raw, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}
