// Package corpus loads embedded popular-package name snapshots.
//
// Each ecosystem ships one gzip-compressed JSON snapshot named
// "<ecosystem>.json.gz" next to this file, plus a shared meta.json written by
// scripts/update-corpus. Snapshots are either a JSON array of
// {"name","rank"} objects (preferred) or a legacy array of name strings.
package corpus

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"sync"
)

//go:embed *.json.gz meta.json
var files embed.FS

// maxSnapshotSize caps decompressed snapshot size as a guard against a
// corrupted or malicious corpus refresh.
const maxSnapshotSize = 64 << 20

// Meta describes when and from where the corpus was built.
type Meta struct {
	GeneratedAt string                   `json:"generated_at"`
	Ecosystems  map[string]EcosystemMeta `json:"ecosystems"`
}

// EcosystemMeta describes one ecosystem snapshot.
type EcosystemMeta struct {
	Count     int    `json:"count"`
	Source    string `json:"source"`
	OrderedBy string `json:"ordered_by,omitempty"`
}

// Entry is one popular package with an optional 1-based download rank.
type Entry struct {
	Name string `json:"name"`
	Rank int    `json:"rank,omitempty"`
}

// ErrUnknown is returned when no snapshot exists for an ecosystem.
var ErrUnknown = errors.New("no embedded corpus")

var (
	metaOnce sync.Once
	meta     Meta
	metaErr  error

	setsMu sync.Mutex
	sets   = map[string]*Set{}
)

// MetaInfo returns corpus metadata.
func MetaInfo() (Meta, error) {
	metaOnce.Do(func() {
		raw, err := files.ReadFile("meta.json")
		if err != nil {
			metaErr = fmt.Errorf("corpus meta: %w", err)
			return
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			metaErr = fmt.Errorf("corpus meta: %w", err)
		}
	})
	return meta, metaErr
}

// Load returns the indexed snapshot for ecosystem name, normalizing every
// entry with normalize (nil keeps names as-is). Results are cached per name,
// so callers must use a consistent normalizer for a given ecosystem.
func Load(name string, normalize func(string) string) (*Set, error) {
	setsMu.Lock()
	defer setsMu.Unlock()
	if s, ok := sets[name]; ok {
		return s, nil
	}
	raw, err := files.ReadFile(name + ".json.gz")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w for ecosystem %q", ErrUnknown, name)
	}
	if err != nil {
		return nil, err
	}
	entries, err := decode(raw)
	if err != nil {
		return nil, fmt.Errorf("corpus %s: %w", name, err)
	}
	s := NewSet(entries, normalize)
	sets[name] = s
	return s, nil
}

func decode(raw []byte) ([]Entry, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	data, err := io.ReadAll(io.LimitReader(zr, maxSnapshotSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSnapshotSize {
		return nil, errors.New("snapshot exceeds size limit")
	}
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err == nil && looksLikeEntries(entries) {
		return entries, nil
	}
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(names))
	for _, n := range names {
		out = append(out, Entry{Name: n})
	}
	return out, nil
}

// looksLikeEntries distinguishes [{"name":"x"}] from a legacy ["x"] decode
// that would produce zero-value Entry structs if unmarshaled into []Entry.
func looksLikeEntries(entries []Entry) bool {
	if len(entries) == 0 {
		return true
	}
	for _, e := range entries {
		if e.Name != "" {
			return true
		}
	}
	return false
}

// Set is an indexed popular-name corpus for one ecosystem. Lookups use
// normalized keys; Display maps a key back to the registry spelling.
type Set struct {
	display    map[string]string
	rank       map[string]int
	byLen      map[int][]string
	byStripped map[int][]string
}

// NewSet indexes entries for exact and length-bucketed lookup.
// When two names normalize to the same key, the first wins for Display and Rank.
func NewSet(entries []Entry, normalize func(string) string) *Set {
	s := &Set{
		display:    make(map[string]string, len(entries)),
		rank:       make(map[string]int, len(entries)),
		byLen:      make(map[int][]string),
		byStripped: make(map[int][]string),
	}
	for _, e := range entries {
		n := e.Name
		key := n
		if normalize != nil {
			key = normalize(n)
		}
		if key == "" {
			continue
		}
		if _, dup := s.display[key]; dup {
			continue
		}
		s.display[key] = n
		if e.Rank > 0 {
			s.rank[key] = e.Rank
		}
		s.byLen[len(key)] = append(s.byLen[len(key)], key)
		sl := strippedLen(key)
		s.byStripped[sl] = append(s.byStripped[sl], key)
	}
	for _, m := range []map[int][]string{s.byLen, s.byStripped} {
		for _, keys := range m {
			sort.Strings(keys)
		}
	}
	return s
}

// NewSetNames is a convenience for tests that only have bare names.
func NewSetNames(names []string, normalize func(string) string) *Set {
	entries := make([]Entry, len(names))
	for i, n := range names {
		entries[i] = Entry{Name: n}
	}
	return NewSet(entries, normalize)
}

// Contains reports whether key is an exact corpus member.
func (s *Set) Contains(key string) bool {
	if s == nil {
		return false
	}
	_, ok := s.display[key]
	return ok
}

// Display returns the registry spelling for key, or key if unknown.
func (s *Set) Display(key string) string {
	if s != nil {
		if d, ok := s.display[key]; ok {
			return d
		}
	}
	return key
}

// Rank returns the 1-based download rank for key when the corpus is
// rank-ordered. ok is false when the snapshot has no ranks or key is unknown.
func (s *Set) Rank(key string) (rank int, ok bool) {
	if s == nil {
		return 0, false
	}
	rank, ok = s.rank[key]
	return rank, ok
}

// Candidates calls fn for every corpus key that could be within maxDist of
// key, either by raw length or by separator-stripped length. A key may be
// visited twice; callers dedupe if needed.
func (s *Set) Candidates(key string, maxDist int, fn func(candidate string)) {
	if s == nil {
		return
	}
	l, sl := len(key), strippedLen(key)
	for d := -maxDist; d <= maxDist; d++ {
		for _, c := range s.byLen[l+d] {
			fn(c)
		}
		for _, c := range s.byStripped[sl+d] {
			fn(c)
		}
	}
}

// Len returns the number of distinct keys.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.display)
}

func strippedLen(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '-' && c != '_' && c != '.' {
			n++
		}
	}
	return n
}
