// Package discover walks a project tree and finds dependency manifests.
package discover

import (
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	"github.com/omni-line/omni-audit/internal/match"
)

// SkipDirs are never descended into (dependency caches, VCS, build output).
var SkipDirs = map[string]struct{}{
	"node_modules":     {},
	"bower_components": {},
	"jspm_packages":    {},
	"vendor":           {},
	".git":             {},
	".svn":             {},
	".hg":              {},
	"dist":             {},
	"build":            {},
	".venv":            {},
	"venv":             {},
	"__pycache__":      {},
	"site-packages":    {},
	".eggs":            {},
	".tox":             {},
	".nox":             {},
	".mypy_cache":      {},
	".pytest_cache":    {},
	".ruff_cache":      {},
}

// Manifest is a discovered dependency manifest on disk.
type Manifest struct {
	// Path is the file path as reachable from the working directory.
	Path string
	// Rel is Path relative to the scan root, slash-separated.
	Rel string
	// Ecosystem is the name of the ecosystem that claimed the file.
	Ecosystem string
}

// Problem is a path that could not be walked or was deliberately skipped.
type Problem struct {
	Path string
	Err  error
}

// Options configures Walk.
type Options struct {
	// Classify returns the ecosystem name for a slash-separated path relative
	// to the root, or "" if the file is not a manifest.
	Classify func(rel string) string
	// Exclude skips files and directories whose relative path or base name
	// matches a pattern.
	Exclude *match.Matcher
}

// Result is the outcome of Walk.
type Result struct {
	Manifests []Manifest
	Problems  []Problem
}

// ErrOutsideRoot marks a symlinked manifest that resolves outside the root.
var ErrOutsideRoot = errors.New("symlink resolves outside the scan root; skipped")

// Walk finds manifests under root. Unreadable subdirectories are reported as
// problems rather than aborting the walk; an unreadable root is an error.
// Symlinked directories are not followed, and symlinked manifests are only
// read when they resolve inside root.
func Walk(root string, opts Options) (Result, error) {
	var res Result
	if opts.Classify == nil {
		return res, errors.New("discover: Classify is required")
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return res, err
	}

	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if p == root {
				return walkErr
			}
			res.Problems = append(res.Problems, Problem{Path: p, Err: walkErr})
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		rel := relSlash(root, p)
		if p != root {
			if _, skip := SkipDirs[d.Name()]; skip && d.IsDir() {
				return filepath.SkipDir
			}
			if opts.Exclude.Match(rel) || opts.Exclude.Match(d.Name()) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			return nil
		}

		eco := opts.Classify(rel)
		if eco == "" {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 && !insideRoot(realRoot, p) {
			res.Problems = append(res.Problems, Problem{Path: p, Err: ErrOutsideRoot})
			return nil
		}
		res.Manifests = append(res.Manifests, Manifest{Path: p, Rel: rel, Ecosystem: eco})
		return nil
	})
	return res, err
}

func relSlash(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == "." {
		return path.Base(filepath.ToSlash(p))
	}
	return filepath.ToSlash(rel)
}

func insideRoot(realRoot, p string) bool {
	target, err := filepath.EvalSymlinks(p)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(realRoot, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
