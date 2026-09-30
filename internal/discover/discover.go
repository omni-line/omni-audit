package discover

import (
	"io/fs"
	"path/filepath"
	"strings"
)

var skipDirs = map[string]struct{}{
	"node_modules": {},
	"vendor":       {},
	".git":         {},
	"dist":         {},
	"build":        {},
	".svn":         {},
	".hg":          {},
}

// Manifest is a discovered dependency manifest on disk.
type Manifest struct {
	Path      string
	Ecosystem string // "npm" or "composer"
}

// Walk finds package.json and composer.json under root, skipping common junk dirs.
func Walk(root string) ([]Manifest, error) {
	var out []Manifest
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if _, skip := skipDirs[name]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(d.Name()) {
		case "package.json":
			out = append(out, Manifest{Path: path, Ecosystem: "npm"})
		case "composer.json":
			out = append(out, Manifest{Path: path, Ecosystem: "composer"})
		}
		return nil
	})
	return out, err
}
