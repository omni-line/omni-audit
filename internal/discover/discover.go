package discover

import (
	"io/fs"
	"path/filepath"
	"strings"
)

var skipDirs = map[string]struct{}{
	"node_modules":  {},
	"vendor":        {},
	".git":          {},
	"dist":          {},
	"build":         {},
	".svn":          {},
	".hg":           {},
	".venv":         {},
	"venv":          {},
	"__pycache__":   {},
	".tox":          {},
	".mypy_cache":   {},
	".pytest_cache": {},
}

// Manifest is a discovered dependency manifest on disk.
type Manifest struct {
	Path      string
	Ecosystem string // "npm", "composer", or "pypi"
}

// Walk finds supported manifests under root, skipping common junk dirs.
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
		name := strings.ToLower(d.Name())
		switch name {
		case "package.json":
			out = append(out, Manifest{Path: path, Ecosystem: "npm"})
		case "composer.json":
			out = append(out, Manifest{Path: path, Ecosystem: "composer"})
		case "requirements.txt":
			out = append(out, Manifest{Path: path, Ecosystem: "pypi"})
		case "pyproject.toml":
			out = append(out, Manifest{Path: path, Ecosystem: "pypi"})
		default:
			// requirements-*.txt, requirements/*.txt handled only as exact requirements.txt for v1
			// Also accept common variants:
			if strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt") {
				out = append(out, Manifest{Path: path, Ecosystem: "pypi"})
			}
		}
		return nil
	})
	return out, err
}
