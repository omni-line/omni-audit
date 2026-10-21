package scan

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// gitignored reports whether rel (slash-separated, relative to root) is
// excluded by a .gitignore in root or a directory between root and the
// file. It understands the common forms (name, *.ext, /anchored/path,
// **/name) and ignores negations, so it may miss an ignore but never
// invents one. A file it misses is still reported, which is the safe side.
func gitignored(root, rel string) bool {
	dir := path.Dir(rel)
	for {
		if ignoredBy(filepath.Join(root, filepath.FromSlash(dir), ".gitignore"), relTo(dir, rel)) {
			return true
		}
		if dir == "." {
			return false
		}
		dir = path.Dir(dir)
	}
}

func relTo(dir, rel string) string {
	if dir == "." {
		return rel
	}
	return strings.TrimPrefix(rel, dir+"/")
}

func ignoredBy(gitignore, rel string) bool {
	data, err := os.ReadFile(gitignore)
	if err != nil {
		return false
	}
	base := path.Base(rel)
	for _, l := range strings.Split(string(data), "\n") {
		p := strings.TrimSpace(strings.TrimSuffix(l, "\r"))
		if p == "" || p[0] == '#' || p[0] == '!' || strings.HasSuffix(p, "/") {
			continue
		}
		p = strings.TrimPrefix(p, "**/")
		if !strings.Contains(p, "/") {
			if ok, _ := path.Match(p, base); ok {
				return true
			}
			continue
		}
		if ok, _ := path.Match(strings.TrimPrefix(p, "/"), rel); ok {
			return true
		}
	}
	return false
}
