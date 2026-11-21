package scan

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/omni-line/omni-audit/internal/discover"
	"github.com/omni-line/omni-audit/internal/installhook"
	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/match"
)

// WarnInstalled marks an installed-tree path that could not be read, or a
// walk that stopped early.
const WarnInstalled = "installed"

const (
	maxSearchDepth       = 40
	maxPackageDepth      = 16
	maxPythonDepth       = 8
	maxInstalledPackages = 20000
	maxPythonFiles       = 5000
)

// auditInstallHooks scans project files that run at install time. With
// opts.Installed it also scans node_modules and virtualenvs, and compares
// installed npm packages to locks (npm lockfiles, keyed by directory).
// Offline. --ignore skips a package; --safe-namespace does not, because a
// namespace you own can still ship a malicious install script.
func auditInstallHooks(root string, opts Options, locks []lockIndex, res *Result) {
	if opts.NoInstallHook {
		return
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		res.Warnings = append(res.Warnings, Warning{Kind: WarnInstalled, Message: err.Error()})
		return
	}
	auditProjectHooks(root, realRoot, opts, res)
	if !opts.Installed {
		return
	}
	info, err := os.Lstat(root)
	if err != nil {
		res.Warnings = append(res.Warnings, Warning{Kind: WarnInstalled, Manifest: root, Message: err.Error()})
		return
	}
	if !info.IsDir() {
		return
	}
	st := &installedState{
		root:     root,
		realRoot: realRoot,
		exclude:  opts.Exclude,
		opts:     opts,
		res:      res,
		locks:    locks,
	}
	st.walkSearch(root, 0)
	if st.truncated {
		res.Warnings = append(res.Warnings, Warning{
			Kind:    WarnInstalled,
			Message: "installed-tree scan stopped early; the tree is larger than the scan cap",
		})
	}
}

func auditProjectHooks(root, realRoot string, opts Options, res *Result) {
	walk, err := discover.Walk(root, discover.Options{
		Classify: func(rel string) string {
			if isProjectHook(rel) {
				return "hook"
			}
			return ""
		},
		Exclude: opts.Exclude,
	})
	if err != nil {
		res.Warnings = append(res.Warnings, Warning{Kind: WarnInstalled, Message: err.Error()})
		return
	}
	for _, p := range walk.Problems {
		res.Warnings = append(res.Warnings, Warning{Kind: WarnWalk, Manifest: p.Path, Message: p.Err.Error()})
	}
	res.Stats.HookFiles = len(walk.Manifests)
	for _, m := range walk.Manifests {
		data, err := readInside(realRoot, m.Path)
		if err != nil {
			res.Warnings = append(res.Warnings, Warning{Kind: WarnInstalled, Manifest: m.Path, Message: err.Error()})
			continue
		}
		auditHookFile(realRoot, m.Path, data, opts, res)
	}
}

func isProjectHook(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	switch base {
	case "package.json", "setup.py", "binding.gyp":
		return true
	}
	return strings.HasSuffix(base, ".pth")
}

func auditHookFile(realRoot, file string, data []byte, opts Options, res *Result) {
	base := strings.ToLower(filepath.Base(file))
	if base == "package.json" {
		pkg, err := installhook.ParsePackage(data)
		if err != nil {
			return // the manifest parser already warns on a broken package.json
		}
		name := pkg.Name
		if name == "" {
			name = npmDirName(filepath.Dir(file))
		}
		if ignoredName(opts, name) {
			res.Stats.Skipped++
			return
		}
		for _, script := range pkg.Scripts {
			addHookHits(res, "npm", name, pkg.Version, file, script.Name, script.Line, installhook.ScanScript(script.Body))
			for _, rel := range script.Files {
				followScript(realRoot, filepath.Dir(file), rel, "npm", name, pkg.Version, script.Name, res)
			}
		}
		return
	}
	name := filepath.Base(filepath.Dir(file))
	if ignoredName(opts, name) {
		res.Stats.Skipped++
		return
	}
	eco := "pypi"
	group := base
	if base == "binding.gyp" {
		eco = "npm"
	}
	addHookHits(res, eco, name, "", file, group, 0, installhook.ScanFile(base, data))
}

func followScript(realRoot, dir, rel, eco, name, version, group string, res *Result) {
	full := filepath.Join(dir, filepath.FromSlash(rel))
	relToDir, err := filepath.Rel(dir, full)
	if err != nil || relToDir == ".." || strings.HasPrefix(relToDir, ".."+string(filepath.Separator)) {
		return
	}
	data, err := readInside(realRoot, full)
	if err != nil {
		return // missing or outside the tree; the script body was already scanned
	}
	hits := installhook.ScanFile(filepath.Base(full), data)
	addHookHits(res, eco, name, version, full, group, 0, hits)
}

func addHookHits(res *Result, eco, name, version, file, group string, line int, hits []installhook.Hit) {
	for _, h := range hits {
		at := h.Line
		if line > 0 {
			at = line
		}
		res.Findings = append(res.Findings, Finding{
			Ecosystem:   eco,
			Package:     name,
			Version:     version,
			Manifest:    file,
			Line:        at,
			Group:       group,
			Reason:      ReasonInstallHook,
			Severity:    SeverityHigh,
			Kind:        h.Kind,
			Message:     h.Message,
			Remediation: installhook.Remediation(h.Kind),
		})
	}
}

type lockIndex struct {
	dir      string
	versions map[string]map[string]struct{}
}

// addLockedVersion records an npm lockfile entry for the installed-tree drift
// check. versions is keyed by the lockfile's directory.
func addLockedVersion(indexes map[string]*lockIndex, order *[]string, dir, name, version string) {
	if name == "" {
		return
	}
	dir = filepath.Clean(dir)
	idx := indexes[dir]
	if idx == nil {
		idx = &lockIndex{dir: dir, versions: map[string]map[string]struct{}{}}
		indexes[dir] = idx
		*order = append(*order, dir)
	}
	set := idx.versions[name]
	if set == nil {
		set = map[string]struct{}{}
		idx.versions[name] = set
	}
	ver := strings.TrimSpace(version)
	if ver == "" {
		set["*"] = struct{}{}
		return
	}
	set[ver] = struct{}{}
}

func nearestLock(locks []lockIndex, dir, root string) *lockIndex {
	dir = filepath.Clean(dir)
	root = filepath.Clean(root)
	for {
		for i := range locks {
			if locks[i].dir == dir {
				return &locks[i]
			}
		}
		if dir == root {
			return nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

type installedState struct {
	root      string
	realRoot  string
	exclude   *match.Matcher
	opts      Options
	res       *Result
	locks     []lockIndex
	seen      map[string]struct{}
	packages  int
	python    int
	truncated bool
}

func (st *installedState) walkSearch(dir string, depth int) {
	if depth > maxSearchDepth {
		st.truncated = true
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		st.res.Warnings = append(st.res.Warnings, Warning{Kind: WarnInstalled, Manifest: dir, Message: err.Error()})
		return
	}
	for _, e := range entries {
		name := e.Name()
		p := filepath.Join(dir, name)
		rel := installRel(st.root, p)
		if st.exclude != nil && (st.exclude.Match(rel) || st.exclude.Match(name)) {
			continue
		}
		isDir := e.IsDir()
		if e.Type()&os.ModeSymlink != 0 {
			if !insideRoot(st.realRoot, p) {
				continue
			}
			info, statErr := os.Stat(p)
			if statErr != nil || !info.IsDir() {
				continue
			}
			isDir = true
		}
		if !isDir {
			continue
		}
		switch name {
		case "node_modules":
			st.scanNodeModules(p)
		case ".venv", "venv", "site-packages":
			st.walkPython(p, 0)
		default:
			if _, skip := discover.SkipDirs[name]; skip {
				continue
			}
			st.walkSearch(p, depth+1)
		}
	}
}

func (st *installedState) scanNodeModules(dir string) {
	if st.seen == nil {
		st.seen = map[string]struct{}{}
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		st.res.Warnings = append(st.res.Warnings, Warning{Kind: WarnInstalled, Manifest: dir, Message: err.Error()})
		return
	}
	st.walkPackages(dir, real, 0)
}

func (st *installedState) walkPackages(dir, nodeModulesReal string, depth int) {
	if depth > maxPackageDepth || st.packages >= maxInstalledPackages {
		st.truncated = true
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		st.res.Warnings = append(st.res.Warnings, Warning{Kind: WarnInstalled, Manifest: dir, Message: err.Error()})
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == ".bin" || name == ".cache" {
			continue
		}
		if strings.HasPrefix(name, ".") && name != ".pnpm" {
			continue
		}
		p := filepath.Join(dir, name)
		if !st.enterDir(p, nodeModulesReal) {
			continue
		}
		pkgJSON := filepath.Join(p, "package.json")
		if _, err := os.Stat(pkgJSON); err == nil {
			st.inspectPackage(p, pkgJSON)
			nested := filepath.Join(p, "node_modules")
			if _, err := os.Stat(nested); err == nil {
				st.walkPackages(nested, nodeModulesReal, depth+1)
			}
			continue
		}
		st.walkPackages(p, nodeModulesReal, depth+1)
	}
}

// enterDir accepts a real directory, or a symlink that stays inside this
// node_modules tree. Workspace links point at the repo and are skipped.
// Each real path is visited once.
func (st *installedState) enterDir(p, nodeModulesReal string) bool {
	info, err := os.Lstat(p)
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(p)
		if err != nil || !insideRoot(nodeModulesReal, target) {
			return false
		}
		if _, seen := st.seen[target]; seen {
			return false
		}
		st.seen[target] = struct{}{}
		info, err = os.Stat(p)
		if err != nil || !info.IsDir() {
			return false
		}
		return true
	}
	if !info.IsDir() {
		return false
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		real = p
	}
	if _, seen := st.seen[real]; seen {
		return false
	}
	st.seen[real] = struct{}{}
	return true
}

func (st *installedState) inspectPackage(dir, pkgJSON string) {
	if st.packages >= maxInstalledPackages {
		st.truncated = true
		return
	}
	data, err := readInside(st.realRoot, pkgJSON)
	if err != nil {
		return
	}
	pkg, err := installhook.ParsePackage(data)
	if err != nil {
		st.res.Warnings = append(st.res.Warnings, Warning{Kind: WarnInstalled, Ecosystem: "npm", Manifest: pkgJSON, Message: err.Error()})
		return
	}
	st.packages++
	st.res.Stats.InstalledPackages++
	name := pkg.Name
	if name == "" {
		name = npmDirName(dir)
	}
	if ignoredName(st.opts, name) {
		st.res.Stats.Skipped++
		return
	}
	for _, script := range pkg.Scripts {
		addHookHits(st.res, "npm", name, pkg.Version, pkgJSON, script.Name, script.Line, installhook.ScanScript(script.Body))
		for _, rel := range script.Files {
			followScript(st.realRoot, dir, rel, "npm", name, pkg.Version, script.Name, st.res)
		}
	}
	for _, extra := range []string{"binding.gyp", "setup.py"} {
		extraPath := filepath.Join(dir, extra)
		body, err := readInside(st.realRoot, extraPath)
		if err != nil {
			continue
		}
		addHookHits(st.res, "npm", name, pkg.Version, extraPath, strings.ToLower(extra), 0, installhook.ScanFile(extra, body))
	}
	idx := nearestLock(st.locks, installedOwner(pkgJSON), st.root)
	if idx == nil {
		return
	}
	kind, msg := drift(name, pkg.Version, idx.versions)
	if kind == "" {
		return
	}
	st.res.Findings = append(st.res.Findings, Finding{
		Ecosystem:   "npm",
		Package:     name,
		Version:     pkg.Version,
		Manifest:    pkgJSON,
		Line:        1,
		Group:       "installed",
		Reason:      ReasonInstallHook,
		Severity:    SeverityHigh,
		Kind:        kind,
		Message:     msg,
		Remediation: installhook.Remediation(kind),
	})
}

func drift(name, version string, locked map[string]map[string]struct{}) (kind, msg string) {
	if name == "" || locked == nil {
		return "", ""
	}
	vers, found := locked[name]
	if !found {
		return installhook.KindNotInLockfile, installhook.Message(installhook.KindNotInLockfile)
	}
	if version == "" {
		return "", ""
	}
	if _, any := vers["*"]; any {
		return "", ""
	}
	if _, ok := vers[version]; ok {
		return "", ""
	}
	return installhook.KindVersionMismatch, installhook.MismatchMessage(version, vers)
}

// installedOwner is the project directory that owns this package: the parent
// of the nearest node_modules above pkgJSON.
func installedOwner(pkgJSON string) string {
	dir := filepath.Dir(pkgJSON)
	for {
		if filepath.Base(dir) == "node_modules" {
			return filepath.Dir(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return filepath.Dir(pkgJSON)
		}
		dir = parent
	}
}

func (st *installedState) walkPython(dir string, depth int) {
	if depth > maxPythonDepth || st.python >= maxPythonFiles {
		st.truncated = true
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		st.res.Warnings = append(st.res.Warnings, Warning{Kind: WarnInstalled, Manifest: dir, Message: err.Error()})
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == "node_modules" || name == "__pycache__" || strings.HasSuffix(name, ".dist-info") || strings.HasSuffix(name, ".egg-info") {
			continue
		}
		p := filepath.Join(dir, name)
		if e.IsDir() {
			if _, skip := discover.SkipDirs[name]; skip && name != "site-packages" && name != ".venv" && name != "venv" {
				continue
			}
			st.walkPython(p, depth+1)
			continue
		}
		lower := strings.ToLower(name)
		if lower != "setup.py" && !strings.HasSuffix(lower, ".pth") {
			continue
		}
		st.python++
		data, err := readInside(st.realRoot, p)
		if err != nil {
			continue
		}
		pkgName := strings.TrimSuffix(name, filepath.Ext(name))
		if lower == "setup.py" {
			pkgName = filepath.Base(filepath.Dir(p))
		}
		if ignoredName(st.opts, pkgName) {
			st.res.Stats.Skipped++
			continue
		}
		addHookHits(st.res, "pypi", pkgName, "", p, lower, 0, installhook.ScanFile(name, data))
	}
}

func ignoredName(opts Options, name string) bool {
	return opts.Ignore.Match(name)
}

func npmDirName(dir string) string {
	base := filepath.Base(dir)
	parent := filepath.Base(filepath.Dir(dir))
	if strings.HasPrefix(parent, "@") && parent != "@" {
		return parent + "/" + base
	}
	return base
}

func installRel(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == "." {
		return filepath.ToSlash(filepath.Base(p))
	}
	return filepath.ToSlash(rel)
}

func readInside(realRoot, p string) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 && !insideRoot(realRoot, p) {
		return nil, errOutsideRoot
	}
	return manifest.ReadFile(p)
}

var errOutsideRoot = errors.New("symlink resolves outside the scan root; skipped")

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
