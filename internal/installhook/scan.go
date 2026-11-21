// Package installhook finds install-time payloads in files that package
// managers execute: npm lifecycle scripts, the one local file they invoke,
// setup.py, .pth files, and binding.gyp.
//
// It is a heuristic. A hit means the file both can run code and contains a
// pattern common to install-time malware. It does not execute anything and
// does not download a package.
package installhook

import (
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Kinds reported on hits. Drift kinds are assigned by the scan orchestrator
// when an installed npm package disagrees with the lockfile; the messages
// and remediations live here so every output format shares them.
const (
	// KindShell is a shell downloader or a shell spawned next to an exec API
	// (curl, wget, bash -c, a pipe into a shell).
	KindShell = "shell_exec"
	// KindDecode is eval/exec/Function next to a base64 (or similar) decode.
	KindDecode = "decode_exec"
	// KindCredential is a credential path or token next to a network call.
	KindCredential = "credential_exfil"
	// KindNotInLockfile is an installed package the nearest lockfile does not name.
	KindNotInLockfile = "not_in_lockfile"
	// KindVersionMismatch is an installed version the nearest lockfile does not pin.
	KindVersionMismatch = "version_mismatch"
)

// shortFileLines is the size at which a source file is correlated as a
// whole. Longer files use a sliding window so a comment and an unrelated
// call do not combine.
const shortFileLines = 40

// correlateWindow is how many lines apart a capability and a payload may be
// in a long source file.
const correlateWindow = 12

// Hit is one pattern match. Line is 1-based within the scanned text.
type Hit struct {
	Kind    string
	Line    int
	Message string
}

// Script is one npm lifecycle script that runs on install.
type Script struct {
	Name  string
	Body  string
	Line  int
	Files []string // relative paths the script invokes, safe to open
}

// Package is the install-relevant slice of a package.json.
type Package struct {
	Name    string
	Version string
	Scripts []Script
}

// lifecycle scripts that run when a package is installed. prepare and
// prepublish run for local and git installs; prepublishOnly does not.
var lifecycle = []string{"preinstall", "install", "postinstall", "prepare", "prepublish"}

var (
	reShellCmd = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])(?:curl|wget|certutil)(?:\.exe)?(?:[^A-Za-z0-9_.]|$)`)
	reShellC   = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])(?:bash|dash|zsh|sh)\s+-c\b`)
	rePipeSh   = regexp.MustCompile(`(?i)\|\s*(?:bash|dash|zsh|sh)\b`)
	reBase64D  = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])base64\s+(?:-d|--decode)\b`)
	rePS       = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)(?:[^A-Za-z0-9_]|$)`)
	reCmd      = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])cmd(?:\.exe)?\s+/c\b`)
	reExecJS   = regexp.MustCompile(`(?:\bexec(?:Sync|File)?\s*\(|\bspawn(?:Sync)?\s*\(|child_process)`)
	reExecPy   = regexp.MustCompile(`(?i)(?:os\.system\s*\(|os\.popen\s*\(|subprocess\.(?:call|run|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\()`)
	reDynJS    = regexp.MustCompile(`(?:\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\()`)
	reDynPy    = regexp.MustCompile(`(?i)(?:\bexec\s*\(|\beval\s*\()`)
	reDecode   = regexp.MustCompile(`(?i)(?:base64|atob\s*\(|b64decode|fromCharCode\s*\(|Buffer\.from\s*\()`)
	reCred     = regexp.MustCompile(`(?i)(?:` +
		`\.npmrc|\.git-credentials|\bid_rsa\b|` +
		`(?:~|/|\\)\.ssh(?:/|\\|$)|` +
		`(?:~|/|\\)\.aws(?:/|\\|$)|` +
		`(?:~|/|\\)\.kube(?:/|\\|$)|` +
		`['"\x60](?:\./)?\.env['"\x60]|` +
		`(?:~|/|\\)\.env\b|` +
		`\b(?:NPM_TOKEN|NODE_AUTH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN)\b)`)
	reNet = regexp.MustCompile(`(?i)(?:https?://|\bfetch\s*\(|\bhttp\.get\s*\(|\bhttp\.request\s*\(|\bnet\.connect\s*\(|\brequests\.(?:get|post|put|patch|request)\s*\(|\burlopen\s*\(|\burllib\b|\bXMLHttpRequest\b|\baxios\b)`)
	// Interpreter plus a following token. Group 1 is an inline -e/-c flag;
	// group 2 is the argument (a file path, or the inline program).
	reInvoke = regexp.MustCompile(`(?i)(?:^|[;&|\s])((?:node|nodejs|python3?|bash|sh|pwsh|powershell)(?:\.exe)?)\s+(?:(-[eEc])\s+)?("[^"]+"|'[^']+'|\S+)`)
)

type lang int

const (
	langAny lang = iota
	langJS
	langPy
)

// Message describes a kind without quoting file contents.
func Message(kind string) string {
	switch kind {
	case KindShell:
		return "install script runs a shell downloader or pipes a command into a shell"
	case KindDecode:
		return "install script decodes a payload and executes it"
	case KindCredential:
		return "install script reads credentials and opens a network connection"
	case KindNotInLockfile:
		return "installed package is not in the nearest lockfile"
	case KindVersionMismatch:
		return "installed version is not pinned by the nearest lockfile"
	default:
		return ""
	}
}

// Remediation is the default fix for a kind.
func Remediation(kind string) string {
	switch kind {
	case KindNotInLockfile, KindVersionMismatch:
		return "Reinstall from the lockfile (npm ci, or yarn install --frozen-lockfile) so the tree matches what was reviewed. A package or version that exists only on disk was not part of that review."
	case KindShell, KindDecode, KindCredential:
		return "Treat the machine as compromised: remove the package, delete the installed tree, and reinstall from a trusted lockfile. Install scripts run before the application starts."
	default:
		return ""
	}
}

// MismatchMessage describes an installed version that is not locked.
// locked is the set of versions the lockfile pins for this name; a "*"
// entry means the lockfile names the package without a version.
func MismatchMessage(installed string, locked map[string]struct{}) string {
	msg := "installed version " + clip(installed) + " is not pinned by the nearest lockfile"
	vs := listVersions(locked)
	if len(vs) == 0 {
		return msg
	}
	return msg + " (locked " + vs + ")"
}

// ScanFile scans a source file. name is used only to pick the language and
// whether the whole file is an install script (.pth, binding.gyp, shell).
func ScanFile(name string, data []byte) []Hit {
	return scanText(name, data, scriptFile(name), language(name))
}

// ScanScript scans one lifecycle-script body. The body is executed by the
// package manager, so a shell token anywhere in it is a hit.
func ScanScript(body string) []Hit {
	return scanText("install-script.sh", []byte(body), true, langAny)
}

// ParsePackage reads name, version, and lifecycle scripts from package.json.
func ParsePackage(data []byte) (Package, error) {
	var raw struct {
		Name    string                     `json:"name"`
		Version string                     `json:"version"`
		Scripts map[string]json.RawMessage `json:"scripts"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return Package{}, err
	}
	pkg := Package{Name: strings.TrimSpace(raw.Name), Version: strings.TrimSpace(raw.Version)}
	for _, name := range lifecycle {
		rawBody, ok := raw.Scripts[name]
		if !ok {
			continue
		}
		var body string
		if err := json.Unmarshal(rawBody, &body); err != nil {
			continue // not a string; ignore rather than fail the package
		}
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		pkg.Scripts = append(pkg.Scripts, Script{
			Name:  name,
			Body:  body,
			Line:  jsonKeyLine(data, name),
			Files: scriptFiles(body),
		})
	}
	return pkg, nil
}

func scanText(name string, data []byte, script bool, language lang) []Hit {
	if !utf8.Valid(data) {
		data = []byte(strings.ToValidUTF8(string(data), ""))
	}
	lines := strings.Split(string(data), "\n")
	if script || len(lines) <= shortFileLines {
		return correlate(lines, script, language)
	}
	seen := map[string]bool{}
	var hits []Hit
	for start := 0; start < len(lines); start++ {
		end := start + correlateWindow
		if end > len(lines) {
			end = len(lines)
		}
		for _, h := range correlate(lines[start:end], script, language) {
			if seen[h.Kind] {
				continue
			}
			seen[h.Kind] = true
			h.Line += start
			hits = append(hits, h)
		}
		if len(seen) == 3 {
			break
		}
	}
	return hits
}

func correlate(lines []string, script bool, language lang) []Hit {
	var shellLine, dynLine, credLine int
	var shell, exec, dynamic, decode, cred, net bool
	for i, line := range lines {
		s := classify(line, language)
		n := i + 1
		if s.shell && shellLine == 0 {
			shell, shellLine = true, n
		}
		if s.exec {
			exec = true
		}
		if s.dynamic && dynLine == 0 {
			dynamic, dynLine = true, n
		}
		if s.decode {
			decode = true
		}
		if s.cred && credLine == 0 {
			cred, credLine = true, n
		}
		if s.net {
			net = true
		}
	}
	var hits []Hit
	if shell && (script || exec) {
		hits = append(hits, hit(KindShell, shellLine))
	}
	if dynamic && decode {
		hits = append(hits, hit(KindDecode, dynLine))
	}
	if cred && net {
		hits = append(hits, hit(KindCredential, credLine))
	}
	return hits
}

type signals struct {
	shell, exec, dynamic, decode, cred, net bool
}

func classify(line string, language lang) signals {
	var s signals
	s.shell = reShellCmd.MatchString(line) || reShellC.MatchString(line) || rePipeSh.MatchString(line) ||
		reBase64D.MatchString(line) || rePS.MatchString(line) || reCmd.MatchString(line)
	s.decode = reDecode.MatchString(line)
	s.cred = reCred.MatchString(line)
	s.net = reNet.MatchString(line)
	switch language {
	case langJS:
		s.exec = reExecJS.MatchString(line)
		s.dynamic = reDynJS.MatchString(line)
	case langPy:
		s.exec = reExecPy.MatchString(line)
		s.dynamic = reDynPy.MatchString(line)
	default:
		s.exec = reExecJS.MatchString(line) || reExecPy.MatchString(line)
		s.dynamic = reDynJS.MatchString(line) || reDynPy.MatchString(line)
	}
	return s
}

func hit(kind string, line int) Hit {
	return Hit{Kind: kind, Line: line, Message: Message(kind)}
}

func scriptFile(name string) bool {
	base := strings.ToLower(path.Base(name))
	switch base {
	case "binding.gyp":
		return true
	}
	switch path.Ext(base) {
	case ".pth", ".sh", ".bash", ".ps1", ".bat", ".cmd":
		return true
	}
	return false
}

func language(name string) lang {
	switch strings.ToLower(path.Ext(name)) {
	case ".js", ".mjs", ".cjs":
		return langJS
	case ".py", ".pth":
		return langPy
	default:
		return langAny
	}
}

// scriptFiles returns relative paths a lifecycle script launches.
// Inline programs (-e, -c) and anything that leaves the package directory
// are omitted.
func scriptFiles(body string) []string {
	matches := reInvoke.FindAllStringSubmatch(body, -1)
	var out []string
	seen := map[string]struct{}{}
	for _, m := range matches {
		if m[2] != "" {
			continue // -e / -c is inline; the body itself is scanned
		}
		p := strings.TrimSpace(strings.Trim(m[3], `"'`))
		p = path.Clean(strings.ReplaceAll(p, "\\", "/"))
		if !safeRel(p) {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
		if len(out) == 8 {
			break
		}
	}
	return out
}

func safeRel(p string) bool {
	if p == "" || p == "." {
		return false
	}
	if strings.ContainsAny(p, "*?$~") || strings.Contains(p, "://") {
		return false
	}
	if path.IsAbs(p) || strings.HasPrefix(p, "/") {
		return false
	}
	if p == ".." || strings.HasPrefix(p, "../") {
		return false
	}
	return true
}

// jsonKeyLine finds the line of `"key":`. It is a textual search, good enough
// to point a finding at a lifecycle script.
func jsonKeyLine(data []byte, key string) int {
	needle := []byte(`"` + key + `"`)
	from := 0
	for from < len(data) {
		rel := bytes.Index(data[from:], needle)
		if rel < 0 {
			return 0
		}
		i := from + rel
		j := i + len(needle)
		for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\r' || data[j] == '\n') {
			j++
		}
		if j < len(data) && data[j] == ':' {
			return bytes.Count(data[:i], []byte{'\n'}) + 1
		}
		from = i + 1
	}
	return 0
}

func listVersions(locked map[string]struct{}) string {
	var vs []string
	for v := range locked {
		if v == "" || v == "*" {
			continue
		}
		vs = append(vs, clip(v))
	}
	sort.Strings(vs)
	if len(vs) > 3 {
		vs = append(vs[:3], "…")
	}
	return strings.Join(vs, ", ")
}

func clip(s string) string {
	if len(s) > 256 {
		return s[:256]
	}
	return s
}
