// Package regconfig audits package-manager configuration files (.npmrc,
// pip.conf, composer.json, Gemfile, .cargo/config.toml, …) for settings that
// enable dependency confusion, leak registry credentials, or disable TLS.
// It is offline: files are read, nothing is fetched.
package regconfig

import (
	"net"
	"net/url"
	"path"
	"strings"

	"github.com/omni-line/omni-audit/internal/lockfile"
)

// Risks reported on issues.
const (
	// RiskExtraIndex is a resolver that merges several indexes and installs
	// the highest version it finds (pip --extra-index-url, pipenv
	// install_search_all_sources), so a public upload of an internal name wins.
	RiskExtraIndex = "extra_index"
	// RiskUnsafeIndexStrategy is a uv index strategy that looks past the
	// first index that has a package.
	RiskUnsafeIndexStrategy = "unsafe_index_strategy"
	// RiskNonCanonical is a Composer repository with "canonical": false, so
	// Composer also looks for its packages in later repositories (Packagist).
	RiskNonCanonical = "non_canonical_repository"
	// RiskMultipleSources is a Gemfile with more than one global source.
	RiskMultipleSources = "multiple_global_sources"
	// RiskCredential is a registry token or password written in plain text.
	RiskCredential = "plaintext_credential" //nolint:gosec // G101: a risk label, not a credential
	// RiskInsecure is a registry reached over plain HTTP or without TLS
	// verification.
	RiskInsecure = "insecure_transport"
)

// Issue is one risky setting in a configuration file.
type Issue struct {
	// Risk is one of the Risk* constants.
	Risk string
	// Setting is the key or flag as written (URLs have credentials redacted).
	Setting string
	// URL is the redacted registry URL the setting names, if any.
	URL string
	// Line is the 1-based line of the setting.
	Line int
	// Message explains the issue. It never contains a secret value.
	Message string
}

// File is a supported configuration file format.
type File struct {
	// Ecosystem is the stable ecosystem id (npm, pypi, composer, …).
	Ecosystem string
	// Match reports whether rel (slash-separated) is this kind of file.
	Match func(rel string) bool
	// Audit returns the risky settings in the file.
	Audit func(data []byte) []Issue
}

// Default returns the configuration files audited by omni-audit.
func Default() []File {
	return []File{
		{Ecosystem: "npm", Match: base(".npmrc"), Audit: auditNpmrc},
		{Ecosystem: "npm", Match: base(".yarnrc.yml", ".yarnrc.yaml"), Audit: auditYarnrcYML},
		{Ecosystem: "npm", Match: base(".yarnrc"), Audit: auditYarnrc},
		{Ecosystem: "pypi", Match: base("pip.conf", "pip.ini"), Audit: auditPipConf},
		{Ecosystem: "pypi", Match: isRequirements, Audit: auditRequirements},
		{Ecosystem: "pypi", Match: base("pyproject.toml"), Audit: auditPyProject},
		{Ecosystem: "pypi", Match: base("uv.toml"), Audit: auditUVToml},
		{Ecosystem: "pypi", Match: base("Pipfile"), Audit: auditPipfile},
		{Ecosystem: "pypi", Match: isBuildScript, Audit: auditBuildScript},
		{Ecosystem: "composer", Match: base("composer.json"), Audit: auditComposerJSON},
		{Ecosystem: "composer", Match: base("auth.json"), Audit: auditComposerAuth},
		{Ecosystem: "rubygems", Match: base("Gemfile", "gems.rb"), Audit: auditGemfile},
		{Ecosystem: "cargo", Match: isCargoConfig, Audit: auditCargo},
		{Ecosystem: "maven", Match: base("settings.xml"), Audit: auditMavenSettings},
	}
}

// Classify returns the ecosystem for a configuration file path, or "".
func Classify(files []File, rel string) string {
	if f, ok := find(files, rel); ok {
		return f.Ecosystem
	}
	return ""
}

// AuditFile audits data with the first file format that matches rel.
func AuditFile(files []File, rel string, data []byte) []Issue {
	if f, ok := find(files, rel); ok {
		return f.Audit(data)
	}
	return nil
}

// Remediation is the default fix for a risk.
func Remediation(risk string) string {
	switch risk {
	case RiskExtraIndex:
		return "Install from one index: point --index-url (or index-url in pip.conf) at a registry that serves both internal and public packages, and drop --extra-index-url. pip queries every index and installs the highest version, so a public upload of an internal name wins."
	case RiskUnsafeIndexStrategy:
		return "Remove the unsafe index strategy so uv uses its default first-index strategy, and list the internal index first."
	case RiskNonCanonical:
		return "Remove \"canonical\": false so Composer takes each package only from the first repository that provides it, or limit the repository with \"only\" / \"exclude\"."
	case RiskMultipleSources:
		return "Keep a single global source and declare internal gems inside a `source \"…\" do … end` block, so Bundler resolves each gem from exactly one source."
	case RiskCredential:
		return "Rotate the credential now, remove it from the file, and read it from an environment variable (for example ${NPM_TOKEN}) or a user-level config outside the repository."
	case RiskInsecure:
		return "Reach every registry over HTTPS with certificate verification on. Plain HTTP or disabled TLS lets anyone on the network replace packages in transit."
	}
	return ""
}

func find(files []File, rel string) (File, bool) {
	for _, f := range files {
		if f.Match(rel) {
			return f, true
		}
	}
	return File{}, false
}

func base(names ...string) func(string) bool {
	return func(rel string) bool {
		b := path.Base(rel)
		for _, n := range names {
			if strings.EqualFold(b, n) {
				return true
			}
		}
		return false
	}
}

// isRequirements matches the files the PyPI ecosystem reads as requirements,
// plus constraints files (they accept the same index options).
func isRequirements(rel string) bool {
	b := strings.ToLower(path.Base(rel))
	if !strings.HasSuffix(b, ".txt") {
		return false
	}
	return strings.HasPrefix(b, "requirements") || strings.HasPrefix(b, "constraints") ||
		strings.EqualFold(path.Base(path.Dir(rel)), "requirements")
}

// isBuildScript matches files that commonly run pip / uv: Dockerfiles, CI
// pipelines, Makefiles, and shell scripts.
func isBuildScript(rel string) bool {
	b := strings.ToLower(path.Base(rel))
	dir := strings.ToLower(path.Dir(rel))
	switch {
	case b == "dockerfile", b == "containerfile", strings.HasPrefix(b, "dockerfile."), strings.HasSuffix(b, ".dockerfile"):
		return true
	case b == ".gitlab-ci.yml", b == "bitbucket-pipelines.yml", b == "azure-pipelines.yml", b == "jenkinsfile", b == "makefile":
		return true
	case strings.HasSuffix(b, ".sh"):
		return true
	case strings.HasSuffix(dir, ".github/workflows") || strings.HasSuffix(dir, ".circleci"):
		return strings.HasSuffix(b, ".yml") || strings.HasSuffix(b, ".yaml")
	}
	return false
}

func isCargoConfig(rel string) bool {
	if path.Base(path.Dir(rel)) != ".cargo" {
		return false
	}
	switch path.Base(rel) {
	case "config", "config.toml", "credentials", "credentials.toml":
		return true
	}
	return false
}

// lines splits data into lines without trailing CR.
func lines(data []byte) []string {
	ls := strings.Split(string(data), "\n")
	for i, l := range ls {
		ls[i] = strings.TrimSuffix(l, "\r")
	}
	return ls
}

// unquote strips one pair of matching quotes.
func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// literal reports whether a configured secret is written out rather than
// read from the environment (${VAR}, $VAR, %VAR%) or left empty.
func literal(v string) bool {
	v = unquote(v)
	return v != "" && !strings.Contains(v, "${") && !strings.HasPrefix(v, "$") &&
		!(strings.HasPrefix(v, "%") && strings.HasSuffix(v, "%"))
}

func isFalse(v string) bool {
	return strings.EqualFold(unquote(v), "false")
}

// urlIssues reports plain-HTTP and embedded-credential problems for a
// registry URL found at line under setting.
func urlIssues(setting, raw string, line int) []Issue {
	raw = unquote(raw)
	u, ok := parseRegistryURL(raw)
	if !ok {
		return nil
	}
	safe := lockfile.RedactURL(raw)
	var out []Issue
	if u.Scheme == "http" && !loopback(u.Hostname()) {
		out = append(out, Issue{
			Risk: RiskInsecure, Setting: setting, URL: safe, Line: line,
			Message: "registry " + u.Hostname() + " is reached over plain HTTP",
		})
	}
	if credentialInURL(u) {
		out = append(out, Issue{
			Risk: RiskCredential, Setting: setting, URL: safe, Line: line,
			Message: "registry URL for " + u.Hostname() + " embeds a plaintext credential",
		})
	}
	return out
}

func parseRegistryURL(raw string) (*url.URL, bool) {
	for _, p := range []string{"sparse+", "registry+"} {
		raw = strings.TrimPrefix(raw, p)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, false
	}
	return u, true
}

// credentialInURL reports a literal password, or a username long enough to
// be a token (https://<token>@host), in the URL userinfo.
func credentialInURL(u *url.URL) bool {
	if u.User == nil {
		return false
	}
	if pass, ok := u.User.Password(); ok {
		return literal(pass)
	}
	name := u.User.Username()
	return len(name) >= 20 && literal(name)
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}
