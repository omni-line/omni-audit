package regconfig

import (
	"regexp"
	"strings"
)

// npmAuthKeys are .npmrc keys whose values are credentials. They are
// usually scoped to a registry: //npm.acme.corp/:_authToken=…
var npmAuthKeys = map[string]struct{}{
	"_authtoken": {},
	"_auth":      {},
	"_password":  {},
}

// auditNpmrc checks an .npmrc (ini-style key=value) for literal auth
// tokens, plain-HTTP registries, and strict-ssl=false.
func auditNpmrc(data []byte) []Issue {
	var out []Issue
	for i, l := range lines(data) {
		key, value, ok := iniPair(l)
		if !ok {
			continue
		}
		line := i + 1
		attr := key
		if j := strings.LastIndex(key, ":"); j >= 0 && strings.HasPrefix(key, "//") {
			attr = key[j+1:]
		}
		switch {
		case isNpmAuthKey(attr):
			if literal(value) {
				out = append(out, Issue{
					Risk: RiskCredential, Setting: key, Line: line,
					Message: "plaintext npm credential (" + attr + ") in .npmrc",
				})
			}
		case key == "registry" || strings.HasSuffix(key, ":registry"):
			out = append(out, urlIssues(key, value, line)...)
		case key == "strict-ssl" && isFalse(value):
			out = append(out, Issue{
				Risk: RiskInsecure, Setting: key, Line: line,
				Message: "strict-ssl=false disables TLS certificate checks for npm registries",
			})
		}
	}
	return out
}

func isNpmAuthKey(attr string) bool {
	_, ok := npmAuthKeys[strings.ToLower(attr)]
	return ok
}

// iniPair parses "key = value" lines, skipping blanks, comments, and
// section headers. Keys keep their case; values are trimmed.
func iniPair(l string) (key, value string, ok bool) {
	t := strings.TrimSpace(l)
	if t == "" || t[0] == '#' || t[0] == ';' || t[0] == '[' {
		return "", "", false
	}
	key, value, ok = strings.Cut(t, "=")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(key), strings.TrimSpace(value), true
}

var yarnSetting = regexp.MustCompile(`^\s*"?(npmAuthToken|npmAuthIdent|npmRegistryServer|enableStrictSsl|unsafeHttpWhitelist)"?\s*:\s*(.*?)\s*$`)

// auditYarnrcYML checks a Yarn Berry .yarnrc.yml. The keys are the same at
// the top level and under npmScopes / npmRegistries, so a line match covers
// both.
func auditYarnrcYML(data []byte) []Issue {
	var out []Issue
	for i, l := range lines(data) {
		m := yarnSetting.FindStringSubmatch(stripYAMLComment(l))
		if m == nil {
			continue
		}
		key, value, line := m[1], m[2], i+1
		switch key {
		case "npmAuthToken", "npmAuthIdent":
			if literal(value) {
				out = append(out, Issue{
					Risk: RiskCredential, Setting: key, Line: line,
					Message: "plaintext Yarn registry credential (" + key + ") in .yarnrc.yml",
				})
			}
		case "npmRegistryServer":
			out = append(out, urlIssues(key, value, line)...)
		case "enableStrictSsl":
			if isFalse(value) {
				out = append(out, Issue{
					Risk: RiskInsecure, Setting: key, Line: line,
					Message: "enableStrictSsl: false disables TLS certificate checks for Yarn registries",
				})
			}
		case "unsafeHttpWhitelist":
			out = append(out, Issue{
				Risk: RiskInsecure, Setting: key, Line: line,
				Message: "unsafeHttpWhitelist lets Yarn fetch packages over plain HTTP",
			})
		}
	}
	return out
}

// auditYarnrc checks a Yarn classic .yarnrc (`key value` lines).
func auditYarnrc(data []byte) []Issue {
	var out []Issue
	for i, l := range lines(data) {
		t := strings.TrimSpace(l)
		if t == "" || t[0] == '#' {
			continue
		}
		key, value, ok := strings.Cut(t, " ")
		if !ok {
			continue
		}
		key, value = unquote(key), strings.TrimSpace(value)
		switch {
		case key == "registry" || strings.HasSuffix(key, ":registry"):
			out = append(out, urlIssues(key, value, i+1)...)
		case key == "strict-ssl" && isFalse(value):
			out = append(out, Issue{
				Risk: RiskInsecure, Setting: key, Line: i + 1,
				Message: "strict-ssl false disables TLS certificate checks for Yarn registries",
			})
		}
	}
	return out
}

// stripYAMLComment drops a trailing " # comment" from a YAML line.
func stripYAMLComment(l string) string {
	if strings.HasPrefix(strings.TrimSpace(l), "#") {
		return ""
	}
	if i := strings.Index(l, " #"); i >= 0 {
		return l[:i]
	}
	return l
}
