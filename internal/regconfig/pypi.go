package regconfig

import (
	"regexp"
	"strings"
)

const extraIndexMessage = "pip queries every index and installs the highest version it finds, so a public package with an internal name wins"

// auditPipConf checks pip.conf / pip.ini. Values may continue on indented
// lines (one URL per line).
func auditPipConf(data []byte) []Issue {
	var out []Issue
	key := ""
	for i, l := range lines(data) {
		line := i + 1
		t := strings.TrimSpace(l)
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		var value string
		if l[0] == ' ' || l[0] == '\t' {
			if key == "" {
				continue
			}
			value = t // continuation of the previous key
		} else {
			k, v, ok := iniPair(l)
			if !ok {
				key = ""
				continue
			}
			key, value = strings.ReplaceAll(strings.ToLower(k), "_", "-"), v
			switch key {
			case "extra-index-url":
				out = append(out, Issue{Risk: RiskExtraIndex, Setting: key, Line: line, Message: "pip.conf sets extra-index-url: " + extraIndexMessage})
			case "trusted-host":
				out = append(out, trustedHost(key, line))
			}
		}
		if key == "index-url" || key == "extra-index-url" || key == "find-links" {
			for _, u := range strings.Fields(value) {
				out = append(out, urlIssues(key, u, line)...)
			}
		}
	}
	return out
}

// auditRequirements checks index options in requirements / constraints files.
func auditRequirements(data []byte) []Issue {
	var out []Issue
	for i, l := range lines(data) {
		if j := strings.Index(l, " #"); j >= 0 {
			l = l[:j]
		}
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		out = append(out, pipFlags(fieldsOf(l, i+1), "requirements file", false)...)
	}
	return out
}

// field is a whitespace-separated word and the 1-based line it is on.
type field struct {
	text string
	line int
}

func fieldsOf(l string, line int) []field {
	var out []field
	for _, f := range strings.Fields(l) {
		out = append(out, field{f, line})
	}
	return out
}

// pipFlags checks pip command-line style index options in fields. When uv
// is true the command is uv, whose default first-index strategy makes
// --extra-index-url safe.
func pipFlags(fields []field, where string, uv bool) []Issue {
	var out []Issue
	for j, f := range fields {
		flag, value, hasValue := strings.Cut(f.text, "=")
		if !hasValue && j+1 < len(fields) {
			value = fields[j+1].text
		}
		line := f.line
		switch flag {
		case "--extra-index-url":
			if !uv {
				out = append(out, Issue{Risk: RiskExtraIndex, Setting: flag, Line: line, Message: where + " uses --extra-index-url: " + extraIndexMessage})
			}
			out = append(out, urlIssues(flag, value, line)...)
		case "-i", "--index-url", "--index", "--default-index", "-f", "--find-links":
			out = append(out, urlIssues(flag, value, line)...)
		case "--trusted-host", "--allow-insecure-host":
			out = append(out, trustedHost(flag, line))
		case "--index-strategy":
			if v := unquote(value); strings.HasPrefix(v, "unsafe-") {
				out = append(out, unsafeStrategy(flag, v, line))
			}
		}
	}
	return out
}

var (
	// envAssign matches VAR=value, VAR: value, and ENV VAR value forms, but
	// not $VAR / ${VAR} references.
	envAssign = regexp.MustCompile(`(?:^|[^$\w{])(PIP_EXTRA_INDEX_URL|PIP_TRUSTED_HOST|UV_INDEX_STRATEGY|UV_INSECURE_HOST)\b["']?\s*[:= ]\s*["']?([^\s"']*)`)
	// pipCommand and uvCommand find pip / uv invocations in a shell command.
	pipCommand = regexp.MustCompile(`(^|[\s;&|(/])pip3?(\.\d+)?\s`)
	uvCommand  = regexp.MustCompile(`(^|[\s;&|(/])uv\s`)
)

// auditBuildScript checks Dockerfiles, CI pipelines, Makefiles, and shell
// scripts for pip / uv index options on install commands and in env vars.
// Backslash-continued lines are joined so flags on later lines keep the
// command they belong to; issues carry the physical line of the flag.
func auditBuildScript(data []byte) []Issue {
	var out []Issue
	var cmd []field
	var text strings.Builder
	flush := func() {
		t := text.String()
		if uv := uvCommand.MatchString(t); uv || pipCommand.MatchString(t) {
			out = append(out, pipFlags(cmd, "install command", uv)...)
		}
		cmd, text = nil, strings.Builder{}
	}
	for i, l := range lines(data) {
		t := strings.TrimSpace(l)
		if t == "" || t[0] == '#' || strings.HasPrefix(t, "//") {
			if len(cmd) > 0 && t == "" {
				flush()
			}
			continue
		}
		line := i + 1
		for _, m := range envAssign.FindAllStringSubmatch(t, -1) {
			switch m[1] {
			case "PIP_EXTRA_INDEX_URL":
				out = append(out, Issue{Risk: RiskExtraIndex, Setting: m[1], Line: line, Message: "PIP_EXTRA_INDEX_URL is set: " + extraIndexMessage})
				out = append(out, urlIssues(m[1], m[2], line)...)
			case "PIP_TRUSTED_HOST", "UV_INSECURE_HOST":
				out = append(out, trustedHost(m[1], line))
			case "UV_INDEX_STRATEGY":
				if strings.HasPrefix(m[2], "unsafe-") {
					out = append(out, unsafeStrategy(m[1], m[2], line))
				}
			}
		}
		cont := strings.HasSuffix(t, "\\")
		t = strings.TrimSuffix(t, "\\")
		cmd = append(cmd, fieldsOf(t, line)...)
		text.WriteString(" " + t + " ")
		if !cont {
			flush()
		}
	}
	if len(cmd) > 0 {
		flush()
	}
	return out
}

var (
	tomlSection  = regexp.MustCompile(`^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(#.*)?$`)
	tomlKeyValue = regexp.MustCompile(`^\s*"?([A-Za-z0-9_.-]+)"?\s*=\s*(.*?)\s*$`)
	quotedURL    = regexp.MustCompile(`["'](https?://[^"']+)["']`)
)

// auditPyProject checks the uv and Poetry index settings in pyproject.toml.
func auditPyProject(data []byte) []Issue {
	return auditPythonTOML(data, func(section string) bool {
		return section == "tool.uv" || strings.HasPrefix(section, "tool.uv.") ||
			section == "tool.poetry.source" || section == "tool.pdm.source"
	}, "tool.uv")
}

// auditUVToml checks uv.toml, where uv settings live at the top level.
func auditUVToml(data []byte) []Issue {
	return auditPythonTOML(data, func(string) bool { return true }, "")
}

// auditPythonTOML checks index URLs in the sections inScope accepts, and
// index-strategy in strategySection.
func auditPythonTOML(data []byte, inScope func(section string) bool, strategySection string) []Issue {
	var out []Issue
	section := ""
	for i, l := range lines(data) {
		line := i + 1
		if m := tomlSection.FindStringSubmatch(l); m != nil {
			section = m[1]
			continue
		}
		if !inScope(section) {
			continue
		}
		kv := tomlKeyValue.FindStringSubmatch(l)
		if kv != nil && kv[1] == "index-strategy" && section == strategySection {
			if v := unquote(stripTOMLComment(kv[2])); strings.HasPrefix(v, "unsafe-") {
				out = append(out, unsafeStrategy(kv[1], v, line))
			}
		}
		setting := "url"
		if kv != nil {
			setting = kv[1]
		}
		for _, m := range quotedURL.FindAllStringSubmatch(l, -1) {
			out = append(out, urlIssues(setting, m[1], line)...)
		}
	}
	return out
}

// auditPipfile checks Pipfile sources and the pipenv option that makes it
// search every source for every package.
func auditPipfile(data []byte) []Issue {
	var out []Issue
	section := ""
	for i, l := range lines(data) {
		line := i + 1
		if m := tomlSection.FindStringSubmatch(l); m != nil {
			section = m[1]
			continue
		}
		kv := tomlKeyValue.FindStringSubmatch(l)
		if kv == nil {
			continue
		}
		switch {
		case section == "pipenv" && kv[1] == "install_search_all_sources" && strings.EqualFold(unquote(stripTOMLComment(kv[2])), "true"):
			out = append(out, Issue{Risk: RiskExtraIndex, Setting: kv[1], Line: line,
				Message: "install_search_all_sources = true makes pipenv search every [[source]] for every package, so a public upload of an internal name can win"})
		case section == "source" && kv[1] == "url":
			out = append(out, urlIssues(kv[1], stripTOMLComment(kv[2]), line)...)
		case section == "source" && kv[1] == "verify_ssl" && isFalse(stripTOMLComment(kv[2])):
			out = append(out, Issue{Risk: RiskInsecure, Setting: kv[1], Line: line,
				Message: "verify_ssl = false disables TLS certificate checks for this Pipfile source"})
		}
	}
	return out
}

func trustedHost(setting string, line int) Issue {
	return Issue{Risk: RiskInsecure, Setting: setting, Line: line,
		Message: setting + " disables TLS certificate checks (and allows plain HTTP) for a package index"}
}

func unsafeStrategy(setting, value string, line int) Issue {
	return Issue{Risk: RiskUnsafeIndexStrategy, Setting: setting, Line: line,
		Message: "uv index strategy " + value + " looks past the first index that has a package, so a public upload of an internal name can win"}
}
