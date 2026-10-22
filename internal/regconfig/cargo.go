package regconfig

import "strings"

// auditCargo checks .cargo/config.toml and .cargo/credentials.toml for
// literal registry tokens and plain-HTTP registry indexes.
func auditCargo(data []byte) []Issue {
	var out []Issue
	for i, l := range lines(data) {
		kv := tomlKeyValue.FindStringSubmatch(l)
		if kv == nil || strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		line := i + 1
		switch kv[1] {
		case "token":
			if literal(stripTOMLComment(kv[2])) {
				out = append(out, Issue{Risk: RiskCredential, Setting: kv[1], Line: line,
					Message: "plaintext Cargo registry token in .cargo configuration"})
			}
		case "index":
			out = append(out, urlIssues(kv[1], stripTOMLComment(kv[2]), line)...)
		}
	}
	return out
}

// stripTOMLComment drops a trailing comment after a quoted value.
func stripTOMLComment(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 0 && (v[0] == '"' || v[0] == '\'') {
		if j := strings.IndexByte(v[1:], v[0]); j >= 0 {
			return v[:j+2]
		}
	}
	if j := strings.Index(v, " #"); j >= 0 {
		return strings.TrimSpace(v[:j])
	}
	return v
}
