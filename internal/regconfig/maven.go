package regconfig

import (
	"bytes"
	"regexp"
	"strings"
)

var (
	mavenPassword = regexp.MustCompile(`<password>\s*([^<]*?)\s*</password>`)
	mavenURL      = regexp.MustCompile(`<url>\s*([^<]*?)\s*</url>`)
)

// auditMavenSettings checks a Maven settings.xml for plaintext server
// passwords and plain-HTTP mirrors / repositories. Passwords encrypted with
// `mvn --encrypt-password` ({…}) and ${env.X} references are fine.
func auditMavenSettings(data []byte) []Issue {
	if !bytes.Contains(data, []byte("<settings")) {
		return nil
	}
	var out []Issue
	for i, l := range lines(data) {
		line := i + 1
		for _, m := range mavenPassword.FindAllStringSubmatch(l, -1) {
			v := m[1]
			if literal(v) && !(strings.HasPrefix(v, "{") && strings.HasSuffix(v, "}")) {
				out = append(out, Issue{Risk: RiskCredential, Setting: "password", Line: line,
					Message: "plaintext Maven server password in settings.xml"})
			}
		}
		for _, m := range mavenURL.FindAllStringSubmatch(l, -1) {
			out = append(out, urlIssues("url", m[1], line)...)
		}
	}
	return out
}
