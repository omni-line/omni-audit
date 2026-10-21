package regconfig

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
)

var (
	canonicalFalse  = regexp.MustCompile(`"canonical"\s*:\s*false`)
	secureHTTPFalse = regexp.MustCompile(`"secure-http"\s*:\s*false`)
)

type composerRepo struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Canonical *bool  `json:"canonical"`
}

// auditComposerJSON checks composer.json repositories and config. Composer
// treats repositories as canonical by default (a package found in one is
// never looked up in later ones); "canonical": false undoes that.
func auditComposerJSON(data []byte) []Issue {
	var doc struct {
		Repositories json.RawMessage `json:"repositories"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil // the composer ecosystem reports parse errors
	}
	var out []Issue
	for _, repo := range composerRepos(doc.Repositories) {
		if repo.Canonical != nil && !*repo.Canonical {
			out = append(out, Issue{Risk: RiskNonCanonical, Setting: "canonical", URL: repo.URL,
				Message: "repository " + repo.URL + " is not canonical, so Composer also looks for its packages in later repositories such as Packagist"})
		}
		if repo.URL != "" {
			out = append(out, urlIssues("repositories.url", repo.URL, lineOf(data, repo.URL))...)
		}
	}
	canonicalLines(out, canonicalFalse.FindAllIndex(data, -1), data)
	if loc := secureHTTPFalse.FindIndex(data); loc != nil {
		out = append(out, Issue{Risk: RiskInsecure, Setting: "secure-http", Line: lineAt(data, loc[0]),
			Message: "\"secure-http\": false lets Composer download packages over plain HTTP"})
	}
	return out
}

// canonicalLines assigns the n-th "canonical": false match to the n-th
// non-canonical issue, in file order.
func canonicalLines(issues []Issue, matches [][]int, data []byte) {
	n := 0
	for i := range issues {
		if issues[i].Risk != RiskNonCanonical {
			continue
		}
		if n < len(matches) {
			issues[i].Line = lineAt(data, matches[n][0])
		}
		n++
	}
}

// composerRepos decodes "repositories" as either a list or an object (the
// older keyed form). Entries such as {"packagist.org": false} are skipped.
// Object keys are visited in file order.
func composerRepos(raw json.RawMessage) []composerRepo {
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return nil
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return bytes.Index(raw, []byte(`"`+keys[i]+`"`)) < bytes.Index(raw, []byte(`"`+keys[j]+`"`))
		})
		for _, k := range keys {
			list = append(list, obj[k])
		}
	}
	var out []composerRepo
	for _, r := range list {
		var repo composerRepo
		if json.Unmarshal(r, &repo) == nil {
			out = append(out, repo)
		}
	}
	return out
}

// composerAuthKeys are the credential sections of a Composer auth.json.
var composerAuthKeys = []string{"http-basic", "github-oauth", "gitlab-token", "gitlab-oauth", "bitbucket-oauth", "bearer", "forgejo-token"}

// auditComposerAuth flags credentials in a Composer auth.json. Composer
// reads it from the project root, so a committed one is a leaked token.
// auth.json does not expand environment variables.
func auditComposerAuth(data []byte) []Issue {
	var doc map[string]json.RawMessage
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []Issue
	for _, k := range composerAuthKeys {
		raw, ok := doc[k]
		if !ok {
			continue
		}
		var hosts map[string]json.RawMessage
		if json.Unmarshal(raw, &hosts) != nil || len(hosts) == 0 {
			continue
		}
		out = append(out, Issue{Risk: RiskCredential, Setting: k, Line: lineOf(data, `"`+k+`"`),
			Message: "auth.json holds Composer " + k + " credentials"})
	}
	return out
}

// lineOf is the 1-based line of the first occurrence of s, or 0.
func lineOf(data []byte, s string) int {
	if s == "" {
		return 0
	}
	i := bytes.Index(data, []byte(s))
	if i < 0 {
		return 0
	}
	return lineAt(data, i)
}

func lineAt(data []byte, offset int) int {
	return bytes.Count(data[:offset], []byte("\n")) + 1
}
