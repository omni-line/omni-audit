package regconfig_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/omni-line/omni-audit/internal/regconfig"
)

// got renders issues as "risk@line" for compact comparisons.
func got(issues []regconfig.Issue) string {
	parts := make([]string, len(issues))
	for i, is := range issues {
		parts[i] = fmt.Sprintf("%s@%d", is.Risk, is.Line)
	}
	return strings.Join(parts, " ")
}

func TestAuditFile(t *testing.T) {
	files := regconfig.Default()
	cases := []struct {
		name, rel, data, want string
	}{
		{"npmrc", ".npmrc", `registry=https://npm.acme.corp/
@acme:registry=http://npm.acme.corp/
//npm.acme.corp/:_authToken=not-a-real-token
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
; comment
_auth = "dXNlcjpwYXNz"
strict-ssl=false
registry=http://localhost:4873/`,
			"insecure_transport@2 plaintext_credential@3 plaintext_credential@6 insecure_transport@7"},
		{"npmrc clean", "web/.npmrc", "@acme:registry=https://npm.acme.corp/\n//npm.acme.corp/:_authToken=${NPM_TOKEN}\n", ""},
		{"yarnrc.yml", ".yarnrc.yml", `npmRegistryServer: "http://npm.acme.corp"
npmAuthToken: "${NPM_TOKEN}"
npmScopes:
  acme:
    npmAuthToken: not-a-real-token # oops
    npmAuthIdent: "${IDENT}"
enableStrictSsl: false
unsafeHttpWhitelist:
  - "*.acme.corp"
# npmAuthToken: commented-out`,
			"insecure_transport@1 plaintext_credential@5 insecure_transport@7 insecure_transport@8"},
		{"yarnrc classic", ".yarnrc", "registry \"http://npm.acme.corp/\"\nstrict-ssl false\n# registry http://x\n", "insecure_transport@1 insecure_transport@2"},
		{"pip.conf", "pip.conf", `[global]
index-url = https://user:not-a-real-password@pypi.acme.corp/simple
extra_index_url =
    https://pypi.org/simple
    http://mirror.acme.corp/simple
trusted-host = mirror.acme.corp
timeout = 60`,
			"plaintext_credential@2 extra_index@3 insecure_transport@5 insecure_transport@6"},
		{"pip.ini env creds", "pip.ini", "[global]\nindex-url = https://${PIP_USER}:${PIP_PASSWORD}@pypi.acme.corp/simple\n", ""},
		{"requirements", "requirements/dev.txt", `-i https://pypi.acme.corp/simple
--extra-index-url=https://pypi.org/simple
--trusted-host pypi.acme.corp
requests==2.32.3  # --extra-index-url in a comment
# --extra-index-url https://x`,
			"extra_index@2 insecure_transport@3"},
		{"constraints", "constraints.txt", "--index-url http://pypi.acme.corp/simple\n", "insecure_transport@1"},
		{"not requirements", "notes.txt", "--extra-index-url https://x\n", ""},
		{"dockerfile", "docker/Dockerfile.ci", `FROM python:3.12
RUN pip install \
    --extra-index-url https://download.pytorch.org/whl/cu121 \
    torch
RUN uv pip install --extra-index-url https://pypi.acme.corp/simple acme-sdk
RUN uv sync --index-strategy unsafe-best-match
RUN curl -i http://example.com/install.sh | sh
ENV PIP_TRUSTED_HOST=pypi.acme.corp
RUN echo $PIP_EXTRA_INDEX_URL`,
			"extra_index@3 unsafe_index_strategy@6 insecure_transport@8"},
		{"workflow", ".github/workflows/ci.yaml", `env:
  PIP_EXTRA_INDEX_URL: https://pypi.acme.corp/simple
  UV_INDEX_STRATEGY: unsafe-first-match
steps:
  - run: python -m pip install --extra-index-url "$EXTRA" -r requirements.txt`,
			"extra_index@2 unsafe_index_strategy@3 extra_index@5"},
		{"other yaml", "config/app.yml", "PIP_EXTRA_INDEX_URL: x\n", ""},
		{"pyproject", "pyproject.toml", `[project]
dependencies = ["requests"]
urls = { homepage = "http://acme.example" }

[tool.uv]
index-strategy = "unsafe-best-match" # see docs

[[tool.uv.index]]
url = "http://pypi.acme.corp/simple"

[[tool.poetry.source]]
name = "acme"
url = "https://ci:not-a-real-password@pypi.acme.corp/simple"`,
			"unsafe_index_strategy@6 insecure_transport@9 plaintext_credential@13"},
		{"uv.toml", "uv.toml", "index-strategy = 'unsafe-first-match'\n[[index]]\nurl = \"http://127.0.0.1:8080/simple\"\n", "unsafe_index_strategy@1"},
		{"pipfile", "Pipfile", `[[source]]
url = "http://pypi.acme.corp/simple"
verify_ssl = false

[pipenv]
install_search_all_sources = true # search everything`,
			"insecure_transport@2 insecure_transport@3 extra_index@6"},
		{"pipfile default", "Pipfile", "[[source]]\nurl = \"https://pypi.org/simple\"\n[[source]]\nurl = \"https://pypi.acme.corp/simple\"\n", ""},
		{"composer", "composer.json", `{
  "repositories": [
    {"packagist.org": false},
    {"type": "composer", "url": "https://repo.acme.corp", "canonical": true},
    {"type": "composer", "url": "https://mirror.acme.corp", "canonical": false},
    {"type": "vcs", "url": "http://git.acme.corp/tools.git"}
  ],
  "funding": [{"type": "custom", "url": "http://acme.example/fund"}],
  "config": {"secure-http": false}
}`,
			"non_canonical_repository@5 insecure_transport@6 insecure_transport@9"},
		{"composer keyed repositories", "composer.json", `{
  "repositories": {
    "b-first": {"type": "composer", "url": "https://one.acme.corp", "canonical": false},
    "a-second": {"type": "composer", "url": "https://two.acme.corp", "canonical": false}
  }
}`,
			"non_canonical_repository@3 non_canonical_repository@4"},
		{"composer invalid", "composer.json", "{", ""},
		{"auth.json", "auth.json", `{
  "github-oauth": {"github.com": "not-a-real-token"},
  "http-basic": {}
}`, "plaintext_credential@2"},
		{"unrelated auth.json", "frontend/auth.json", `{"clientId": "web"}`, ""},
		{"gemfile", "Gemfile", `source "https://rubygems.org"
source('http://gems.acme.corp')

source "https://gems.acme.corp" do
  gem "acme-internal"
end
source "https://gems.acme.corp" do gem "x" end`,
			"insecure_transport@2 multiple_global_sources@2"},
		{"gemfile single", "gems.rb", "source \"https://rubygems.org\"\nsource \"https://gems.acme.corp\" {\n}\n", ""},
		{"cargo config", ".cargo/config.toml", `[registries.acme]
index = "sparse+http://cargo.acme.corp/index/" # internal
token = "not-a-real-token"

[registry]
token = "${CARGO_TOKEN}"`,
			"insecure_transport@2 plaintext_credential@3"},
		{"cargo credentials", "crates/.cargo/credentials", "[registry]\ntoken = 'not-a-real-token'\n", "plaintext_credential@2"},
		{"not cargo", "config.toml", "token = \"x\"\n", ""},
		{"maven", ".mvn/settings.xml", `<settings>
  <servers>
    <server><password>not-a-real-password</password></server>
    <server><password>${env.MAVEN_PASSWORD}</password></server>
    <server><password>{COQLCE6DU6GtcS5P=}</password></server>
  </servers>
  <mirrors><mirror><url>http://maven.acme.corp/repo</url></mirror></mirrors>
</settings>`,
			"plaintext_credential@3 insecure_transport@7"},
		{"not maven", "app/settings.xml", "<config><password>x</password></config>", ""},
		{"unsupported", "README.md", "--extra-index-url https://x", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues := regconfig.AuditFile(files, tc.rel, []byte(tc.data))
			if g := got(issues); g != tc.want {
				t.Fatalf("issues = %q, want %q\n%+v", g, tc.want, issues)
			}
			for _, is := range issues {
				if is.Message == "" || is.Setting == "" {
					t.Errorf("issue lacks detail: %+v", is)
				}
				if strings.Contains(is.Message+is.Setting+is.URL, "not-a-real") {
					t.Errorf("issue leaks a secret: %+v", is)
				}
				if regconfig.Remediation(is.Risk) == "" {
					t.Errorf("no remediation for %s", is.Risk)
				}
			}
		})
	}
}

func TestClassify(t *testing.T) {
	files := regconfig.Default()
	for rel, want := range map[string]string{
		".npmrc":                       "npm",
		"pkg/.yarnrc.yml":              "npm",
		"pip.conf":                     "pypi",
		"requirements.txt":             "pypi",
		"Containerfile":                "pypi",
		"scripts/bootstrap.sh":         "pypi",
		".circleci/config.yml":         "pypi",
		"composer.json":                "composer",
		"Gemfile":                      "rubygems",
		".cargo/config":                "cargo",
		"settings.xml":                 "maven",
		"package.json":                 "",
		".github/actions/x/action.yml": "",
	} {
		if g := regconfig.Classify(files, rel); g != want {
			t.Errorf("Classify(%q) = %q, want %q", rel, g, want)
		}
	}
	if regconfig.AuditFile(files, "package.json", []byte("{}")) != nil {
		t.Error("unsupported file audited")
	}
	if regconfig.Remediation("nope") != "" {
		t.Error("unknown risk has a remediation")
	}
}

// Credentials are redacted from the URL kept on the issue.
func TestURLRedacted(t *testing.T) {
	issues := regconfig.AuditFile(regconfig.Default(), "requirements.txt",
		[]byte("--extra-index-url https://deploy:not-a-real-password@pypi.acme.corp/simple\n--index-url https://abcdefghijklmnopqrstuvwxyz@pypi.acme.corp/simple\n"))
	if g := got(issues); g != "extra_index@1 plaintext_credential@1 plaintext_credential@2" {
		t.Fatalf("issues = %q", g)
	}
	if issues[1].URL != "https://deploy:xxxxx@pypi.acme.corp/simple" || issues[2].URL != "https://xxxxx@pypi.acme.corp/simple" {
		t.Fatalf("urls = %q, %q", issues[1].URL, issues[2].URL)
	}
}
