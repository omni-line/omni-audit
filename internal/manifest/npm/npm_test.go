package npm_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest/npm"
)

func TestParse(t *testing.T) {
	data := []byte(`{
		"dependencies": {"lodash": "1.0.0", "@acme/x": "2.0.0"},
		"devDependencies": {"lodash": "2.0.0", "typescript": "5.0.0"},
		"peerDependencies": {"react": "18"},
		"optionalDependencies": {"fsevents": "1"}
	}`)
	deps, err := npm.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range deps {
		got[d.Name] = d.Version
	}
	if got["lodash"] != "1.0.0" {
		t.Fatalf("lodash version = %q, want first-seen 1.0.0", got["lodash"])
	}
	for _, name := range []string{"@acme/x", "typescript", "react", "fsevents"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("missing dependency %s", name)
		}
	}
	if len(deps) != 5 {
		t.Fatalf("len=%d want 5", len(deps))
	}
}
