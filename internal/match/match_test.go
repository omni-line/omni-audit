package match_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/match"
)

func TestMatcher(t *testing.T) {
	m := match.New("@acme/*", "corp/*", "skip-me")
	cases := map[string]bool{
		"@acme/utils": true,
		"@other/x":    false,
		"corp/sdk":    true,
		"skip-me":     true,
		"lodash":      false,
	}
	for name, want := range cases {
		if got := m.Match(name); got != want {
			t.Errorf("Match(%q)=%v want %v", name, got, want)
		}
	}
}

func TestCommaSplit(t *testing.T) {
	m := match.New("@a/*, @b/*")
	if !m.Match("@a/x") || !m.Match("@b/y") {
		t.Fatal("comma-separated patterns should both work")
	}
}

func TestCompileRejectsMalformed(t *testing.T) {
	if _, err := match.Compile("@acme/["); err == nil {
		t.Fatal("expected error for malformed pattern")
	}
	if _, err := match.Compile("@acme/*", "acme-?"); err != nil {
		t.Fatal(err)
	}
}

func TestNilMatcher(t *testing.T) {
	var m *match.Matcher
	if m.Match("x") || !m.Empty() {
		t.Fatal("nil matcher should match nothing and be empty")
	}
}
