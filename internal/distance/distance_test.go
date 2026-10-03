package distance_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/distance"
)

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		d    int
	}{
		{"requests", "requests", 0},
		{"requests", "reqeusts", 2},
		{"react-dom", "react-domm", 1},
		{"", "abc", 3},
		{"abc", "", 3},
		{"kitten", "sitting", 3},
	}
	for _, tc := range cases {
		if got := distance.Levenshtein(tc.a, tc.b); got != tc.d {
			t.Errorf("Levenshtein(%q,%q)=%d want %d", tc.a, tc.b, got, tc.d)
		}
	}
}

func TestOSA(t *testing.T) {
	cases := []struct {
		a, b string
		d    int
	}{
		{"requests", "reqeusts", 1},
		{"axios", "axois", 1},
		{"ca", "abc", 3},
		{"lodash", "lodahs", 1},
		{"lodash", "lodash", 0},
	}
	for _, tc := range cases {
		if got := distance.OSA(tc.a, tc.b); got != tc.d {
			t.Errorf("OSA(%q,%q)=%d want %d", tc.a, tc.b, got, tc.d)
		}
	}
}

func TestDistance(t *testing.T) {
	cases := []struct {
		a, b string
		d    int
	}{
		{"crossenv", "cross-env", 1},
		{"cross_env", "cross-env", 1},
		{"reqeusts", "requests", 1},
		{"react-domm", "react-dom", 1},
		{"beautifulsoup", "beautifulsoup4", 1},
		{"lodash", "lodash", 0},
	}
	for _, tc := range cases {
		if got := distance.Distance(tc.a, tc.b); got != tc.d {
			t.Errorf("Distance(%q,%q)=%d want %d", tc.a, tc.b, got, tc.d)
		}
	}
}

func TestWithinMatchesDistance(t *testing.T) {
	words := []string{"", "a", "ab", "abc", "react", "reatc", "react-dom", "reactdom", "react_domm",
		"lodash", "lodahs", "l0dash", "requests", "reqeusts", "request", "express", "expres", "xepress"}
	for _, a := range words {
		for _, b := range words {
			full := distance.Distance(a, b)
			for max := 0; max <= 3; max++ {
				d, ok := distance.Within(a, b, max)
				if ok != (full <= max) {
					t.Errorf("Within(%q,%q,%d) ok=%v but Distance=%d", a, b, max, ok, full)
				}
				if ok && d != full {
					t.Errorf("Within(%q,%q,%d)=%d but Distance=%d", a, b, max, d, full)
				}
			}
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		suspect, target string
		want            distance.Technique
	}{
		{"crossenv", "cross-env", distance.TechniqueSeparator},
		{"React", "react", distance.TechniqueCase},
		{"reqeusts", "requests", distance.TechniqueTransposition},
		{"react-domm", "react-dom", distance.TechniqueExtraChar},
		{"expres", "express", distance.TechniqueMissingChar},
		{"l0dash", "lodash", distance.TechniqueSubstitution},
		{"lodahs-x", "lodash", distance.TechniqueMultiple},
		{"cross-envv", "crossenv", distance.TechniqueExtraChar},
		{"same", "same", ""},
	}
	for _, tc := range cases {
		if got := distance.Classify(tc.suspect, tc.target); got != tc.want {
			t.Errorf("Classify(%q,%q)=%q want %q", tc.suspect, tc.target, got, tc.want)
		}
	}
}

func FuzzWithin(f *testing.F) {
	f.Add("react-dom", "reactdom", 2)
	f.Add("reqeusts", "requests", 1)
	f.Add("", "abc", 0)
	f.Fuzz(func(t *testing.T, a, b string, max int) {
		if len(a) > 64 || len(b) > 64 {
			t.Skip()
		}
		max = ((max % 4) + 4) % 4
		full := distance.Distance(a, b)
		if full != distance.Distance(b, a) {
			t.Fatalf("Distance not symmetric for %q, %q", a, b)
		}
		d, ok := distance.Within(a, b, max)
		if ok != (full <= max) || (ok && d != full) {
			t.Fatalf("Within(%q,%q,%d)=(%d,%v) but Distance=%d", a, b, max, d, ok, full)
		}
	})
}
