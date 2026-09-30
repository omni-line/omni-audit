package report_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/report"
)

func TestParseColorMode(t *testing.T) {
	cases := map[string]report.ColorMode{
		"auto":   report.ColorAuto,
		"always": report.ColorAlways,
		"never":  report.ColorNever,
		"on":     report.ColorAlways,
		"off":    report.ColorNever,
		"":       report.ColorAuto,
	}
	for in, want := range cases {
		got, err := report.ParseColorMode(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
	if _, err := report.ParseColorMode("rainbow"); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestPalette(t *testing.T) {
	on := report.NewPalette(report.ColorAlways, false)
	if !on.Enabled() {
		t.Fatal("always should enable")
	}
	s := on.Red("x")
	if s == "x" || !containsESC(s) {
		t.Fatalf("expected ansi wrap: %q", s)
	}
	off := report.NewPalette(report.ColorNever, true)
	if off.Red("x") != "x" {
		t.Fatal("never should be plain")
	}
}

func containsESC(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			return true
		}
	}
	return false
}
