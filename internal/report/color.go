package report

import (
	"fmt"
	"os"
	"strings"
)

// ColorMode controls ANSI styling.
type ColorMode string

const (
	ColorAuto   ColorMode = "auto"
	ColorAlways ColorMode = "always"
	ColorNever  ColorMode = "never"
)

// Palette applies optional ANSI styles.
type Palette struct {
	enabled bool
}

// NewPalette builds a palette from mode and whether the destination is a TTY.
func NewPalette(mode ColorMode, isTTY bool) Palette {
	switch mode {
	case ColorAlways:
		return Palette{enabled: true}
	case ColorNever:
		return Palette{enabled: false}
	default:
		if envTruthy("NO_COLOR") {
			return Palette{enabled: false}
		}
		if v := strings.ToLower(strings.TrimSpace(os.Getenv("FORCE_COLOR"))); v == "1" || v == "true" || v == "yes" {
			return Palette{enabled: true}
		}
		return Palette{enabled: isTTY}
	}
}

func (p Palette) wrap(code, s string) string {
	if !p.enabled || s == "" {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func (p Palette) Bold(s string) string   { return p.wrap("1", s) }
func (p Palette) Dim(s string) string    { return p.wrap("2", s) }
func (p Palette) Red(s string) string    { return p.wrap("31", s) }
func (p Palette) Green(s string) string  { return p.wrap("32", s) }
func (p Palette) Yellow(s string) string { return p.wrap("33", s) }
func (p Palette) Blue(s string) string   { return p.wrap("34", s) }
func (p Palette) Magenta(s string) string {
	return p.wrap("35", s)
}
func (p Palette) Cyan(s string) string { return p.wrap("36", s) }

func (p Palette) BoldRed(s string) string    { return p.wrap("1;31", s) }
func (p Palette) BoldGreen(s string) string  { return p.wrap("1;32", s) }
func (p Palette) BoldYellow(s string) string { return p.wrap("1;33", s) }
func (p Palette) BoldCyan(s string) string   { return p.wrap("1;36", s) }

// Enabled reports whether colors are active.
func (p Palette) Enabled() bool { return p.enabled }

func envTruthy(key string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		// NO_COLOR is truthy when set to any non-empty value per the standard.
		if key == "NO_COLOR" {
			return strings.TrimSpace(os.Getenv(key)) != ""
		}
		return false
	}
}

// ParseColorMode validates --color values.
func ParseColorMode(s string) (ColorMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return ColorAuto, nil
	case "always", "on", "yes", "true", "1":
		return ColorAlways, nil
	case "never", "off", "no", "false", "0":
		return ColorNever, nil
	default:
		return ColorAuto, fmt.Errorf("invalid --color %q (want auto|always|never)", s)
	}
}
