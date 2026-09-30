package report

import (
	"fmt"
	"os"
	"strings"
)

// ColorMode controls ANSI styling.
type ColorMode string

// Supported color modes.
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
// In auto mode, NO_COLOR (any non-empty value, per no-color.org) disables
// colors and FORCE_COLOR enables them for non-TTY destinations.
func NewPalette(mode ColorMode, isTTY bool) Palette {
	switch mode {
	case ColorAlways:
		return Palette{enabled: true}
	case ColorNever:
		return Palette{enabled: false}
	default:
		if os.Getenv("NO_COLOR") != "" {
			return Palette{enabled: false}
		}
		if forceColor() {
			return Palette{enabled: true}
		}
		return Palette{enabled: isTTY}
	}
}

func forceColor() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("FORCE_COLOR"))) {
	case "", "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func (p Palette) wrap(code, s string) string {
	if !p.enabled || s == "" {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

// Style helpers.
func (p Palette) Bold(s string) string       { return p.wrap("1", s) }
func (p Palette) Dim(s string) string        { return p.wrap("2", s) }
func (p Palette) Red(s string) string        { return p.wrap("31", s) }
func (p Palette) Green(s string) string      { return p.wrap("32", s) }
func (p Palette) Yellow(s string) string     { return p.wrap("33", s) }
func (p Palette) Cyan(s string) string       { return p.wrap("36", s) }
func (p Palette) BoldRed(s string) string    { return p.wrap("1;31", s) }
func (p Palette) BoldGreen(s string) string  { return p.wrap("1;32", s) }
func (p Palette) BoldYellow(s string) string { return p.wrap("1;33", s) }
func (p Palette) BoldCyan(s string) string   { return p.wrap("1;36", s) }

// Enabled reports whether colors are active.
func (p Palette) Enabled() bool { return p.enabled }

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
