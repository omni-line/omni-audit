package distance

import "strings"

// Technique names the kind of edit that turns a target name into a suspect.
type Technique string

// Techniques reported by Classify.
const (
	TechniqueCase          Technique = "case"
	TechniqueSeparator     Technique = "separator"
	TechniqueTransposition Technique = "transposition"
	TechniqueExtraChar     Technique = "extra-character"
	TechniqueMissingChar   Technique = "missing-character"
	TechniqueSubstitution  Technique = "substitution"
	TechniqueMultiple      Technique = "multiple-edits"
)

// Describe returns a short human-readable explanation of t.
func (t Technique) Describe() string {
	switch t {
	case TechniqueCase:
		return "differs only by letter case"
	case TechniqueSeparator:
		return "differs only by '-', '_' or '.' separators"
	case TechniqueTransposition:
		return "two adjacent characters swapped"
	case TechniqueExtraChar:
		return "one extra character"
	case TechniqueMissingChar:
		return "one character missing"
	case TechniqueSubstitution:
		return "one character replaced"
	case TechniqueMultiple:
		return "two edits apart"
	default:
		return string(t)
	}
}

// Classify reports how suspect differs from target. It returns "" when the
// names are identical.
func Classify(suspect, target string) Technique {
	if suspect == target {
		return ""
	}
	if strings.EqualFold(suspect, target) {
		return TechniqueCase
	}
	ss, st := StripSeparators(suspect), StripSeparators(target)
	if ss == st {
		return TechniqueSeparator
	}
	x, y := strings.ToLower(suspect), strings.ToLower(target)
	if OSA(x, y) != 1 {
		if OSA(ss, st) != 1 {
			return TechniqueMultiple
		}
		x, y = ss, st
	}
	switch len(x) - len(y) {
	case 1:
		return TechniqueExtraChar
	case -1:
		return TechniqueMissingChar
	}
	if isTransposition(x, y) {
		return TechniqueTransposition
	}
	return TechniqueSubstitution
}

func isTransposition(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i+1 < len(a); i++ {
		if a[i] != b[i] {
			return a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:]
		}
	}
	return false
}
