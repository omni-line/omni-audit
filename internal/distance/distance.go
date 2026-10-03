// Package distance implements edit-distance helpers for typosquat detection.
//
// All functions operate on bytes. npm and PyPI only permit ASCII package
// names, so byte and rune semantics coincide for valid input; non-ASCII input
// simply scores as a larger distance.
package distance

import "strings"

// Levenshtein returns the classic edit distance (insert, delete, substitute)
// between a and b.
func Levenshtein(a, b string) int {
	return bounded(a, b, -1, false)
}

// OSA returns the optimal string alignment distance between a and b:
// Levenshtein plus transposition of two adjacent characters as one edit, so
// "reqeusts" is one edit away from "requests".
func OSA(a, b string) int {
	return bounded(a, b, -1, true)
}

// Distance returns the minimum of the raw OSA distance and the OSA distance
// after stripping separators. Names that differ only by separators
// ("crossenv" vs "cross-env") count as distance 1.
func Distance(a, b string) int {
	d, _ := Within(a, b, -1)
	return d
}

// Within computes Distance(a, b) but gives up early once the result is known
// to exceed max. It reports whether the distance is <= max. A negative max
// disables the bound.
func Within(a, b string, max int) (int, bool) {
	if a == b {
		return 0, true
	}
	sa, sb := StripSeparators(a), StripSeparators(b)
	if sa == sb {
		return 1, max < 0 || max >= 1
	}
	d := bounded(a, b, max, true)
	if s := bounded(sa, sb, max, true); s < d {
		d = s
	}
	return d, max < 0 || d <= max
}

// StripSeparators lowercases s and removes '-', '_' and '.' for
// separator-insensitive comparison.
func StripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-' || c == '_' || c == '.':
			continue
		case 'A' <= c && c <= 'Z':
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// bounded computes Levenshtein (or OSA when transpose is set). When max >= 0
// it returns max+1 as soon as every alignment is known to exceed max.
func bounded(a, b string, max int, transpose bool) int {
	if a == b {
		return 0
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	la, lb := len(a), len(b)
	if max >= 0 && lb-la > max {
		return max + 1
	}
	if la == 0 {
		return lb
	}
	prev2 := make([]int, la+1)
	prev := make([]int, la+1)
	curr := make([]int, la+1)
	for i := range prev {
		prev[i] = i
	}
	prevMin := 0
	for j := 1; j <= lb; j++ {
		curr[0] = j
		rowMin := curr[0]
		bj := b[j-1]
		for i := 1; i <= la; i++ {
			cost := 1
			if a[i-1] == bj {
				cost = 0
			}
			v := min3(prev[i]+1, curr[i-1]+1, prev[i-1]+cost)
			if transpose && i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == bj {
				if t := prev2[i-2] + 1; t < v {
					v = t
				}
			}
			curr[i] = v
			if v < rowMin {
				rowMin = v
			}
		}
		// A transposition can reach back two rows at +1, so both rows must
		// be out of budget before no later cell can come back within max.
		if max >= 0 && rowMin > max && prevMin >= max {
			return max + 1
		}
		prevMin = rowMin
		prev2, prev, curr = prev, curr, prev2
	}
	return prev[la]
}

func min3(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}
