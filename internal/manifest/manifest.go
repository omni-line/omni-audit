// Package manifest holds types and helpers shared by the per-ecosystem
// manifest parsers.
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// Dependency is a package declared in a manifest.
type Dependency struct {
	// Name is the package name as it would be requested from the registry.
	Name string
	// Version is the declared constraint, verbatim; may be empty.
	Version string
	// Group is the manifest section, e.g. "devDependencies" or "require-dev".
	Group string
	// Line is the 1-based line of the declaration, or 0 when unknown.
	Line int
}

// MaxFileSize bounds how much of a manifest is read into memory.
const MaxFileSize = 10 << 20

// ErrTooLarge is returned by ReadFile for files above MaxFileSize.
var ErrTooLarge = fmt.Errorf("manifest exceeds %d MiB limit", MaxFileSize>>20)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// ReadFile reads a manifest from disk. It refuses non-regular files (FIFOs,
// devices) that could block or stream forever, enforces MaxFileSize, and
// strips a leading UTF-8 BOM.
func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, ErrTooLarge
	}
	return bytes.TrimPrefix(data, utf8BOM), nil
}

// LineAt returns the 1-based line number of byte offset off in data.
func LineAt(data []byte, off int) int {
	if off < 0 {
		return 0
	}
	if off > len(data) {
		off = len(data)
	}
	return bytes.Count(data[:off], []byte{'\n'}) + 1
}

// JSONKeyLine returns the line of the first object key named key that appears
// after the key named section, or 0 if either is not found. It is a textual
// search, good enough to point humans and SARIF viewers at a declaration.
func JSONKeyLine(data []byte, section, key string) int {
	start := indexJSONKey(data, section, 0)
	if start < 0 {
		return 0
	}
	off := indexJSONKey(data, key, start+len(section)+2)
	if off < 0 {
		return 0
	}
	return LineAt(data, off)
}

func indexJSONKey(data []byte, key string, from int) int {
	needle := []byte(`"` + key + `"`)
	for from < len(data) {
		i := bytes.Index(data[from:], needle)
		if i < 0 {
			return -1
		}
		i += from
		j := i + len(needle)
		for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\r' || data[j] == '\n') {
			j++
		}
		if j < len(data) && data[j] == ':' {
			return i
		}
		from = i + 1
	}
	return -1
}
