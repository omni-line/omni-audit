//go:build unix

package manifest_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest"
)

func TestReadFileRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	// Opening a FIFO for reading blocks until a writer appears; hold one open.
	w, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := manifest.ReadFile(path); err == nil {
		t.Fatal("expected error for FIFO")
	}
}
