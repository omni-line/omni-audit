//go:build unix

package manifest_test

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/omni-line/omni-audit/internal/manifest"
)

func TestReadFileRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	// Must reject via Lstat without opening the FIFO (opening for read would
	// block until a writer appears). Use a short deadline so a hang fails loud.
	done := make(chan error, 1)
	go func() {
		_, err := manifest.ReadFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error for FIFO")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFile blocked on FIFO; expected Lstat rejection")
	}
}
