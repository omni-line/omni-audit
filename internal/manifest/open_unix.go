//go:build unix

package manifest

import (
	"os"
	"syscall"
)

// openRegular opens path for reading without blocking on FIFOs/devices.
// Callers must have already verified the path is a regular file via Lstat;
// O_NONBLOCK closes the TOCTOU window where the path is replaced with a FIFO
// between that check and open.
func openRegular(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
