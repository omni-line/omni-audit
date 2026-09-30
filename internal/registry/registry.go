// Package registry defines the public-registry existence check contract and a
// shared, hardened HTTP prober used by every registry client.
package registry

import (
	"context"
	"errors"
	"fmt"
)

// Status is the result of a public registry existence check.
type Status int

const (
	// Exists means the package name is claimed on the public registry.
	Exists Status = iota
	// NotFound means the package name is unclaimed (404).
	NotFound
	// Unknown means the check failed (network / unexpected status).
	Unknown
)

func (s Status) String() string {
	switch s {
	case Exists:
		return "exists"
	case NotFound:
		return "not_found"
	default:
		return "unknown"
	}
}

// ErrInvalidName is returned when a name cannot be a valid package on the
// registry. Such names are never sent over the network.
var ErrInvalidName = errors.New("invalid package name")

// InvalidNameError wraps ErrInvalidName with context.
func InvalidNameError(ecosystem, name string) error {
	return fmt.Errorf("%w for %s: %q", ErrInvalidName, ecosystem, name)
}

// Checker checks whether a package name exists on a public registry.
type Checker interface {
	Exists(ctx context.Context, name string) (Status, error)
}

// CheckerFunc adapts a function to the Checker interface.
type CheckerFunc func(ctx context.Context, name string) (Status, error)

// Exists implements Checker.
func (f CheckerFunc) Exists(ctx context.Context, name string) (Status, error) {
	return f(ctx, name)
}
