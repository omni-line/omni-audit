package registry

import "context"

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

// Checker checks whether a package name exists on a public registry.
type Checker interface {
	Exists(ctx context.Context, name string) (Status, error)
}
