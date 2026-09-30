// Package version reports the omni-audit build version.
package version

import "runtime/debug"

// Version is set at build time via -ldflags.
var Version = "dev"

// String returns Version, falling back to the module version recorded by
// `go install github.com/omni-line/omni-audit/cmd/omni-audit@vX.Y.Z` when
// ldflags were not set.
func String() string {
	if Version != "" && Version != "dev" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
