// Package buildinfo exposes version metadata, injectable at build time via
// -ldflags "-X github.com/veilvpn/veil/internal/buildinfo.Version=...".
package buildinfo

// Version is the semantic version or git describe of this build.
var Version = "0.0.0-dev"

// Commit is the git commit the binary was built from.
var Commit = "unknown"
