// Command portal connects to a TCP port, detects which service is running
// there, and hands the terminal over to the matching client program.
//
// Usage:
//
//	portal <host:port | host port> [flags] [-- client args...]
//
// Run "portal --help" for all flags and examples.
package main

import (
	"os"
	"runtime/debug"

	"github.com/modermatt44/portal/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	os.Exit(cli.Execute(buildVersion()))
}

// buildVersion returns the version set by -ldflags, or the module version
// recorded by "go install", or "dev".
func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}
