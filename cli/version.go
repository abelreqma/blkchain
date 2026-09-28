package main

import (
	"fmt"
	"os"
	"runtime/debug"
)

// version is the release string, overridable at build time with
//
//	go build -ldflags "-X main.version=v1.2.3"
//
// It falls back to the VCS revision embedded by `go build`, then "dev".
var version = ""

// printVersion writes the version plus Go toolchain and VCS build info.
func printVersion(w *os.File) {
	v, rev, dirty, gover := versionInfo()
	fmt.Fprintf(w, "%s %s\n", H1.Render("blk"), v)
	if rev != "" {
		state := ""
		if dirty {
			state = " " + Caut.Render("(dirty)")
		}
		fmt.Fprintf(w, "  %s %s%s\n", Meta.Render("commit"), rev, state)
	}
	fmt.Fprintf(w, "  %s %s\n", Meta.Render("built with"), gover)
}

// versionInfo resolves the version string and build metadata from ldflags and
// the embedded build info. Pure enough to test.
func versionInfo() (v, rev string, dirty bool, gover string) {
	gover = "unknown"
	v = version
	info, ok := debug.ReadBuildInfo()
	if ok {
		gover = info.GoVersion
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
	}
	if v == "" {
		if rev != "" {
			v = "dev+" + shortRev(rev)
		} else {
			v = "dev"
		}
	}
	return v, rev, dirty, gover
}

// shortRev abbreviates a git revision to 12 characters.
func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}
