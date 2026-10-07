package secgate

import (
	"os"
	"path/filepath"
	"testing"
)

// targetexec_offhost_test.go covers the target-self-exec denial for a command
// that executes on a declared foothold rather than on this host. PATH lookup and
// symlink resolution describe this host, so they cannot establish the identity of
// a file on the foothold: the off-host comparison is lexical and fails closed on
// the spellings host resolution could not see.

// offHostGate returns a gate whose policy declares a foothold covering surface.
func offHostGate(surface Surface) *Gate {
	return &Gate{Policy: &Policy{Foothold: &Foothold{Host: "10.0.0.9", Surfaces: []Surface{surface}}}}
}

func TestExecOffHostFollowsFootholdSurfaceCoverage(t *testing.T) {
	g := offHostGate(SurfaceLocal)
	if !g.execOffHost(Command{Surface: SurfaceLocal}) {
		t.Error("a command on a covered surface executes off host")
	}
	if g.execOffHost(Command{Surface: SurfaceNetwork}) {
		t.Error("a command on an uncovered surface executes in the worker")
	}
	if (&Gate{}).execOffHost(Command{Surface: SurfaceLocal}) {
		t.Error("no policy means no foothold, so nothing executes off host")
	}
	if (&Gate{Policy: &Policy{}}).execOffHost(Command{Surface: SurfaceLocal}) {
		t.Error("no declared foothold means nothing executes off host")
	}
}

// A bare binary name that would resolve to the target on the foothold is the
// spelling host resolution cannot see: exec.LookPath here finds nothing, or finds
// an unrelated file, so the host comparison went inert and let the target run.
func TestOffHostDeniesBareNameMatchingTargetBaseName(t *testing.T) {
	if _, bad := TargetSelfExecViolation(
		Command{Kind: "target-analysis", Target: "/usr/local/bin/vendor-agent", Binary: "vendor-agent"},
		"", true); !bad {
		t.Error("a bare name matching the target base name must be denied off host")
	}
	// The same command on this host, where the name resolves to nothing, stays
	// inert, which is the behavior the off-host branch replaces.
	if _, bad := TargetSelfExecViolation(
		Command{Kind: "target-analysis", Target: "/usr/local/bin/vendor-agent", Binary: "vendor-agent"},
		"", false); bad {
		t.Error("host resolution of an absent name is inert; this pins the contrast")
	}
}

// A read-only inspection tool named by its absolute path keeps working, which is
// what makes the base-name denial above a usable rule rather than a shutdown of
// target analysis over a foothold.
func TestOffHostAllowsAbsoluteInspectionTool(t *testing.T) {
	for _, bin := range []string{"/usr/bin/file", "/usr/bin/strings", "/usr/bin/readelf"} {
		if tgt, bad := TargetSelfExecViolation(
			Command{Kind: "target-analysis", Target: "/usr/local/bin/vendor-agent", Binary: bin,
				Args: []string{"/usr/local/bin/vendor-agent"}},
			"", true); bad {
			t.Errorf("%s inspecting %s off host must be allowed", bin, tgt)
		}
	}
}

// Two absolute paths name two files on the foothold, so equal paths deny and
// different paths allow even when the base names coincide.
func TestOffHostComparesAbsolutePathsLexically(t *testing.T) {
	if _, bad := TargetSelfExecViolation(
		Command{Kind: "target-analysis", Target: "/usr/local/bin/agent", Binary: "/usr/local/bin/agent"},
		"", true); !bad {
		t.Error("the target's own absolute path must be denied")
	}
	if _, bad := TargetSelfExecViolation(
		Command{Kind: "target-analysis", Target: "/usr/local/bin/agent", Binary: "/usr/local/bin/./sub/../agent"},
		"", true); !bad {
		t.Error("a dot-segment spelling of the target must be denied")
	}
	if _, bad := TargetSelfExecViolation(
		Command{Kind: "target-analysis", Target: "/opt/vendor/strings", Binary: "/usr/bin/strings"},
		"", true); bad {
		t.Error("a different absolute path sharing the base name must be allowed")
	}
}

// A relative binary resolves against the foothold's working directory, which this
// host does not know, so the base name is the only comparable part.
func TestOffHostDeniesRelativeSpellingOfTarget(t *testing.T) {
	for _, bin := range []string{"./agent", "bin/agent", "../bin/agent"} {
		if _, bad := TargetSelfExecViolation(
			Command{Kind: "target-analysis", Target: "/usr/local/bin/agent", Binary: bin},
			"", true); !bad {
			t.Errorf("relative spelling %q of the target must be denied off host", bin)
		}
	}
}

// The rule stays inert for a non-target-analysis kind and an empty target, off
// host exactly as on host, so it moves no other command's verdict.
func TestOffHostInertWithoutTargetAnalysisContext(t *testing.T) {
	if _, bad := TargetSelfExecViolation(Command{Kind: "recon", Target: "/usr/local/bin/agent", Binary: "agent"}, "", true); bad {
		t.Error("a non-target-analysis kind must be inert")
	}
	if _, bad := TargetSelfExecViolation(Command{Kind: "target-analysis", Target: "", Binary: "agent"}, "", true); bad {
		t.Error("an empty target must be inert")
	}
	if _, bad := TargetSelfExecViolation(Command{Kind: "target-analysis", Target: "/usr/local/bin/agent", Binary: ""}, "", true); bad {
		t.Error("an empty binary must be inert")
	}
}

// Host resolution still governs a command that runs in the worker, so a foothold
// covering another surface does not change an on-host verdict.
func TestOnHostPathResolutionUnchangedByUncoveredFoothold(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "ta-offhost-probe-bin")
	if err := os.WriteFile(fixture, []byte("\x7fELF fixture bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	c := Command{Kind: "target-analysis", Target: fixture, Binary: filepath.Base(fixture), Surface: SurfaceNetwork}
	g := offHostGate(SurfaceLocal)
	if _, bad := TargetSelfExecViolation(c, "", g.execOffHost(c)); !bad {
		t.Error("a PATH-resolved self-exec in the worker must still be denied")
	}
}
