package secgate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// localenum_test.go is the acceptance + adversarial suite for the
// gate-level target-self-execution denial: a Kind=="target-analysis" command
// whose resolved binary is its own analysis target must be denied, before
// confirmation, on every path, and arming/mode/profile must not relax it. The
// read-only inspection of that same target (the target as an ARG to a tool) must
// stay allowed, and the EXTERNAL profile must be unaffected.

// x2Cmd builds a target-analysis Command for the given binary and target.
func x2Cmd(binary, target string, args ...string) Command {
	return Command{Kind: "target-analysis", Target: target, Binary: binary, Args: args}
}

// x2WriteFixture writes an executable regular file and returns its path.
func x2WriteFixture(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("\x7fELF fixture bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// x2WantDeny asserts c is denied by the self-exec rule (the Reason names the
// analysis target), not by some other layer.
func x2WantDeny(t *testing.T, g *Gate, c Command) {
	t.Helper()
	d := g.Authorize(context.Background(), c)
	if d.Allowed {
		t.Fatalf("target-analysis self-exec must be denied: %+v", c)
	}
	if !strings.Contains(d.Reason, "analysis target") {
		t.Errorf("want the distinct self-exec reason, got %q", d.Reason)
	}
}

// x2ExternalGate builds an EXTERNAL-profile gate (network scope + allowlist).
func x2ExternalGate(t *testing.T) *Gate {
	t.Helper()
	s, err := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: s, Allow: NewAllowlist("nmap")}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

// (a) direct path: binary IS the target.
func TestX2DeniesSelfExecBarePath(t *testing.T) {
	dir := t.TempDir()
	fixture := x2WriteFixture(t, dir, "ta-sample-bin")
	x2WantDeny(t, localGate(t, "local\n"), x2Cmd(fixture, fixture))
}

// (a) PATH-resolved: a bare binary name that resolves via PATH to the target.
func TestX2DeniesSelfExecPathResolvedName(t *testing.T) {
	dir := t.TempDir()
	fixture := x2WriteFixture(t, dir, "ta-uniq-probe-bin")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	x2WantDeny(t, localGate(t, "local\n"), x2Cmd(filepath.Base(fixture), fixture))
}

// (b) symlink: binary spelled as a symlink to the target, and the mirror
// spelling (target given as the symlink). EvalSymlinks collapses both; on macOS
// t.TempDir is under /var -> /private/var, exercising the root-symlink case too.
func TestX2DeniesSelfExecSymlink(t *testing.T) {
	dir := t.TempDir()
	fixture := x2WriteFixture(t, dir, "ta-sample-bin")
	link := filepath.Join(dir, "ta-link")
	if err := os.Symlink(fixture, link); err != nil {
		t.Fatal(err)
	}
	g := localGate(t, "local\n")
	x2WantDeny(t, g, x2Cmd(link, fixture))
	x2WantDeny(t, g, x2Cmd(fixture, link))
}

// (b) relative: binary spelled relative to run_command's scratch dir.
func TestX2DeniesSelfExecRelative(t *testing.T) {
	dir := t.TempDir()
	fixture := x2WriteFixture(t, dir, "ta-sample-bin")
	g := localGate(t, "local\n")
	g.Scratch = dir
	x2WantDeny(t, g, x2Cmd("./"+filepath.Base(fixture), fixture))
}

// (b) .. traversal: binary spelled with a parent-dir hop that collapses to the
// target, both through an existing intermediate and a non-existent one.
func TestX2DeniesSelfExecDotDot(t *testing.T) {
	dir := t.TempDir()
	fixture := x2WriteFixture(t, dir, "ta-sample-bin")
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	g := localGate(t, "local\n")
	// Existing intermediate: /dir/sub/../ta-sample-bin.
	x2WantDeny(t, g, x2Cmd(filepath.Join(sub, "..", "ta-sample-bin"), fixture))
	// Non-existent intermediate: /dir/nope/../ta-sample-bin (collapses to the
	// existing target, so canonicalization must still catch it).
	x2WantDeny(t, g, x2Cmd(filepath.Join(dir, "nope", "..", "ta-sample-bin"), fixture))
}

// Passing the target as an ARG to a read-only inspection tool is allowed: the
// binary is the tool, never the target.
func TestX2AllowsReadOnlyInspection(t *testing.T) {
	dir := t.TempDir()
	fixture := x2WriteFixture(t, dir, "ta-sample-bin")
	g := localGate(t, "local\n")
	for _, tool := range []string{"file", "stat", "nm", "readelf", "strings", "ldd", "getcap"} {
		c := x2Cmd(tool, fixture, fixture)
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("read-only inspection %q TARGET must be allowed: %q", tool, d.Reason)
		}
	}
}

// A non-target-analysis Kind running that same binary is not affected by the rule.
func TestX2RuleIsKindScoped(t *testing.T) {
	dir := t.TempDir()
	fixture := x2WriteFixture(t, dir, "ta-sample-bin")
	g := localGate(t, "local\n")
	for _, kind := range []string{"recon", "", "local"} {
		c := Command{Kind: kind, Target: fixture, Binary: fixture}
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("Kind %q running the binary must not be denied by the self-exec rule: %q", kind, d.Reason)
		}
	}
}

// Arming does not relax the rule: an armed post-ex target-analysis self-exec is
// still denied even with an approving confirmer present.
func TestX2ArmingDoesNotRelaxSelfExec(t *testing.T) {
	dir := t.TempDir()
	fixture := x2WriteFixture(t, dir, "ta-sample-bin")
	c := x2Cmd(fixture, fixture)
	c.Phase = PhasePostEx
	c.Armed = true
	x2WantDeny(t, localGate(t, "local\n"), c)
}

// Fail-closed / mixed scope: the self-exec denial holds even when the scope also
// lists network targets, while a normal read-only inspection still proceeds.
func TestX2SelfExecDeniedUnderMixedScope(t *testing.T) {
	dir := t.TempDir()
	fixture := x2WriteFixture(t, dir, "ta-sample-bin")
	g := localGate(t, "local\n10.0.0.0/24\n")
	x2WantDeny(t, g, x2Cmd(fixture, fixture))
	if d := g.Authorize(context.Background(), x2Cmd("file", fixture, fixture)); !d.Allowed {
		t.Errorf("read-only inspection under a mixed scope must be allowed: %q", d.Reason)
	}
}

// The EXTERNAL profile is UNTOUCHED: a normal allowlisted external command is
// allowed exactly as before (the new deny layer, which runs before the profile
// split, does not fire for a non-target-analysis command), and a
// target-analysis-kind external command that is NOT self-exec (binary != target)
// is likewise unaffected.
func TestX2LeavesExternalProfileUnaffected(t *testing.T) {
	g := x2ExternalGate(t)
	// Normal external recon, no Kind (bounded nmap so the classifier allows it):
	// allowed as before.
	if d := g.Authorize(context.Background(), Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}); !d.Allowed {
		t.Errorf("external nmap in-scope must stay allowed (X2 must not touch it): %q", d.Reason)
	}
	// target-analysis Kind but binary != target (target is a host, not the tool):
	// the rule is inert, so the external verdict is unchanged (allowed).
	if d := g.Authorize(context.Background(), Command{Kind: "target-analysis", Target: "10.0.0.5", Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}); !d.Allowed {
		t.Errorf("non-self-exec target-analysis external command must be unaffected: %q", d.Reason)
	}
}
