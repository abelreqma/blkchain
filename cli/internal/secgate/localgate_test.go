package secgate

import (
	"context"
	"strings"
	"testing"
)

func localGate(t *testing.T, scope string) *Gate {
	t.Helper()
	s, err := ParseScope(strings.NewReader(scope))
	if err != nil {
		t.Fatal(err)
	}
	// The LOCAL profile requires per-command confirmation in every mode, so an
	// approving confirmer is supplied. These tests exercise the deny-layers, which
	// run before confirmation: a denied command never reaches the confirmer, and
	// an allowed-by-denylist command is confirmed and passes.
	g := &Gate{Mode: Auto, Scope: s, Confirm: stubConfirmer{true}}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

// localGateNoConfirmer is a LOCAL gate with NO confirmer. LOCAL always-confirm plus
// no confirmer means no human is in the loop, so humanGovernedPath is false and the
// structural shell/interpreter/exec-wrapper/exec-flag/metacharacter denials are
// ENFORCED (and audited at the classifier layer, before the confirm layer). This is
// the fail-closed path for the HITL denial-relaxation: with an approving confirmer
// these same commands are surfaced for approval instead (see hitlrelax_test.go).
func localGateNoConfirmer(t *testing.T, scope string) *Gate {
	t.Helper()
	s, err := ParseScope(strings.NewReader(scope))
	if err != nil {
		t.Fatal(err)
	}
	g := &Gate{Mode: Auto, Scope: s, Confirm: nil}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	return g
}

// The enforceability invariant on the no-human path: with no confirmer available,
// shells, interpreters, exec-wrappers, find code-exec predicates, and raw-shell
// metacharacters stay denied in local mode (fail closed). Under HITL (an approving
// confirmer) these are instead surfaced for approval - see hitlrelax_test.go.
func TestLocalProfileKeepsEnforceabilityDenials(t *testing.T) {
	g := localGateNoConfirmer(t, "local\n")
	denied := []Command{
		{Binary: "bash", Args: []string{"-c", "x"}},
		{Binary: "/bin/sh"},
		{Binary: "python3", Args: []string{"-c", "x"}},
		{Binary: "perl", Args: []string{"-e", "x"}},
		{Binary: "awk", Args: []string{"BEGIN{}"}},
		{Binary: "env", Args: []string{"X=1", "id"}},
		{Binary: "xargs", Args: []string{"rm"}},
		{Binary: "find", Args: []string{"/", "-perm", "-4000", "-exec", "sh", "{}", ";"}},
		{Binary: "find", Args: []string{".", "-delete"}},
		{Binary: "find", Args: []string{".", "-execdir", "id", "{}", "+"}},
		{Binary: "find", Args: []string{".", "-ok", "id", "{}", "+"}},
		{Binary: "find", Args: []string{".", "-okdir", "id", "{}", "+"}},
		{Binary: "find", Args: []string{".", "-fprintf", "out", "%p"}},
		{Binary: "find", Args: []string{".", "-fprint", "out"}},
		{Binary: "find", Args: []string{".", "-fprint0", "out"}},
		{Binary: "find", Args: []string{".", "-fls", "out"}},
		{Binary: "/usr/bin/find", Args: []string{".", "-DELETE"}},
		{Binary: "ls;", Args: []string{"rm"}},
		{Binary: "ls", Args: []string{"-la;", "rm"}},
		{Binary: "ls | grep x"},
		{Binary: "cat", Args: []string{"$(id)"}},
		{Binary: "cat", Args: []string{"a", ">", "b"}},
		{Binary: ""},
	}
	for _, c := range denied {
		if d := g.Authorize(context.Background(), c); d.Allowed {
			t.Errorf("%v must be denied in local mode", c)
		}
	}
}

// Exec-wrappers and macOS interpreters that re-exec or script
// arbitrary code must be denied in the LOCAL profile on the no-human path (no
// confirmer), by base name, whatever their args and whatever their path. Under HITL
// they are surfaced for approval instead.
func TestLocalProfileDeniesExecWrappersAndMacInterpreters(t *testing.T) {
	g := localGateNoConfirmer(t, "local\n")
	denied := []Command{
		{Binary: "nsenter", Args: []string{"-t", "1", "-m"}},
		{Binary: "unshare", Args: []string{"-r"}},
		{Binary: "setpriv", Args: []string{"--reuid", "0"}},
		{Binary: "flock", Args: []string{"/tmp/x", "id"}},
		{Binary: "capsh", Args: []string{"--"}},
		{Binary: "ionice", Args: []string{"-c", "3", "id"}},
		{Binary: "taskset", Args: []string{"-c", "0", "id"}},
		{Binary: "setarch", Args: []string{"x86_64", "id"}},
		{Binary: "chrt", Args: []string{"-f", "99", "id"}},
		{Binary: "runcon", Args: []string{"unconfined_t", "id"}},
		{Binary: "eatmydata", Args: []string{"id"}},
		{Binary: "expect", Args: []string{"-c", "spawn id"}},
		{Binary: "tclsh"},
		{Binary: "wish"},
		{Binary: "osascript", Args: []string{"-e", "do shell script \"id\""}},
		{Binary: "lldb", Args: []string{"-o", "run"}},
		{Binary: "dtrace", Args: []string{"-n", "syscall:::entry"}},
		{Binary: "/usr/bin/osascript", Args: []string{"-e", "x"}}, // path-qualified still denied by base name
	}
	for _, c := range denied {
		if d := g.Authorize(context.Background(), c); d.Allowed {
			t.Errorf("%q must be denied in the local profile (S1)", c.Binary)
		}
	}
}

// The known per-binary code-exec flags stay denied in local mode on the no-human
// path (no confirmer), in every spelling the external profile denies; the same
// tools run without them under HITL. Under HITL the exec-flag forms are surfaced
// for approval instead (see hitlrelax_test.go).
func TestLocalProfileDeniesCodeExecFlags(t *testing.T) {
	g := localGateNoConfirmer(t, "local\n")
	denied := []Command{
		{Binary: "nc", Args: []string{"-e", "/bin/sh", "10.0.0.5"}},
		{Binary: "nc", Args: []string{"-ve/bin/sh", "10.0.0.5", "80"}},
		{Binary: "nc", Args: []string{"-c", "id", "10.0.0.5"}},
		{Binary: "ncat", Args: []string{"--exec", "/bin/sh"}},
		{Binary: "ncat", Args: []string{"--sh-ex=id"}},
		{Binary: "ncat", Args: []string{"--lua-exec", "x.lua"}},
		{Binary: "nmap", Args: []string{"--script", "http-vuln", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"-script=vuln", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--scr", "vuln", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--datadir", "/tmp/x", "10.0.0.5"}},
		{Binary: "nmap", Args: []string{"--interactive"}},
		{Binary: "smbclient", Args: []string{"//x/y", "-c", "ls"}},
		{Binary: "rpcclient", Args: []string{"-c", "srvinfo", "10.0.0.5"}},
		{Binary: "curl", Args: []string{"--unix-socket", "/run/x", "http://x/"}},
		{Binary: "curl", Args: []string{"--abstract-unix-socket=x", "http://x/"}},
		{Binary: "ip", Args: []string{"netns", "exec", "x", "id"}},
		{Binary: "ip", Args: []string{"net", "exec", "x", "id"}},
		{Binary: "ip", Args: []string{"vrf", "exec", "x", "id"}},
		{Binary: "ip", Args: []string{"-batch", "f"}},
		{Binary: "ffuf", Args: []string{"-input-cmd", "id"}},
		{Binary: "ffuf", Args: []string{"-input-shell", "sh"}},
		{Binary: "nikto", Args: []string{"-Plugins", "x"}},
		{Binary: "nikto", Args: []string{"-Option", "PLUGINDIR=/tmp"}},
		{Binary: "/usr/bin/nc", Args: []string{"-e", "/bin/sh"}},
	}
	for _, c := range denied {
		if d := g.Authorize(context.Background(), c); d.Allowed {
			t.Errorf("%v must be denied in local mode", c)
		}
	}
	// The same tools without an exec flag run under HITL (an approving confirmer).
	gc := localGate(t, "local\n")
	allowed := []Command{
		{Binary: "nc", Args: []string{"-v", "10.0.0.5", "80"}},
		{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}},
		{Binary: "curl", Args: []string{"http://10.0.0.5/"}},
		{Binary: "smbclient", Args: []string{"//10.0.0.5/share", "-N", "-L"}},
		{Binary: "ip", Args: []string{"addr"}},
	}
	for _, c := range allowed {
		if d := gc.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("%v must be allowed in local mode: %q", c, d.Reason)
		}
	}
}

// find runs in local mode when it uses no code-exec or file-writing predicate.
func TestLocalProfileAllowsPlainFind(t *testing.T) {
	g := localGate(t, "local\n")
	c := Command{Binary: "find", Args: []string{"/etc", "-name", "*.conf", "-perm", "-4000"}}
	if d := g.Authorize(context.Background(), c); !d.Allowed {
		t.Errorf("plain find must be allowed in local mode: %q", d.Reason)
	}
}

// The local profile has no binary allowlist: any non-shell native binary passes
// this layer, with or without an Allow list.
func TestLocalProfileHasNoBinaryAllowlist(t *testing.T) {
	g := localGate(t, "local\n")
	allowed := []Command{
		{Binary: "id"},
		{Binary: "uname", Args: []string{"-a"}},
		{Binary: "cat", Args: []string{"/etc/os-release"}},
		{Binary: "ls", Args: []string{"-la", "/etc"}},
		{Binary: "ps", Args: []string{"aux"}},
		{Binary: "lsof", Args: []string{"-i"}},
		{Binary: "socat", Args: []string{"internal-host"}},
		{Binary: "curl", Args: []string{"intranet"}},
	}
	for _, c := range allowed {
		if d := g.Authorize(context.Background(), c); !d.Allowed {
			t.Errorf("%v must be allowed in local mode: %q", c, d.Reason)
		}
	}
	// An explicit Allow list is ignored, not consulted, in local mode.
	g.Allow = NewAllowlist("id")
	if d := g.Authorize(context.Background(), Command{Binary: "lsof"}); !d.Allowed {
		t.Errorf("local mode must not consult the allowlist: %q", d.Reason)
	}
}

// Episode caps still apply in the local profile.
func TestLocalProfileStillEnforcesEpisodeCap(t *testing.T) {
	g := localGate(t, "local\n")
	g.Episode = NewEpisode(Caps{MaxCommands: 2}, nil)
	var allowed int
	for i := 0; i < 5; i++ {
		if g.Authorize(context.Background(), Command{Binary: "id"}).Allowed {
			allowed++
		}
	}
	if allowed != 2 {
		t.Errorf("allowed = %d, want 2 (cap)", allowed)
	}
}

// On the no-human path (no confirmer) a structural denial in local mode is audited
// at the classifier layer, before the confirm layer. (This also proves the
// structural denial still fires there: were it not, the deny would be at the
// confirm layer instead.)
func TestLocalProfileAuditsStructuralDenial(t *testing.T) {
	g := localGateNoConfirmer(t, "local\n")
	var actions []string
	recordingGate(g, &actions)
	g.Authorize(context.Background(), Command{Binary: "bash", Args: []string{"-c", "x"}})
	if got := lastAction(t, actions); got != "deny:classifier" {
		t.Errorf("want deny:classifier, got %q", got)
	}
}

// Safe mode still confirms in the local profile. An ordinary command is confirmed;
// under the HITL denial-relaxation a shell is SURFACED for approval (allowed when
// the confirmer approves, denied when it refuses) rather than auto-denied.
func TestLocalProfileSafeConfirms(t *testing.T) {
	s, _ := ParseScope(strings.NewReader("local\n"))
	g := &Gate{Mode: Safe, Scope: s, Confirm: stubConfirmer{false}}
	if d := g.Authorize(context.Background(), Command{Binary: "id"}); d.Allowed {
		t.Error("safe mode with a refusing confirmer must deny")
	}
	g.Confirm = stubConfirmer{true}
	if d := g.Authorize(context.Background(), Command{Binary: "id"}); !d.Allowed {
		t.Errorf("safe mode with an approving confirmer must allow: %q", d.Reason)
	}
	// HITL relaxation: a shell is surfaced and allowed when the operator approves.
	if d := g.Authorize(context.Background(), Command{Binary: "bash", Args: []string{"-lc", "id"}}); !d.Allowed {
		t.Errorf("a shell must be surfaced and allowed under HITL when approved: %q", d.Reason)
	}
	// And denied when the operator refuses (surfaced, not auto-allowed).
	g.Confirm = stubConfirmer{false}
	if d := g.Authorize(context.Background(), Command{Binary: "bash", Args: []string{"-lc", "id"}}); d.Allowed {
		t.Error("a shell must be denied under HITL when the operator refuses")
	}
}

// A scope that lists in-scope network targets alongside `local` still scopes a
// command that names a network target: an out-of-scope target is denied, an
// in-scope one is allowed.
func TestLocalProfileMixedScopeStillChecksNetworkTargets(t *testing.T) {
	g := localGate(t, "local\n10.0.0.0/24\n")
	if d := g.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"http://8.8.8.8/"}}); d.Allowed {
		t.Error("out-of-scope network target must be denied in a mixed scope")
	}
	if d := g.Authorize(context.Background(), Command{Binary: "curl", Args: []string{"http://10.0.0.5/"}}); !d.Allowed {
		t.Errorf("in-scope network target must be allowed: %q", d.Reason)
	}
	if d := g.Authorize(context.Background(), Command{Binary: "id"}); !d.Allowed {
		t.Errorf("a no-target local command must be allowed: %q", d.Reason)
	}
}

// The external profile is unchanged: the allowlist, scope, and classifier all
// still apply when the scope has no local directive.
func TestExternalProfileUnchanged(t *testing.T) {
	s, _ := ParseScope(strings.NewReader("10.0.0.0/24\n"))
	g := &Gate{Mode: Auto, Scope: s, Allow: NewAllowlist("nmap", "find")}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if d := g.Authorize(ctx, Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}}); !d.Allowed {
		t.Errorf("in-scope allowlisted command must be allowed: %q", d.Reason)
	}
	if d := g.Authorize(ctx, Command{Binary: "nmap", Args: []string{"-p", "80", "8.8.8.8"}}); d.Allowed {
		t.Error("out-of-scope target must be denied")
	}
	if d := g.Authorize(ctx, Command{Binary: "id"}); d.Allowed {
		t.Error("a non-allowlisted binary must be denied in the external profile")
	}
	if d := g.Authorize(ctx, Command{Binary: "nmap", Args: []string{"-p", "80"}}); d.Allowed {
		t.Error("a no-target command must be denied in the external profile")
	}
	// find stays denied outright in the external profile, even when allowlisted.
	if d := g.Authorize(ctx, Command{Binary: "find", Args: []string{"10.0.0.5"}}); d.Allowed {
		t.Error("find must stay denied in the external profile")
	}
}
