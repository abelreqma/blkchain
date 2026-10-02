package secgate

import (
	"context"
	"path/filepath"
	"testing"
)

// protectedPaths returns the five guarded artifact paths under wsDir, matching
// the engagement workspace layout (engagement.db, audit.jsonl, the evidence
// directory, report.md, report.json).
func protectedPaths(wsDir string) []string {
	return []string{
		filepath.Join(wsDir, "engagement.db"),
		filepath.Join(wsDir, "audit.jsonl"),
		filepath.Join(wsDir, "evidence"),
		filepath.Join(wsDir, "report.md"),
		filepath.Join(wsDir, "report.json"),
	}
}

// A command that references a protected harness artifact or a .env file is
// denied in the local profile, both by SensitivePathViolation directly and
// through the full Authorize pipeline (audited as deny:sensitive-path).
func TestSensitivePathDenied(t *testing.T) {
	wsDir := t.TempDir()
	scratch := t.TempDir()
	protected := protectedPaths(wsDir)

	// A relative ".." traversal from scratch that resolves back into wsDir.
	relDB, err := filepath.Rel(scratch, filepath.Join(wsDir, "engagement.db"))
	if err != nil {
		t.Fatal(err)
	}

	denied := []Command{
		cmd("cat", filepath.Join(wsDir, "engagement.db")),
		cmd("grep", "x", filepath.Join(wsDir, "audit.jsonl")),
		cmd("cat", filepath.Join(wsDir, "report.md")),
		cmd("cat", filepath.Join(wsDir, "report.json")),
		cmd("head", filepath.Join(wsDir, "evidence", "somefile")),
		cmd("cat", relDB),
		cmd("cat", ".env"),
		cmd("cat", "/etc/secret/.env"),
		cmd("grep", "x", "../.env"),
	}
	for _, c := range denied {
		if _, bad := SensitivePathViolation(c, protected, scratch); !bad {
			t.Errorf("SensitivePathViolation must flag %v", c)
		}
		// A fresh gate per command keeps the episode command cap out of the result.
		g := localGate(t, "local\n")
		g.Protected = protected
		g.Scratch = scratch
		var actions []string
		g.Audit = func(a, d string) { actions = append(actions, a) }
		if d := g.Authorize(context.Background(), c); d.Allowed {
			t.Errorf("Authorize must deny %v in local mode", c)
		} else if got := lastAction(t, actions); got != "deny:sensitive-path" {
			t.Errorf("%v must be denied by the sensitive-path layer, got %q (%q)", c, got, d.Reason)
		}
	}
}

// A protected path glued into a flag value (--flag=PATH, -xPATH, or an @file
// data reference) is denied too, both by SensitivePathViolation directly and
// through the full Authorize pipeline (audited as deny:sensitive-path).
func TestSensitivePathGluedDenied(t *testing.T) {
	wsDir := t.TempDir()
	scratch := t.TempDir()
	protected := protectedPaths(wsDir)

	denied := []Command{
		cmd("sort", "--output="+filepath.Join(wsDir, "report.md"), "extra"),
		cmd("sort", "-o"+filepath.Join(wsDir, "engagement.db")),
		cmd("tool", "--file="+filepath.Join(wsDir, "audit.jsonl")),
		cmd("tool", "--data=@"+filepath.Join(wsDir, "audit.jsonl")),
		cmd("tool", "--out="+filepath.Join(wsDir, "evidence", "x")),
		cmd("tool", "--env-file=/some/dir/.env"),
	}
	for _, c := range denied {
		if _, bad := SensitivePathViolation(c, protected, scratch); !bad {
			t.Errorf("SensitivePathViolation must flag %v", c)
		}
		// A fresh gate per command keeps the episode command cap out of the result.
		g := localGate(t, "local\n")
		g.Protected = protected
		g.Scratch = scratch
		var actions []string
		g.Audit = func(a, d string) { actions = append(actions, a) }
		if d := g.Authorize(context.Background(), c); d.Allowed {
			t.Errorf("Authorize must deny %v in local mode", c)
		} else if got := lastAction(t, actions); got != "deny:sensitive-path" {
			t.Errorf("%v must be denied by the sensitive-path layer, got %q (%q)", c, got, d.Reason)
		}
	}
}

// A flag value that does not resolve to a protected path is not flagged, so a
// mis-extracted fragment cannot over-deny a safe command.
func TestSensitivePathGluedAllowed(t *testing.T) {
	wsDir := t.TempDir()
	scratch := t.TempDir()
	protected := protectedPaths(wsDir)

	allowed := []Command{
		cmd("sort", "-rf", "data.txt"),
		cmd("tool", "--output=/tmp/safe.txt"),
		cmd("tool", "--threads=4"),
		cmd("grep", "--color=auto", "pattern", "file"),
	}
	for _, c := range allowed {
		if arg, bad := SensitivePathViolation(c, protected, scratch); bad {
			t.Errorf("SensitivePathViolation must allow %v, flagged %q", c, arg)
		}
	}
}

// A command that references only non-protected files is not flagged.
func TestSensitivePathAllowed(t *testing.T) {
	wsDir := t.TempDir()
	scratch := t.TempDir()
	protected := protectedPaths(wsDir)

	allowed := []Command{
		cmd("cat", "/etc/passwd"),
		cmd("ls", "/proc"),
		cmd("cat", "report.md.txt"),
		cmd("grep", "env", "somefile"),
		cmd("id"),
	}
	for _, c := range allowed {
		if arg, bad := SensitivePathViolation(c, protected, scratch); bad {
			t.Errorf("SensitivePathViolation must allow %v, flagged %q", c, arg)
		}
	}
}

// The external profile never calls the sensitive-path check: authorizing a
// command whose argument names a protected artifact takes the external branch
// and is never audited as deny:sensitive-path.
func TestSensitivePathNotAppliedInExternalProfile(t *testing.T) {
	wsDir := t.TempDir()
	var actions []string
	g := &Gate{
		Mode:      Auto,
		Scope:     okScope(t),
		Allow:     NewAllowlist("cat"),
		Protected: protectedPaths(wsDir),
		Scratch:   t.TempDir(),
		Audit:     func(a, d string) { actions = append(actions, a) },
	}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	c := cmd("cat", filepath.Join(wsDir, "engagement.db"), "10.0.0.5")
	g.Authorize(context.Background(), c)
	for _, a := range actions {
		if a == "deny:sensitive-path" {
			t.Fatalf("external profile must not run the sensitive-path check: %v", actions)
		}
	}
}

// On a case-insensitive filesystem a protected artifact spelled
// with different case still resolves to the same file, and every .env variant is
// a secret. Both must be denied.
func TestSensitivePathCaseFoldAndDotenvVariants(t *testing.T) {
	protected := []string{"/ws/engagement.db", "/ws/audit.jsonl", "/ws/evidence", "/ws/report.md"}
	scratch := "/scratch"
	deny := []Command{
		{Binary: "cat", Args: []string{"/ws/Engagement.DB"}},         // case variant of a protected file
		{Binary: "cat", Args: []string{"/WS/AUDIT.JSONL"}},           // case variant, dir + file
		{Binary: "grep", Args: []string{"x", "/ws/Evidence/e1.txt"}}, // under a protected dir, case variant
		{Binary: "cat", Args: []string{".env"}},
		{Binary: "cat", Args: []string{".env.local"}},
		{Binary: "cat", Args: []string{".ENV"}},
		{Binary: "cat", Args: []string{"/some/dir/.Env.Prod"}},
	}
	for _, c := range deny {
		if _, bad := SensitivePathViolation(c, protected, scratch); !bad {
			t.Errorf("%v must be denied (S2 case-fold / .env.*)", c.Args)
		}
	}
	// Control: a plain file named "env" (no dot) and an unrelated file are allowed.
	for _, c := range []Command{
		{Binary: "cat", Args: []string{"env"}},
		{Binary: "cat", Args: []string{"/etc/hosts"}},
	} {
		if _, bad := SensitivePathViolation(c, protected, scratch); bad {
			t.Errorf("%v must NOT be denied by the harness-artifact check", c.Args)
		}
	}
}
