package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHermesOnPath puts a hermes that answers the one-shot invocation on PATH.
func fakeHermesOnPath(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	script := "#!/bin/sh\nprintf 'hermes-fixture-answer\\n'\n"
	if err := os.WriteFile(filepath.Join(bin, "hermes"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("HERMES_HOME", t.TempDir())
}

func TestHermesWritesNoSession(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	fakeHermesOnPath(t)

	if err := runHermes([]string{"summarize the SSRF notes"}); err != nil {
		t.Fatal(err)
	}
	metas, err := listSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 0 {
		t.Fatalf("a hermes turn created %d sessions", len(metas))
	}
}

func TestHermesHelpSaysLegacy(t *testing.T) {
	c, ok := lookupCommand("hermes")
	if !ok {
		t.Fatal("the hermes command is gone; it must stay as a legacy escape hatch")
	}
	if !strings.Contains(strings.ToLower(c.desc+" "+c.long), "legacy") {
		t.Fatalf("the hermes help does not say it is legacy: %q", c.desc)
	}
}
