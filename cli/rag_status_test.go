package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTUIBareRagReportsToggle(t *testing.T) {
	noColor(t)
	for _, on := range []bool{true, false} {
		m := frameModel(t)
		m.prefs.Rag = on
		_, cmd := m.dispatchInput("/rag")
		var out strings.Builder
		for _, msg := range drain(cmd) {
			fmt.Fprint(&out, msg)
		}
		want := "rag " + boolOnOff(on)
		if !strings.Contains(out.String(), want) {
			t.Errorf("bare /rag with Rag=%v printed %q, want %q", on, out.String(), want)
		}
		if strings.Contains(out.String(), "native specialists") {
			t.Errorf("bare /rag printed the specialist status: %q", out.String())
		}
	}
}

func TestPlainBareRagReportsToggle(t *testing.T) {
	useDeadServices(t)
	noColor(t)
	isolateUserDirs(t)
	t.Chdir(t.TempDir())
	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("/rag on\n/rag\n/rag off\n/rag\n/quit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stdin := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = stdin })
	out := captureStdout(t, func() {
		captureStderr(t, func() {
			if err := plainREPL(); err != nil {
				t.Fatal(err)
			}
		})
	})
	var got []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimPrefix(line, "blk> "); line == "rag on" || line == "rag off" {
			got = append(got, line)
		}
	}
	if want := "rag on,rag on,rag off,rag off"; strings.Join(got, ",") != want {
		t.Fatalf("rag lines = %v, want %s; out=%q", got, want, out)
	}
}
