package main

import (
	"strings"
	"testing"
)

func TestRoEPolicySections(t *testing.T) {
	text := "## In Scope\n10.20.0.5\n## Allowed Actions\ncommand\napi-read\n## Denied Actions\napi-write\n## Denied Commands\nbinary: rm\nargument: curl --upload-file\n## Resource Caps\nmax_commands: 20\nwall_seconds: 120\ncommand_seconds: 10\noutput_bytes: 65536\nparallel: 2\n"
	roe, err := ParseRoE(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if !roe.Scope.InScope("10.20.0.5") {
		t.Fatal("scope was lost while reading policy")
	}
}

func TestRoEPolicyRejectsDuplicateSections(t *testing.T) {
	if _, err := ParseRoE(strings.NewReader("## In Scope\n10.20.0.5\n## In Scope\n10.20.0.6\n")); err == nil {
		t.Fatal("duplicate security section accepted")
	}
}

func TestRoEPolicyRejectsOversizedDocument(t *testing.T) {
	if _, err := ParseRoE(strings.NewReader("## Summary\n" + strings.Repeat("a\n", 200000))); err == nil {
		t.Fatal("oversized policy accepted")
	}
}
