package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// roetemplatewiring_test.go pins that roeTemplate reaches an operator. It had no
// production caller: `blk engage` with no ROE.md refused with "create the file in
// this directory", leaving the operator to write a scope policy from scratch while
// the commented template sat unused. These tests keep the template on that path and
// keep it non-destructive.

// The first run without a policy writes the template, names the path it wrote, and
// still refuses, since the template parses to an empty scope and authorizes nothing.
func TestEngageWritesTheTemplateWhenNoRoEExists(t *testing.T) {
	dir := t.TempDir()
	_, _, err := loadEngageRoE(engageOpts{}, dir, nil)
	if err == nil {
		t.Fatal("engage must refuse to run without a filled-in policy")
	}
	path := filepath.Join(dir, "ROE.md")
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("the template was not written: %v", readErr)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the refusal should name the file it wrote, got %q", err)
	}
	if string(data) != roeTemplate {
		t.Error("the written file must be the template verbatim")
	}
	// It is a policy file, so it is created private like the rest of the workspace.
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("ROE.md mode = %04o, want no group or other access", perm)
	}
}

// The second run reads the template the first run wrote and refuses on the
// empty-scope floor instead, so an unfilled template cannot start an engagement.
func TestUnfilledTemplateStillRefusesOnTheEmptyScopeFloor(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := loadEngageRoE(engageOpts{}, dir, nil); err == nil {
		t.Fatal("the first call must refuse")
	}
	before, err := os.ReadFile(filepath.Join(dir, "ROE.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = loadEngageRoE(engageOpts{}, dir, nil)
	if err == nil {
		t.Fatal("an unfilled template must not start an engagement")
	}
	if !strings.Contains(err.Error(), "in-scope targets") {
		t.Errorf("want the empty-scope refusal, got %q", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "ROE.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("a later run must not rewrite the operator's ROE.md")
	}
}

// An operator's edited policy is never clobbered, and once it carries a scope the
// engagement loads.
func TestAFilledPolicyLoadsAndIsNeverClobbered(t *testing.T) {
	dir := t.TempDir()
	filled := strings.Replace(roeTemplate, "## In Scope\n", "## In Scope\n192.0.2.1\n", 1)
	path := filepath.Join(dir, "ROE.md")
	if err := os.WriteFile(path, []byte(filled), 0o600); err != nil {
		t.Fatal(err)
	}
	roe, used, err := loadEngageRoE(engageOpts{}, dir, nil)
	if err != nil {
		t.Fatalf("a filled policy must load: %v", err)
	}
	if !roe.Scope.InScope("192.0.2.1") {
		t.Error("the declared target is not in scope")
	}
	if used != path {
		t.Errorf("loaded %q, want %q", used, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != filled {
		t.Error("loading a policy must not rewrite it")
	}
}

// An explicit --roe that does not exist is the operator naming a path, so it is a
// plain error: nothing is written into the working directory behind their back.
func TestExplicitRoEPathDoesNotWriteATemplate(t *testing.T) {
	dir := t.TempDir()
	_, _, err := loadEngageRoE(engageOpts{roe: filepath.Join(dir, "absent", "ROE.md")}, dir, nil)
	if err == nil {
		t.Fatal("a missing --roe path must be an error")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "ROE.md")); statErr == nil {
		t.Error("an explicit --roe must not cause a template to be written to the working directory")
	}
}
