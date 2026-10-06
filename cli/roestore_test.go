package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"blkchain/cli/internal/histstore"
)

func TestRoETableRememberRecall(t *testing.T) {
	store, err := histstore.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	db := store.DB()
	if err := ensureRoETable(db); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	roePath := filepath.Join(dir, "ROE.md")
	if err := os.WriteFile(roePath, []byte("## In Scope\n- 10.0.0.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rememberRoE(db, dir, roePath); err != nil {
		t.Fatal(err)
	}
	got, ok := recallRoE(db, dir)
	if !ok || got != roePath {
		t.Errorf("recallRoE = %q,%v; want %q,true", got, ok, roePath)
	}

	// A remembered path whose file no longer exists is not recalled.
	os.Remove(roePath)
	if got, ok := recallRoE(db, dir); ok {
		t.Errorf("recallRoE must miss when the file is gone, got %q", got)
	}
}

func TestRecallRoENilDBGraceful(t *testing.T) {
	if _, ok := recallRoE(nil, "/some/dir"); ok {
		t.Error("recallRoE(nil, ...) must miss, not panic")
	}
	if err := rememberRoE(nil, "/some/dir", "/some/dir/ROE.md"); err != nil {
		t.Errorf("rememberRoE(nil, ...) must be a graceful no-op, got %v", err)
	}
}

func TestWriteRoETemplateCreatesAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	written, err := writeRoETemplate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !written {
		t.Fatal("first writeRoETemplate must create the file")
	}
	path := filepath.Join(dir, "ROE.md")
	edited := "## In Scope\n- edited.example.com\n"
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	written2, err := writeRoETemplate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if written2 {
		t.Error("second writeRoETemplate must not overwrite an existing ROE.md")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != edited {
		t.Error("writeRoETemplate must not clobber an edited ROE.md")
	}
}

func TestRoETemplateParsesAsRoE(t *testing.T) {
	dir := t.TempDir()
	if _, err := writeRoETemplate(dir); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "ROE.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := ParseRoE(f); err != nil {
		t.Errorf("the ROE.md template must parse as a valid RoE: %v", err)
	}
}

func TestRoETemplateAllowedActionsCanBeCommentedOut(t *testing.T) {
	dir := t.TempDir()
	if _, err := writeRoETemplate(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "ROE.md"))
	if err != nil {
		t.Fatal(err)
	}
	roe, err := ParseRoE(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"command", "local", "api-read", "api-write", "browser-read", "browser-write"}
	if !slices.Equal(roe.Policy.Allowed, want) {
		t.Fatalf("template allowed actions = %v, want %v", roe.Policy.Allowed, want)
	}
	if !roe.Scope.Empty() || roe.Scope.Local() {
		t.Fatal("template must still require an operator-defined scope")
	}

	commented := strings.Replace(string(data), "- api-write\n", "<!-- - api-write -->\n", 1)
	if commented == string(data) {
		t.Fatal("template has no api-write entry to comment out")
	}
	roe, err = ParseRoE(strings.NewReader(commented))
	if err != nil {
		t.Fatal(err)
	}
	if roe.Policy.Allows("api-write") || !roe.Policy.Allows("browser-write") {
		t.Fatalf("commented action was not disabled: %v", roe.Policy.Allowed)
	}
}
