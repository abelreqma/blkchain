package engagement

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenWorkspaceCreatesLayout(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "eng1")
	w, err := OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.Store == nil {
		t.Fatal("Store is nil")
	}
	if fi, err := os.Stat(w.EvidenceDir()); err != nil || !fi.IsDir() {
		t.Errorf("evidence dir missing: %v", err)
	}
	// The store works.
	if _, err := w.Store.Apply(Delta{Upserts: []Task{{ID: "t1", Status: StatusTodo}}, Kind: "init"}); err != nil {
		t.Fatal(err)
	}
}

func TestAuditLineSanitizesAndAppends(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "eng2")
	w, err := OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// A hostile detail with a newline and a NUL must not create a second line.
	if err := w.AuditLine("gate", "deny:scope", "target\nout of\x00scope"); err != nil {
		t.Fatal(err)
	}
	if err := w.AuditLine("gate", "allow", "nmap"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 audit lines, got %d: %q", len(lines), string(b))
	}
	if strings.Contains(lines[0], "\x00") {
		t.Error("NUL not sanitized in audit line")
	}
	var denied, allowed auditRecord
	if err := json.Unmarshal([]byte(lines[0]), &denied); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &allowed); err != nil {
		t.Fatal(err)
	}
	if denied.Kind != "decision" || denied.Outcome != "denied" || denied.ReasonCode != "scope" || allowed.Outcome != "allowed" {
		t.Fatalf("structured audit denied=%+v allowed=%+v", denied, allowed)
	}
}

func TestSanitizeAuditDetailTruncates(t *testing.T) {
	long := strings.Repeat("a", auditDetailCap+500)
	got := sanitizeAuditDetail(long)
	if len([]rune(got)) != auditDetailCap {
		t.Errorf("len = %d, want %d", len([]rune(got)), auditDetailCap)
	}
}

func TestExecAuditIsAttempt(t *testing.T) {
	kind, outcome, reason := auditFields("exec")
	if kind != "action" || outcome != "attempted" || reason != "" {
		t.Fatalf("exec fields=%q %q %q", kind, outcome, reason)
	}
}
