package main

import (
	"os"
	"strings"
	"testing"

	"blkchain/cli/internal/secgate"
)

func TestEngageAutoRequiresScope(t *testing.T) {
	err := runEngage([]string{"--auto", "do a scan"})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "scope") {
		t.Errorf("--auto without --scope must be a usage error mentioning scope, got %v", err)
	}
}

func TestEngageRequiresGoal(t *testing.T) {
	err := runEngage([]string{})
	if err == nil {
		t.Error("engage with no goal must be a usage error")
	}
}

func TestDefaultAllowlistExcludesClassifierDeniedBinaries(t *testing.T) {
	al := secgate.NewAllowlist(defaultEngageAllowlist()...)
	// Sanity: an allowlisted recon binary is permitted by the allowlist.
	if !al.Permits("nmap") {
		t.Error("nmap should be in the default allowlist")
	}
	// The default must not list binaries the classifier denies (shells/wrappers/interpreters),
	// since Authorize would deny them anyway; keep the default coherent.
	for _, bad := range []string{"sudo", "env", "bash", "sh", "python", "find", "xargs"} {
		for _, b := range defaultEngageAllowlist() {
			if b == bad {
				t.Errorf("default allowlist should not contain classifier-denied %q", bad)
			}
		}
	}
}

func TestEngageLoadsCatalogFromEnv(t *testing.T) {
	dir := t.TempDir()
	// one valid skill
	sk := dir + "/attacking-oauth"
	if err := os.MkdirAll(sk, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sk+"/SKILL.md", []byte("---\nname: attacking-oauth\ndescription: oauth jwt web\n---\nbody\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_SKILLS_DIR", dir)
	cat, err := loadEngageCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if cat.Len() != 1 {
		t.Errorf("catalog len = %d, want 1", cat.Len())
	}
}

func TestEngageCatalogUnsetIsEmpty(t *testing.T) {
	t.Setenv("BLKCHAIN_SKILLS_DIR", "")
	cat, err := loadEngageCatalog()
	if err != nil || cat.Len() != 0 {
		t.Errorf("unset skills dir: err=%v len=%d", err, cat.Len())
	}
}
