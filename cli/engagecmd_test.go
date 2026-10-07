package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"blkchain/cli/internal/histstore"
	"blkchain/cli/internal/secgate"
)

func TestEngageAutoRequiresScope(t *testing.T) {
	// runEngage reads the working directory to find ROE.md and, finding none, writes
	// the template there. An empty temp directory keeps that out of the package and
	// keeps the verdict from depending on a file an earlier run left behind.
	t.Chdir(t.TempDir())
	err := runEngage([]string{"--auto", "do a scan"})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "scope") {
		t.Errorf("--auto without --scope must be a usage error mentioning scope, got %v", err)
	}
}

func TestEngageRequiresGoal(t *testing.T) {
	t.Chdir(t.TempDir())
	err := runEngage([]string{})
	if err == nil {
		t.Error("engage with no goal must be a usage error")
	}
}

func TestDefaultAllowlistExcludesClassifierDeniedBinaries(t *testing.T) {
	al := secgate.NewAllowlist(externalEngageAllowlist()...)
	// Sanity: an allowlisted recon binary is permitted by the allowlist.
	if !al.Permits("nmap") {
		t.Error("nmap should be in the default allowlist")
	}
	// The default must not list binaries the classifier denies (shells/wrappers/interpreters),
	// since Authorize would deny them anyway; keep the default coherent.
	for _, bad := range []string{"sudo", "env", "bash", "sh", "python", "find", "xargs"} {
		for _, b := range externalEngageAllowlist() {
			if b == bad {
				t.Errorf("default allowlist should not contain classifier-denied %q", bad)
			}
		}
	}
}

func TestDefaultAllowlistIncludesAuditedSMBEnumTools(t *testing.T) {
	al := secgate.NewAllowlist(externalEngageAllowlist()...)
	for _, b := range []string{"smbclient", "rpcclient", "nbtscan", "showmount"} {
		if !al.Permits(b) {
			t.Errorf("%s should be in the default allowlist", b)
		}
	}
}

func TestDefaultAllowlistIncludesAuditedLDAPSNMPHTTPEnumTools(t *testing.T) {
	al := secgate.NewAllowlist(externalEngageAllowlist()...)
	for _, b := range []string{"ldapsearch", "snmpwalk", "ffuf"} {
		if !al.Permits(b) {
			t.Errorf("%s should be in the default allowlist", b)
		}
	}
}

// TestDefaultAllowlistExcludesUnavailableTools pins the other half of the
// contract: a binary the image does not ship must not be allowlisted, so no
// persona is told to run a command that cannot execute. onesixtyone, gobuster
// and nikto have no Alpine package, and dnsrecon's package is unusable; their
// secgate audits stay in place for an operator who adds the binary.
func TestDefaultAllowlistExcludesUnavailableTools(t *testing.T) {
	al := secgate.NewAllowlist(externalEngageAllowlist()...)
	for b := range unavailableTools {
		if al.Permits(b) {
			t.Errorf("%s is unavailable (%s) and must not be allowlisted", b, unavailableTools[b])
		}
	}
}

func TestDefaultAllowlistIncludesAuditedDNSEnumTools(t *testing.T) {
	al := secgate.NewAllowlist(externalEngageAllowlist()...)
	for _, b := range []string{"host", "nslookup"} {
		if !al.Permits(b) {
			t.Errorf("%s should be in the default allowlist", b)
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

// --- scope + config resolution ---

func TestResolveEngageScopeExplicitWins(t *testing.T) {
	sp := filepath.Join(t.TempDir(), "scope.txt")
	writeFile(t, sp, "10.0.0.5\n")
	// An ROE.md in cwd must be ignored when --scope is explicit.
	cwd := t.TempDir()
	writeFile(t, filepath.Join(cwd, "ROE.md"), "## In Scope\n- 8.8.8.8\n")
	scope, desc, roeUsed, err := resolveEngageScope(engageOpts{scope: sp}, cwd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.InScope("10.0.0.5") || scope.InScope("8.8.8.8") {
		t.Error("explicit --scope must win over an ROE.md in cwd")
	}
	if roeUsed != "" || desc != sp {
		t.Errorf("desc=%q roeUsed=%q; want desc=%q roeUsed=\"\"", desc, roeUsed, sp)
	}
}

func TestResolveEngageScopeFromRoEInCwd(t *testing.T) {
	cwd := t.TempDir()
	roePath := filepath.Join(cwd, "ROE.md")
	writeFile(t, roePath, "## In Scope\n- 10.0.0.5\n")
	store, err := histstore.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	db := store.DB()
	scope, _, roeUsed, err := resolveEngageScope(engageOpts{}, cwd, db)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.InScope("10.0.0.5") {
		t.Error("ROE.md in cwd should set the scope")
	}
	if roeUsed != roePath {
		t.Errorf("roeUsed = %q, want %q", roeUsed, roePath)
	}
	if p, ok := recallRoE(db, cwd); !ok || p != roePath {
		t.Errorf("ROE.md should be remembered for cwd: %q,%v", p, ok)
	}
}

func TestResolveEngageScopeRecall(t *testing.T) {
	// No ROE.md in cwd, but one is remembered for it (and still exists).
	cwd := t.TempDir()
	remembered := filepath.Join(t.TempDir(), "ROE.md")
	writeFile(t, remembered, "## In Scope\n- 10.0.0.9\n")
	store, err := histstore.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	db := store.DB()
	if err := ensureRoETable(db); err != nil {
		t.Fatal(err)
	}
	if err := rememberRoE(db, cwd, remembered); err != nil {
		t.Fatal(err)
	}
	scope, _, roeUsed, err := resolveEngageScope(engageOpts{}, cwd, db)
	if err != nil {
		t.Fatal(err)
	}
	if roeUsed != remembered || !scope.InScope("10.0.0.9") {
		t.Errorf("recall should reuse the remembered ROE.md: roeUsed=%q", roeUsed)
	}
}

func TestResolveEngageScopeNone(t *testing.T) {
	scope, desc, roeUsed, err := resolveEngageScope(engageOpts{}, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if scope != nil || desc != "(none)" || roeUsed != "" {
		t.Errorf("no scope source must yield (nil, \"(none)\", \"\"): %v %q %q", scope, desc, roeUsed)
	}
}

func TestResolveEngageConfigPolicyFromConfig(t *testing.T) {
	cwd := t.TempDir()
	writeFile(t, filepath.Join(cwd, ".blkchain", "config.yaml"),
		"denied_binaries: [nc]\nallowed_binaries: [nmap]\nallow_interpreter_poc: true\n")
	pol, err := resolveEngageConfigPolicy(engageOpts{autoOverride: true}, cwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.DeniedBinaries) != 1 || pol.DeniedBinaries[0] != "nc" {
		t.Errorf("denied not threaded: %v", pol.DeniedBinaries)
	}
	if pol.UnattendedAllow == nil || !pol.UnattendedAllow.Permits("nmap") {
		t.Error("allowed_binaries not threaded")
	}
	if !pol.AllowInterpreterPoC || !pol.AutoScopeOverride {
		t.Error("poc/override not threaded")
	}
}

func TestResolveEngageConfigPolicyAllowedTrueNoBound(t *testing.T) {
	cwd := t.TempDir()
	writeFile(t, filepath.Join(cwd, ".blkchain", "config.yaml"), "allowed_binaries: true\n")
	pol, err := resolveEngageConfigPolicy(engageOpts{}, cwd)
	if err != nil {
		t.Fatal(err)
	}
	if pol.UnattendedAllow != nil {
		t.Error("allowed_binaries: true means everything allowed -> no unattended bound (nil UnattendedAllow)")
	}
}

func TestResolveEngageConfigPolicyAbsentEmptyBound(t *testing.T) {
	pol, err := resolveEngageConfigPolicy(engageOpts{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if pol.UnattendedAllow == nil {
		t.Fatal("absent config must still set a (empty) unattended bound, not nil")
	}
	if pol.UnattendedAllow.Permits("nmap") {
		t.Error("an absent config means an empty unattended allowlist (permits nothing)")
	}
}
