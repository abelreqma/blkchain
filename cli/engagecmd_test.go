package main

import (
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
