package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/secgate"
)

// pivotRoE is an external engagement that authorizes commands, which is what a scan needs; loopbackRoE authorizes api-read only.
func pivotRoE(t *testing.T) *RoE {
	t.Helper()
	roe, err := ParseRoE(strings.NewReader(
		"# Rules of Engagement\n\n## Summary\npivot fixture\n\n## Targets\n10.0.0.5\n\n" +
			"## In Scope\n10.0.0.0/24\n\n## Out of Scope\n\n## Rate\n10/s\n\n" +
			"## Allowed Actions\n- command\n- api-read\n\n## Autonomous Actions\n"))
	if err != nil {
		t.Fatal(err)
	}
	return roe
}

// A dependency or image scan runs in an external engagement with no scope target, which is what a pivot from external to internal needs: the scanner addresses no host, so there is nothing to scope, and its own audited rule confines its paths to the scratch directory.
func TestScannersRunInAnExternalEngagementWithNoScopeTarget(t *testing.T) {
	g := loopbackGate(t, pivotRoE(t))
	for _, c := range []secgate.Command{
		{Binary: "osv-scanner", Args: []string{"scan", "source", "--format", "json", "-r", "."},
			Phase: secgate.PhaseRecon, Surface: secgate.SurfaceContainer},
		{Binary: "osv-scanner", Args: []string{"scan", "source", "--format", "json", "-L", "go.mod"},
			Phase: secgate.PhaseRecon, Surface: secgate.SurfaceContainer},
		{Binary: "osv-scanner", Args: []string{"scan", "image", "--archive", "--format", "json", "image.tar"},
			Phase: secgate.PhaseRecon, Surface: secgate.SurfaceContainer},
		{Binary: "grype", Args: []string{"dir:.", "-o", "json"},
			Phase: secgate.PhaseRecon, Surface: secgate.SurfaceContainer},
		{Binary: "grype", Args: []string{"oci-archive:image.tar", "-o", "json"},
			Phase: secgate.PhaseRecon, Surface: secgate.SurfaceWeb},
		{Binary: "grype", Args: []string{"sbom:sbom.json", "-o", "json", "--only-fixed"},
			Phase: secgate.PhaseRecon, Surface: secgate.SurfaceNetwork},
	} {
		if d := g.Check(context.Background(), c); !d.Allowed {
			t.Errorf("%s %v denied: %s", c.Binary, c.Args, d.Reason)
		}
	}
}

// The relaxation is per binary. Any other allowlisted tool with no target is still denied, so a command whose target the extractor missed cannot ride in on it.
func TestNoTargetRelaxationIsLimitedToTheAuditedScanners(t *testing.T) {
	g := loopbackGate(t, pivotRoE(t))
	for _, c := range []secgate.Command{
		{Binary: "curl", Args: []string{"-s"}, Phase: secgate.PhaseRecon, Surface: secgate.SurfaceWeb},
		{Binary: "dig", Args: []string{"+short"}, Phase: secgate.PhaseRecon, Surface: secgate.SurfaceNetwork},
		{Binary: "host", Args: []string{"-t", "A"}, Phase: secgate.PhaseRecon, Surface: secgate.SurfaceNetwork},
		{Binary: "showmount", Args: []string{"-e"}, Phase: secgate.PhaseRecon, Surface: secgate.SurfaceNetwork},
	} {
		d := g.Check(context.Background(), c)
		if d.Allowed {
			t.Errorf("%s %v with no target was allowed", c.Binary, c.Args)
			continue
		}
		if !strings.Contains(d.Reason, "verifiable target") {
			t.Errorf("%s %v denied for %q, want the no-target reason", c.Binary, c.Args, d.Reason)
		}
	}
}

// The scanners stay bound by their own rules in the external profile: the forms that reach a registry, run code from the scanned tree, or leave the scratch directory are denied whether or not a target is present.
func TestScannerRulesStillApplyInAnExternalEngagement(t *testing.T) {
	g := loopbackGate(t, pivotRoE(t))
	for name, c := range map[string]secgate.Command{
		"osv registry image": {Binary: "osv-scanner", Args: []string{"scan", "image", "alpine:3.23"}},
		"osv build scripts":  {Binary: "osv-scanner", Args: []string{"scan", "source", "--call-analysis", "rust", "-r", "."}},
		"osv config":         {Binary: "osv-scanner", Args: []string{"scan", "source", "--config", "osv.toml", "-r", "."}},
		"osv listener":       {Binary: "osv-scanner", Args: []string{"scan", "source", "--serve", "-r", "."}},
		"osv rewrites":       {Binary: "osv-scanner", Args: []string{"fix", "-L", "go.mod"}},
		"osv escaping path":  {Binary: "osv-scanner", Args: []string{"scan", "source", "-r", "/etc"}},
		"grype registry":     {Binary: "grype", Args: []string{"registry:alpine:3.23", "-o", "json"}},
		"grype template":     {Binary: "grype", Args: []string{"dir:.", "-t", "t.tmpl"}},
		"grype config":       {Binary: "grype", Args: []string{"dir:.", "-c", "grype.yaml"}},
		"grype db":           {Binary: "grype", Args: []string{"db", "update"}},
		"grype schemeless":   {Binary: "grype", Args: []string{"alpine:3.23", "-o", "json"}},
		"grype escaping dir": {Binary: "grype", Args: []string{"dir:/etc", "-o", "json"}},
	} {
		c.Phase, c.Surface = secgate.PhaseRecon, secgate.SurfaceContainer
		if d := g.Check(context.Background(), c); d.Allowed {
			t.Errorf("%s: %s %v was allowed", name, c.Binary, c.Args)
		}
	}
}

// A scanner command naming a host is still scope-checked, so the relaxation does not create a path to an out-of-scope destination.
func TestScannerWithAHostIsStillScopeChecked(t *testing.T) {
	g := loopbackGate(t, pivotRoE(t))
	d := g.Check(context.Background(), secgate.Command{
		Binary: "grype", Args: []string{"sbom:sbom.json", "-o", "json", "--name", "198.51.100.7"},
		Phase: secgate.PhaseRecon, Surface: secgate.SurfaceContainer,
	})
	if d.Allowed {
		t.Error("a scanner command naming an out-of-scope host was allowed")
	}
	if !strings.Contains(d.Reason, "out of scope") {
		t.Errorf("denied for %q, want the scope reason", d.Reason)
	}
}

// The no-destination set comes from the catalog, so a tool only gets the relaxation by carrying the reach that records the audit.
func TestNoDestinationSetIsTheScratchReachCatalog(t *testing.T) {
	al := secgate.NewAllowlist(scratchReachBinaries()...)
	for _, b := range scratchReachBinaries() {
		if !al.Permits(b) {
			t.Errorf("%s is in the scratch-reach set but the allowlist refuses it", b)
		}
	}
	for _, b := range []string{"curl", "nmap", "jq", "cat", "grep", "kubectl"} {
		if al.Permits(b) {
			t.Errorf("%s must not be in the no-destination set", b)
		}
	}
	if len(scratchReachBinaries()) == 0 {
		t.Fatal("the catalog declares no scratch-reach tool, so the relaxation reaches nothing")
	}
}

// A gate with no no-destination set keeps the original denial, so the relaxation only exists where it is wired in.
func TestNoTargetDenialHoldsWithoutTheNoDestinationSet(t *testing.T) {
	scope, err := secgate.ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := &secgate.Gate{
		Mode: secgate.Auto, Scope: scope,
		Allow:     secgate.NewAllowlist("osv-scanner", "grype"),
		Approvals: secgate.NewSessionApprovals(),
	}
	d := g.Check(context.Background(), secgate.Command{
		Binary: "osv-scanner", Args: []string{"scan", "source", "--format", "json", "-r", "."},
		Phase: secgate.PhaseRecon, Surface: secgate.SurfaceContainer,
	})
	if d.Allowed {
		t.Error("a no-target command was allowed with no no-destination set")
	}
	if !strings.Contains(d.Reason, "verifiable target") {
		t.Errorf("denied for %q, want the target reason", d.Reason)
	}
}

// The runner pins every operator address out of scope before the gate is built, so a scanner command must still pass after that mutation: it names no target, so there is nothing for the pin to exclude.
func TestScannersSurviveTheRunnerScopePinning(t *testing.T) {
	roe := pivotRoE(t)
	before := roe.Scope.InScope("10.0.0.5")
	if !before {
		t.Fatal("the fixture scope does not admit its own target")
	}
	// The same pinning newEngageRunner performs: the declared network in, every operator address out.
	if err := roe.Scope.PinNetwork([]string{"10.0.0.0/24"}, operatorAddresses()); err != nil {
		t.Fatal(err)
	}
	for _, addr := range operatorAddresses() {
		if roe.Scope.InScope(addr) {
			t.Errorf("operator address %s stayed in scope after pinning", addr)
		}
	}
	g := loopbackGate(t, roe)
	for _, c := range []secgate.Command{
		{Binary: "osv-scanner", Args: []string{"scan", "source", "--format", "json", "-r", "."},
			Phase: secgate.PhaseRecon, Surface: secgate.SurfaceContainer},
		{Binary: "grype", Args: []string{"dir:.", "-o", "json"},
			Phase: secgate.PhaseRecon, Surface: secgate.SurfaceContainer},
	} {
		if d := g.Check(context.Background(), c); !d.Allowed {
			t.Errorf("%s %v denied after scope pinning: %s", c.Binary, c.Args, d.Reason)
		}
	}
	// A command naming a pinned-out address is still refused, so the relaxation did not widen the scope.
	if len(operatorAddresses()) > 0 {
		d := g.Check(context.Background(), secgate.Command{
			Binary: "grype", Args: []string{"dir:.", "-o", "json", "--name", operatorAddresses()[0]},
			Phase: secgate.PhaseRecon, Surface: secgate.SurfaceContainer,
		})
		if d.Allowed {
			t.Error("a scanner command naming a pinned-out operator address was allowed")
		}
	}
}
