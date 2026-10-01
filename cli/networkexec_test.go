package main

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

// networkPromptCaptureModel records the last human tier prompt it was handed and
// then ends the tier (no run_command), so a test can assert what the model
// actually saw. The sufficiency grader call is answered with stop.
type networkPromptCaptureModel struct{ human string }

func (m *networkPromptCaptureModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	var human string
	for _, mc := range msgs {
		if mc.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range mc.Parts {
			if tc, ok := p.(llms.TextContent); ok {
				human += tc.Text
			}
		}
	}
	if strings.Contains(human, "Respond with ONLY one JSON object") {
		return finalResp(`{"continue": false}`), nil
	}
	m.human = human
	return finalResp("tier done"), nil
}

// TestNetworkExecutorRegistered: the network surface resolves to a concrete
// networkExecutor (via init registration), not the generic fallback.
func TestNetworkExecutorRegistered(t *testing.T) {
	d := testDeps(t, &scriptModel{})
	task := engagement.Task{ID: "t1", Surface: engagement.SurfaceNetwork, Phase: engagement.PhaseRecon}
	ex := executorFor(d, task)
	if _, ok := ex.(networkExecutor); !ok {
		t.Fatalf("executorFor(network) = %T, want networkExecutor", ex)
	}
}

// TestNetworkVantageSkewExternalVsInternal: the skew line emphasizes external
// host/port/service enumeration at external (and unset) vantages, and shifts to
// internal SMB/LDAP/lateral enumeration once the vantage is an internal foothold
// or better. Vantage is context, not a persona switch.
func TestNetworkVantageSkewExternalVsInternal(t *testing.T) {
	external := []engagement.Vantage{"", engagement.VantageExternalUnauth, engagement.VantageExternalAuth}
	for _, v := range external {
		skew := networkVantageSkew(v)
		low := strings.ToLower(skew)
		if !strings.Contains(low, "host") || !strings.Contains(low, "port") || !strings.Contains(low, "service") {
			t.Errorf("external skew for %q = %q, want host/port/service emphasis", v, skew)
		}
		if strings.Contains(low, "lateral") {
			t.Errorf("external skew for %q = %q, should not push lateral movement", v, skew)
		}
	}
	internal := []engagement.Vantage{engagement.VantageInternalFoothold, engagement.VantageLocalElevated, engagement.VantageLateralDomain}
	for _, v := range internal {
		skew := networkVantageSkew(v)
		low := strings.ToLower(skew)
		if !strings.Contains(low, "smb") || !strings.Contains(low, "ldap") || !strings.Contains(low, "lateral") {
			t.Errorf("internal skew for %q = %q, want SMB/LDAP/lateral emphasis", v, skew)
		}
	}
}

// TestNetworkReconInjectsVantageSkewIntoTierPrompt: the network executor's recon
// driver appends the vantage skew to the tier prompt the model receives. At an
// internal foothold the model sees the internal (SMB/LDAP/lateral) emphasis on
// top of the base per-tier instruction. The generic executor's recon path does
// not do this, so this test pins the network driver's value-add.
func TestNetworkReconInjectsVantageSkewIntoTierPrompt(t *testing.T) {
	model := &networkPromptCaptureModel{}
	d := testDeps(t, model)
	d.ReconTiers = true
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	foot := engagement.VantageInternalFoothold
	if _, err := d.Store.Apply(engagement.Delta{SetVantage: &foot}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "enumerate",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	ex := executorFor(d, task)
	if _, err := ex.Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(model.human, "Perform ONLY this tier's step") {
		t.Fatalf("tier prompt missing the base per-tier instruction:\n%s", model.human)
	}
	if !strings.Contains(model.human, "SMB") || !strings.Contains(strings.ToLower(model.human), "lateral") {
		t.Fatalf("tier prompt missing the internal vantage skew:\n%s", model.human)
	}
}

// networkSeedScan is the nmap -sV output the acceptance stub returns for the seed
// asset: it discloses a second in-scope host (10.0.0.6) for per-asset recursion
// and an OpenSSH service on 10.0.0.5:22 for a deterministic exploit candidate.
const networkSeedScan = "Nmap scan report for 10.0.0.5\n22/tcp open ssh OpenSSH 8.9p1\nNmap scan report for host6.corp (10.0.0.6)"

// networkScanModel drives the acceptance recon: for the seed asset it runs one
// nmap and records the seed scan verbatim; for any other asset it ends the tier
// without new evidence (so recursion terminates). The grader is answered stop.
type networkScanModel struct{}

func (networkScanModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	var human string
	toolTurns := 0
	for _, m := range msgs {
		if m.Role == llms.ChatMessageTypeTool {
			toolTurns++
		}
		if m.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range m.Parts {
			if tc, ok := p.(llms.TextContent); ok {
				human += tc.Text
			}
		}
	}
	if strings.Contains(human, "Respond with ONLY one JSON object") {
		return finalResp(`{"continue": false}`), nil
	}
	if !strings.Contains(human, "Asset: 10.0.0.5") {
		return finalResp("nothing further on this asset"), nil
	}
	switch toolTurns {
	case 0:
		// Port-bounded so the structural classifier does not deny it as unbounded.
		return toolCallResp("c1", "run_command", `{"binary":"nmap","args":["-sV","-p","22","10.0.0.5"]}`), nil
	case 1:
		return toolCallResp("c2", "record_evidence", `{"task_id":"t1","quote":`+strconv.Quote(networkSeedScan)+`}`), nil
	}
	return finalResp("tier done"), nil
}

func TestNetworkExecutorRunsLadderRecursesAndCorrelates(t *testing.T) {
	d := testDeps(t, networkScanModel{})
	d.ReconTiers = true
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	withStubExec(t, func(_ context.Context, _ string, args []string, _ string, _ int, _ time.Duration) runResult {
		return runResult{Output: networkSeedScan}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "enumerate",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executorFor(d, task).Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}

	// Ladder ran: the seed asset's host-discovery dimension is covered.
	rows, err := d.Store.AllReconCoverage()
	if err != nil {
		t.Fatal(err)
	}
	var seedCovered bool
	for _, r := range rows {
		if r.Asset == "10.0.0.5" && r.Dimensions["hosts"] == engagement.ReconCovered {
			seedCovered = true
		}
	}
	if !seedCovered {
		t.Fatalf("seed asset 10.0.0.5 hosts dimension not covered; coverage=%+v", rows)
	}

	// Per-asset recursion: the discovered in-scope host got its own recon task.
	rec, err := d.Store.GetTask("recon-10.0.0.6")
	if err != nil {
		t.Fatalf("expected a recon task for the discovered host 10.0.0.6: %v", err)
	}
	if rec.Surface != engagement.SurfaceNetwork || rec.Phase != engagement.PhaseRecon {
		t.Errorf("recursed task = %+v, want network/recon", rec)
	}

	cand, err := d.Store.GetTask("exploit-10.0.0.5-22-openssh")
	if err != nil {
		t.Fatalf("expected a deterministic exploit candidate for OpenSSH on 10.0.0.5:22: %v", err)
	}
	if cand.Armed {
		t.Errorf("candidate must be unarmed: %+v", cand)
	}
	if cand.Phase != engagement.PhaseExploit {
		t.Errorf("candidate phase = %q, want exploit", cand.Phase)
	}
	if !cand.CoverageGap || cand.Status != engagement.StatusBlocked {
		t.Errorf("RC=nil (no grounding): candidate must be a non-actionable coverage-gap (blocked+CoverageGap), got Status=%q CoverageGap=%v", cand.Status, cand.CoverageGap)
	}
}

// networkSSHScan is a single-service scan (one host, no second host so no
// recursion): an OpenSSH service for the detection-grounding tests.
const networkSSHScan = "Nmap scan report for 10.0.0.5\n22/tcp open ssh OpenSSH 8.9p1"

// networkSSHModel drives one recon tier: run one bounded nmap, record the SSH
// scan verbatim, then end; the grader (and any selector prompt) is answered
// stop/benign. It keys the tool sequence on the tier-prompt phrase so selector
// calls (which make their own GenerateContent) never emit a run_command.
type networkSSHModel struct{}

func (networkSSHModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	var human string
	toolTurns := 0
	for _, m := range msgs {
		if m.Role == llms.ChatMessageTypeTool {
			toolTurns++
		}
		if m.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range m.Parts {
			if tc, ok := p.(llms.TextContent); ok {
				human += tc.Text
			}
		}
	}
	if strings.Contains(human, "Respond with ONLY one JSON object") {
		return finalResp(`{"continue": false}`), nil // grader stop; also benign for the exploit selector
	}
	if !strings.Contains(human, "Perform ONLY this tier's step") {
		return finalResp("noted"), nil // a selector/other prompt -> fails closed, no run_command
	}
	switch toolTurns {
	case 0:
		return toolCallResp("c1", "run_command", `{"binary":"nmap","args":["-sV","-p","22","10.0.0.5"]}`), nil
	case 1:
		return toolCallResp("c2", "record_evidence", `{"task_id":"t1","quote":`+strconv.Quote(networkSSHScan)+`}`), nil
	}
	return finalResp("tier done"), nil
}

// networkRunSSHRecon seeds an OpenSSH recon task with the given searcher and runs
// the network executor, returning the correlated OpenSSH candidate.
func networkRunSSHRecon(t *testing.T, rc searcher) engagement.Task {
	t.Helper()
	d := testDeps(t, networkSSHModel{})
	d.ReconTiers = true
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	d.RC = rc
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		return runResult{Output: networkSSHScan}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "enumerate",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executorFor(d, task).Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	cand, err := d.Store.GetTask("exploit-10.0.0.5-22-openssh")
	if err != nil {
		t.Fatalf("expected the OpenSSH candidate to be emitted (never silently dropped): %v", err)
	}
	return cand
}

func TestNetworkDetectionGroundedCandidateIsActionable(t *testing.T) {
	rc := &recSearcher{results: []retrieval.Result{
		chunk("offensive-network-attacks", "recon/ssh.md", "OpenSSH CVE", "OpenSSH 8.9 authentication bypass exploitation"),
	}}
	cand := networkRunSSHRecon(t, rc)
	if cand.CoverageGap || cand.Status != engagement.StatusTodo {
		t.Fatalf("grounded candidate must be actionable todo, got Status=%q CoverageGap=%v", cand.Status, cand.CoverageGap)
	}
	if cand.Citation.Source == "" {
		t.Fatalf("grounded candidate must carry a Citation, got %+v", cand.Citation)
	}
}

func TestNetworkDetectionNoSilentDropOnEmptyCorpus(t *testing.T) {
	rc := &recSearcher{results: nil} // corpus coverage removed for this case
	cand := networkRunSSHRecon(t, rc)
	if !cand.CoverageGap || cand.Status != engagement.StatusBlocked {
		t.Fatalf("empty corpus: candidate must be a non-actionable coverage-gap, got Status=%q CoverageGap=%v", cand.Status, cand.CoverageGap)
	}
	if cand.Citation.Source != "" {
		t.Fatalf("coverage-gap candidate must have an empty Citation, got %+v", cand.Citation)
	}
}

func TestNetworkDetectionNoFalseGroundingOnAdjacentCitation(t *testing.T) {
	rc := &recSearcher{results: []retrieval.Result{
		chunk("hacktricks", "network-services/nginx.md", "nginx", "nginx HTTP request splitting technique"),
	}}
	cand := networkRunSSHRecon(t, rc)
	if !cand.CoverageGap || cand.Status != engagement.StatusBlocked {
		t.Fatalf("adjacent non-product citation must NOT ground (no false grounding); want coverage-gap, got Status=%q CoverageGap=%v", cand.Status, cand.CoverageGap)
	}
}

type networkNoRecordModel struct{}

func (networkNoRecordModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	var human string
	toolTurns := 0
	for _, m := range msgs {
		if m.Role == llms.ChatMessageTypeTool {
			toolTurns++
		}
		if m.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range m.Parts {
			if tc, ok := p.(llms.TextContent); ok {
				human += tc.Text
			}
		}
	}
	if strings.Contains(human, "Respond with ONLY one JSON object") {
		return finalResp(`{"continue": false}`), nil
	}
	if !strings.Contains(human, "Perform ONLY this tier's step") {
		return finalResp("noted"), nil
	}
	if toolTurns == 0 {
		return toolCallResp("c1", "run_command", `{"binary":"nmap","args":["-sV","-p","22","10.0.0.5"]}`), nil
	}
	return finalResp("done"), nil // deliberately never record_evidence
}

func TestNetworkCodeSideEvidenceWhenModelDoesNotRecord(t *testing.T) {
	d := testDeps(t, networkNoRecordModel{})
	d.ReconTiers = true
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		return runResult{Output: networkSSHScan}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "enumerate",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executorFor(d, task).Run(context.Background(), task); err != nil {
		t.Fatal(err) // must terminate, not loop to the backstop cap
	}
	// Evidence recorded code-side despite the model never calling record_evidence.
	ev, err := d.Store.EvidenceFor("t1")
	if err != nil {
		t.Fatal(err)
	}
	var captured bool
	for _, q := range ev {
		if q == networkSSHScan {
			captured = true
		}
	}
	if !captured {
		t.Fatalf("code-side capture missing: evidence=%v, want the nmap output recorded verbatim by the backstop", ev)
	}
	// The finding was not dropped: the OpenSSH candidate was correlated from the
	// code-side evidence (coverage-gap here since RC=nil, but present).
	if _, err := d.Store.GetTask("exploit-10.0.0.5-22-openssh"); err != nil {
		t.Fatalf("candidate not correlated from code-side evidence (silent drop): %v", err)
	}
}

// networkProposeModel proposes one run_command (a fixed binary+args) then ends.
// The grader is answered stop. It lets a test assert whether the gate let the
// proposed command reach exec.
type networkProposeModel struct {
	binary string
	args   []string
}

func (m networkProposeModel) GenerateContent(_ context.Context, msgs []llms.MessageContent, _ ...llms.CallOption) (*llms.ContentResponse, error) {
	toolTurns := 0
	var human string
	for _, mc := range msgs {
		if mc.Role == llms.ChatMessageTypeTool {
			toolTurns++
		}
		if mc.Role != llms.ChatMessageTypeHuman {
			continue
		}
		for _, p := range mc.Parts {
			if tc, ok := p.(llms.TextContent); ok {
				human += tc.Text
			}
		}
	}
	if strings.Contains(human, "Respond with ONLY one JSON object") {
		return finalResp(`{"continue": false}`), nil
	}
	if toolTurns == 0 {
		argsJSON, _ := json.Marshal(m.args)
		return toolCallResp("c1", "run_command", `{"binary":`+strconv.Quote(m.binary)+`,"args":`+string(argsJSON)+`}`), nil
	}
	return finalResp("done"), nil
}

// TestNetworkExecutorDeniesOutOfScopeHostAtExec (regression): a recon task whose
// target is out of scope never reaches exec. The gate denies the command
// (resolve-and-pin / scope), so the stubbed runner is never invoked.
func TestNetworkExecutorDeniesOutOfScopeHostAtExec(t *testing.T) {
	d := testDeps(t, networkProposeModel{binary: "nmap", args: []string{"-sV", "-p", "22", "8.8.8.8"}})
	d.ReconTiers = true
	d.Gate = autoGate(t) // scope 10.0.0.0/24
	d.Runs = NewRunOutputs()
	var ran atomic.Bool
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		ran.Store(true)
		return runResult{Output: "should not run"}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "8.8.8.8", Objective: "enumerate",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executorFor(d, task).Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if ran.Load() {
		t.Fatal("out-of-scope host reached exec; the gate must deny it before running")
	}
}

// TestNetworkExecutorUnattendedAutoUsesOnlyAllowedBinaries (regression): in
// unattended /auto (no confirmer) a binary outside allowed_binaries is denied and
// never reaches exec, even for an in-scope target. The gate already enforces
// this; the test asserts it holds through the network executor.
func TestNetworkExecutorUnattendedAutoUsesOnlyAllowedBinaries(t *testing.T) {
	d := testDeps(t, networkProposeModel{binary: "smbclient", args: []string{"-L", "10.0.0.5"}})
	d.ReconTiers = true
	d.Gate = autoGate(t) // Auto, no confirmer, allowlist {nmap, curl}
	d.Runs = NewRunOutputs()
	var ran atomic.Bool
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		ran.Store(true)
		return runResult{Output: "should not run"}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "enumerate",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executorFor(d, task).Run(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if ran.Load() {
		t.Fatal("unattended /auto ran a binary outside allowed_binaries; the allowlist bound must hold")
	}
}

// TestNetworkExecutorFailsClosedOnVantageReadError: if the engagement vantage
// cannot be read, the network recon path refuses the task rather than running
// ungated. Closing the store makes Vantage error.
func TestNetworkExecutorFailsClosedOnVantageReadError(t *testing.T) {
	d := testDeps(t, networkProposeModel{binary: "nmap", args: []string{"-sV", "-p", "22", "10.0.0.5"}})
	d.ReconTiers = true
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	var ran atomic.Bool
	withStubExec(t, func(_ context.Context, _ string, _ []string, _ string, _ int, _ time.Duration) runResult {
		ran.Store(true)
		return runResult{Output: "should not run"}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "t1", Kind: "recon", Target: "10.0.0.5", Objective: "enumerate",
		Status: engagement.StatusTodo, Phase: engagement.PhaseRecon, Surface: engagement.SurfaceNetwork,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("t1")
	if err != nil {
		t.Fatal(err)
	}
	// Close the store so the vantage read errors; Run must fail closed.
	if err := d.Store.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := executorFor(d, task).Run(context.Background(), task)
	if err != nil {
		t.Fatalf("Run returned a hard error, want a graceful refusal: %v", err)
	}
	if !strings.Contains(out, "could not read the engagement vantage") {
		t.Fatalf("Run out = %q, want a vantage-read refusal", out)
	}
	if ran.Load() {
		t.Fatal("task reached exec despite an unreadable vantage; the path must fail closed")
	}
}
