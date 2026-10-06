package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestParseEngageInput(t *testing.T) {
	cases := []struct {
		name    string
		in      mcpEngageIn
		wantErr string // substring; "" means success
		confirm string // expected normalized confirm on success
	}{
		{"ok default confirm", mcpEngageIn{Goal: "enum 10.0.0.5", RoE: "## In Scope\n10.0.0.5\n"}, "", "auto"},
		{"ok explicit auto", mcpEngageIn{Goal: "g", RoE: "## In Scope\n10.0.0.5\n", Confirm: "auto"}, "", "auto"},
		{"ok explicit elicit", mcpEngageIn{Goal: "g", RoE: "## In Scope\nlocal\n## Allowed Actions\nlocal\n", Confirm: "elicit"}, "", "elicit"},
		{"ok local auto", mcpEngageIn{Goal: "g", RoE: "## In Scope\nlocal\n## Allowed Actions\nlocal\n"}, "", "auto"},
		{"missing goal", mcpEngageIn{Goal: "  ", RoE: "## In Scope\n10.0.0.5\n"}, "goal is required", ""},
		{"missing roe", mcpEngageIn{Goal: "g", RoE: "   "}, "roe is required", ""},
		{"empty parsed roe", mcpEngageIn{Goal: "g", RoE: "# only a comment\n"}, "no in-scope targets", ""},
		{"retired scope", mcpEngageIn{Goal: "g", Scope: "10.0.0.5\n"}, "scope is retired", ""},
		{"exclusion-only roe", mcpEngageIn{Goal: "g", RoE: "## Out of Scope\n8.8.8.8\n"}, "no in-scope targets", ""},
		{"bad confirm", mcpEngageIn{Goal: "g", RoE: "## In Scope\n10.0.0.5\n", Confirm: "yes"}, `confirm must be`, ""},
		{"bad confirm case", mcpEngageIn{Goal: "g", RoE: "## In Scope\n10.0.0.5\n", Confirm: "Auto"}, `confirm must be`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := parseEngageInput(c.in)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if p.Confirm != c.confirm {
					t.Errorf("confirm = %q, want %q", p.Confirm, c.confirm)
				}
				if p.Scope == nil {
					t.Errorf("scope must be non-nil on success")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, c.wantErr)
			}
		})
	}
}

type fakeElicitor struct {
	action string
	err    error
	nilRes bool
	calls  int
}

func (f *fakeElicitor) Elicit(_ context.Context, _ *mcp.ElicitParams) (*mcp.ElicitResult, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.nilRes {
		return nil, nil
	}
	return &mcp.ElicitResult{Action: f.action}, nil
}

func TestElicitConfirmer(t *testing.T) {
	cmd := secgate.Command{Binary: "nmap", Args: []string{"10.0.0.5"}}
	cases := []struct {
		name   string
		fake   *fakeElicitor
		expect bool
	}{
		{"accept allows", &fakeElicitor{action: "accept"}, true},
		{"decline denies", &fakeElicitor{action: "decline"}, false},
		{"cancel denies", &fakeElicitor{action: "cancel"}, false},
		{"transport error denies", &fakeElicitor{err: errors.New("closed")}, false},
		{"nil result denies", &fakeElicitor{nilRes: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := elicitConfirmer{e: c.fake}.Confirm(context.Background(), cmd)
			if got != c.expect {
				t.Errorf("Confirm = %v, want %v", got, c.expect)
			}
			if c.fake.calls != 1 {
				t.Errorf("elicit calls = %d, want 1", c.fake.calls)
			}
		})
	}
}

func TestBuildEngageResult(t *testing.T) {
	dir := t.TempDir()
	ws, err := engagement.OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	// Two good audit lines plus one malformed line that must be skipped.
	_ = ws.AuditLine("secgate", "allow", "nmap 10.0.0.5")
	_ = ws.AuditLine("secgate", "deny:scope", "nmap 8.8.8.8 :: out of scope")
	f, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{ this is not json\n")
	f.Close()

	out, err := buildEngageResult(context.Background(), ws, "auto", "done")
	if err != nil {
		t.Fatal(err)
	}
	if out["final"] != "done" || out["confirm"] != "auto" {
		t.Errorf("final/confirm = %v / %v", out["final"], out["confirm"])
	}
	if _, ok := out["engagement"].(engagement.Engagement); !ok {
		t.Errorf("engagement = %T, want engagement.Engagement", out["engagement"])
	}
	audit, ok := out["audit"].([]map[string]any)
	if !ok || len(audit) != 2 {
		t.Fatalf("audit = %v (len want 2, malformed line skipped)", out["audit"])
	}
	if audit[0]["action"] != "allow" {
		t.Errorf("audit[0] action = %v", audit[0]["action"])
	}
}

func TestReadAuditLinesCapAndMissing(t *testing.T) {
	// missing file -> nil, no panic
	if got := readAuditLines(filepath.Join(t.TempDir(), "nope.jsonl"), 10); got != nil {
		t.Errorf("missing file = %v, want nil", got)
	}
	// cap enforced
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	f, _ := os.Create(p)
	for i := 0; i < 20; i++ {
		_, _ = f.WriteString(`{"n":1}` + "\n")
	}
	f.Close()
	if got := readAuditLines(p, 5); len(got) != 5 {
		t.Errorf("capped len = %d, want 5", len(got))
	}
}

// probeRun is a fake orchestrator run: it authorizes one in-scope nmap command
// through the real gate and reflects the decision into the final answer, so the
// round-trip exercises the gate + elicitation without a live model.
func probeRun(ranFlag *bool) func(context.Context, engageDeps, string) (string, error) {
	return func(ctx context.Context, d engageDeps, _ string) (string, error) {
		*ranFlag = true
		dec := d.Gate.Authorize(ctx, secgate.Command{Binary: "nmap", Args: []string{"-p", "80", "10.0.0.5"}})
		if dec.Allowed {
			return "allowed", nil
		}
		return "denied", nil
	}
}

func engageRoundTrip(t *testing.T, protocolVersion, elicitAction string, withHandler bool, in map[string]any) (map[string]any, bool, int, bool) {
	t.Helper()
	stubEngageRunner(t)
	if roe, ok := in["roe"].(string); ok && strings.TrimSpace(roe) != "" {
		path := filepath.Join(t.TempDir(), "ROE.md")
		if err := os.WriteFile(path, []byte(roe), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("BLKCHAIN_MCP_ROE_PATH", path)
	}
	ran := false
	svc := engageService{
		cfg:      ragconfig.Config{},
		run:      probeRun(&ran),
		newModel: func(ragconfig.Config, string) (toolLoopModel, error) { return nil, nil },
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "blkchain-test", Version: "0"}, nil)
	registerEngageTool(srv, svc)

	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()

	elicited := 0
	var opts *mcp.ClientOptions
	if withHandler {
		opts = &mcp.ClientOptions{
			ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				elicited++
				return &mcp.ElicitResult{Action: elicitAction}, nil
			},
		}
	}
	// opts (client capabilities incl. ElicitationHandler) go to NewClient.
	// Connect's third arg is *mcp.ClientSessionOptions, a different type. Pin the
	// protocol version: synchronous elicitation needs protocol < 2026-07-28 per
	// SEP-2322, so callers pass 2025-11-25 to exercise the working elicit path.
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, opts)
	cs, err := client.Connect(ctx, ct, &mcp.ClientSessionOptions{ProtocolVersion: protocolVersion})
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "engage", Arguments: in})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := res.StructuredContent.(map[string]any)
	return out, res.IsError, elicited, ran
}

func TestEngageRoundTripMissingScope(t *testing.T) {
	_, isErr, _, ran := engageRoundTrip(t, "2025-11-25", "accept", true,
		map[string]any{"goal": "g", "roe": "   ", "confirm": "auto"})
	if !isErr {
		t.Error("empty scope must be a tool error")
	}
	if ran {
		t.Error("run must not be invoked on a validation error")
	}
}

func TestEngageRoundTripElicitNoCapability(t *testing.T) {
	_, isErr, _, ran := engageRoundTrip(t, "2025-11-25", "accept", false,
		map[string]any{"goal": "g", "roe": "## In Scope\n10.0.0.5\n", "confirm": "elicit"})
	if !isErr {
		t.Error("confirm=elicit without client capability must be a fail-closed error")
	}
	if ran {
		t.Error("run must not be invoked before the capability precheck passes")
	}
}

func TestEngageRoundTripElicitAcceptAllows(t *testing.T) {
	out, isErr, elicited, ran := engageRoundTrip(t, "2025-11-25", "accept", true,
		map[string]any{"goal": "g", "roe": "## In Scope\n10.0.0.5\n", "confirm": "elicit"})
	if isErr {
		t.Fatalf("unexpected tool error: %v", out)
	}
	if !ran || elicited != 1 || out["final"] != "allowed" {
		t.Errorf("ran=%v elicited=%d final=%v, want true/1/allowed", ran, elicited, out["final"])
	}
	if out["confirm"] != "elicit" {
		t.Errorf("confirm = %v", out["confirm"])
	}
}

func TestEngageRoundTripElicitDeclineDenies(t *testing.T) {
	out, isErr, elicited, _ := engageRoundTrip(t, "2025-11-25", "decline", true,
		map[string]any{"goal": "g", "roe": "## In Scope\n10.0.0.5\n", "confirm": "elicit"})
	if isErr {
		t.Fatalf("unexpected tool error: %v", out)
	}
	if elicited != 1 || out["final"] != "denied" {
		t.Errorf("elicited=%d final=%v, want 1/denied", elicited, out["final"])
	}
}

func TestEngageRoundTripAutoNoElicit(t *testing.T) {
	out, isErr, elicited, ran := engageRoundTrip(t, "2025-11-25", "accept", true,
		map[string]any{"goal": "g", "roe": "## In Scope\n10.0.0.5\n", "confirm": "auto"})
	if isErr {
		t.Fatalf("unexpected tool error: %v", out)
	}
	if !ran || elicited != 0 || out["final"] != "allowed" {
		t.Errorf("ran=%v elicited=%d final=%v, want true/0/allowed", ran, elicited, out["final"])
	}
}

func TestEngageMCPLocalUsesIsolatedRunner(t *testing.T) {
	stubEngageRunner(t)
	trusted := filepath.Join(t.TempDir(), "ROE.md")
	if err := os.WriteFile(trusted, []byte("## In Scope\nlocal\n## Allowed Actions\nlocal\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_MCP_ROE_PATH", trusted)
	var isolated bool
	captureRun := func(ctx context.Context, d engageDeps, _ string) (string, error) {
		r := runtimeFor(ctx)
		isolated = r != nil && r.runner != nil && d.Gate.Policy != nil && d.Gate.Policy.Allows("local")
		return "done", nil
	}
	svc := engageService{
		cfg:      ragconfig.Config{},
		run:      captureRun,
		newModel: func(ragconfig.Config, string) (toolLoopModel, error) { return nil, nil },
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "blkchain-test", Version: "0"}, nil)
	registerEngageTool(srv, svc)

	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()

	opts := &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept"}, nil
		},
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, opts)
	cs, err := client.Connect(ctx, ct, &mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "engage",
		Arguments: map[string]any{"goal": "g", "roe": "## In Scope\nlocal\n## Allowed Actions\nlocal\n", "confirm": "elicit"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %v", res.StructuredContent)
	}
	if !isolated {
		t.Error("MCP local route did not enter the shared RoE runner path")
	}
}

// A client that declares elicitation but negotiates protocol >= 2026-07-28 must
// fail closed up front: the synchronous elicitation this tool uses is forbidden
// there (SEP-2322), so the call errors before any run or elicitation.
func TestEngageRoundTripElicitNewProtocolDenies(t *testing.T) {
	_, isErr, elicited, ran := engageRoundTrip(t, "2026-07-28", "accept", true,
		map[string]any{"goal": "g", "roe": "## In Scope\n10.0.0.5\n", "confirm": "elicit"})
	if !isErr {
		t.Error("confirm=elicit on protocol >= 2026-07-28 must be a fail-closed error")
	}
	if ran {
		t.Error("run must not be invoked when the protocol forbids synchronous elicitation")
	}
	if elicited != 0 {
		t.Errorf("elicited = %d, want 0", elicited)
	}
}

func TestEngageMCPDispatchPersistsPolicyEvidenceTranscriptAndReport(t *testing.T) {
	trusted := filepath.Join(t.TempDir(), "ROE.md")
	if err := os.WriteFile(trusted, []byte("## In Scope\n10.0.0.5\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_MCP_ROE_PATH", trusted)
	previous := newEngageRunnerForRun
	newEngageRunnerForRun = func(context.Context, *RoE) (*engageRunner, error) {
		return &engageRunner{workers: map[string]string{}, runFn: func(context.Context, []pipelineStage, string, int, time.Duration) (runResult, []isolatedStageResult) {
			return runResult{Output: "fixture evidence"}, []isolatedStageResult{{Stdout: "fixture evidence"}}
		}}, nil
	}
	t.Cleanup(func() { newEngageRunnerForRun = previous })
	svc := engageService{cfg: ragconfig.Config{}, run: func(ctx context.Context, d engageDeps, _ string) (string, error) {
		if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{ID: "t1", Surface: engagement.SurfaceNetwork, Status: engagement.StatusTodo}}}); err != nil {
			return "", err
		}
		tool := newRunCommandTool(d.Gate, 65536, time.Second, t.TempDir(), func() string { return "t1" }, func(id, out string) {
			_, _ = d.Store.RecordEvidence(id, out)
		})
		result, err := tool.Call(ctx, `{"binary":"curl","args":["http://10.0.0.5"]}`)
		if err != nil || !strings.Contains(result, "fixture evidence") {
			return "", fmt.Errorf("command result=%q err=%v", result, err)
		}
		return "engagement complete", nil
	}}
	srv := mcp.NewServer(&mcp.Implementation{Name: "blkchain-test", Version: "0"}, nil)
	registerEngageTool(srv, svc)
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "engage", Arguments: map[string]any{"goal": "inspect the lab", "roe": "## In Scope\n10.0.0.5\n"}})
	if err != nil || res.IsError {
		t.Fatalf("MCP dispatch failed: %v %+v", err, res)
	}
	out, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("MCP result type %T", res.StructuredContent)
	}
	workspace, ok := out["workspace"].(string)
	if !ok || workspace == "" || out["policy_hash"] == "" || out["final"] != "engagement complete" {
		t.Fatalf("MCP result missing run identity: %+v", out)
	}
	for _, name := range []string{"policy.json", "run.json", "audit.jsonl", "actions.jsonl", "report.json"} {
		data, err := os.ReadFile(filepath.Join(workspace, name))
		if err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
		if name == "actions.jsonl" && !strings.Contains(string(data), "fixture evidence") || name == "report.json" && !strings.Contains(string(data), "fixture evidence") {
			t.Fatalf("%s lost evidence: %q", name, data)
		}
	}
}

func TestEngageMCPRejectsUnapprovedInlineRoE(t *testing.T) {
	trusted := filepath.Join(t.TempDir(), "ROE.md")
	if err := os.WriteFile(trusted, []byte("## In Scope\n10.0.0.5\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BLKCHAIN_MCP_ROE_PATH", trusted)
	modelBuilt := false
	svc := engageService{newModel: func(ragconfig.Config, string) (toolLoopModel, error) {
		modelBuilt = true
		return nil, nil
	}}
	_, err := svc.handle(context.Background(), nil, mcpEngageIn{Goal: "inspect", RoE: "## In Scope\n8.8.8.8\n", Confirm: "auto"})
	if err == nil || !strings.Contains(err.Error(), "differs from the operator-approved policy") || modelBuilt {
		t.Fatalf("unapproved RoE reached execution: %v modelBuilt=%t", err, modelBuilt)
	}
}
