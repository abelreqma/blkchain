package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/skillcat"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcpengage.go adds the `engage` MCP tool: it runs the gated agentic
// orchestrator to completion for a goal in an ephemeral per-call workspace and
// returns the final answer plus an engagement snapshot. Confirmation adapts to
// MCP: `confirm="elicit"` (default) asks the client to approve each command via
// elicitation; `confirm="auto"` runs /auto where the gate is the whole control.
// Every command still flows through the unchanged secgate.Gate.

// mcpEngageIn is the engage tool input. Scope is required inline content, never
// a path, so a remote call is self-contained and adds no filesystem read.
type mcpEngageIn struct {
	Goal    string `json:"goal" jsonschema:"the engagement goal"`
	Scope   string `json:"scope" jsonschema:"inline scope content: in-scope targets, a 'local' directive, and 'allow <bin>' lines"`
	Confirm string `json:"confirm,omitempty" jsonschema:"confirmation model: 'elicit' (default, per-command approval via elicitation) or 'auto' (no per-command approval; the gate is the whole control)"`
	Model   string `json:"model,omitempty" jsonschema:"chat model id (default: the resolved model)"`
}

// engageParsed is validated, resolved engage input. Confirm is normalized to
// exactly "elicit" or "auto".
type engageParsed struct {
	Goal    string
	Scope   *secgate.Scope
	Confirm string
	Model   string
}

// parseEngageInput validates and resolves the engage input. It rejects a
// missing goal, a missing or semantically empty scope (never run unscoped), an
// unparsable scope, and any confirm value other than "", "elicit", or "auto".
func parseEngageInput(in mcpEngageIn) (engageParsed, error) {
	goal := strings.TrimSpace(in.Goal)
	if goal == "" {
		return engageParsed{}, fmt.Errorf("engage: goal is required")
	}
	if strings.TrimSpace(in.Scope) == "" {
		return engageParsed{}, fmt.Errorf("engage: scope is required (never run unscoped)")
	}
	scope, err := secgate.ParseScope(strings.NewReader(in.Scope))
	if err != nil {
		return engageParsed{}, fmt.Errorf("engage: invalid scope: %w", err)
	}
	if scope.Empty() && !scope.Local() {
		return engageParsed{}, fmt.Errorf("engage: scope has no in-scope targets or a 'local' directive")
	}
	confirm := in.Confirm
	if confirm == "" {
		confirm = "elicit"
	}
	if confirm != "elicit" && confirm != "auto" {
		return engageParsed{}, fmt.Errorf(`engage: confirm must be "elicit" or "auto", got %q`, in.Confirm)
	}
	// A local/post-access scope requires per-command approval, which confirm="auto"
	// (no per-command approval) cannot provide: the gate would deny every command.
	// Reject the combination up front so a local run must elicit.
	if scope.Local() && confirm == "auto" {
		return engageParsed{}, fmt.Errorf(`engage: local/post-access scope requires confirm="elicit" (per-command approval); "auto" is not permitted for local`)
	}
	return engageParsed{Goal: goal, Scope: scope, Confirm: confirm, Model: in.Model}, nil
}

// engageElicitSchema is a form elicitation with no fields: the client shows the
// command and the operator accepts or declines. Accept approves the command.
var engageElicitSchema = map[string]any{"type": "object", "properties": map[string]any{}}

// elicitor is the subset of *mcp.ServerSession that elicitConfirmer needs, so a
// fake can drive it in tests.
type elicitor interface {
	Elicit(ctx context.Context, params *mcp.ElicitParams) (*mcp.ElicitResult, error)
}

// elicitConfirmer is a secgate.Confirmer that asks the MCP client to approve one
// command via elicitation. It fails closed: a declined or cancelled action, or
// any transport error, denies.
type elicitConfirmer struct {
	e elicitor
}

func (c elicitConfirmer) Confirm(ctx context.Context, cmd secgate.Command) bool {
	res, err := c.e.Elicit(ctx, &mcp.ElicitParams{
		Message:         "Approve this command in the authorized engagement:\n" + secgate.Signature(cmd),
		RequestedSchema: engageElicitSchema,
	})
	if err != nil || res == nil {
		return false
	}
	return res.Action == "accept"
}

// engageAuditCap bounds how many audit lines the result returns. The gate's
// episode caps already bound how many commands (hence audit lines) a run can
// produce; this is a defensive ceiling on memory.
const engageAuditCap = 500

// readAuditLines returns up to limit parsed objects from a JSON-lines audit file.
// It is best-effort: a missing or unreadable file returns nil, and a malformed
// line is skipped rather than failing the whole read.
func readAuditLines(path string, limit int) []map[string]any {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() && len(out) < limit {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		out = append(out, m)
	}
	return out
}

// buildEngageResult assembles the engage tool result from the finished
// engagement: the final answer, the confirmation model used, the engagement
// snapshot, and a bounded, best-effort audit trail.
func buildEngageResult(ctx context.Context, ws *engagement.Workspace, confirm, final string) (map[string]any, error) {
	snap, err := ws.Store.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("engage: snapshot: %w", err)
	}
	out := map[string]any{
		"final":      final,
		"confirm":    confirm,
		"engagement": snap,
	}
	if audit := readAuditLines(filepath.Join(ws.Dir, "audit.jsonl"), engageAuditCap); audit != nil {
		out["audit"] = audit
	}
	return out, nil
}

// engageService carries the engage tool's shared dependencies plus two seams,
// run and newModel, so a round-trip test can drive the tool without a live model
// or LLM server. defaultEngageService wires the real orchestrator and model.
type engageService struct {
	rc       *retrieval.Client
	cfg      ragconfig.Config
	cat      *skillcat.Catalog
	run      func(ctx context.Context, d engageDeps, goal string) (string, error)
	newModel func(cfg ragconfig.Config, model string) (toolLoopModel, error)
}

func defaultEngageService(rc *retrieval.Client, cfg ragconfig.Config, cat *skillcat.Catalog) engageService {
	return engageService{
		rc:  rc,
		cfg: cfg,
		cat: cat,
		run: runOrchestrator,
		newModel: func(cfg ragconfig.Config, model string) (toolLoopModel, error) {
			m, err := newOMLX(cfg, model)
			if err != nil {
				return nil, err
			}
			return m, nil
		},
	}
}

// sessionCanElicit reports whether the connected client declared the elicitation
// capability during initialize.
func sessionCanElicit(ss *mcp.ServerSession) bool {
	p := ss.InitializeParams()
	return p != nil && p.Capabilities != nil && p.Capabilities.Elicitation != nil
}

// syncElicitProtocolCutoff is the first MCP protocol version that forbids a
// server-initiated elicitation/create while serving a tool call (SEP-2322, the
// SDK's protocolVersion20260728).
const syncElicitProtocolCutoff = "2026-07-28"

// syncElicitSupported reports whether the negotiated protocol allows the
// synchronous ss.Elicit() that elicitConfirmer uses. At protocol >= 2026-07-28
// (SEP-2322) that call is rejected by the SDK, which would make every command
// silently deny, so it is treated as unsupported. Nil initialize params fail
// closed. The version comes from the same source the SDK's own check uses.
func syncElicitSupported(ss *mcp.ServerSession) bool {
	p := ss.InitializeParams()
	return p != nil && p.ProtocolVersion < syncElicitProtocolCutoff
}

// handle runs one gated engagement to completion in an ephemeral workspace and
// returns the result map. It validates first, resolves the confirmation model
// (failing closed when confirm=elicit but the client cannot elicit) before any
// side effect, then builds the gate, deps, and result.
func (svc engageService) handle(ctx context.Context, ss *mcp.ServerSession, in mcpEngageIn) (map[string]any, error) {
	p, err := parseEngageInput(in)
	if err != nil {
		return nil, err
	}

	mode := secgate.Safe
	var confirm secgate.Confirmer
	var approvals *secgate.SessionApprovals
	if p.Confirm == "auto" {
		mode = secgate.Auto
	} else {
		if !sessionCanElicit(ss) {
			return nil, fmt.Errorf("engage: confirm=elicit requires the MCP client to support elicitation; enable it or pass confirm=auto")
		}
		if !syncElicitSupported(ss) {
			ver := ""
			if ip := ss.InitializeParams(); ip != nil {
				ver = ip.ProtocolVersion
			}
			return nil, fmt.Errorf("engage: confirm=elicit is unavailable on this client's negotiated MCP protocol version %q; protocol >= %s forbids the synchronous elicitation this tool uses (SEP-2322). Pass confirm=auto.", ver, syncElicitProtocolCutoff)
		}
		confirm = elicitConfirmer{e: ss}
		approvals = secgate.NewSessionApprovals()
	}

	wsDir, err := os.MkdirTemp("", "blkengage-mcp-ws-")
	if err != nil {
		return nil, fmt.Errorf("engage: cannot create workspace: %w", err)
	}
	defer os.RemoveAll(wsDir)
	ws, err := engagement.OpenWorkspace(wsDir)
	if err != nil {
		return nil, fmt.Errorf("engage: cannot open workspace: %w", err)
	}
	defer ws.Close()

	scratch, err := os.MkdirTemp("", "blkengage-mcp-")
	if err != nil {
		return nil, fmt.Errorf("engage: cannot create scratch dir: %w", err)
	}
	defer os.RemoveAll(scratch)

	gate := buildEngageGate(ws, p.Scope, mode, confirm, approvals, scratch, gatePolicy{}, func(action, detail string) {
		_ = ws.AuditLine("secgate", action, detail)
	})
	if err := gate.Start(); err != nil {
		return nil, fmt.Errorf("engage: %w", err)
	}

	model, err := svc.newModel(svc.cfg, p.Model)
	if err != nil {
		return nil, fmt.Errorf("engage: %w", err)
	}

	deps := buildEngageDeps(model, svc.rc, svc.cfg, loadPrefs(), ws.Store, gate, scratch, svc.cat, askuser.AutoAsker{}, nil, nil)
	toolHelp, toolHelpClose := openToolHelpCache()
	defer toolHelpClose()
	deps.ToolHelp = toolHelp

	if serr := seedInitialVantage(ctx, ws.Store, p.Scope); serr != nil {
		fmt.Fprintf(os.Stderr, "engage: vantage seed failed: %v\n", serr)
	}
	final, err := svc.run(ctx, deps, p.Goal)
	if err != nil {
		return nil, fmt.Errorf("engage: %w", err)
	}
	return buildEngageResult(ctx, ws, p.Confirm, final)
}

// registerEngageTool registers the engage tool on s, backed by svc.
func registerEngageTool(s *mcp.Server, svc engageService) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "engage",
		Description: "Run the bounded, gated agentic engagement to completion for a goal, then return the final answer and an engagement snapshot. `scope` is required inline content (in-scope targets, `local`, `allow <bin>` lines); the run never goes unscoped and every command passes the security gate. `confirm` is 'elicit' (default: approve each command via elicitation; requires client elicitation support and an MCP protocol older than 2026-07-28 (SEP-2322), so on newer protocols use confirm=auto) or 'auto' (no per-command approval; the gate's classifier, allowlist, scope, and file-access checks are the whole control).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in mcpEngageIn) (*mcp.CallToolResult, any, error) {
		out, err := svc.handle(ctx, req.Session, in)
		if err != nil {
			return nil, nil, err
		}
		return nil, out, nil
	})
}
