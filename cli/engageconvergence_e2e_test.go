package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"blkchain/cli/internal/askuser"
	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"github.com/tmc/langchaingo/llms"
)

type convergenceLiveModel struct {
	mu        sync.Mutex
	model     toolLoopModel
	forceTool string
	forceOnce bool
	forced    bool
	stages    []string
	models    []string
	tools     []string
	offered   []string
	answers   []string
}

func (m *convergenceLiveModel) GenerateContent(ctx context.Context, msgs []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error) {
	var settings llms.CallOptions
	for _, opt := range opts {
		opt(&settings)
	}
	stage, _ := ctx.Value(stageKey{}).(string)
	m.mu.Lock()
	m.stages = append(m.stages, stage)
	m.models = append(m.models, settings.Model)
	m.mu.Unlock()
	available := false
	var offered []string
	for _, tool := range settings.Tools {
		if tool.Function != nil {
			offered = append(offered, tool.Function.Name)
		}
		if tool.Function != nil && tool.Function.Name == m.forceTool {
			available = true
			break
		}
	}
	m.mu.Lock()
	m.offered = append(m.offered, strings.Join(offered, ","))
	force := available && (!m.forceOnce || !m.forced)
	if force {
		m.forced = true
	}
	m.mu.Unlock()
	if force {
		opts = append(opts, llms.WithToolChoice(llms.ToolChoice{Type: "function", Function: &llms.FunctionReference{Name: m.forceTool}}))
	}
	response, err := m.model.GenerateContent(ctx, msgs, opts...)
	if response != nil && len(response.Choices) > 0 && response.Choices[0] != nil {
		m.mu.Lock()
		m.answers = append(m.answers, capRunes(response.Choices[0].Content, 250))
		for _, call := range response.Choices[0].ToolCalls {
			if call.FunctionCall != nil {
				m.tools = append(m.tools, call.FunctionCall.Name)
			}
		}
		m.mu.Unlock()
	}
	return response, err
}

func TestEngageConvergenceLocalLLM(t *testing.T) {
	if os.Getenv("BLKCHAIN_ENGAGE_LLM_E2E") != "1" {
		t.Skip("requires the local LLM and retrieval stack")
	}
	t.Setenv("BLK_ENABLE_THINKING", "0")
	cfg := ragconfig.Load()
	modelID := resolveModel(cfg)
	base, err := newOMLX(cfg, modelID)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := newRetrievalClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	results, err := rc.Search(ctx, "HTTP response fingerprinting headers", 3, nil)
	if err != nil || len(results) == 0 {
		t.Fatalf("live retrieval: results=%d err=%v", len(results), err)
	}
	t.Logf("retrieval: %d corpus results through embed, Qdrant, and rerank", len(results))
	t.Setenv("BLKCHAIN_ENGAGE_ORCHESTRATOR_MODEL", modelID)
	for _, tc := range []struct {
		name, tool, goal, reason string
		rounds, calls, idle      string
	}{
		{"round-cap", "plan_add", "Create one web inspection task for 192.0.2.1, then stop. Do not complete it or claim findings.", "round cap", "1", "20", "3"},
		{"call-cap", "plan_add", "Create one web inspection task for 192.0.2.1, then stop. Do not complete it or claim findings.", "tool call cap", "20", "1", "3"},
		{"no-progress", "ask_user", "Ask the operator which goal to use. If clarification is suppressed, ask again. Do not create tasks or claim findings.", "no-progress", "20", "20", "2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", tc.rounds)
			t.Setenv("BLKCHAIN_ENGAGE_MAX_CALLS", tc.calls)
			t.Setenv("BLKCHAIN_ENGAGE_NO_PROGRESS_ROUNDS", tc.idle)
			m := &convergenceLiveModel{model: base, forceTool: tc.tool}
			d := testDeps(t, m)
			d.Cfg, d.RC = cfg, rc
			out, err := runOrchestrator(ctx, d, tc.goal)
			if err != nil || !strings.Contains(out, tc.reason) || strings.Contains(out, "Final synthesis unavailable") || len(out) < 100 {
				t.Fatalf("out=%q stages=%v err=%v", out, m.stages, err)
			}
			if m.stages[len(m.stages)-1] != "engagement_synthesis" {
				t.Fatalf("stages=%v", m.stages)
			}
			for _, id := range m.models {
				if id != modelID {
					t.Fatalf("model override=%q want=%q", id, modelID)
				}
			}
			t.Logf("model=%s stages=%v report:\n%s", modelID, m.stages, out)
		})
	}
	t.Run("repl-executor", func(t *testing.T) {
		t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", "5")
		t.Setenv("BLKCHAIN_ENGAGE_MAX_CALLS", "64")
		t.Setenv("BLKCHAIN_ENGAGE_NO_PROGRESS_ROUNDS", "3")
		fixtureIP, fixtureName := startDockerHTTPFixture(t, "convergence", "convergence-fixture-ok")
		fixtureURL := "http://" + fixtureIP + ":8080/"
		cwd, wsDir := t.TempDir(), t.TempDir()
		if err := os.WriteFile(filepath.Join(cwd, "ROE.md"), []byte("## In Scope\n"+fixtureIP+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		goal := "Create one web task for " + fixtureURL + ". Dispatch that task. Use only curl with --max-time 5 to fetch the HTTP response. Record exact response evidence, complete the task, and return a report. Do not scan ports or add follow-on tasks."
		live := &convergenceLiveModel{model: base, forceTool: "run_command", forceOnce: true}
		out, err := runReplEngage(ctx, wsDir, cwd, secgate.Auto, false, live, rc, cfg, modelPrefs{}, nil, nil, askuser.AutoAsker{}, nil, goal, nil)
		if err != nil {
			t.Fatalf("REPL: %v; report=%q", err, out)
		}
		ws, err := engagement.OpenWorkspace(wsDir)
		if err != nil {
			t.Fatal(err)
		}
		defer ws.Close()
		ev, err := ws.Store.AllEvidence()
		if err != nil {
			t.Fatal(err)
		}
		captured := false
		for _, quotes := range ev {
			for _, quote := range quotes {
				if strings.Contains(quote, "convergence-fixture-ok") {
					captured = true
				}
			}
		}
		reportMD, readErr := os.ReadFile(filepath.Join(wsDir, "report.md"))
		if readErr != nil {
			t.Fatal(readErr)
		}
		logs, logErr := exec.Command("docker", "logs", fixtureName).CombinedOutput()
		if logErr != nil || !strings.Contains(string(logs), "GET /") || !captured || !strings.Contains(string(reportMD), "convergence-fixture-ok") || !strings.Contains(out, "Engagement paused: round cap") || strings.Contains(out, "Final synthesis unavailable") {
			t.Fatalf("fixture logs=%q err=%v captured=%v stages=%v tools=%v offered=%v answers=%v report=%q", logs, logErr, captured, live.stages, live.tools, live.offered, live.answers, out)
		}
		t.Logf("REPL Docker fixture: %d HTTP requests; report:\n%s", strings.Count(string(logs), "GET /"), out)
	})
	t.Run("cli-round-cap", func(t *testing.T) {
		t.Setenv("BLKCHAIN_ENGAGE_MAX_ROUNDS", "1")
		t.Setenv("BLKCHAIN_ENGAGE_MAX_CALLS", "20")
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		binary := os.Getenv("BLK_BIN")
		if binary == "" {
			var err error
			binary, err = filepath.Abs("blk")
			if err != nil {
				t.Fatal(err)
			}
		}
		cwd, wsDir := t.TempDir(), t.TempDir()
		roe := filepath.Join(cwd, "ROE.md")
		if err := os.WriteFile(roe, []byte("## In Scope\n192.0.2.1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, binary, "engage", "--auto", "--roe", roe, "--workspace", wsDir, "--model", modelID,
			"Create one web inspection task for 192.0.2.1. Create the task first. Do not dispatch it or claim findings.")
		command.Dir = cwd
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "Engagement paused: round cap") || strings.Contains(string(output), "Final synthesis unavailable") {
			t.Fatalf("CLI err=%v output=%s", err, output)
		}
		for _, name := range []string{"report.md", "report.json"} {
			if _, err := os.Stat(filepath.Join(wsDir, name)); err != nil {
				t.Fatal(err)
			}
		}
		reportData, err := os.ReadFile(filepath.Join(wsDir, "report.json"))
		if err != nil {
			t.Fatal(err)
		}
		var persisted struct {
			Status string `json:"status"`
			Final  string `json:"final"`
		}
		if err := json.Unmarshal(reportData, &persisted); err != nil {
			t.Fatal(err)
		}
		if persisted.Status != "paused" || strings.TrimSpace(persisted.Final) == "" {
			t.Fatalf("persisted report status=%q final=%q", persisted.Status, persisted.Final)
		}
		markdown, err := os.ReadFile(filepath.Join(wsDir, "report.md"))
		if err != nil || !strings.Contains(string(markdown), "## Final assessment") {
			t.Fatalf("final assessment missing from Markdown: %v", err)
		}
		t.Logf("CLI round-cap report:\n%s", output)
	})
}
