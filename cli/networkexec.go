package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"

	"github.com/tmc/langchaingo/llms"
)

// networkExecutor is the concrete network-surface executor. It embeds
// genericExecutor so it reuses the vantage reachability check, gate stamping,
// and the shared recon/exploit adapters; its value-add is network-shaped recon
// with vantage-skewed technique emphasis. Every identifier in this file is
// network-prefixed so it cannot collide with a sibling surface executor at
// merge time.
type networkExecutor struct {
	genericExecutor
}

// init registers the network executor. The network recon tier ladder is already
// defined in recon_ladder.go and the "recon" persona in domains.go, so this file
// only wires the executor factory; it registers neither a ladder nor a persona.
func init() {
	registerExecutor(engagement.SurfaceNetwork, func(d engageDeps) surfaceExecutor {
		return networkExecutor{genericExecutor{d: d}}
	})
}

// networkVantageSkew returns a one-line technique-emphasis note for the network
// recon tier prompt, skewed by the engagement vantage. Vantage is CONTEXT, not a
// persona axis: there is one network/recon persona, and this note only shifts
// which techniques it leans on. From outside (external or unset vantage) the
// emphasis is host/port/service enumeration; from an internal foothold or better
// it shifts to internal SMB/LDAP/SNMP and lateral-movement surface. The note is
// non-binding guidance appended to the tier prompt; the model still proposes
// structured commands that pass help-grounding and the gate.
func networkVantageSkew(v engagement.Vantage) string {
	// Reaches(SurfaceLocal) is true only at internal-foothold or higher, so it is
	// the external-vs-internal boundary (an unset vantage reads as external).
	if v.Reaches(engagement.SurfaceLocal) {
		return "Vantage context: internal foothold (" + string(v) + "). You are inside the network, so emphasize internal enumeration over external host discovery: SMB/NetBIOS shares and sessions (smbclient, rpcclient, nbtscan), LDAP/directory (ldapsearch), SNMP (snmpwalk), and the lateral-movement surface. Skew kb_search and route_skill queries toward internal network enumeration and lateral movement."
	}
	pos := string(v)
	if pos == "" {
		pos = "unset, treated as external"
	}
	return "Vantage context: external (" + pos + "). Enumerate from outside: emphasize host discovery, port and service sweeps, and service/version detection (nmap, DNS). Skew kb_search and route_skill queries toward external host, port, and service enumeration."
}

// Run routes a network task. A recon-phase task, when the code-orchestrated tier
// ladder is enabled and the gated command path is available, runs the network
// recon driver below (the generic ladder plus vantage-skewed technique emphasis).
// Every other phase (exploit/post-ex and the no-gate path) delegates to the
// embedded genericExecutor, which keeps the shared vantage check, gate stamping,
// and the exploitation lifecycle.
func (e networkExecutor) Run(ctx context.Context, task engagement.Task) (string, error) {
	if e.d.ReconTiers && task.Phase == engagement.PhaseRecon && e.d.Gate != nil && e.d.Runs != nil {
		// Read the vantage once, for the technique skew. The reachability refusal
		// below is defense-in-depth: SurfaceNetwork is reachable at every vantage
		// (engagement/vantage.go), so it never fires for this executor, but it fails
		// closed on a store read error and mirrors genericExecutor.Run's contract.
		v, err := e.d.Store.Vantage(ctx)
		if err != nil {
			return fmt.Sprintf("executor: task %s could not read the engagement vantage: %v", task.ID, err), nil
		}
		if v != "" && !v.Reaches(task.Surface) {
			return fmt.Sprintf("executor: task %s surface %q is not reachable at the current vantage %q; advance the vantage first", task.ID, task.Surface, v), nil
		}
		return e.networkRunReconPhase(ctx, task, v)
	}
	return e.genericExecutor.Run(ctx, task)
}

// networkRunReconPhase drives the network recon tier ladder for one recon-phase
// task. It reuses the shared live-recon machinery (the same gated tool set,
// code-owned per-tier evidence capture, and the correlateNewEvidence parsing
// that recurses in-scope assets and plans deterministic exploit candidates); its
// only divergence from genericExecutor.runReconPhase is networkTierPrompt, which
// appends the vantage-skewed technique emphasis so external vs internal recon
// leans on the right techniques. correlateNewEvidence is the embedded generic
// method (the shared parsers), reached here by explicit call, not by Go
// embedding dispatch.
func (e networkExecutor) networkRunReconPhase(ctx context.Context, task engagement.Task, v engagement.Vantage) (string, error) {
	runTimeout, runCap := resolveRunCaps()
	execDir, cleanup, err := newExecutorScratchDir(ctx, e.d)
	if err != nil {
		return "", err
	}
	defer cleanup()

	cmdCtx := secgate.Command{
		TaskID:  task.ID,
		Phase:   secgate.Phase(string(task.Phase)),
		Surface: secgate.Surface(string(task.Surface)),
		Armed:   task.Armed,
		Kind:    task.Kind,
		Target:  task.Target,
	}
	grounder := newTaskGrounder(e.d.ToolHelp, e.d.Gate, execDir, cmdCtx)
	activeTask := func() string { return task.ID }
	runCommand := newRunCommandToolForTask(e.d.Gate, runCap, runTimeout, execDir, activeTask, e.d.Runs.Add, cmdCtx, grounder)

	reg := tooldef.NewRegistry()
	for _, t := range []tooldef.Tool{
		newKBSearchTool(e.d.RC, e.d.Cfg),
		newKBAnswerTool(e.d.RC, e.d.Cfg, !e.d.Prefs.Web),
		newRouteSkillTool(e.d.Catalog, e.d.Store, activeTask),
		runCommand,
		newVerifiedRecordEvidenceTool(e.d.Store, e.d.Runs.Contains),
	} {
		if err := reg.Register(t); err != nil {
			return "", err
		}
	}

	dom := domainFor(task.Kind)

	var exploitSel exploitSelector
	if e.d.RC != nil {
		exploitSel = newKBExploitSelector(e.d.Model, e.d.RC, e.d.Cfg)
	}
	headerAttempts := map[int]bool{}

	runTier := func(ctx context.Context, _ engagement.Surface, asset string, tier reconTier, sel reconSelection) (tierOutcome, error) {
		beforeCmds := e.d.Runs.Count(task.ID)
		beforeRows, err := e.d.Store.EvidenceRowsFor(task.ID)
		if err != nil {
			return tierOutcome{}, err
		}
		msgs := []llms.MessageContent{
			{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextPart(dom.Prompt)}},
			{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextPart(networkTierPrompt(task, asset, tier, sel, v) + reconEvidenceContext(beforeRows))}},
		}
		if _, _, err := runToolLoop(ctx, e.d.Model, reg, msgs, LoopCaps{MaxRounds: 4, MaxCalls: 8, StopReason: engageStopOnPolicy(e.d.Gate)}); err != nil {
			return tierOutcome{}, err
		}
		if e.d.Gate.PolicyCapReason() == "" {
			quotes, err := captureRequestedHTTPHeaders(ctx, task, asset, e.d.Runs.Outputs(task.ID), beforeRows, headerAttempts, runCommand)
			if err != nil {
				return tierOutcome{}, err
			}
			if len(quotes) > 0 {
				current, err := e.d.Store.EvidenceRowsFor(task.ID)
				if err != nil {
					return tierOutcome{}, err
				}
				seen := map[string]bool{}
				for _, row := range current {
					seen[row.Quote] = true
				}
				for _, quote := range quotes {
					if seen[quote] {
						continue
					}
					if _, err := e.d.Store.RecordEvidence(task.ID, quote); err != nil {
						return tierOutcome{}, err
					}
					seen[quote] = true
				}
			}
		}
		// Code-side evidence capture: do not rely on the model's
		// record_evidence. captureTierEvidence returns the model's rows when it
		// recorded any, else a code-side backstop records this pass's captured
		// run_command output as evidence, and surfaces a coverage-gap audit when
		// nothing was captured - closing no-silent-drop on this bespoke driver the
		// same way the shared generic runReconPhase does.
		newRows, err := e.captureTierEvidence(task.ID, string(task.Surface), asset, tier.Name, beforeRows, beforeCmds)
		if err != nil {
			return tierOutcome{}, err
		}
		out := tierOutcomeFromSignals(tier, e.d.Runs.Count(task.ID)-beforeCmds, len(newRows))
		out.NewAssets = e.correlateNewEvidence(ctx, task.ID, asset, newRows, exploitSel)
		return out, nil
	}

	d := reconDeps{
		Store:     e.d.Store,
		Surface:   task.Surface,
		Grader:    newLLMReconGrader(e.d.Model, e.d.Cfg),
		RunTier:   runTier,
		Backstop:  defaultReconBackstop(),
		Now:       time.Now,
		TaskIDFor: func(string) string { return task.ID },
	}
	if e.d.RC != nil {
		d.Selector = newKBReconSelector(e.d.Model, e.d.RC, e.d.Cfg)
	}
	res, err := ReconLoop(ctx, d, reconSeeds(task.Target), task.ID)
	if err != nil {
		return "", err
	}
	return reconSummary(task, res), nil
}

var openHTTPPort = regexp.MustCompile(`(?m)^([0-9]{1,5})/tcp[[:space:]]+open[[:space:]]+((?:ssl/)?https?(?:-[a-z0-9]+)?)\b`)

func captureRequestedHTTPHeaders(ctx context.Context, task engagement.Task, asset string, outputs []string, evidence []engagement.EvidenceRow, attempted map[int]bool, runCommand tooldef.Tool) ([]string, error) {
	request := strings.ToLower(task.Objective + " " + task.DoneWhen)
	if !strings.Contains(request, "server header") && !strings.Contains(request, "banner") {
		return nil, nil
	}
	for _, row := range evidence {
		if strings.Contains(strings.ToLower(row.Quote), "\nserver:") || strings.HasPrefix(strings.ToLower(row.Quote), "server:") {
			return nil, nil
		}
	}
	for _, output := range outputs {
		if strings.Contains(strings.ToLower(output), "\nserver:") || strings.HasPrefix(strings.ToLower(output), "server:") {
			return nil, nil
		}
	}
	var quotes []string
	for _, output := range outputs {
		for _, match := range openHTTPPort.FindAllStringSubmatch(output, -1) {
			port, err := strconv.Atoi(match[1])
			if err != nil || port < 1 || port > 65535 || attempted[port] || len(attempted) >= 4 {
				continue
			}
			attempted[port] = true
			scheme := "http"
			if strings.Contains(match[2], "https") || strings.HasPrefix(match[2], "ssl/") {
				scheme = "https"
			}
			target := (&url.URL{Scheme: scheme, Host: net.JoinHostPort(asset, match[1]), Path: "/"}).String()
			args, err := json.Marshal(runCommandArgs{Binary: "curl", Args: []string{"-sS", "-I", "--max-time", "5", target}})
			if err != nil {
				return nil, err
			}
			result, err := runCommand.Call(ctx, string(args))
			if err != nil {
				return nil, err
			}
			for _, line := range strings.Split(result, "\n") {
				line = strings.TrimSuffix(line, "\r")
				if strings.HasPrefix(strings.ToLower(line), "server:") {
					quotes = append(quotes, match[0], line)
					break
				}
			}
		}
	}
	return quotes, nil
}

// networkTierPrompt is the per-tier human prompt for network recon: the shared
// per-tier instruction (reconTierPrompt) plus the vantage-skewed technique
// emphasis. One persona, vantage only colors the emphasis.
func networkTierPrompt(task engagement.Task, asset string, tier reconTier, sel reconSelection, v engagement.Vantage) string {
	prompt := reconTierPrompt(task, asset, tier, sel) + "\n" + networkVantageSkew(v)
	if tier.Name == "version-safe-script-enum" {
		prompt += "\nFor an open HTTP service, capture response headers with a bounded curl request when the objective needs a banner. A scanner service/version label is not the exact HTTP Server header. Do not repeat a completed port sweep."
	}
	return prompt
}
