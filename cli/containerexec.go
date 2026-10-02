package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"

	"github.com/tmc/langchaingo/llms"
)

// containerexec.go adds the container/Kubernetes assessment surface executor for
// authorized, single-user engagements. It is a CODE-ORCHESTRATED, scope-gated,
// read-only-first executor: every probe runs through the shared security gate
// (scope resolve-and-pin, phase tier, denylists, HITL) and every finding is
// recorded as exact-quote evidence with provenance. The executor adds no gate
// logic of its own; it reuses genericExecutor's gate stamping, evidence capture,
// and the exploit/post-ex adapter, and contributes the container recon tier
// ladder, a dedicated container persona, and a vantage-skewed recon driver.
//
// Registration-seam only: this file registers the executor and ladder from init()
// and does not edit surfaceexec.go, recon_ladder.go, or domains.go. The dedicated
// container persona is NOT added to the shared domains map; it is selected
// in-driver by containerDomainFor (see its note), because registering a persona
// named "container" would shadow route_skill's resolveDomain and stop the
// "container" keyword from resolving to the k8s skill bucket. The existing "k8s"
// persona is untouched and still serves Kind="k8s". Every package-level
// identifier is prefixed "container" to stay collision-free with the sibling
// surface files in package main.

// containerExecutor runs one container/Kubernetes task. It embeds genericExecutor
// for the exploit/post-ex lifecycle and the generic fallback loop, and overrides
// Run so a recon-phase task drives containerRunReconPhase: the same gated tool
// set as the generic recon path, but with the engagement vantage threaded into
// every tier prompt (vantage-as-context). Generic correlation attaches
// Provenance{TaskID, EvidenceID} to every parsed finding.
type containerExecutor struct {
	genericExecutor
}

// containerLadder is the container/Kubernetes recon tier ladder. The tiers and
// their order are the deterministic backbone (the LLM only proposes commands
// within a tier): T0 discovers exposed surface (k8s API server / kubelet / etcd
// ports and container-runtime sockets); T1 enumerates RBAC and service accounts;
// T2 inspects workload and cluster misconfiguration; T3 runs escape-vector /
// finding-driven probes.
var containerLadder = reconLadder{
	{Index: 0, Name: "exposed-surface-discovery", Dimensions: []string{"exposed-ports", "runtime-sockets"}},
	{Index: 1, Name: "rbac-serviceaccount-enum", Dimensions: []string{"rbac", "service-accounts"}},
	{Index: 2, Name: "workload-cluster-misconfig", Dimensions: []string{"workloads", "misconfig"}},
	{Index: 3, Name: "escape-vector-probes", Dimensions: []string{"escape-vectors"}},
}

// containerPersonaPrompt is the dedicated container/Kubernetes persona. A
// Kind="container" task resolves to this persona; Kind="k8s" uses the shared one.
const containerPersonaPrompt = executorPreamble + "Domain: Kubernetes and container compromise. Map exposed API, kubelet, etcd, and runtime surfaces, then identify the active identity and enumerate namespace, workload, service-account, and RBAC permissions. Use curl and nmap when registered; do not assume kubectl, docker, or crictl exist. Trace each permission or workload setting to the shortest path toward workload control, node access, credential access, or cluster-admin. At an external vantage, prioritize exposed control-plane and anonymous access. From an in-cluster foothold, prioritize service-account token permissions, privileged workloads, hostPath/host-namespace mounts, and escape paths. Use route_skill with domain \"k8s\" and kb_search to choose a technique that fits the observed configuration. Recon records exact requests, responses, identity, and permission evidence; exploit/post-ex tasks validate the boundary crossing through run_command under the current execution policy. Create a basis_ids-linked task for each distinct escalation step. Redact secrets in evidence and capture only the minimum proof needed."

func init() {
	registerExecutor(engagement.SurfaceContainer, func(d engageDeps) surfaceExecutor {
		return containerExecutor{genericExecutor{d: d}}
	})
	registerLadder(engagement.SurfaceContainer, containerLadder)
}

// containerPersona is the dedicated container/Kubernetes persona, selected
// in-driver rather than registered in the shared domains map.
var containerPersona = domain{Name: "container", Prompt: containerPersonaPrompt}

// containerDomainFor resolves the persona for a container-surface task. A
// container kind (or an unset kind) gets the dedicated container persona; any
// other kind defers to the shared registry, so Kind="k8s" keeps the existing k8s
// persona. It deliberately does NOT register "container" in the domains map:
// doing so would make route_skill's resolveDomain treat "container" as a persona
// name and stop the "container" keyword from resolving to the k8s skill bucket
// (skillcat maps the container keyword to the k8s domain). This keeps a real,
// non-generic persona for Kind="container" while preserving route_skill.
func containerDomainFor(kind string) domain {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "container", "":
		return containerPersona
	}
	return domainFor(kind)
}

// Run routes a recon-phase task through the container recon driver (vantage skew)
// and delegates every other phase to the embedded genericExecutor (exploit/post-ex
// lifecycle and the generic fallback loop). It mirrors genericExecutor.Run's
// vantage reachability check for the recon path, since Go embedding has no virtual
// dispatch (the embedded Run would otherwise call the generic recon driver).
func (e containerExecutor) Run(ctx context.Context, task engagement.Task) (string, error) {
	if e.d.ReconTiers && task.Phase == engagement.PhaseRecon && e.d.Gate != nil && e.d.Runs != nil {
		v, err := e.d.Store.Vantage(ctx)
		if err != nil {
			return fmt.Sprintf("executor: task %s could not read the engagement vantage: %v", task.ID, err), nil
		}
		if v != "" && !v.Reaches(task.Surface) {
			return fmt.Sprintf("executor: task %s surface %q is not reachable at the current vantage %q; advance the vantage first", task.ID, task.Surface, v), nil
		}
		return e.containerRunReconPhase(ctx, task, v)
	}
	return e.genericExecutor.Run(ctx, task)
}

// containerVantageSkew returns the vantage-as-context guidance for the tier
// prompt: external vantages skew to exposed-surface and misconfiguration
// discovery; an internal foothold or deeper skews to in-pod privilege and
// container-escape assessment. An unset or unknown vantage adds no skew (fails
// safe to no extra guidance). One persona; only the guidance text changes.
func containerVantageSkew(v engagement.Vantage) string {
	switch v {
	case engagement.VantageExternalUnauth, engagement.VantageExternalAuth:
		return "external vantage - prioritize discovery of exposed control-plane and node surface (reachable API server, kubelet, etcd, and runtime sockets) and cluster misconfiguration from outside the cluster"
	case engagement.VantageInternalFoothold, engagement.VantageLocalElevated, engagement.VantageLateralDomain:
		return "internal foothold - prioritize in-pod service-account and RBAC privilege assessment and container-escape vectors toward the node and cluster"
	}
	return ""
}

// containerTierPrompt instructs the model to perform only this tier's step for
// this asset through the gated tools. It mirrors reconTierPrompt and adds a
// vantage-skew line when a skew is present (empty skew adds no line).
func containerTierPrompt(task engagement.Task, asset string, tier reconTier, sel reconSelection, skew string) string {
	hint := ""
	if sel.Parsed && sel.Action != "" {
		hint = fmt.Sprintf("Corpus-prioritized technique for this tier (guidance, not a command): %s\n", sel.Action)
	}
	skewLine := ""
	if skew != "" {
		skewLine = "Vantage focus: " + skew + "\n"
	}
	return fmt.Sprintf(
		"Engagement recon task %s on the %s surface.\n"+
			"Asset: %s\n"+
			"Tier: %s (coverage: %s)\n"+
			"Objective: %s\n"+
			"%s%s"+
			"Perform ONLY this tier's step for this asset now. Propose commands with run_command "+
			"(structured argv, no shell, in scope). When a command returns useful output, record an "+
			"exact quote of it with record_evidence for this task id. Do not move on to other tiers or "+
			"other assets; the harness advances the ladder.",
		task.ID, task.Surface, asset, tier.Name, strings.Join(tier.Dimensions, ", "), task.Objective, hint, skewLine)
}

// containerRunReconPhase runs the container recon tier ladder for one recon-phase
// task. It mirrors genericExecutor.runReconPhase (same gated tool set, caps,
// code-owned evidence-delta signal capture, and correlation) and differs only by
// threading the engagement vantage into each tier prompt via containerTierPrompt.
// It uses containerDomainFor(task.Kind), so Kind="container" gets the container
// persona and Kind="k8s" gets the existing k8s persona. The caller has applied the
// vantage reachability check and passes the vantage it already read, so it is not
// re-read here.
func (e containerExecutor) containerRunReconPhase(ctx context.Context, task engagement.Task, v engagement.Vantage) (string, error) {
	runTimeout, runCap := resolveRunCaps()
	execDir, cleanup, err := newExecutorScratchDir(e.d.WorkDir)
	if err != nil {
		return "", err
	}
	defer cleanup()

	cmdCtx := secgate.Command{
		Phase:   secgate.Phase(string(task.Phase)),
		Surface: secgate.Surface(string(task.Surface)),
		Armed:   task.Armed,
	}
	grounder := newTaskGrounder(e.d.ToolHelp, e.d.Gate, execDir, cmdCtx)
	activeTask := func() string { return task.ID }

	reg := tooldef.NewRegistry()
	for _, t := range []tooldef.Tool{
		newKBSearchTool(e.d.RC, e.d.Cfg),
		newKBAnswerTool(e.d.RC, e.d.Cfg, !e.d.Prefs.Web),
		newRouteSkillTool(e.d.Catalog, e.d.Store, activeTask),
		newRunCommandToolForTask(e.d.Gate, runCap, runTimeout, execDir, activeTask, e.d.Runs.Add, cmdCtx, grounder),
		newVerifiedRecordEvidenceTool(e.d.Store, e.d.Runs.Contains),
	} {
		if err := reg.Register(t); err != nil {
			return "", err
		}
	}

	dom := containerDomainFor(task.Kind)

	// Vantage-as-context: skew every tier prompt by the vantage Run already read.
	// One persona; the skew only shapes the per-tier guidance.
	skew := containerVantageSkew(v)

	var exploitSel exploitSelector
	if e.d.RC != nil {
		exploitSel = newKBExploitSelector(e.d.Model, e.d.RC, e.d.Cfg)
	}

	runTier := func(ctx context.Context, _ engagement.Surface, asset string, tier reconTier, sel reconSelection) (tierOutcome, error) {
		beforeCmds := e.d.Runs.Count(task.ID)
		beforeRows, err := e.d.Store.EvidenceRowsFor(task.ID)
		if err != nil {
			return tierOutcome{}, err
		}
		msgs := []llms.MessageContent{
			{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextPart(dom.Prompt)}},
			{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextPart(containerTierPrompt(task, asset, tier, sel, skew))}},
		}
		if _, _, err := runToolLoop(ctx, e.d.Model, reg, msgs, LoopCaps{MaxRounds: 4, MaxCalls: 8}); err != nil {
			return tierOutcome{}, err
		}
		// Code-side evidence capture (captureTierEvidence): do not rely on the
		// model's record_evidence. A code-side backstop records this pass's captured
		// command output as evidence and surfaces a coverage-gap when nothing was
		// captured, so non-nmap container recon (kubectl/capsh/crictl/escape probes)
		// cannot silently drop its findings. Container has a bespoke recon driver, so
		// it adopts the shared helper explicitly rather than inheriting it.
		newRows, err := e.captureTierEvidence(task.ID, string(task.Surface), asset, tier.Name, beforeRows, beforeCmds)
		if err != nil {
			return tierOutcome{}, err
		}
		out := tierOutcomeFromSignals(tier, e.d.Runs.Count(task.ID)-beforeCmds, len(newRows))
		out.NewAssets = e.correlateNewEvidence(ctx, task.ID, newRows, exploitSel)
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
