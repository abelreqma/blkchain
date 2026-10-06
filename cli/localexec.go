package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"

	"github.com/tmc/langchaingo/llms"
)

// localexec.go is the LOCAL surface executor: post-access privilege-escalation
// enumeration and read-only target/binary analysis. It registers through the
// surfaceExecutor/recon-ladder seams and prefixes every package identifier with
// "local" so it cannot collide with a sibling surface.
//
// Two behaviors:
//   - local enumeration (Kind "local"/"exploit-dev"): reuses genericExecutor, so
//     a recon-phase task runs the localLadder below and an exploit task runs the
//     armed lifecycle.
//   - target analysis (Kind "target-analysis"): a dedicated read-only loop whose
//     run_command is wrapped with the target-self-exec guarantee - the analysis
//     target is inspected, never executed. Defects parsed from the verbatim
//     evidence feed the correlation chain with provenance.
//
// The LOCAL gate profile (cli/internal/secgate) already confirms every command
// and fails closed with no confirmer; this file does not change the gate. The
// guard here is an executor-owned structural control; the durable gate-level rule
// lives in secgate.

func init() {
	registerExecutor(engagement.SurfaceLocal, func(d engageDeps) surfaceExecutor {
		return localExecutor{genericExecutor{d: d}}
	})
	registerLadder(engagement.SurfaceLocal, localLadder)
}

// localLadder is the local post-access enumeration ladder (deterministic
// backbone; the LLM proposes commands within a tier, the tiers and their order
// are fixed). It mirrors the "local" persona's non-destructive enumeration:
// T0 identity + sudo, T1 SUID/SGID + capabilities, T2 cron + services +
// world-writable, T3 read-only analysis of a specific binary.
var localLadder = reconLadder{
	{Index: 0, Name: "identity-sudo", Dimensions: []string{"identity", "sudo"}},
	{Index: 1, Name: "suid-sgid-caps", Dimensions: []string{"suid", "capabilities"}},
	{Index: 2, Name: "cron-services-writable", Dimensions: []string{"cron", "services", "world-writable"}},
	{Index: 3, Name: "binary-analysis", Dimensions: []string{"binary-analysis"}},
}

// localExecutor runs the local surface. It embeds genericExecutor to reuse the
// vantage reachability check, gate stamping, and the recon/exploit adapters for
// ordinary local work, and adds the X2-guarded read-only loop for a
// target-analysis task.
type localExecutor struct {
	genericExecutor
}

// Run routes a target-analysis task to the dedicated read-only loop (X2 guard)
// and every other local task to the generic path (local recon ladder / exploit
// lifecycle).
func (e localExecutor) Run(ctx context.Context, task engagement.Task) (string, error) {
	if !strings.EqualFold(strings.TrimSpace(task.Kind), "target-analysis") {
		return e.genericExecutor.Run(ctx, task)
	}
	// Vantage reachability (fail-closed), mirroring genericExecutor.Run: a surface
	// the current vantage does not reach cannot be entered; a store read error
	// does not proceed ungated. An unset vantage ("") is unrestricted.
	v, err := e.d.Store.Vantage(ctx)
	if err != nil {
		return fmt.Sprintf("executor: task %s could not read the engagement vantage: %v", task.ID, err), nil
	}
	if v != "" && !v.Reaches(task.Surface) {
		return fmt.Sprintf("executor: task %s surface %q is not reachable at the current vantage %q; advance the vantage first", task.ID, task.Surface, v), nil
	}
	return e.localRunTargetAnalysis(ctx, task)
}

// localRunTargetAnalysis drives one read-only target-analysis task. It builds the
// same read-only tool set the generic loop uses, but swaps in the X2-guarded
// run_command so the analysis target can never be executed. After the loop it
// scans the evidence this run recorded for local privesc defects and applies the
// unarmed follow-on candidates they imply (with provenance).
func (e localExecutor) localRunTargetAnalysis(ctx context.Context, task engagement.Task) (string, error) {
	dom := domainFor(task.Kind) // the existing "target-analysis" persona
	activeTask := func() string { return task.ID }

	reg := tooldef.NewRegistry()
	tools := []tooldef.Tool{
		newKBSearchTool(e.d.RC, e.d.Cfg),
		newKBAnswerTool(e.d.RC, e.d.Cfg, !e.d.Prefs.Web),
		newPlanAddTool(e.d.Store),
		newPlanUpdateTool(e.d.Store),
		newRouteSkillTool(e.d.Catalog, e.d.Store, activeTask),
	}
	if e.d.Gate != nil && e.d.Runs != nil {
		runTimeout, runCap := resolveRunCaps()
		execDir, cleanup, err := newExecutorScratchDir(e.d.WorkDir)
		if err != nil {
			return "", err
		}
		defer cleanup()
		defer releaseEngageWorker(ctx, execDir)
		cmdCtx := secgate.Command{
			TaskID:  task.ID,
			Phase:   secgate.Phase(string(task.Phase)),
			Surface: secgate.Surface(string(task.Surface)),
			Armed:   task.Armed,
			// Kind/Target carry the read-only invariant to the gate so the
			// gate-level TargetSelfExecViolation governs this primary target-analysis
			// path too, with localIsTargetBinary below as the pre-gate belt.
			Kind:   task.Kind,
			Target: task.Target,
		}
		grounder := newTaskGrounder(e.d.ToolHelp, e.d.Gate, execDir, cmdCtx)
		tools = append(tools,
			localNewTargetAnalysisRunCommand(e.d.Gate, task, e.d.Store, runCap, runTimeout, execDir, activeTask, e.d.Runs.Add, cmdCtx, grounder),
			newVerifiedRecordEvidenceTool(e.d.Store, e.d.Runs.Contains),
		)
	} else {
		tools = append(tools, newRecordEvidenceTool(e.d.Store))
	}
	for _, t := range tools {
		if err := reg.Register(t); err != nil {
			return "", err
		}
	}

	beforeRows, err := e.d.Store.EvidenceRowsFor(task.ID)
	if err != nil {
		return "", err
	}

	proj, err := projectionText(ctx, e.d.Store)
	if err != nil {
		return "", err
	}
	msgs := []llms.MessageContent{
		{Role: llms.ChatMessageTypeSystem, Parts: []llms.ContentPart{llms.TextPart(effectiveEngagePrompt(e.d.Gate, dom.Prompt))}},
		{Role: llms.ChatMessageTypeHuman, Parts: []llms.ContentPart{llms.TextPart(localTargetAnalysisPrompt(proj, task))}},
	}
	final, _, err := runToolLoop(ctx, e.d.Model, reg, msgs, LoopCaps{MaxRounds: 6, MaxCalls: 12})
	if err != nil {
		return final, err
	}

	e.localApplyDefectCandidates(ctx, task.ID, beforeRows)
	return final, nil
}

func (e localExecutor) localApplyDefectCandidates(ctx context.Context, taskID string, beforeRows []engagement.EvidenceRow) {
	afterRows, err := e.d.Store.EvidenceRowsFor(taskID)
	if err != nil || len(afterRows) <= len(beforeRows) {
		return
	}
	audit := func(action, detail string) { _ = e.d.Store.Audit("correlate-defects", action, detail) }
	seen := map[string]bool{}
	var cands []engagement.Task
	for _, r := range afterRows[len(beforeRows):] {
		prov := Provenance{TaskID: taskID, EvidenceID: r.ID}
		for _, c := range localCorrelateDefects(ctx, e.d.RC, e.d.Cfg, audit, prov, r.Quote) {
			if seen[c.ID] {
				continue
			}
			seen[c.ID] = true
			cands = append(cands, c)
		}
	}
	if len(cands) > 0 {
		if _, err := e.d.Store.Apply(engagement.Delta{Kind: "correlate-defects", Detail: taskID, Upserts: cands}); err != nil {
			audit("apply-failed", err.Error())
		}
	}
}

func localTargetAnalysisPrompt(proj string, task engagement.Task) string {
	return fmt.Sprintf("Engagement state:\n%s\n\nTarget-analysis task %s [%s]:\n target: %s\n objective: %s\n done when: %s\n\nInspect the target NON-destructively now with run_command (file, stat, ls -l, getcap, ldd, strings, nm, readelf, objdump) and record an exact-quote of each real output with record_evidence. NEVER execute the target itself; it is inspected, not run. Use kb_search and route_skill (domain \"target-analysis\" or \"local\") to ground a GTFOBins-style or known-CVE assessment. The harness correlates defects into follow-on tasks; do not call plan_add for this task.",
		proj, task.ID, task.Kind, task.Target, task.Objective, task.DoneWhen)
}

// localNewTargetAnalysisRunCommand builds the X2-guarded run_command for a
// target-analysis task. Before grounding/gate/confirmation it structurally
// refuses any command whose resolved binary is the task's own analysis target
// (a hard deny, flagged distinctly - the target is inspected, never executed),
// and re-applies the check to the authorized command so an operator edit cannot
// substitute the target as the binary. Otherwise it runs the full gate (LOCAL
// confirms every command) and, on a real result, captures the output and records
// a verbatim quote as evidence in code (the model misroutes record_evidence;
// code owns the authoritative evidence). Read-only inspections run one at a time
// (no pipeline).
func localNewTargetAnalysisRunCommand(g *secgate.Gate, task engagement.Task, store *engagement.Store, capBytes int, timeout time.Duration, workDir string, activeTask func() string, capture func(taskID, output string), cmdCtx secgate.Command, grounder *helpGrounder) tooldef.Tool {
	return newStoreTool("run_command",
		"Run ONE bounded, shell-free, read-only inspection command: a bare binary name and literal args (no shell, no pipeline). The analysis target itself is never executed; inspect it only with read-only tools (file, stat, ls, nm, readelf, objdump, strings, ldd, getcap). The operator confirms every command.",
		runCommandArgs{},
		func(ctx context.Context, argsJSON string) (string, error) {
			var a runCommandArgs
			if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
				return "run_command: invalid arguments: " + err.Error(), nil
			}
			if len(a.Pipeline) > 0 {
				return "run_command: target analysis runs one read-only inspection at a time; provide a single binary + args, not a pipeline", nil
			}
			if strings.TrimSpace(a.Binary) == "" {
				return "run_command: invalid arguments: binary is required", nil
			}
			// X2 read-only guarantee (structural, executor-owned): a target-analysis
			// task must never execute its own analysis target. Hard deny, flagged
			// distinctly, before grounding/gate/confirm.
			if localIsTargetBinary(a.Binary, task.Target) {
				if g != nil && g.Audit != nil {
					g.Audit("x2-deny", "target-analysis refused to execute its own target: "+secgate.Signature(secgate.Command{Binary: a.Binary, Args: a.Args}))
				}
				return localX2Refusal(task.Target, false), nil
			}

			cmd := secgate.Command{Binary: a.Binary, Args: a.Args, Phase: cmdCtx.Phase, Surface: cmdCtx.Surface, Armed: cmdCtx.Armed, Kind: cmdCtx.Kind, Target: cmdCtx.Target}
			oc := grounder.ground(ctx, cmd)
			if oc.Reject {
				return oc.Msg, nil
			}
			run, msg := authorizeCommand(ctx, g, cmd)
			if msg != "" {
				return msg, nil
			}
			// Re-apply X2 to the authorized command so an operator edit at the confirm
			// overlay cannot slip the target in as the binary.
			if localIsTargetBinary(run.Binary, task.Target) {
				if g != nil && g.Audit != nil {
					g.Audit("x2-deny", "edited command would execute the analysis target")
				}
				return localX2Refusal(task.Target, true), nil
			}
			if g != nil && g.Audit != nil {
				g.Audit("exec", secgate.Signature(run))
			}
			res := runAuthorized(ctx, g, run.Binary, run.Args, workDir, capBytes, timeout, actionOrigin{TaskID: task.ID, Surface: run.Surface})
			if capture != nil {
				capture(activeTask(), res.Output)
			}
			if store != nil && strings.TrimSpace(res.Output) != "" {
				_, _ = store.RecordEvidence(task.ID, res.Output)
			}
			var b strings.Builder
			if res.TimedOut {
				fmt.Fprintf(&b, "run_command: the command timed out and was terminated after %s\n", timeout)
			}
			if oc.Msg != "" {
				fmt.Fprintf(&b, "(grounding: %s)\n", oc.Msg)
			}
			if res.Err != nil {
				fmt.Fprintf(&b, "(command exited with an error: %s)\n", res.Err.Error())
			}
			if res.EphemeralFiles {
				b.WriteString("(isolated command files are temporary; capture stdout or stderr as evidence)\n")
			}
			b.WriteString(secgate.WrapUntrusted("command", res.Output))
			return b.String(), nil
		})
}

// localX2Refusal is the distinct X2 refusal message. The "X2" marker makes an
// attempted target execution unmistakable in the operator view and the audit log.
func localX2Refusal(target string, edited bool) string {
	if edited {
		return fmt.Sprintf("run_command refused (X2 read-only guarantee, edited command): the analysis target %q must not be executed; inspect it read-only instead (file, stat, nm, readelf, objdump, strings, ldd, getcap).", target)
	}
	return fmt.Sprintf("run_command refused (X2 read-only guarantee): a target-analysis task must not execute its own analysis target %q; inspect it read-only instead (file, stat, nm, readelf, objdump, strings, ldd, getcap).", target)
}

// localIsTargetBinary reports whether the proposed binary resolves to the task's
// analysis target. It compares by exact string, then by canonical path: a binary
// containing a path separator is resolved directly, a bare name is resolved via
// PATH. Both sides are canonicalized (absolute + symlinks resolved) so a symlink
// or a relative spelling of the target is still caught. Empty inputs are not a
// match.
func localIsTargetBinary(binary, target string) bool {
	b := strings.TrimSpace(binary)
	t := strings.TrimSpace(target)
	if b == "" || t == "" {
		return false
	}
	if b == t {
		return true
	}
	tc := localCanonPath(t)
	var cands []string
	if strings.ContainsRune(b, '/') {
		cands = append(cands, b)
	} else if p, err := exec.LookPath(b); err == nil {
		cands = append(cands, p)
	}
	for _, c := range cands {
		if c == t || localCanonPath(c) == tc {
			return true
		}
	}
	return false
}

// localCanonPath canonicalizes p to an absolute, symlink-resolved path. Both the
// target and a candidate binary go through it, so (for example) the macOS
// /tmp -> /private/tmp symlink resolves identically on both sides. A path that
// cannot be resolved falls back to its cleaned absolute form.
func localCanonPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return filepath.Clean(p)
}

// localDefectRule is one deterministic local-privesc defect indicator: a stable
// key, the follow-on task it implies (kind/phase/surface), a human objective, the
// corpus skill that advises the technique, and a matcher over the verbatim quote.
type localDefectRule struct {
	key       string
	objective string
	kind      string
	phase     engagement.Phase
	surface   engagement.Surface
	skill     string

	query string
	// term is the defect-class distinctive token a grounding hit must mention
	// (acceptCitation) so a generic/keyword-adjacent hit does not falsely ground;
	// for local (version-less) defects it is the technique-class token.
	term    string
	re      *regexp.Regexp // nil means use the phrase matcher
	phrases []string       // lowercased substrings; any match triggers the rule
}

// localDefectRules are evaluated in this fixed order, so a quote that trips
// several yields candidates in a stable sequence. Each rule reads read-only
// enumeration/analysis output (getcap, ls -l, sudo -l, id, strings, file
// contents) and names a privesc vector. Vectors that only need more read-only
// inspection become a target-analysis follow-on (stays in scope); vectors that
// require an active step become an UNARMED exploit candidate (the armed
// lifecycle gates execution); a credential becomes an auth follow-on.
var localDefectRules = []localDefectRule{
	{
		key:       "capability-privesc",
		objective: "Linux capability grants privilege escalation",
		kind:      "target-analysis",
		phase:     engagement.PhaseRecon,
		surface:   engagement.SurfaceLocal,
		skill:     "offensive-linux-privesc",
		query:     "linux file capability privilege escalation cap_setuid getcap",
		term:      "capabilities",
		re:        regexp.MustCompile(`(?i)cap_(setuid|setgid|dac_override|dac_read_search|sys_admin|sys_ptrace|sys_module|chown|fowner)`),
	},
	{
		key:       "suid-sgid",
		objective: "SUID/SGID binary (GTFOBins-style privilege-escalation vector)",
		kind:      "target-analysis",
		phase:     engagement.PhaseRecon,
		surface:   engagement.SurfaceLocal,
		skill:     "offensive-linux-privesc",
		query:     "SUID SGID binary privilege escalation GTFOBins",
		term:      "suid",
		re:        regexp.MustCompile(`[-dplbc]rw[sS]`),
	},
	{
		key:       "sudo-nopasswd",
		objective: "sudo NOPASSWD entry (privilege-escalation vector)",
		kind:      "exploit",
		phase:     engagement.PhaseExploit,
		surface:   engagement.SurfaceLocal,
		skill:     "offensive-linux-privesc",
		query:     "sudo NOPASSWD sudoers privilege escalation GTFOBins",
		term:      "nopasswd",
		re:        regexp.MustCompile(`(?i)NOPASSWD`),
	},
	{
		key:       "world-writable",
		objective: "world-writable path (privilege-escalation vector if root-owned or service/cron)",
		kind:      "exploit",
		phase:     engagement.PhaseExploit,
		surface:   engagement.SurfaceLocal,
		skill:     "offensive-linux-privesc",
		query:     "world-writable file directory privilege escalation",
		// Two tokens (word-boundary gate): "world" and "writable" both match the
		// hyphenated "world-writable" and the spaced "world writable" corpus phrasings.
		term:    "world writable",
		re:      regexp.MustCompile(`[-dpl][rwxsStT-]{5}[rwxsStT-][r-]w[xtT-]`),
		phrases: []string{"world-writable", "world writable"},
	},
	{
		key:       "nfs-no-root-squash",
		objective: "NFS export with no_root_squash (remote-root SUID privilege escalation)",
		kind:      "exploit",
		phase:     engagement.PhaseExploit,
		surface:   engagement.SurfaceLocal,
		skill:     "offensive-linux-privesc",
		query:     "NFS no_root_squash privilege escalation SUID",
		term:      "no_root_squash",
		phrases:   []string{"no_root_squash"},
	},
	{
		key:       "container-group",
		objective: "docker/lxd group membership (host-root-equivalent escape)",
		kind:      "exploit",
		phase:     engagement.PhaseExploit,
		surface:   engagement.SurfaceLocal,
		skill:     "offensive-linux-privesc",
		query:     "docker lxd group membership container escape privilege escalation",
		term:      "docker",
		re:        regexp.MustCompile(`(?i)\d+\((docker|lxd)\)`),
	},
	{
		key:       "private-key",
		objective: "exposed private key (credential for lateral movement or authentication)",
		kind:      "auth",
		phase:     engagement.PhaseRecon,
		surface:   engagement.SurfaceLocal,
		skill:     "offensive-linux-privesc",
		query:     "exposed private key credential lateral movement SSH",
		term:      "private key",
		phrases:   []string{"begin openssh private key", "begin rsa private key", "begin ec private key", "begin dsa private key", "begin private key"},
	},
	{
		key:       "cloud-access-key",
		objective: "embedded cloud access key (credential)",
		kind:      "auth",
		phase:     engagement.PhaseRecon,
		surface:   engagement.SurfaceLocal,
		skill:     "offensive-linux-privesc",
		query:     "embedded cloud access key credential AWS AKIA",
		term:      "aws",
		re:        regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		key:       "known-cve",
		objective: "referenced CVE (verify applicability to this binary/version)",
		kind:      "target-analysis",
		phase:     engagement.PhaseRecon,
		surface:   engagement.SurfaceLocal,
		skill:     "offensive-linux-privesc",
		query:     "linux privilege escalation CVE kernel exploit",
		term:      "cve",
		re:        regexp.MustCompile(`CVE-\d{4}-\d{4,7}`),
	},
}

func localCorrelateDefects(ctx context.Context, rc searcher, cfg ragconfig.Config, audit func(action, detail string), prov Provenance, quote string) []engagement.Task {
	if !prov.valid() {
		return nil
	}
	lower := strings.ToLower(quote)
	var cands []engagement.Task
	for _, rule := range localDefectRules {
		if !rule.matches(quote, lower) {
			continue
		}
		base := engagement.Task{
			ID:        "localdefect-" + rule.key + "-" + prov.TaskID + "-" + strconv.FormatInt(prov.EvidenceID, 10),
			Kind:      rule.kind,
			Objective: rule.objective + "; technique via " + rule.skill,
			Status:    engagement.StatusTodo,
			Phase:     rule.phase,
			Surface:   rule.surface,
			Armed:     false,
			BasisIDs:  []string{prov.TaskID},
		}
		cands = append(cands, groundCandidate(ctx, rc, cfg, audit, base, rule.query, rule.term))
	}
	return cands
}

// matches reports whether this rule fires on the quote. A regex rule tests the
// raw quote (its own (?i) handles case); a phrase rule tests the lowercased
// quote. A rule may carry both; either hit fires it.
func (r localDefectRule) matches(quote, lower string) bool {
	if r.re != nil && r.re.MatchString(quote) {
		return true
	}
	for _, p := range r.phrases {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
