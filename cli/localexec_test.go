package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/secgate"

	"github.com/tmc/langchaingo/llms"
)

// localCorpus returns a stub retriever whose single hit mentions text, so
// acceptCitation grounds any rule whose defect-class term appears in text.
// &recSearcher{} (no results) is the no-coverage path.
func localCorpus(text string) *recSearcher {
	return &recSearcher{results: []retrieval.Result{chunk("offensive-linux-privesc", "skill.md", "privesc", text)}}
}

// localNoAudit is a no-op audit sink for tests that do not assert on audit rows.
func localNoAudit(string, string) {}

// TestLocalLadderAndExecutorRegistered verifies the init() registration seams:
// the local surface resolves to a localExecutor and to the dedicated local recon
// ladder (not the single-tier generic fallback).
func TestLocalLadderAndExecutorRegistered(t *testing.T) {
	l := ladderFor(engagement.SurfaceLocal)
	if len(l) < 4 {
		t.Fatalf("local ladder has %d tiers, want >= 4 (T0..T3)", len(l))
	}
	// Tiers are ordered lowest-index first and cover the privesc enumeration
	// dimensions the local persona describes.
	for i, tier := range l {
		if tier.Index != i {
			t.Errorf("tier %d has Index %d, want %d", i, tier.Index, i)
		}
		if tier.Name == "" || len(tier.Dimensions) == 0 {
			t.Errorf("tier %d is missing a name or dimensions: %+v", i, tier)
		}
	}

	d := testDeps(t, nil)
	task := engagement.Task{ID: "t1", Kind: "local", Surface: engagement.SurfaceLocal}
	if _, ok := executorFor(d, task).(localExecutor); !ok {
		t.Fatalf("executorFor(SurfaceLocal) = %T, want localExecutor", executorFor(d, task))
	}
}

// TestLocalIsTargetBinary covers the target-self-exec resolution: a proposed binary that is the
// analysis target (by direct path, by PATH resolution, or through a symlink) is
// recognized, while a read-only tool that merely takes the target as an argument
// is not.
func TestLocalIsTargetBinary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(target, []byte("\x7fELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlink to the target must resolve to the same canonical path.
	link := filepath.Join(dir, "link.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	// A PATH-resolvable copy under a dir we put on PATH.
	pathDir := t.TempDir()
	onPath := filepath.Join(pathDir, "onpathtool")
	if err := os.WriteFile(onPath, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cases := []struct {
		name   string
		binary string
		target string
		want   bool
	}{
		{"exact path", target, target, true},
		{"symlink to target", link, target, true},
		{"relative dot-slash is not the target", "./file", target, false},
		{"read-only tool, target is an arg not the binary", "file", target, false},
		{"different absolute binary", "/bin/ls", target, false},
		{"path-resolved name equals target", "onpathtool", onPath, true},
		{"empty binary", "", target, false},
		{"empty target", target, "", false},
	}
	for _, c := range cases {
		if got := localIsTargetBinary(c.binary, c.target); got != c.want {
			t.Errorf("%s: localIsTargetBinary(%q,%q)=%v want %v", c.name, c.binary, c.target, got, c.want)
		}
	}
}

// TestLocalTargetAnalysisRunCommandDeniesTarget is the acceptance-critical self-exec
// structural check at the tool boundary: the guarded run_command refuses to
// execute the task's own analysis target (flagged distinctly), yet runs a
// read-only inspection that passes the target as an argument.
func TestLocalTargetAnalysisRunCommandDeniesTarget(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "target.bin")
	before := []byte("\x7fELF fixture bytes")
	if err := os.WriteFile(fixture, before, 0o755); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var got [][]string
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		mu.Lock()
		got = append(got, append([]string{bin}, args...))
		mu.Unlock()
		if bin == fixture {
			t.Errorf("X2 violated: the analysis target was executed: %s %v", bin, args)
		}
		return runResult{Output: "ok"}
	})

	g := safeLocalGate(t, &countingConfirmer{ok: true})
	task := engagement.Task{ID: "t1", Kind: "target-analysis", Target: fixture, Surface: engagement.SurfaceLocal}
	runs := NewRunOutputs()
	tool := localNewTargetAnalysisRunCommand(g, task, nil, 1<<20, time.Second, "", func() string { return "t1" }, runs.Add, secgate.Command{Surface: secgate.Surface("local")}, nil)

	// Executing the target itself is refused, distinctly flagged, never run.
	out, err := tool.Call(context.Background(), `{"binary":"`+fixture+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "X2") || !strings.Contains(strings.ToLower(out), "target") {
		t.Errorf("refusal is not distinctly flagged: %q", out)
	}

	// Inspecting the target with a read-only tool is allowed and runs.
	if _, err := tool.Call(context.Background(), `{"binary":"file","args":["`+fixture+`"]}`); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0][0] != "file" {
		t.Fatalf("expected exactly one executed command (file), got %v", got)
	}
	after, err := os.ReadFile(fixture)
	if err != nil || string(after) != string(before) {
		t.Fatalf("fixture changed or gone after guarded run: err=%v", err)
	}
}

// TestLocalExecutorNeverExecutesTargetEndToEnd drives a full target-analysis
// executor whose model tries to execute the target; the self-exec guarantee holds
// structurally through runExecutor, not by prompt alone.
func TestLocalExecutorNeverExecutesTargetEndToEnd(t *testing.T) {
	d := testDeps(t, nil)
	fixture := filepath.Join(t.TempDir(), "target.bin")
	before := []byte("\x7fELF fixture bytes")
	if err := os.WriteFile(fixture, before, 0o755); err != nil {
		t.Fatal(err)
	}
	name, active := "eng", "t1"
	stage := engagement.Stage{Label: "dispatch", Tool: "target-analysis"}
	if _, err := d.Store.Apply(engagement.Delta{
		Upserts:     []engagement.Task{{ID: "t1", Kind: "target-analysis", Target: fixture, Objective: "assess", Status: engagement.StatusActive}},
		SetName:     &name,
		SetActiveID: &active,
		SetStage:    &stage,
		Kind:        "init",
	}); err != nil {
		t.Fatal(err)
	}
	d.Gate = safeLocalGate(t, &countingConfirmer{ok: true})
	d.Runs = NewRunOutputs()

	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		if bin == fixture {
			t.Errorf("X2 violated end-to-end: target executed: %s %v", bin, args)
		}
		return runResult{Output: "inspection of " + bin}
	})

	// The model (adversarially) first tries to execute the target, then inspects it.
	d.Model = &scriptModel{resps: []*llms.ContentResponse{
		{Choices: []*llms.ContentChoice{{ToolCalls: []llms.ToolCall{
			runCall("c1", fixture),
			runCall("c2", "file", fixture),
		}}}},
		finalResp("verdict: inspected only"),
	}}

	if _, err := runExecutor(context.Background(), d, "t1"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(fixture)
	if err != nil || string(after) != string(before) {
		t.Fatalf("fixture changed after end-to-end run: err=%v", err)
	}
}

func TestLocalCorrelateDefectsProvenance(t *testing.T) {
	prov := Provenance{TaskID: "t1", EvidenceID: 7}
	// A getcap line granting cap_setuid is a privesc defect; a NOPASSWD sudo entry
	// is another; a SUID bit a third. All are read-only enumeration output.
	quote := "/usr/bin/python3 = cap_setuid+ep\n(root) NOPASSWD: /usr/bin/vim\n-rwsr-xr-x 1 root root 1234 /usr/bin/find"
	// A corpus hit mentioning every defect-class term (word-boundary forms) so each
	// matched rule grounds.
	rc := localCorpus("suid sgid binaries, linux capabilities cap_setuid getcap, sudo nopasswd, docker lxd, private key, aws, cve, world writable, no_root_squash")
	cands := localCorrelateDefects(context.Background(), rc, kbTestCfg(), localNoAudit, prov, quote)
	if len(cands) == 0 {
		t.Fatalf("expected defect candidates from %q", quote)
	}
	for _, c := range cands {
		if c.CoverageGap || c.Status != engagement.StatusTodo {
			t.Errorf("grounded candidate %q must be an armable todo, got gap=%v status=%q", c.ID, c.CoverageGap, c.Status)
		}
		foundBasis := false
		for _, b := range c.BasisIDs {
			if b == prov.TaskID {
				foundBasis = true
			}
		}
		if !foundBasis {
			t.Errorf("candidate %q missing BasisIDs provenance to %q: %+v", c.ID, prov.TaskID, c.BasisIDs)
		}
		if !strings.Contains(c.ID, "7") {
			t.Errorf("candidate id %q does not embed the evidence id 7", c.ID)
		}
		if c.Armed {
			t.Errorf("defect candidate %q must be unarmed", c.ID)
		}
		if c.Citation == (engagement.Citation{}) {
			t.Errorf("grounded candidate %q must carry a citation", c.ID)
		}
	}

	if got := localCorrelateDefects(context.Background(), rc, kbTestCfg(), localNoAudit, Provenance{}, quote); got != nil {
		t.Errorf("invalid provenance must yield nothing, got %d", len(got))
	}
	if got := localCorrelateDefects(context.Background(), rc, kbTestCfg(), localNoAudit, prov, "nothing interesting here"); got != nil {
		t.Errorf("benign quote must yield nothing, got %d", len(got))
	}
}

func TestLocalCorrelateDefectsRAGGateMutate(t *testing.T) {
	prov := Provenance{TaskID: "t1", EvidenceID: 3}
	quote := "-rwsr-xr-x 1 root root 1234 /usr/bin/find" // matches suid-sgid (term "suid")

	cands := localCorrelateDefects(context.Background(), localCorpus("suid privesc via gtfobins"), kbTestCfg(), localNoAudit, prov, quote)
	if len(cands) != 1 || cands[0].CoverageGap || cands[0].Status != engagement.StatusTodo || cands[0].Citation.Origin != "trusted" {
		t.Fatalf("covered: want 1 grounded todo candidate with a trusted citation, got %+v", cands)
	}

	// Mutate: no corpus coverage -> emitted as a BLOCKED coverage-gap (not dropped),
	// empty citation, shared marker, and a corpus-coverage-gap audit row.
	var audited [][2]string
	audit := func(action, detail string) { audited = append(audited, [2]string{action, detail}) }
	gapc := localCorrelateDefects(context.Background(), &recSearcher{}, kbTestCfg(), audit, prov, quote)
	if len(gapc) != 1 {
		t.Fatalf("mutate: the finding must still be emitted (not dropped), got %d", len(gapc))
	}
	if gapc[0].Status != engagement.StatusBlocked || !gapc[0].CoverageGap || gapc[0].Citation != (engagement.Citation{}) {
		t.Errorf("mutate: want a blocked coverage-gap with no citation, got %+v", gapc[0])
	}
	if !strings.Contains(gapc[0].Objective, "corpus-coverage-gap") {
		t.Errorf("mutate: coverage-gap candidate must carry the shared Objective marker, got %q", gapc[0].Objective)
	}
	sawGapAudit := false
	for _, a := range audited {
		if a[0] == "corpus-coverage-gap" {
			sawGapAudit = true
		}
	}
	if !sawGapAudit {
		t.Errorf("mutate: a corpus-coverage-gap audit row must be written, got %v", audited)
	}

	// Inverse false-grounding: the only hit is generic (does not mention "suid") ->
	// acceptCitation rejects it -> coverage-gap, not a false finding.
	gen := localCorrelateDefects(context.Background(), localCorpus("completely unrelated kernel changelog notes"), kbTestCfg(), localNoAudit, prov, quote)
	if len(gen) != 1 || !gen[0].CoverageGap || gen[0].Status != engagement.StatusBlocked {
		t.Fatalf("inverse: a non-defect-class hit must not ground (coverage-gap), got %+v", gen)
	}
}

func TestLocalApplyDefectCandidatesRAGGated(t *testing.T) {
	findLocalDefect := func(d engageDeps) *engagement.Task {
		snap, err := d.Store.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for i := range snap.Tasks {
			if strings.HasPrefix(snap.Tasks[i].ID, "localdefect-") {
				return &snap.Tasks[i]
			}
		}
		return nil
	}
	run := func(rc searcher) *engagement.Task {
		d := testDeps(t, nil)
		d.RC = rc
		e := localExecutor{genericExecutor{d: d}}
		name := "eng"
		if _, err := d.Store.Apply(engagement.Delta{
			Upserts: []engagement.Task{{ID: "t1", Kind: "target-analysis", Target: "/usr/bin/find", Status: engagement.StatusActive}},
			SetName: &name, Kind: "init",
		}); err != nil {
			t.Fatal(err)
		}
		before, _ := d.Store.EvidenceRowsFor("t1")
		if _, err := d.Store.RecordEvidence("t1", "-rwsr-xr-x 1 root root 1234 /usr/bin/find"); err != nil {
			t.Fatal(err)
		}
		e.localApplyDefectCandidates(context.Background(), "t1", before)
		return findLocalDefect(d)
	}

	// Ungrounded (no corpus): a blocked coverage-gap candidate is applied (no silent drop).
	gap := run(&recSearcher{})
	if gap == nil {
		t.Fatalf("ungrounded defect must be emitted (blocked), not dropped")
	}
	if gap.Status != engagement.StatusBlocked || !gap.CoverageGap || gap.Citation != (engagement.Citation{}) {
		t.Errorf("ungrounded defect must be a blocked coverage-gap with no citation, got %+v", *gap)
	}

	found := run(localCorpus("suid privesc via gtfobins"))
	if found == nil {
		t.Fatalf("grounded defect must be applied as a task")
	}
	if found.Status != engagement.StatusTodo || found.CoverageGap || found.Citation == (engagement.Citation{}) {
		t.Errorf("grounded defect must be an armable todo with a citation, got %+v", *found)
	}
	if found.Armed {
		t.Errorf("applied defect task must be unarmed")
	}
}

func TestLocalDefectTermsGroundUnderWordBoundary(t *testing.T) {
	// A representative corpus snippet for each rule key (what a real grounding hit
	// would contain). Every rule MUST have one, so a new rule cannot ship without a
	// word-boundary-valid term.
	snippets := map[string]string{
		"capability-privesc": "linux capabilities let a binary with cap_setuid escalate; enumerate with getcap -r /",
		"suid-sgid":          "find suid and sgid binaries with find / -perm -4000 and abuse them via gtfobins",
		"sudo-nopasswd":      "sudo -l shows a nopasswd entry you can abuse to run a shell as root",
		"world-writable":     "world-writable files and directories are a privilege escalation vector",
		"nfs-no-root-squash": "an nfs export with no_root_squash lets a remote root create a suid shell",
		"container-group":    "membership in the docker group is root-equivalent on the host",
		"private-key":        "an exposed private key enables lateral movement over ssh",
		"cloud-access-key":   "an embedded aws access key (akia...) is a cloud credential",
		"known-cve":          "a known cve such as cve-2022-0847 dirtypipe affects this kernel",
	}
	for _, rule := range localDefectRules {
		snip, ok := snippets[rule.key]
		if !ok {
			t.Errorf("rule %q has no representative grounding snippet (add one so its term is verified)", rule.key)
			continue
		}
		if strings.TrimSpace(rule.term) == "" {
			t.Errorf("rule %q has an empty term", rule.key)
			continue
		}
		if !citationMentions(retrieval.Payload{Text: snip}, rule.term) {
			t.Errorf("rule %q term %q does not word-boundary-ground its representative corpus snippet %q", rule.key, rule.term, snip)
		}
	}
}

// TestLocalCoverageGapNotDispatchedNotArmable is the point-5b non-vacuous
// enforcement test: a LOCAL coverage-gap candidate (emitted blocked by the RAG gate
// when the corpus does not cover it) is NOT auto-dispatched (dispatch_batch skips a
// blocked task) AND is NOT armable (armTask rejects a blocked task). It fails if
// either enforcement is removed, so "Status=blocked" is a real, acted-on control,
// not a cosmetic flag.
func TestLocalCoverageGapNotDispatchedNotArmable(t *testing.T) {
	d := testDeps(t, nil)
	d.RC = &recSearcher{} // no corpus coverage -> the local defect is a coverage-gap
	e := localExecutor{genericExecutor{d: d}}
	name := "eng"
	if _, err := d.Store.Apply(engagement.Delta{
		Upserts: []engagement.Task{{ID: "t1", Kind: "target-analysis", Target: "/usr/bin/find", Status: engagement.StatusActive}},
		SetName: &name, Kind: "init",
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := d.Store.EvidenceRowsFor("t1")
	if _, err := d.Store.RecordEvidence("t1", "-rwsr-xr-x 1 root root 1234 /usr/bin/find"); err != nil {
		t.Fatal(err)
	}
	e.localApplyDefectCandidates(context.Background(), "t1", before)

	snap, err := d.Store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var gap *engagement.Task
	for i := range snap.Tasks {
		if strings.HasPrefix(snap.Tasks[i].ID, "localdefect-") {
			gap = &snap.Tasks[i]
			break
		}
	}
	if gap == nil || gap.Status != engagement.StatusBlocked || !gap.CoverageGap {
		t.Fatalf("expected a local blocked coverage-gap candidate, got %+v", gap)
	}

	// NOT dispatched: dispatch_batch skips the blocked task; its executor never runs.
	var ran atomic.Int32
	exec := func(context.Context, engageDeps, string) (string, error) { ran.Add(1); return "", nil }
	out, err := newDispatchBatchToolWith(d, exec).Call(context.Background(), `{"task_ids":["`+gap.ID+`"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if ran.Load() != 0 {
		t.Errorf("a local coverage-gap must NOT be dispatched: ran=%d", ran.Load())
	}
	if !strings.Contains(out, "blocked") {
		t.Errorf("dispatch_batch must skip the blocked coverage-gap with a note: out=%q", out)
	}

	// NOT armable: armTask rejects the blocked task; it stays unarmed.
	if err := armTask(context.Background(), d.Store, gap.ID); err == nil {
		t.Errorf("armTask must reject a blocked coverage-gap, got nil error")
	}
	if got, _ := d.Store.GetTask(gap.ID); got.Armed {
		t.Errorf("a rejected coverage-gap must remain unarmed")
	}
}
