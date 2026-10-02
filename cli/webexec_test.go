package main

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/secgate"

	"github.com/tmc/langchaingo/llms"
)

// TestWebLadderIsWSTGAligned pins the web recon ladder shape: a
// WSTG-aligned T0..T3 ladder over the already-allowlisted web tools. T0
// liveness + server/TLS fingerprint (WSTG-INFO-02, CRYP-01, CONF-07) -> T1
// content/dir discovery (INFO-04, CONF-03/04) -> T2 param/entry-point discovery
// (INFO-06) -> T3 finding-driven WSTG probes (INPV/ATHZ, corpus-grounded).
func TestWebLadderIsWSTGAligned(t *testing.T) {
	l := ladderFor(engagement.SurfaceWeb)
	want := []struct {
		name string
		dims []string
	}{
		{"liveness-fingerprint", []string{"liveness", "server", "tls"}},
		{"content-discovery", []string{"content", "paths"}},
		{"param-discovery", []string{"params", "endpoints"}},
		{"finding-driven-probes", []string{"probes"}},
	}
	if len(l) != len(want) {
		t.Fatalf("web ladder has %d tiers, want %d", len(l), len(want))
	}
	for i, w := range want {
		if l[i].Index != i {
			t.Errorf("tier %d Index = %d, want %d", i, l[i].Index, i)
		}
		if l[i].Name != w.name {
			t.Errorf("tier %d Name = %q, want %q", i, l[i].Name, w.name)
		}
		if len(l[i].Dimensions) != len(w.dims) {
			t.Fatalf("tier %d has %d dims, want %d", i, len(l[i].Dimensions), len(w.dims))
		}
		for j, d := range w.dims {
			if l[i].Dimensions[j] != d {
				t.Errorf("tier %d dim %d = %q, want %q", i, j, l[i].Dimensions[j], d)
			}
		}
	}
}

// TestWebExecutorRegisteredForWebSurface pins the registration seam: the web
// surface resolves to the concrete webExecutor, not the generic fallback.
func TestWebExecutorRegisteredForWebSurface(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	ex := executorFor(d, engagement.Task{ID: "t", Surface: engagement.SurfaceWeb, Kind: "web"})
	if _, ok := ex.(webExecutor); !ok {
		t.Fatalf("executorFor(SurfaceWeb) = %T, want webExecutor", ex)
	}
}

// TestWebExecutorDeniesOutOfScopeURL: a web task whose executor proposes a
// command against an out-of-scope host is denied by the gate (in-scope
// enforcement already lives in the gate) and the subprocess never runs. The
// security property is that execRunner is never reached; the gate's denial is
// surfaced to the model as a tool observation, not the executor's return value
// (which is the model's final text), so the assertion is on the exec stub.
func TestWebExecutorDeniesOutOfScopeURL(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{
		// 8.8.8.8 is outside the autoGate scope (10.0.0.0/24); the model proposes
		// it, so a non-call can only mean the gate denied it.
		toolCallResp("c1", "run_command", `{"binary":"curl","args":["-sS","http://8.8.8.8/"]}`),
		finalResp("done"),
	}})
	// An audit-capturing gate (same posture as autoGate: Auto, 10.0.0.0/24, allow
	// nmap+curl) so the test can confirm the denial is specifically a SCOPE denial,
	// not an incidental non-call.
	scope, err := secgate.ParseScope(strings.NewReader("10.0.0.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	var audits []string
	d.Gate = &secgate.Gate{
		Mode:  secgate.Auto,
		Scope: scope,
		Allow: secgate.NewAllowlist("nmap", "curl"),
		Audit: func(action, detail string) { audits = append(audits, action) },
	}
	d.Runs = NewRunOutputs()

	ran := false
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		ran = true
		return runResult{Output: "should not run"}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
		{ID: "t1", Kind: "web", Surface: engagement.SurfaceWeb, Target: "http://10.0.0.5/", Objective: "probe", Status: engagement.StatusTodo, Phase: engagement.PhaseRecon},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := runExecutor(context.Background(), d, "t1"); err != nil {
		t.Fatal(err)
	}
	if ran {
		t.Fatal("an out-of-scope web target must be denied before the subprocess runs")
	}
	scopeDenied := false
	for _, a := range audits {
		if strings.HasPrefix(a, "deny:scope") || strings.HasPrefix(a, "deny:resolve") {
			scopeDenied = true
			break
		}
	}
	if !scopeDenied {
		t.Errorf("expected the out-of-scope target to be denied at the scope layer, audits=%v", audits)
	}
}

// TestWebExecutorGroundsUnknownWebTool: help-grounding (newTaskGrounder) applies
// to web tools too. A hallucinated curl flag is rejected against the tool-help
// cache before the gate authorizes it and before the subprocess runs.
func TestWebExecutorGroundsUnknownWebTool(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{
		toolCallResp("c1", "run_command", `{"binary":"curl","args":["--totally-not-a-flag","http://10.0.0.5/"]}`),
		finalResp("done"),
	}})
	d.Gate = autoGate(t)
	d.Runs = NewRunOutputs()
	cache := &stubCache{}
	_ = cache.Store("curl", resolveBinVersion("curl"), toolInterface{Flags: []string{"-sS", "-I", "-L"}})
	d.ToolHelp = cache

	ran := false
	withStubExec(t, func(ctx context.Context, bin string, args []string, dir string, capBytes int, timeout time.Duration) runResult {
		ran = true
		return runResult{Output: "should not run"}
	})
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
		{ID: "t1", Kind: "web", Surface: engagement.SurfaceWeb, Target: "http://10.0.0.5/", Objective: "probe", Status: engagement.StatusTodo, Phase: engagement.PhaseRecon},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := runExecutor(context.Background(), d, "t1"); err != nil {
		t.Fatal(err)
	}
	if ran {
		t.Fatal("help-grounding must reject the hallucinated web-tool flag before the subprocess runs")
	}
}

// TestWebFindingsCarryProvenance: web-surface evidence correlates into a
// persisted candidate carrying Provenance back to the running task
// (BasisIDs == [taskID]). The web executor reuses the shared code-owned
// correlation, so findings keep their provenance on the web surface.
func TestWebFindingsCarryProvenance(t *testing.T) {
	d := testDeps(t, nil)
	d.Gate = autoGate(t) // scope 10.0.0.0/24
	ex := webExecutor{genericExecutor{d: d}}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
		ID: "w1", Kind: "web", Target: "http://10.0.0.5/", Status: engagement.StatusTodo,
		Phase: engagement.PhaseRecon, Surface: engagement.SurfaceWeb,
	}}}); err != nil {
		t.Fatal(err)
	}
	quote := "Nmap scan report for 10.0.0.5\n22/tcp open ssh OpenSSH 8.2p1\n"
	id, err := d.Store.RecordEvidence("w1", quote)
	if err != nil {
		t.Fatal(err)
	}
	rows := []engagement.EvidenceRow{{ID: id, Quote: quote}}

	ex.correlateNewEvidence(context.Background(), "w1", rows, nil)

	cand, err := d.Store.GetTask("exploit-10.0.0.5-22-openssh")
	if err != nil {
		t.Fatalf("candidate exploit task not persisted from web evidence: %v", err)
	}
	if len(cand.BasisIDs) != 1 || cand.BasisIDs[0] != "w1" {
		t.Errorf("candidate BasisIDs = %v, want [w1] (provenance to the web task)", cand.BasisIDs)
	}
}

// TestWebExecutorReachableAtExternalVantage: the web surface is reachable at an
// external vantage, so a web task is not refused on vantage grounds (it is an
// externally reachable surface).
func TestWebExecutorReachableAtExternalVantage(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	ext := engagement.VantageExternalUnauth
	if _, err := d.Store.Apply(engagement.Delta{SetVantage: &ext}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{
		{ID: "t1", Kind: "web", Surface: engagement.SurfaceWeb, Target: "http://10.0.0.5/", Objective: "probe", Status: engagement.StatusTodo, Phase: engagement.PhaseRecon},
	}}); err != nil {
		t.Fatal(err)
	}
	out, _ := runExecutor(context.Background(), d, "t1")
	if strings.Contains(strings.ToLower(out), "vantage") {
		t.Errorf("web surface at external-unauth: out=%q, should NOT refuse on vantage", out)
	}
}

func TestWebSurfaceLogicGapNoSilentDrop(t *testing.T) {
	quote := "GET /api/orders?order_id=1001 HTTP/1.1\n"
	seed := func(d engageDeps) string {
		if _, err := d.Store.Apply(engagement.Delta{Upserts: []engagement.Task{{
			ID: "w1", Kind: "web", Target: "http://10.0.0.5/", Status: engagement.StatusTodo,
			Phase: engagement.PhaseRecon, Surface: engagement.SurfaceWeb,
		}}}); err != nil {
			t.Fatal(err)
		}
		id, err := d.Store.RecordEvidence("w1", quote)
		if err != nil {
			t.Fatal(err)
		}
		return "bizlogic-idor-w1-" + strconv.FormatInt(id, 10)
	}

	t.Run("coverage removed -> coverage-gap blocked, not dropped", func(t *testing.T) {
		d := testDeps(t, nil)
		d.Gate = autoGate(t)
		gapID := seed(d)
		rows, _ := d.Store.EvidenceRowsFor("w1")
		genericExecutor{d: d}.correlateNewEvidence(context.Background(), "w1", rows, nil)
		cand, err := d.Store.GetTask(gapID)
		if err != nil {
			t.Fatalf("web logic-gap candidate DROPPED (no-silent-drop violated): %v", err)
		}
		if !cand.CoverageGap {
			t.Error("CoverageGap = false, want true (structured discriminator, no Objective string-parsing)")
		}
		if cand.Status != engagement.StatusBlocked {
			t.Errorf("Status = %q, want blocked (non-actionable; an uncited web match must not be a todo)", cand.Status)
		}
		if cand.Citation != (engagement.Citation{}) {
			t.Errorf("coverage-gap Citation = %+v, want empty", cand.Citation)
		}
		if !strings.Contains(cand.Objective, "corpus-coverage-gap") {
			t.Errorf("Objective missing the gap marker: %q", cand.Objective)
		}
	})

	t.Run("corpus covers -> grounded actionable todo", func(t *testing.T) {
		d := testDeps(t, nil)
		d.Gate = autoGate(t)
		d.RC = &recSearcher{results: []retrieval.Result{
			chunk("offensive-idor", "idor.md", "IDOR", "insecure direct object reference abuse"),
		}}
		gapID := seed(d)
		rows, _ := d.Store.EvidenceRowsFor("w1")
		genericExecutor{d: d}.correlateNewEvidence(context.Background(), "w1", rows, nil)
		cand, err := d.Store.GetTask(gapID)
		if err != nil {
			t.Fatalf("web logic-gap candidate missing: %v", err)
		}
		if cand.CoverageGap || cand.Status != engagement.StatusTodo {
			t.Errorf("grounded web candidate = {CoverageGap:%v Status:%q}, want {false todo}", cand.CoverageGap, cand.Status)
		}
		if cand.Citation.Source != "offensive-idor" {
			t.Errorf("Citation.Source = %q, want offensive-idor", cand.Citation.Source)
		}
	})

	t.Run("non-class-specific hit (idor-in-corridor) -> coverage-gap, no false grounding", func(t *testing.T) {
		d := testDeps(t, nil)
		d.Gate = autoGate(t)
		d.RC = &recSearcher{results: []retrieval.Result{
			chunk("offensive-web", "corridor.md", "Corridor", "server corridor mapping and physical access notes"),
		}}
		gapID := seed(d)
		rows, _ := d.Store.EvidenceRowsFor("w1")
		genericExecutor{d: d}.correlateNewEvidence(context.Background(), "w1", rows, nil)
		cand, err := d.Store.GetTask(gapID)
		if err != nil {
			t.Fatalf("web logic-gap candidate dropped: %v", err)
		}
		if !cand.CoverageGap || cand.Status != engagement.StatusBlocked {
			t.Errorf("a non-class-specific hit (idor only inside corridor) must NOT ground: {CoverageGap:%v Status:%q}, want a blocked coverage-gap", cand.CoverageGap, cand.Status)
		}
		if cand.Citation != (engagement.Citation{}) {
			t.Errorf("false-grounding rejected but Citation set: %+v", cand.Citation)
		}
	})
}

// TestWebCitationRejectsFalseGrounding is the INVERSE no-false-grounding
// test against the acceptCitation term gate, with a web-server product term:
// a corpus hit that does NOT name the subject-specific term must NOT ground (it
// would otherwise become an actionable candidate on a keyword-adjacent hit), while
// a hit that names it does ground. This is the gate that keeps a web service
// detection from false-grounding on an unrelated neighbor.
func TestWebCitationRejectsFalseGrounding(t *testing.T) {
	term := citationTerm("nginx")
	offTerm := []retrieval.Result{chunk("offensive-web", "apache.md", "Apache", "apache httpd mod_cgi exploitation")}
	if _, ok := acceptCitation(offTerm, term); ok {
		t.Error("acceptCitation grounded on an off-term hit (apache) for term nginx: false grounding not rejected")
	}
	onTerm := []retrieval.Result{chunk("offensive-web", "nginx.md", "nginx", "nginx alias traversal and known-CVE exploitation")}
	cit, ok := acceptCitation(onTerm, term)
	if !ok {
		t.Fatal("acceptCitation rejected a genuine term-specific nginx hit")
	}
	if cit.Source != "offensive-web" || cit.Origin != "trusted" {
		t.Errorf("accepted citation = %+v, want source offensive-web origin trusted", cit)
	}
}
