package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"github.com/tmc/langchaingo/llms"
)

func TestVulnFetchNameRejectsUntrustedURLForms(t *testing.T) {
	for _, tc := range []struct {
		url, want string
	}{
		{"https://example.test/package-lock.json", "package-lock.json"},
		{"http://example.test/image.tar", "image.tar"},
		{"https://example.test/unknown.txt", ""},
		{"https://user:pass@example.test/package-lock.json", ""},
		{"https://example.test/package-lock.json?token=secret", ""},
		{"https://example.test/image%0a.tar", ""},
		{"file:///tmp/package-lock.json", ""},
		{"https://example.test/%2e%2e/package-lock.json", ""},
	} {
		if got := vulnFetchName(tc.url); got != tc.want {
			t.Errorf("vulnFetchName(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

func TestVulnAnalysisDispatchFetchesAndStoresScannerResults(t *testing.T) {
	d := testDeps(t, &scriptModel{resps: []*llms.ContentResponse{finalResp("done")}})
	d.ReconTiers = true
	d.Gate = loopbackGate(t, pivotRoE(t))
	attachServiceDispatcher(d.Gate, d.Store)
	seedOpenService(t, d.Store, "10.0.0.5", "tcp", 80)
	d.Runs = NewRunOutputs()
	d.WorkDir = t.TempDir()
	if _, err := d.Store.Apply(eng.Delta{Upserts: []eng.Task{{
		ID: "v1", Kind: "vuln-analysis", Target: "http://10.0.0.5/package-lock.json",
		Objective: "scan the lockfile", Status: eng.StatusTodo,
		Phase: eng.PhaseRecon, Surface: eng.SurfaceContainer,
	}}}); err != nil {
		t.Fatal(err)
	}
	task, err := d.Store.GetTask("v1")
	if err != nil {
		t.Fatal(err)
	}
	var curlCalls int
	ctx := scanRuntime(t, d.Gate, func(binary string) (string, int) {
		switch binary {
		case "curl":
			curlCalls++
			return "200", 0
		case "osv-scanner":
			return string(readFixture(t, "osv-scanner.json")), 1
		case "grype":
			return string(readFixture(t, "grype-dir.json")), 0
		}
		t.Fatalf("unexpected command %s", binary)
		return "", -1
	})
	runtimeFor(ctx).store = d.Store
	out, err := executorFor(d, task).Run(ctx, task)
	if err != nil || !strings.Contains(out, "done") || curlCalls != 1 {
		t.Fatalf("dispatch output=%q curl calls=%d err=%v", out, curlCalls, err)
	}
	rows, err := d.Store.Vulns(ctx, eng.VulnFilter{})
	if err != nil || len(rows) == 0 {
		t.Fatalf("automatic scans stored %d advisories: %v", len(rows), err)
	}
	scanners := map[string]bool{}
	for _, row := range rows {
		if row.TaskID != task.ID || row.EvidenceID <= 0 {
			t.Fatalf("scanner result lacks task evidence: %+v", row)
		}
		scanners[row.Scanner] = true
	}
	if !scanners["osv-scanner"] || !scanners["grype"] {
		t.Fatalf("automatic scans missed a scanner: %+v", scanners)
	}
}

func TestVulnAnalysisAutoFetchRespectsScope(t *testing.T) {
	d := testDeps(t, &scriptModel{})
	d.Gate = loopbackGate(t, pivotRoE(t))
	task := eng.Task{ID: "v1", Kind: "vuln-analysis", Target: "http://10.0.1.5/package-lock.json",
		Phase: eng.PhaseRecon, Surface: eng.SurfaceContainer}
	ctx := scanRuntime(t, d.Gate, func(string) (string, int) {
		t.Fatal("out-of-scope fetch reached the runner")
		return "", -1
	})
	runtimeFor(ctx).store = d.Store
	msg, ok := autoFetchVulnMaterial(ctx, d, task, t.TempDir(), 65536, time.Second)
	if ok || !strings.Contains(msg, "out of scope") || !strings.Contains(scanAuditTrail(t, d.Store), "fetch-gap") {
		t.Fatalf("out-of-scope fetch was not preserved as a gap: ok=%t message=%q", ok, msg)
	}
}

func TestVulnAnalysisAutoFetchRejectsRedirectBody(t *testing.T) {
	d := testDeps(t, &scriptModel{})
	d.Gate = loopbackGate(t, pivotRoE(t))
	attachServiceDispatcher(d.Gate, d.Store)
	seedOpenService(t, d.Store, "10.0.0.5", "tcp", 80)
	task := eng.Task{ID: "v1", Kind: "vuln-analysis", Target: "http://10.0.0.5/package-lock.json",
		Phase: eng.PhaseRecon, Surface: eng.SurfaceContainer}
	ctx := scanRuntime(t, d.Gate, func(binary string) (string, int) {
		if binary != "curl" {
			t.Fatalf("redirect body reached scanner %s", binary)
		}
		return "302", 0
	})
	runtimeFor(ctx).store = d.Store
	msg, ok := autoFetchVulnMaterial(ctx, d, task, t.TempDir(), 65536, time.Second)
	if ok || !strings.Contains(msg, "HTTP 302") || !strings.Contains(scanAuditTrail(t, d.Store), "fetch-gap") {
		t.Fatalf("redirect was treated as a manifest: ok=%t message=%q", ok, msg)
	}
}

// The scan is triggered by the output path a staging command names, not by a task kind the model must choose.
func TestStagedMaterialReadsTheCommandsOutputPath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		binary string
		args   []string
		want   []string
	}{
		{"short flag", "curl", []string{"-s", "-o", "go.mod", "http://h/go.mod"}, []string{"go.mod"}},
		{"long flag", "curl", []string{"--output", "package-lock.json", "http://h/p"}, []string{"package-lock.json"}},
		{"equals form", "curl", []string{"--output=Cargo.lock", "http://h/c"}, []string{"Cargo.lock"}},
		{"sbom suffix", "curl", []string{"-o", "app.spdx.json", "http://h/s"}, []string{"app.spdx.json"}},
		{"image archive", "curl", []string{"-o", "image.tar", "http://h/i"}, []string{"image.tar"}},
		{"output directory", "curl", []string{"--output-dir", "sub", "-o", "image.tar", "http://h/i"}, []string{"sub/image.tar"}},
		{"short glued", "curl", []string{"-ogo.mod", "http://h/g"}, []string{"go.mod"}},
		{"nested path", "curl", []string{"-o", "sub/go.sum", "http://h/g"}, []string{"sub/go.sum"}},
		{"header dump is not a manifest", "curl", []string{"-D", "go.sum", "http://h/g"}, nil},
		{"body and headers", "curl", []string{"-o", "go.mod", "-D", "go.sum", "http://h/g"}, []string{"go.mod"}},
		{"not scannable", "curl", []string{"-o", "index.html", "http://h/"}, nil},
		{"no output flag", "curl", []string{"-s", "http://h/go.mod"}, nil},
		{"request host is not material", "curl", []string{"-s", "http://go.mod/x"}, nil},
		{"binary without output flags", "nmap", []string{"-oN", "go.mod", "h"}, nil},
		{"scanner report is not source material", "osv-scanner", []string{"scan", "source", "--output", "go.mod"}, nil},
	} {
		got, gap := stagedMaterial(tc.binary, tc.args)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") || gap != "" {
			t.Errorf("%s: %s %v staged %v with gap %q, want %v", tc.name, tc.binary, tc.args, got, gap, tc.want)
		}
	}
}

func TestStagedMaterialRespectsCurlOutputNaming(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
		gap  bool
	}{
		{"next resets directory", []string{"--output-dir", "a", "-o", "image.tar", "http://h/a", "--next", "--output-dir", "b", "-o", "go.mod", "http://h/b"}, []string{"a/image.tar", "b/go.mod"}, false},
		{"directory follows output", []string{"-o", "go.mod", "http://h/a", "--output-dir", "sub"}, []string{"sub/go.mod"}, false},
		{"remote name", []string{"-O", "http://h/go.mod"}, []string{"go.mod"}, false},
		{"mixed output modes", []string{"--remote-name-all", "-o", "go.mod", "http://h/go.mod"}, []string{"go.mod"}, true},
		{"glob filename", []string{"-o", "#1.tar", "http://h/{a,b}"}, nil, true},
		{"header filename", []string{"-OJ", "http://h/go.mod"}, nil, true},
		{"multiple remote names", []string{"-O", "http://h/go.mod", "-O", "http://h/go.sum"}, nil, true},
	} {
		got, gap := stagedMaterial("curl", tc.args)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") || (gap != "") != tc.gap {
			t.Errorf("%s: material %v, gap %q; want %v, gap %v", tc.name, got, gap, tc.want, tc.gap)
		}
	}
}

// A scanner's own argv stages nothing, so a scan cannot trigger another scan.
func TestScanCommandsStageNoMaterial(t *testing.T) {
	for _, argv := range vulnScanCommands() {
		if got, gap := stagedMaterial(argv[0], argv[1:]); got != nil || gap != "" {
			t.Errorf("%v stages %v with gap %q, which would re-trigger the scan", argv, got, gap)
		}
	}
}

func TestImageArchiveUsesArchiveScans(t *testing.T) {
	jobs := vulnScanJobs([]string{"image.tar"})
	if len(jobs) != 3 {
		t.Fatalf("archive produced %d scans, want OSV and both local Grype formats", len(jobs))
	}
	for _, job := range jobs {
		if job.input != "image.tar" || strings.Contains(strings.Join(job.argv, " "), "dir:.") ||
			strings.Contains(strings.Join(job.argv, " "), "source -r .") {
			t.Errorf("archive was scanned as a source directory: %+v", job)
		}
	}
	if !slices.Contains(jobs[0].argv, "--archive") || !slices.Contains(jobs[0].argv, "--offline") ||
		jobs[1].argv[1] != "docker-archive:image.tar" || jobs[2].argv[1] != "oci-archive:image.tar" {
		t.Errorf("archive scan forms = %+v", jobs)
	}
}

func TestArchiveScanUsesTheMatchingGrypeFormat(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dockerOK   bool
		wantRuns   int
		wantOCIRun bool
	}{
		{"docker archive", true, 2, false},
		{"oci archive", false, 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := scanFixtureStore(t)
			g := loopbackGate(t, pivotRoE(t))
			ctx := scanRuntime(t, g, func(string) (string, int) { return "", 0 })
			ociRun := false
			runtimeFor(ctx).runner.runFn = func(_ context.Context, stages []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
				argv := stages[0]
				if argv.Binary == "osv-scanner" {
					return runResult{Output: "archive database missing", Err: fmt.Errorf("exit status 128")},
						[]isolatedStageResult{{Stderr: "archive database missing", ExitCode: 128}}
				}
				if strings.HasPrefix(argv.Args[0], "oci-archive:") {
					ociRun = true
				}
				if tc.dockerOK || ociRun {
					out := `{"matches": [], "descriptor": {"name": "grype"}}`
					return runResult{Output: out}, []isolatedStageResult{{Stdout: out, ExitCode: 0}}
				}
				return runResult{Output: "wrong archive format", Err: fmt.Errorf("exit status 1")},
					[]isolatedStageResult{{Stderr: "wrong archive format", ExitCode: 1}}
			}
			dir := t.TempDir()
			q := newVulnScanQueue()
			q.note(dir, "v1", []pipelineStage{{Binary: "curl", Args: []string{"-o", "image.tar", "http://h/image"}}})
			if ran := runStagedVulnScans(ctx, vulnScanDeps{Gate: g, Store: store}, q, dir); ran != tc.wantRuns || ociRun != tc.wantOCIRun {
				t.Errorf("ran %d scans, OCI attempt %v; want %d and %v", ran, ociRun, tc.wantRuns, tc.wantOCIRun)
			}
			trail := scanAuditTrail(t, store)
			if !strings.Contains(trail, "grype over image.tar: 0 advisories") || strings.Contains(trail, "docker archive form also failed") {
				t.Errorf("matching archive scan was not recorded: %s", trail)
			}
		})
	}
}

// Material is recorded per working directory, deduplicated and bounded, and one directory is scanned once.
func TestVulnScanQueueTracksMaterialPerDirectory(t *testing.T) {
	q := newVulnScanQueue()
	if _, ok := q.take("/a", false); ok {
		t.Error("an unstaged directory was due")
	}
	q.note("/a", "task-a", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/g"}}})
	q.note("/a", "task-a", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/g"}}})
	q.note("/b", "task-b", []pipelineStage{{Binary: "curl", Args: []string{"-o", "Cargo.lock", "http://h/c"}}})
	q.note("/c", "task-c", []pipelineStage{{Binary: "curl", Args: []string{"-o", "index.html", "http://h/"}}})
	staged, ok := q.take("/a", false)
	if !ok || staged.taskID != "task-a" || strings.Join(staged.material, ",") != "go.mod" {
		t.Errorf("/a staged %+v (ok=%v), want task-a and one go.mod", staged, ok)
	}
	if _, ok := q.take("/a", false); ok {
		t.Error("/a was due a second time")
	}
	if staged, ok := q.take("/b", false); !ok || staged.taskID != "task-b" || strings.Join(staged.material, ",") != "Cargo.lock" {
		t.Errorf("/b staged %+v (ok=%v), want task-b and Cargo.lock", staged, ok)
	}
	if _, ok := q.take("/c", false); ok {
		t.Error("a non-scannable output path made /c due")
	}
	if _, ok := q.take("", false); ok {
		t.Error("the empty directory was due")
	}
	var nilQueue *vulnScanQueue
	nilQueue.note("/a", "task-a", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/g"}}})
	if _, ok := nilQueue.take("/a", false); ok {
		t.Error("a nil queue reported material")
	}
	for i := 0; i < maxStagedMaterial+20; i++ {
		q.note("/d", "task-d", []pipelineStage{{Binary: "curl", Args: []string{"-o", "sub" + strings.Repeat("x", i) + "/go.mod", "http://h/g"}}})
	}
	bounded, _ := q.take("/d", false)
	if len(bounded.material) > maxStagedMaterial || !bounded.overflow {
		t.Errorf("material bound was not recorded: %+v", bounded)
	}
	q.note("/raw", "task-raw", []pipelineStage{
		{Binary: "nmap", Args: []string{"-sS", "host"}},
		{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/g"}},
	})
	if _, ok := q.take("/raw", false); ok {
		t.Error("material from the raw worker was assigned to the general worker")
	}
	if staged, ok := q.take("/raw", true); !ok || staged.taskID != "task-raw" || strings.Join(staged.material, ",") != "go.mod" {
		t.Errorf("raw worker staged %+v (ok=%v), want task-raw and go.mod", staged, ok)
	}
}

// The argv is fixed in code, so no model text reaches the scanner, and every command the gate must permit is one of the audited forms.
func TestVulnScanCommandsAreTheAuditedForms(t *testing.T) {
	cmds := vulnScanCommands()
	if len(cmds) != 2 {
		t.Fatalf("got %d scan commands, want one per scanner", len(cmds))
	}
	g := loopbackGate(t, pivotRoE(t))
	binaries := map[string]bool{}
	for _, argv := range cmds {
		binaries[argv[0]] = true
		d := g.Check(context.Background(), secgate.Command{
			Binary: argv[0], Args: argv[1:],
			Phase: secgate.PhaseRecon, Surface: secgate.SurfaceContainer,
		})
		if !d.Allowed {
			t.Errorf("%v is denied by the gate: %s", argv, d.Reason)
		}
		if !strings.Contains(strings.Join(argv, " "), "json") {
			t.Errorf("%v does not ask for JSON, which the parser reads", argv)
		}
	}
	for _, want := range scratchReachBinaries() {
		if !binaries[want] {
			t.Errorf("the code-owned scan does not run %s", want)
		}
	}
	for _, job := range vulnScanJobs([]string{"image.tar"}) {
		if d := g.Check(context.Background(), secgate.Command{
			Binary: job.argv[0], Args: job.argv[1:],
			Phase: secgate.PhaseRecon, Surface: secgate.SurfaceContainer,
		}); !d.Allowed {
			t.Errorf("archive scan %v is denied by the gate: %s", job.argv, d.Reason)
		}
	}
}

// The scan is inert without its dependencies, so an engagement with no gate runs unchanged.
func TestRunStagedVulnScansIsInertWithoutDependencies(t *testing.T) {
	q := newVulnScanQueue()
	q.note("/a", "v1", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/g"}}})
	if n := runStagedVulnScans(context.Background(), vulnScanDeps{}, q, "/a"); n != 0 {
		t.Errorf("the scan ran %d commands with no dependencies", n)
	}
	if n := runStagedVulnScans(context.Background(), vulnScanDeps{}, nil, "/a"); n != 0 {
		t.Errorf("the scan ran %d commands with no queue", n)
	}
	q.note("/host", "v1", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/g"}}})
	hostCalls := 0
	withStubExec(t, func(context.Context, string, []string, string, int, time.Duration) runResult {
		hostCalls++
		return runResult{}
	})
	if n := runStagedVulnScans(context.Background(), vulnScanDeps{Gate: &secgate.Gate{}, Store: scanFixtureStore(t)}, q, "/host"); n != 0 || hostCalls != 0 {
		t.Errorf("scanner fell back to host execution: scans=%d host calls=%d", n, hostCalls)
	}
}

// A directory no command staged material in is not scanned, so an engagement that fetched nothing spends no actions.
func TestRunStagedVulnScansSkipsADirectoryWithNoMaterial(t *testing.T) {
	ws, err := eng.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	deps := vulnScanDeps{Gate: loopbackGate(t, pivotRoE(t)), Store: ws.Store}
	if n := runStagedVulnScans(context.Background(), deps, newVulnScanQueue(), t.TempDir()); n != 0 {
		t.Errorf("the scan ran %d commands over an unstaged directory", n)
	}
}

func TestCanceledStagedScanRecordsAGap(t *testing.T) {
	store := scanFixtureStore(t)
	dir := t.TempDir()
	q := newVulnScanQueue()
	q.note(dir, "v1", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/go.mod"}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ran := runStagedVulnScans(ctx, vulnScanDeps{Gate: loopbackGate(t, pivotRoE(t)), Store: store}, q, dir); ran != 0 {
		t.Errorf("canceled scan ran %d commands", ran)
	}
	if trail := scanAuditTrail(t, store); !strings.Contains(trail, "scan-gap") {
		t.Errorf("canceled scan lost its staged material without a gap: %s", trail)
	}
}

func TestUnknownCurlOutputNameRecordsAScanGap(t *testing.T) {
	store := scanFixtureStore(t)
	dir := t.TempDir()
	q := newVulnScanQueue()
	q.note(dir, "v1", []pipelineStage{{Binary: "curl", Args: []string{"-o", "#1.tar", "http://h/{a,b}"}}})
	if ran := runStagedVulnScans(context.Background(), vulnScanDeps{
		Gate: loopbackGate(t, pivotRoE(t)), Store: store,
	}, q, dir); ran != 0 {
		t.Errorf("indeterminate curl output ran %d scans", ran)
	}
	if trail := scanAuditTrail(t, store); !strings.Contains(trail, "scan-gap") || !strings.Contains(trail, "URL glob variable") {
		t.Errorf("indeterminate curl filename was not recorded as a gap: %s", trail)
	}
}

// Without the isolated runner on the context the scan records the failure and stores nothing, rather than executing on the operator host.
func TestRunStagedVulnScansWithoutARunnerAuditsAndStoresNothing(t *testing.T) {
	ws, err := eng.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if _, err := ws.Store.Apply(eng.Delta{Kind: "fixture", Upserts: []eng.Task{
		{ID: "v1", Kind: "vuln-analysis", Target: "image.tar", Objective: "scan", DoneWhen: "done",
			Status: eng.StatusActive},
	}}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	q := newVulnScanQueue()
	q.note(dir, "v1", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/go.mod"}}})
	deps := vulnScanDeps{Gate: loopbackGate(t, pivotRoE(t)), Store: ws.Store}
	ran := runStagedVulnScans(context.Background(), deps, q, dir)
	if ran == 0 {
		t.Fatal("the scan attempted nothing")
	}
	rows, err := ws.Store.Vulns(context.Background(), eng.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("advisories were stored with no runner: %+v", rows)
	}
	page, err := ws.Store.Records(context.Background(), "audit", "", 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	var trail string
	for _, r := range page.Records {
		trail += string(r.Document)
	}
	if !strings.Contains(trail, "vulnscan") {
		t.Errorf("the scan attempt was not audited:\n%s", trail)
	}
}

// Real scanner output reaching the ingest is persisted and queryable, which is the step the code-owned scan performs after each run.
func TestIngestVulnOutputStoresRealScannerOutput(t *testing.T) {
	ws, err := eng.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if _, err := ws.Store.Apply(eng.Delta{Kind: "fixture", Upserts: []eng.Task{
		{ID: "v1", Kind: "vuln-analysis", Target: "/work", Objective: "scan", DoneWhen: "done",
			Status: eng.StatusActive},
	}}); err != nil {
		t.Fatal(err)
	}
	task, err := ws.Store.GetTask("v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ scanner, fixture string }{
		{"osv-scanner", "osv-scanner.json"},
		{"grype", "grype-dir.json"},
	} {
		stored, err := ingestVulnOutput(context.Background(), ws.Store, task, tc.scanner,
			string(readFixture(t, tc.fixture))+"\nScanned 72 packages\n")
		if err != nil {
			t.Fatalf("%s: %v", tc.scanner, err)
		}
		if stored == 0 {
			t.Errorf("%s: stored no advisories from real output", tc.scanner)
		}
	}
	rows, err := ws.Store.Vulns(context.Background(), eng.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("nothing queryable after the ingest")
	}
	// The asset is the report's own when it names one and the task target when it does not: grype reports its source, osv-scanner does not.
	for _, r := range rows {
		if r.TaskID != "v1" || r.EvidenceID <= 0 {
			t.Errorf("%s is not bound to the task and its output: %+v", r.Advisory, r)
		}
		switch r.Scanner {
		case "osv-scanner":
			if r.Asset != "/work" {
				t.Errorf("%s names asset %q, want the task target", r.Advisory, r.Asset)
			}
		case "grype":
			if r.Asset == "/work" {
				t.Errorf("%s took the task target over the report's own source", r.Advisory)
			}
		default:
			t.Errorf("%s came from unexpected scanner %q", r.Advisory, r.Scanner)
		}
	}
}

// A scanner that could not consult its database prints the same empty report as a clean scan, so the exit status decides whether a result exists.
func TestVulnScanResultBearingFollowsEachScannersExitCodes(t *testing.T) {
	for _, tc := range []struct {
		scanner string
		exit    int
		want    bool
	}{
		{"osv-scanner", 0, true},
		{"osv-scanner", 1, true},
		{"osv-scanner", 126, true},
		{"osv-scanner", 127, false},
		{"osv-scanner", 128, false},
		{"osv-scanner", -1, false},
		{"grype", 0, true},
		{"grype", 1, false},
		{"grype", 2, false},
		{"grype", -1, false},
	} {
		if got := vulnScanResultBearing(tc.scanner, tc.exit); got != tc.want {
			t.Errorf("%s exit %d: result-bearing %v, want %v", tc.scanner, tc.exit, got, tc.want)
		}
	}
}

// Only output carrying a report a parser recognizes counts as a result.
func TestScanProducedReportRecognizesEachScannersReport(t *testing.T) {
	for _, tc := range []struct {
		name, scanner string
		output        string
		want          bool
	}{
		{"empty", "osv-scanner", "", false},
		{"progress only", "osv-scanner", "Scanning dir .\nScanned go.mod\n", false},
		{"unrelated json", "osv-scanner", `{"hello":"world"}`, false},
		{"osv empty report", "osv-scanner", `{"results": []}`, true},
		{"osv report after progress", "osv-scanner", "Scanning dir .\n" + `{"results": []}`, true},
		{"grype report", "grype", `{"matches": [], "descriptor": {"name": "grype"}}`, true},
		{"wrong scanner", "grype", `{"results": []}`, false},
		{"truncated json", "osv-scanner", `{"results": [`, false},
	} {
		if got := scanProducedReport(tc.scanner, tc.output); got != tc.want {
			t.Errorf("%s: scanProducedReport = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A scan whose scanner never reached its database records a gap and stores no advisories, so an unscanned dependency set never reads as a clean one.
func TestRunStagedVulnScansRecordsAGapWhenTheScannerProducedNoResult(t *testing.T) {
	ws, err := eng.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if _, err := ws.Store.Apply(eng.Delta{Kind: "fixture", Upserts: []eng.Task{
		{ID: "v1", Kind: "vuln-analysis", Target: "go.mod", Objective: "scan", DoneWhen: "done",
			Status: eng.StatusActive},
	}}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	q := newVulnScanQueue()
	q.note(dir, "v1", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/go.mod"}}})
	deps := vulnScanDeps{Gate: loopbackGate(t, pivotRoE(t)), Store: ws.Store}
	if ran := runStagedVulnScans(context.Background(), deps, q, dir); ran == 0 {
		t.Fatal("the scan attempted nothing")
	}
	page, err := ws.Store.Records(context.Background(), "audit", "", 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	var trail string
	for _, r := range page.Records {
		trail += string(r.Document)
	}
	if !strings.Contains(trail, "scan-gap") {
		t.Errorf("a scan with no usable result was not recorded as a gap:\n%s", trail)
	}
	if strings.Contains(trail, "0 advisories") {
		t.Errorf("a scan with no usable result was recorded as a clean scan:\n%s", trail)
	}
}

// OSV scans only the database setup provisioned; a missing database is a scan gap.
func TestVulnScanCommandsUseTheOfflineDatabase(t *testing.T) {
	var osv []string
	for _, argv := range vulnScanCommands() {
		if argv[0] == "osv-scanner" {
			osv = argv
		}
	}
	if osv == nil {
		t.Fatal("the scan does not run osv-scanner")
	}
	if !slices.Contains(osv, "--offline") || slices.Contains(osv, "--download-offline-databases") {
		t.Errorf("osv-scanner is not restricted to the prewarmed database: %v", osv)
	}
}

// A command's environment is built from scratch, so grype cannot update the shared cache from a worker.
func TestRunnerCommandEnvironmentDisablesGrypeUpdates(t *testing.T) {
	script, err := engageRunnerFiles.ReadFile("runner/execute.py")
	if err != nil {
		t.Fatal(err)
	}
	body := string(script)
	base := strings.Index(body, "command_env.update(")
	if base < 0 {
		t.Fatal("the runner script does not build a fixed command environment")
	}
	fixed := body[base:]
	if !strings.Contains(fixed, `"GRYPE_CHECK_FOR_APP_UPDATE": "false"`) {
		t.Error("the fixed command environment does not suppress grype's release-version check")
	}
	if !strings.Contains(fixed, `"GRYPE_DB_AUTO_UPDATE": "false"`) {
		t.Error("grype can update its database from a worker")
	}
	if strings.Contains(strings.Join(engageWorkerArgs("w", "g", "img", "", "", nil), " "), "GRYPE") {
		t.Error("the worker sets a GRYPE variable, which execute.py drops from every command")
	}
}

// scanRuntime puts a stubbed isolated runner on the context so a scan's exact output and exit status drive the decision.
func scanRuntime(t *testing.T, g *secgate.Gate, out func(scanner string) (string, int)) context.Context {
	t.Helper()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "actions.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	trace := newActionTranscript(workspace, "off", "worker", 100, 1<<20, nil)
	runner := &engageRunner{workers: map[string]string{},
		runFn: func(_ context.Context, stages []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
			stdout, exit := out(stages[0].Binary)
			result := runResult{Output: stdout}
			if exit != 0 {
				result.Err = fmt.Errorf("exit status %d", exit)
			}
			return result, []isolatedStageResult{{Stdout: stdout, ExitCode: exit}}
		}}
	return context.WithValue(context.Background(), engageRuntimeKey{},
		&engageRuntime{runner: runner, trace: trace, policy: g.Policy, cancel: func() {}, staged: newVulnScanQueue()})
}

func TestAuthorizedScannerOutputIngestsDespiteModelEvidence(t *testing.T) {
	store := scanFixtureStore(t)
	if _, err := store.RecordEvidence("v1", "model note"); err != nil {
		t.Fatal(err)
	}
	g := loopbackGate(t, pivotRoE(t))
	ctx := scanRuntime(t, g, func(scanner string) (string, int) {
		if scanner != "osv-scanner" {
			t.Fatalf("unexpected scanner %s", scanner)
		}
		return string(readFixture(t, "osv-scanner.json")), 1
	})
	runtimeFor(ctx).store = store
	argv := vulnScanCommands()[0]
	result := runAuthorized(ctx, g, argv[0], argv[1:], t.TempDir(), 1<<20, time.Second,
		actionOrigin{TaskID: "v1", Surface: secgate.SurfaceContainer})
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	rows, err := store.Vulns(context.Background(), eng.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("authorized scanner output was not ingested")
	}
}

// scanAuditTrail returns the engagement's audit text.
func scanAuditTrail(t *testing.T, store *eng.Store) string {
	t.Helper()
	page, err := store.Records(context.Background(), "audit", "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var trail string
	for _, r := range page.Records {
		trail += string(r.Document)
	}
	return trail
}

// scanFixtureStore opens a workspace holding one active task a scan can cite.
func scanFixtureStore(t *testing.T) *eng.Store {
	t.Helper()
	ws, err := eng.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })
	if _, err := ws.Store.Apply(eng.Delta{Kind: "fixture", Upserts: []eng.Task{
		{ID: "v1", Kind: "vuln-analysis", Target: "go.mod", Objective: "scan", DoneWhen: "done",
			Status: eng.StatusActive},
	}}); err != nil {
		t.Fatal(err)
	}
	return ws.Store
}

// A scanner with no database prints the same well-formed empty report as a clean scan and reports the failure only on stderr, so an empty report with a failing exit status is a gap and never a clean result.
func TestEmptyReportWithAFailingExitStatusIsAGapNotACleanScan(t *testing.T) {
	for _, tc := range []struct {
		name    string
		exit    int
		wantGap bool
	}{
		{"database unavailable", 127, true},
		{"no packages found", 128, true},
		{"clean scan", 0, false},
	} {
		store := scanFixtureStore(t)
		g := loopbackGate(t, pivotRoE(t))
		ctx := scanRuntime(t, g, func(scanner string) (string, int) {
			if scanner == "osv-scanner" {
				return `{"results": []}`, tc.exit
			}
			return `{"matches": [], "descriptor": {"name": "grype"}}`, 0
		})
		dir := t.TempDir()
		q := newVulnScanQueue()
		q.note(dir, "v1", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/go.mod"}}})
		if ran := runStagedVulnScans(ctx, vulnScanDeps{Gate: g, Store: store}, q, dir); ran != 2 {
			t.Fatalf("%s: the scan ran %d commands, want one per scanner", tc.name, ran)
		}
		trail := scanAuditTrail(t, store)
		gapped := strings.Contains(trail, "scan-gap") && strings.Contains(trail, "osv-scanner")
		if gapped != tc.wantGap {
			t.Errorf("%s: osv-scanner exit %d recorded a gap = %v, want %v:\n%s",
				tc.name, tc.exit, gapped, tc.wantGap, trail)
		}
		if tc.wantGap && strings.Contains(trail, "osv-scanner over go.mod: 0 advisories") {
			t.Errorf("%s: a scan that reached no database was recorded as a clean scan:\n%s", tc.name, trail)
		}
		if !tc.wantGap && !strings.Contains(trail, "osv-scanner over go.mod: 0 advisories") {
			t.Errorf("%s: a clean scan was not recorded as one:\n%s", tc.name, trail)
		}
		// The second scanner is unaffected by the first one's outcome.
		if !strings.Contains(trail, "grype over go.mod: 0 advisories") {
			t.Errorf("%s: grype's own clean result was not recorded:\n%s", tc.name, trail)
		}
	}
}

func TestStagedScanDoesNotParseReportShapedStderr(t *testing.T) {
	store := scanFixtureStore(t)
	g := loopbackGate(t, pivotRoE(t))
	ctx := scanRuntime(t, g, func(string) (string, int) { return "", 0 })
	runtimeFor(ctx).runner.runFn = func(_ context.Context, stages []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
		if stages[0].Binary == "osv-scanner" {
			fake := string(readFixture(t, "osv-scanner.json"))
			return runResult{Output: fake}, []isolatedStageResult{{Stderr: fake, ExitCode: 0}}
		}
		out := `{"matches": [], "descriptor": {"name": "grype"}}`
		return runResult{Output: out}, []isolatedStageResult{{Stdout: out, ExitCode: 0}}
	}
	dir := t.TempDir()
	q := newVulnScanQueue()
	q.note(dir, "v1", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/go.mod"}}})
	runStagedVulnScans(ctx, vulnScanDeps{Gate: g, Store: store}, q, dir)
	rows, err := store.Vulns(context.Background(), eng.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 || !strings.Contains(scanAuditTrail(t, store), "scan-gap") {
		t.Errorf("report-shaped stderr created advisories or lacked a gap: %+v", rows)
	}
}

func TestStagedScanDoesNotIngestAfterActionFailure(t *testing.T) {
	store := scanFixtureStore(t)
	g := loopbackGate(t, pivotRoE(t))
	ctx := scanRuntime(t, g, func(string) (string, int) { return "", 0 })
	runtimeFor(ctx).runner.runFn = func(_ context.Context, stages []pipelineStage, _ string, _ int, _ time.Duration) (runResult, []isolatedStageResult) {
		if stages[0].Binary == "osv-scanner" {
			out := string(readFixture(t, "osv-scanner.json"))
			return runResult{Output: out, Err: fmt.Errorf("policy byte budget exhausted")},
				[]isolatedStageResult{{Stdout: out, ExitCode: 0}}
		}
		out := `{"matches": [], "descriptor": {"name": "grype"}}`
		return runResult{Output: out}, []isolatedStageResult{{Stdout: out, ExitCode: 0}}
	}
	dir := t.TempDir()
	q := newVulnScanQueue()
	q.note(dir, "v1", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/go.mod"}}})
	runStagedVulnScans(ctx, vulnScanDeps{Gate: g, Store: store}, q, dir)
	rows, err := store.Vulns(context.Background(), eng.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 || !strings.Contains(scanAuditTrail(t, store), "scan-gap") {
		t.Errorf("failed action created advisories or lacked a gap: %+v", rows)
	}
}

// Real scanner output reaching the scan through the runner is persisted and queryable.
func TestRunStagedVulnScansStoresAdvisoriesFromRealScannerOutput(t *testing.T) {
	store := scanFixtureStore(t)
	g := loopbackGate(t, pivotRoE(t))
	ctx := scanRuntime(t, g, func(scanner string) (string, int) {
		if scanner == "osv-scanner" {
			return string(readFixture(t, "osv-scanner.json")), 1
		}
		return string(readFixture(t, "grype-dir.json")), 0
	})
	dir := t.TempDir()
	q := newVulnScanQueue()
	q.note(dir, "v1", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/go.mod"}}})
	if ran := runStagedVulnScans(ctx, vulnScanDeps{Gate: g, Store: store}, q, dir); ran != 2 {
		t.Fatalf("the scan ran %d commands, want one per scanner", ran)
	}
	rows, err := store.Vulns(context.Background(), eng.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no advisories are queryable after a scan of real output")
	}
	scanners := map[string]bool{}
	for _, r := range rows {
		scanners[r.Scanner] = true
		if r.TaskID != "v1" || r.EvidenceID <= 0 {
			t.Errorf("%s is not bound to the task and the output it came from: %+v", r.Advisory, r)
		}
	}
	for _, want := range []string{"osv-scanner", "grype"} {
		if !scanners[want] {
			t.Errorf("no advisory came from %s", want)
		}
	}
	if trail := scanAuditTrail(t, store); strings.Contains(trail, "scan-gap") {
		t.Errorf("a scan that produced advisories recorded a gap:\n%s", trail)
	}
}

func TestRunStagedVulnScansUsesTheStagingTask(t *testing.T) {
	store := scanFixtureStore(t)
	active := "v1"
	if _, err := store.Apply(eng.Delta{Kind: "fixture", SetActiveID: &active, Upserts: []eng.Task{
		{ID: "v2", Kind: "vuln-analysis", Target: "other/go.mod", Objective: "scan", DoneWhen: "done",
			Status: eng.StatusActive, Surface: eng.SurfaceContainer},
	}}); err != nil {
		t.Fatal(err)
	}
	g := loopbackGate(t, pivotRoE(t))
	ctx := scanRuntime(t, g, func(scanner string) (string, int) {
		if scanner == "osv-scanner" {
			return string(readFixture(t, "osv-scanner.json")), 1
		}
		return `{"matches": [], "descriptor": {"name": "grype"}}`, 0
	})
	dir := t.TempDir()
	q := newVulnScanQueue()
	q.note(dir, "v2", []pipelineStage{{Binary: "curl", Args: []string{"-o", "go.mod", "http://h/go.mod"}}})
	if ran := runStagedVulnScans(ctx, vulnScanDeps{Gate: g, Store: store}, q, dir); ran != 2 {
		t.Fatalf("ran %d scans, want 2", ran)
	}
	rows, err := store.Vulns(context.Background(), eng.VulnFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("scanner results were not stored")
	}
	for _, row := range rows {
		if row.TaskID != "v2" {
			t.Errorf("%s attached to %s, want v2", row.Advisory, row.TaskID)
		}
	}
}
