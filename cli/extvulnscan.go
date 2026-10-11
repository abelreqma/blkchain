package main

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
)

// extvulnscan.go runs the scanners in code with a fixed argv over material a command staged in the worker, so the advisory records depend on neither a dispatch nor what the model writes.

// maxStagedMaterial bounds the material recorded for one working directory.
const maxStagedMaterial = 64

func vulnFetchName(raw string) string {
	u, err := url.ParseRequestURI(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return ""
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return ""
		}
	}
	name := path.Base(u.Path)
	if len(name) > 128 || !scannableName(name) {
		return ""
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') ||
			('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' {
			continue
		}
		return ""
	}
	return name
}

func autoFetchVulnMaterial(ctx context.Context, d engageDeps, task eng.Task, dir string, limit int, timeout time.Duration) (string, bool) {
	name := vulnFetchName(task.Target)
	if task.Kind != "vuln-analysis" || name == "" || d.Gate == nil || d.Gate.Policy == nil || d.Store == nil {
		return "", false
	}
	args := []string{"--disable", "--fail", "--silent", "--show-error", "--max-time", "10",
		"--max-filesize", "16M", "--output", name, "--write-out", "%{http_code}", task.Target}
	cmd := secgate.Command{TaskID: task.ID, Binary: "curl", Args: args,
		Phase: secgate.Phase(task.Phase), Surface: secgate.Surface(task.Surface),
		Armed: task.Armed, Kind: task.Kind, Target: task.Target}
	run, denial := authorizeCommand(ctx, d.Gate, cmd)
	if denial != "" {
		_ = d.Store.Audit("vulnscan", "fetch-gap", task.ID+": "+denial)
		return denial, false
	}
	if d.Gate.Audit != nil {
		d.Gate.Audit("exec", secgate.Signature(run))
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	result := runAuthorized(ctx, d.Gate, run.Binary, run.Args, dir, limit, timeout,
		actionOrigin{TaskID: task.ID, Surface: run.Surface, RequireHTTP200: true})
	if result.Err != nil || result.TimedOut || result.ExitCode != 0 || strings.TrimSpace(result.Stdout) != "200" {
		detail := strings.TrimSpace(result.Output)
		if result.Err == nil && !result.TimedOut && result.ExitCode == 0 {
			detail = "HTTP " + strings.TrimSpace(result.Stdout)
		}
		if result.Err != nil {
			detail += " " + result.Err.Error()
		}
		if result.TimedOut {
			detail += " timed out"
		}
		gap := fmt.Sprintf("vuln-analysis: could not fetch %s: %s", name, capRunes(strings.TrimSpace(detail), 300))
		_ = d.Store.Audit("vulnscan", "fetch-gap", task.ID+": "+gap)
		return gap, false
	}
	if runtime := runtimeFor(ctx); runtime != nil && runtime.staged != nil {
		runStagedVulnScans(ctx, vulnScanDeps{Gate: d.Gate, Store: d.Store}, runtime.staged, dir)
	}
	return "Fetched " + name + "; inspect the offline scanner records and gaps before reporting findings.", true
}

// vulnScanCommands are the scans run over one directory; each prints JSON to stdout and needs no scope target.
func vulnScanCommands() [][]string {
	return [][]string{
		{"osv-scanner", "scan", "source", "--offline", "--format", "json", "-r", "."},
		{"grype", "dir:.", "-o", "json"},
	}
}

type vulnScanJob struct {
	argv  []string
	input string
}

func vulnScanJobs(material []string) []vulnScanJob {
	var source, archives []string
	for _, name := range material {
		if strings.HasSuffix(strings.ToLower(name), ".tar") {
			archives = append(archives, name)
		} else {
			source = append(source, name)
		}
	}
	var jobs []vulnScanJob
	if len(source) > 0 {
		for _, argv := range vulnScanCommands() {
			jobs = append(jobs, vulnScanJob{argv: argv, input: strings.Join(source, ", ")})
		}
	}
	for _, name := range archives {
		jobs = append(jobs,
			vulnScanJob{argv: []string{"osv-scanner", "scan", "image", "--offline", "--archive", name, "--format", "json"}, input: name},
			vulnScanJob{argv: []string{"grype", "docker-archive:" + name, "-o", "json"}, input: name},
			vulnScanJob{argv: []string{"grype", "oci-archive:" + name, "-o", "json"}, input: name},
		)
	}
	return jobs
}

// vulnScanResultBearing reports whether a scanner's exit status means it produced a result rather than failing to produce one.
func vulnScanResultBearing(scanner string, exit int) bool {
	if exit < 0 {
		return false
	}
	// osv-scanner reserves 0 for a clean scan and 1-126 for vulnerability results; 127 is a general error and 128 means no packages were found.
	if scanner == "osv-scanner" {
		return exit <= 126
	}
	// grype returns 2 only under --fail-on, which the scan does not pass, so any nonzero status is an error.
	return exit == 0
}

// scanProducedReport reports whether output carries a report from the scanner that ran.
func scanProducedReport(scanner, output string) bool {
	raw, ok := reportObject(output)
	if !ok {
		return false
	}
	reported, ok := scannerFromReport(raw)
	return ok && reported == scanner
}

// scannableNames are the dependency and image files a scan has something to read.
func scannableNames() []string {
	return []string{
		"go.mod", "go.sum", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"requirements.txt", "poetry.lock", "Pipfile.lock", "Gemfile.lock",
		"Cargo.lock", "composer.lock", "pom.xml", "build.gradle", "gradle.lockfile",
		"sbom.json", "bom.json",
	}
}

// scannableName reports whether p names a lockfile, manifest, SBOM or image archive a scanner can read.
func scannableName(p string) bool {
	name := strings.ToLower(path.Base(filepath.ToSlash(strings.TrimSpace(p))))
	if name == "" || name == "." || name == "/" {
		return false
	}
	for _, known := range scannableNames() {
		if name == strings.ToLower(known) {
			return true
		}
	}
	return strings.HasSuffix(name, ".spdx.json") ||
		strings.HasSuffix(name, ".cdx.json") || strings.HasSuffix(name, ".tar")
}

// stagedMaterial returns known response-body paths and a gap for filenames curl decides at runtime.
func stagedMaterial(binary string, args []string) ([]string, string) {
	if !strings.EqualFold(path.Base(filepath.ToSlash(binary)), "curl") {
		return nil, ""
	}
	var out, gaps []string
	start := 0
	for i := 0; i <= len(args); i++ {
		if i < len(args) && args[i] != "--next" {
			continue
		}
		paths, gap := curlOperationMaterial(args[start:i])
		out = append(out, paths...)
		if gap != "" {
			gaps = append(gaps, gap)
		}
		start = i + 1
	}
	return out, strings.Join(gaps, "; ")
}

func curlOperationMaterial(args []string) ([]string, string) {
	var outputDir string
	var names, urls []string
	remoteName, headerName, globOff := false, false, false
	for i, a := range args {
		if a == "--output-dir" && i+1 < len(args) {
			outputDir = args[i+1]
		} else if dir, ok := strings.CutPrefix(a, "--output-dir="); ok {
			outputDir = dir
		}
		if a == "-J" || a == "--remote-header-name" || a == "-OJ" || a == "-JO" {
			headerName = true
		}
		if a == "--globoff" || a == "-g" {
			globOff = true
		}
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--output-dir" || a == "--url":
			if i+1 < len(args) {
				if a == "--url" {
					urls = append(urls, args[i+1])
				}
				i++
			}
		case a == "-o" || a == "--output":
			if i+1 < len(args) {
				i++
				names = append(names, args[i])
			}
		case strings.HasPrefix(a, "--output="):
			names = append(names, strings.TrimPrefix(a, "--output="))
		case strings.HasPrefix(a, "-o") && !strings.HasPrefix(a, "--"):
			names = append(names, strings.TrimPrefix(a, "-o"))
		case a == "-O" || a == "--remote-name" || a == "--remote-name-all" || a == "-OJ" || a == "-JO":
			remoteName = true
		case strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://"):
			urls = append(urls, a)
		}
	}
	var out, gaps []string
	for _, name := range names {
		if strings.Contains(name, "#") {
			gaps = append(gaps, "curl output filename uses a URL glob variable")
			continue
		}
		if outputDir != "" {
			name = filepath.Join(outputDir, name)
		}
		if scannableName(name) {
			out = append(out, name)
		}
	}
	if remoteName {
		switch {
		case len(names) > 0:
			gaps = append(gaps, "curl combines explicit and remote output modes")
		case headerName:
			gaps = append(gaps, "curl response headers choose the output filename")
		case len(urls) != 1 || !globOff && strings.ContainsAny(urls[0], "{}[]"):
			gaps = append(gaps, "curl remote filename cannot be determined from one URL")
		default:
			u, err := url.Parse(urls[0])
			if err != nil || u.Hostname() == "" {
				gaps = append(gaps, "curl remote filename has no valid URL")
			} else {
				name := path.Base(u.EscapedPath())
				if outputDir != "" {
					name = filepath.Join(outputDir, name)
				}
				if scannableName(name) {
					out = append(out, name)
				}
			}
		}
	}
	return out, strings.Join(gaps, "; ")
}

// vulnScanQueue records the material commands staged in each worker working directory, which exists only until that worker is released.
type vulnScanQueue struct {
	mu     sync.Mutex
	staged map[scanQueueKey]stagedScan
}

type scanQueueKey struct {
	dir string
	raw bool
}

type stagedScan struct {
	taskID   string
	material []string
	conflict bool
	overflow bool
	gap      string
}

func newVulnScanQueue() *vulnScanQueue { return &vulnScanQueue{staged: map[scanQueueKey]stagedScan{}} }

// note records the scannable material these stages wrote in dir.
func (q *vulnScanQueue) note(dir, taskID string, stages []pipelineStage) {
	if q == nil || dir == "" || taskID == "" {
		return
	}
	var found []string
	var gaps []string
	for _, s := range stages {
		paths, gap := stagedMaterial(s.Binary, s.Args)
		found = append(found, paths...)
		if gap != "" {
			gaps = append(gaps, gap)
		}
	}
	if len(found) == 0 && len(gaps) == 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.staged == nil {
		q.staged = map[scanQueueKey]stagedScan{}
	}
	key := scanQueueKey{dir: dir, raw: pipelineNeedsRawSocket(stages)}
	entry := q.staged[key]
	if entry.taskID != "" && entry.taskID != taskID {
		entry.conflict = true
	}
	entry.taskID = taskID
	if len(gaps) > 0 {
		if entry.gap != "" {
			entry.gap += "; "
		}
		entry.gap += capRunes(strings.Join(gaps, "; "), 400)
	}
	have := map[string]bool{}
	for _, p := range entry.material {
		have[p] = true
	}
	for _, p := range found {
		if have[p] {
			continue
		}
		if len(entry.material) >= maxStagedMaterial {
			entry.overflow = true
			continue
		}
		have[p] = true
		entry.material = append(entry.material, p)
	}
	q.staged[key] = entry
}

// take returns the material staged in dir and forgets it, so one directory is scanned once.
func (q *vulnScanQueue) take(dir string, raw bool) (stagedScan, bool) {
	if q == nil || dir == "" {
		return stagedScan{}, false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	key := scanQueueKey{dir: dir, raw: raw}
	entry := q.staged[key]
	if len(entry.material) == 0 && entry.gap == "" {
		return stagedScan{}, false
	}
	delete(q.staged, key)
	return entry, true
}

// vulnScanDeps are the collaborators the code-owned scan needs.
type vulnScanDeps struct {
	Gate  *secgate.Gate
	Store *eng.Store
}

// runStagedVulnScans scans dir when a command staged material there, ingests what the scanners reported, audits every outcome, and returns how many scans ran.
func runStagedVulnScans(ctx context.Context, d vulnScanDeps, q *vulnScanQueue, dir string) int {
	return runStagedVulnScansForWorker(ctx, d, q, dir, false) +
		runStagedVulnScansForWorker(ctx, d, q, dir, true)
}

func runStagedVulnScansForWorker(ctx context.Context, d vulnScanDeps, q *vulnScanQueue, dir string, raw bool) int {
	if d.Gate == nil || d.Gate.Policy == nil || d.Store == nil {
		return 0
	}
	staged, ok := q.take(dir, raw)
	if !ok {
		return 0
	}
	material := staged.material
	if staged.gap != "" {
		_ = d.Store.Audit("vulnscan", "scan-gap", staged.taskID+": "+staged.gap)
	}
	if len(material) == 0 {
		return 0
	}
	if staged.overflow {
		_ = d.Store.Audit("vulnscan", "scan-gap", staged.taskID+": staged material limit reached; some files were not scanned")
	}
	if staged.conflict {
		_ = d.Store.Audit("vulnscan", "ambiguous-task", "material staged by multiple tasks: "+strings.Join(material, ", "))
		return 0
	}
	task, err := d.Store.GetTask(staged.taskID)
	if err != nil {
		_ = d.Store.Audit("vulnscan", "no-task", "material staged with no task to cite: "+strings.Join(material, ", "))
		return 0
	}
	timeout, outputCap := resolveRunCaps()
	ran := 0
	dockerScanned := map[string]bool{}
	dockerFailed := map[string]string{}
	for _, job := range vulnScanJobs(material) {
		argv := job.argv
		dockerArchive := argv[0] == "grype" && strings.HasPrefix(argv[1], "docker-archive:")
		ociArchive := argv[0] == "grype" && strings.HasPrefix(argv[1], "oci-archive:")
		if ociArchive && dockerScanned[job.input] {
			continue
		}
		if err := ctx.Err(); err != nil {
			_ = d.Store.Audit("vulnscan", "scan-gap", task.ID+" "+job.input+": scan canceled before completion")
			return ran
		}
		cmd := secgate.Command{
			Binary: argv[0], Args: argv[1:],
			Phase: secgate.Phase(task.Phase), Surface: secgate.Surface(task.Surface),
		}
		run, msg := authorizeCommand(ctx, d.Gate, cmd)
		if msg != "" {
			_ = d.Store.Audit("vulnscan", "scan-denied", task.ID+" "+argv[0]+": "+capRunes(msg, 300))
			continue
		}
		res := runAuthorized(ctx, d.Gate, run.Binary, run.Args, dir, outputCap, timeout,
			actionOrigin{TaskID: task.ID, Surface: run.Surface, SkipVulnIngest: true, UseRawWorker: raw})
		ran++
		// An empty report is a clean result only when the scanner consulted its database: without one it prints the same empty report and reports the failure on stderr alone.
		if res.Err != nil || res.TimedOut || !vulnScanResultBearing(argv[0], res.ExitCode) || !scanProducedReport(argv[0], res.Stdout) {
			detail := fmt.Sprintf(
				"%s %s over %s: the scan produced no usable result, so the advisories affecting it are unknown (exit %d): %s",
				task.ID, argv[0], job.input, res.ExitCode, capRunes(strings.TrimSpace(res.Output), 300))
			if dockerArchive {
				dockerFailed[job.input] = detail
				continue
			}
			if ociArchive && dockerFailed[job.input] != "" {
				detail += "; docker archive form also failed"
			}
			_ = d.Store.Audit("vulnscan", "scan-gap", detail)
			continue
		}
		stored, err := ingestVulnOutput(ctx, d.Store, task, argv[0], res.Stdout)
		if err != nil {
			_ = d.Store.Audit("vulnscan", "ingest-failed", task.ID+" "+argv[0]+": "+capRunes(err.Error(), 300))
			continue
		}
		if dockerArchive {
			dockerScanned[job.input] = true
		}
		_ = d.Store.Audit("vulnscan", "scanned",
			fmt.Sprintf("%s %s over %s: %d advisories", task.ID, argv[0], job.input, stored))
	}
	return ran
}

// ingestVulnOutput records one scan's output as evidence and persists the advisories it reported.
func ingestVulnOutput(ctx context.Context, store *eng.Store, task eng.Task, scanner, output string) (int, error) {
	if !scanProducedReport(scanner, output) {
		return 0, fmt.Errorf("%s did not produce its expected report", scanner)
	}
	quote := scanner + " scan of " + task.ID + "\n" + output
	id, err := store.RecordEvidence(task.ID, quote)
	if err != nil {
		return 0, err
	}
	return ingestVulnReports(ctx, store, task.ID, task.Target, task.Surface,
		[]eng.EvidenceRow{{ID: id, Quote: quote}})
}
