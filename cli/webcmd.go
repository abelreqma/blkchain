package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
	"blkchain/cli/internal/webcollect"
)

var webPlaceholder = regexp.MustCompile(`\{([^{}]+)\}`)

type webOpts struct {
	workspace, scope, roe, file, role, session, view, task, operation, values, resume string
	transcript                                                                        string
	asJSON, auto, browser, headed, noRDNS                                             bool
	safe                                                                              bool
	depth, states, example                                                            int
	assistSeconds                                                                     int
	interactions                                                                      webStringFlags
}
type webStringFlags []string

func (s *webStringFlags) String() string { return strings.Join(*s, ",") }
func (s *webStringFlags) Set(v string) error {
	if len(*s) >= 20 {
		return errors.New("interaction limit")
	}
	*s = append(*s, v)
	return nil
}
func defineWebFlags(fs *flag.FlagSet, o *webOpts) {
	fs.StringVar(&o.workspace, "workspace", "", "engagement workspace (default: latest)")
	fs.StringVar(&o.scope, "scope", "", "legacy scope filter for read-only workspace views")
	fs.StringVar(&o.roe, "roe", "", "operator ROE.md for collection, replay, and import")
	fs.StringVar(&o.transcript, "transcript", "important", "action output: off, important, or full")
	fs.StringVar(&o.file, "file", "", "target list or HAR input")
	fs.StringVar(&o.role, "role", "", "supplied session role (default: all supplied roles)")
	fs.StringVar(&o.session, "session", "", "isolated role sessions with environment references")
	fs.StringVar(&o.view, "view", "summary", "summary, apis, artifacts, functions, features, findings, coverage, exports, all")
	fs.StringVar(&o.task, "task", "", "existing engagement task for active actions")
	fs.StringVar(&o.operation, "operation", "", "API operation id for export or replay")
	fs.StringVar(&o.values, "values", "", "JSON replay values or WebSocket message transcript")
	fs.IntVar(&o.example, "example", 0, "stored HTTP example number for exact body replay")
	fs.StringVar(&o.resume, "resume", "", "archive resume key")
	fs.BoolVar(&o.asJSON, "json", false, "emit structured JSON with exact operation records")
	fs.BoolVar(&o.auto, "auto", false, "run RoE-authorized web actions without prompts (default)")
	fs.BoolVar(&o.safe, "safe", false, "approve RoE-authorized web actions interactively")
	fs.BoolVar(&o.browser, "browser", false, "collect runtime scripts with the isolated browser")
	fs.BoolVar(&o.headed, "headed", false, "use an operator-provisioned isolated headed browser")
	fs.BoolVar(&o.noRDNS, "no-rdns", false, "skip IP reverse-DNS discovery")
	fs.IntVar(&o.assistSeconds, "assist-seconds", 0, "headed operator-assistance window (0 to 120 seconds)")
	fs.IntVar(&o.depth, "depth", 3, "maximum discovery depth (1 to 8)")
	fs.IntVar(&o.states, "states", 30, "maximum page states (1 to 100)")
	fs.Var(&o.interactions, "interaction", "scroll or click:<selector> (repeatable)")
}
func runWebAnalysis(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	out, e := webExecute(ctx, args, secgate.Auto, nil, false, 100)
	if out != "" {
		fmt.Fprint(os.Stdout, out)
	}
	return e
}
func webExecute(ctx context.Context, args []string, mode secgate.Mode, confirm secgate.Confirmer, interactive bool, width int) (output string, runErr error) {
	if len(args) > 0 && args[0] == "help" {
		var b strings.Builder
		printCommandHelp(&b, engageWebSpec())
		return b.String(), nil
	}
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "-help" {
			var b strings.Builder
			printCommandHelp(&b, engageWebSpec())
			return b.String(), nil
		}
	}
	command := "inspect"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}
	valid := map[string]bool{"collect": true, "analyze": true, "inspect": true, "import": true, "archive": true, "export": true, "replay": true}
	if !valid[command] {
		return "", usageErr("web: use collect, analyze, inspect, import, archive, export, or replay")
	}
	fs := newFlagSet("engage web")
	var o webOpts
	defineWebFlags(fs, &o)
	valueFlags := map[string]bool{}
	for _, k := range []string{"workspace", "scope", "roe", "transcript", "file", "role", "session", "view", "task", "operation", "values", "depth", "states", "interaction", "resume", "assist-seconds", "example"} {
		valueFlags[k] = true
	}
	if e := parseFlags(fs, reorder(args, valueFlags)); e != nil {
		return "", e
	}
	if o.safe && o.auto {
		return "", usageErr("web: choose --safe or --auto")
	}
	if !validTranscriptMode(o.transcript) {
		return "", usageErr("web: transcript must be off, important, or full")
	}
	views := map[string]bool{"summary": true, "apis": true, "artifacts": true, "functions": true, "features": true, "findings": true, "coverage": true, "exports": true, "all": true}
	if o.example < 0 || o.example > 20 || o.example > 0 && o.values != "" || !views[o.view] || o.depth < 1 || o.depth > 8 || o.states < 1 || o.states > 100 || o.assistSeconds < 0 || o.assistSeconds > 120 || o.assistSeconds > 0 && !o.headed {
		return "", usageErr("web: invalid view or discovery budget")
	}
	inputs := append([]string{}, fs.Args()...)
	if o.file != "" && command != "import" {
		inputs = append(inputs, o.file)
	}
	targets, e := webResolveTargets(ctx, inputs, !o.noRDNS)
	if e != nil {
		return "", e
	}
	if o.workspace == "" {
		o.workspace, e = latestEngagementDir()
		if e != nil {
			return "", fmt.Errorf("web: supply --workspace for a new collection: %w", e)
		}
	}
	network := command == "collect" || command == "archive" || command == "replay"
	policyRelevant := network || command == "import"
	if !network {
		if _, e = os.Stat(filepath.Join(o.workspace, "engagement.db")); e != nil {
			return "", errors.New("web: engagement database not found")
		}
	}
	ws, e := engagement.OpenWorkspace(o.workspace)
	if e != nil {
		return "", e
	}
	defer ws.Close()
	if !o.asJSON {
		removeFindings := subscribeWebFindingOutput(ctx, ws.Store, os.Stdout)
		defer removeFindings()
	}
	cwd, _ := os.Getwd()
	scope := targets.Scope
	var roe *RoE
	var roePath string
	if policyRelevant {
		if o.scope != "" {
			return "", usageErr("web: --scope is retired for engagement actions; use --roe ROE.md")
		}
		if o.roe == "" {
			for _, input := range inputs {
				if strings.HasSuffix(strings.ToLower(input), ".md") {
					o.roe = input
					break
				}
			}
		}
		roe, roePath, e = loadEngageRoE(engageOpts{roe: o.roe}, cwd, nil)
		if e != nil {
			return "", e
		}
		scope = roe.Scope
	} else if o.roe != "" {
		data, e := webReadFile(o.roe, 1<<20)
		if e != nil {
			return "", e
		}
		roe, e := ParseRoE(strings.NewReader(string(data)))
		if e != nil {
			return "", e
		}
		scope = roe.Scope
		if len(targets.URLs) == 0 {
			targets, e = webResolveTargets(ctx, []string{o.roe}, !o.noRDNS)
			if e != nil {
				return "", e
			}
		}
	}
	if !policyRelevant && (scope == nil || o.scope != "") {
		scope, _, _, e = resolveEngageScope(engageOpts{scope: o.scope}, cwd, nil)
		if e != nil {
			return "", e
		}
	}
	if network && (scope == nil || scope.Empty()) {
		return "", errors.New("web: acquisition requires --scope, --roe, an engagement Markdown target, or the project's ROE.md")
	}
	if o.auto {
		mode = secgate.Auto
	}
	if o.safe {
		mode = secgate.Safe
	}
	if mode == secgate.Safe && confirm == nil && isTerminalFile(os.Stdin) && !interactive {
		confirm = newTerminalConfirmer(os.Stdin, os.Stdout)
	}
	if !network && (scope == nil || scope.Empty()) {
		mode = secgate.Safe
	}
	policy := gatePolicy{RoE: roe}
	if !policyRelevant {
		policy, e = resolveEngageConfigPolicy(engageOpts{}, cwd)
		if e != nil {
			return "", e
		}
	}
	var trace *actionTranscript
	var webMetadata engageRunMetadata
	var webDeadline time.Time
	webExisting := false
	webIncomplete := false
	var actionView strings.Builder
	var auditMu sync.Mutex
	var auditErr error
	ctx, stopWeb := context.WithCancel(ctx)
	defer stopWeb()
	if policyRelevant {
		lease, err := acquireEngageLock(ws.Dir)
		if err != nil {
			return "", err
		}
		defer lease.Close()
		runPath := filepath.Join(ws.Dir, "run.json")
		if _, err := os.Lstat(runPath); err == nil {
			webExisting = true
			if err := readEngageMetadata(runPath, &webMetadata); err != nil {
				return "", err
			}
			if webMetadata.PolicyHash != roe.Policy.Hash {
				return "", errors.New("web: ROE.md differs from the workspace policy")
			}
			if webMetadata.Mode == "safe" {
				mode = secgate.Safe
			}
		} else if os.IsNotExist(err) {
			webMetadata = engageRunMetadata{Goal: "web " + command, Mode: mode.String(), ProjectDir: cwd, RoE: roePath, PolicyHash: roe.Policy.Hash, Started: time.Now().UTC().Format(time.RFC3339Nano)}
		} else {
			return "", err
		}
		started, err := time.Parse(time.RFC3339Nano, webMetadata.Started)
		if err != nil {
			return "", errors.New("web: invalid engagement start time")
		}
		webDeadline = started.Add(time.Duration(roe.Policy.WallSeconds) * time.Second)
		if !time.Now().Before(webDeadline) {
			return "", errors.New("web: engagement deadline has expired")
		}
		var deadlineCancel context.CancelFunc
		ctx, deadlineCancel = context.WithDeadline(ctx, webDeadline)
		defer deadlineCancel()
		if mode == secgate.Safe && confirm == nil && isTerminalFile(os.Stdin) && !interactive {
			confirm = newTerminalConfirmer(os.Stdin, os.Stdout)
		}
		in, out, _, err := runnerScope(ctx, scope)
		if err != nil {
			return "", err
		}
		declared, _ := scope.Entries()
		exact := map[string]bool{}
		for _, entry := range declared {
			if ip := net.ParseIP(entry); ip != nil {
				exact[ip.String()] = true
			}
		}
		for _, address := range operatorAddresses() {
			if !exact[address] {
				out = append(out, address)
			}
		}
		if err := scope.PinNetwork(in, out); err != nil {
			return "", err
		}
		policyPath := filepath.Join(ws.Dir, "policy.json")
		if _, err := os.Stat(policyPath); err == nil {
			if err := verifyEngagePolicy(policyPath, roe.Policy.Canonical); err != nil {
				return "", err
			}
		} else if os.IsNotExist(err) {
			if webExisting {
				return "", errors.New("web: saved policy is missing from the workspace")
			}
			file, err := os.OpenFile(policyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return "", err
			}
			_, writeErr := file.WriteString(roe.Policy.Canonical)
			closeErr := file.Close()
			if writeErr != nil {
				return "", writeErr
			}
			if closeErr != nil {
				return "", closeErr
			}
		} else {
			return "", err
		}
		trace = newActionTranscript(ws.Dir, o.transcript, "web-broker", roe.Policy.MaxActions, roe.Policy.TotalBytes, &lockedWriter{w: &actionView})
		trace.otherRunner = roe.Policy.RunnerID
		if _, err := os.Stat(trace.path); err == nil {
			if err := trace.restore(); err != nil {
				return "", err
			}
			if webMetadata.CommandAttempts < trace.actions || webMetadata.ByteUsage < int64(trace.used) {
				return "", errors.New("web: checkpoint usage is less than recorded actions")
			}
		} else if os.IsNotExist(err) {
			if webExisting {
				return "", errors.New("web: action transcript is missing from the workspace")
			}
			file, err := os.OpenFile(trace.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return "", err
			}
			if err := file.Close(); err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}
	gate := buildEngageGate(ws, scope, mode, confirm, secgate.NewSessionApprovals(), "", policy, func(a, d string) {
		if err := ws.AuditLine("secgate", a, webanalysis.RedactText(d)); err != nil {
			auditMu.Lock()
			auditErr = errors.Join(auditErr, fmt.Errorf("web audit write failed: %w", err))
			auditMu.Unlock()
			stopWeb()
		}
		if trace != nil {
			var traceErr error
			if a == "allow" {
				id, _, err := trace.begin("", "web-policy", d, 1)
				if err == nil {
					traceErr = trace.record(actionRecord{ID: id, Kind: "web-policy", Command: d, Status: "complete", Reason: a})
				} else {
					traceErr = err
				}
			} else {
				traceErr = trace.record(actionRecord{Kind: "web-policy", Command: d, Status: "denied", Reason: a})
			}
			if traceErr != nil {
				auditMu.Lock()
				auditErr = errors.Join(auditErr, fmt.Errorf("web transcript write failed: %w", traceErr))
				auditMu.Unlock()
				stopWeb()
			}
		}
	})
	if e = gate.Start(); e != nil {
		return "", e
	}
	if policyRelevant {
		if err := gate.RestorePolicyUsage(webMetadata.CommandAttempts, webDeadline, webMetadata.ByteUsage); err != nil {
			return "", err
		}
		writer := newReportWriter(ws.Store, ws.Dir, webMetadata.Goal, webMetadata.RoE, mode.String())
		if err := writer.RestoreFinal(); err != nil {
			return "", err
		}
		if err := os.Remove(filepath.Join(ws.Dir, "STOP")); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		webMetadata.Status = "in-progress"
		if err := writeEngageMetadata(ws.Dir, webMetadata); err != nil {
			return "", err
		}
		if err := writer.Flush("in-progress"); err != nil {
			return "", err
		}
		defer func() {
			auditMu.Lock()
			runErr = errors.Join(runErr, auditErr)
			auditMu.Unlock()
			status := "complete"
			if runErr != nil {
				status = "interrupted"
			} else if webIncomplete {
				status = "paused"
			}
			if _, err := os.Stat(filepath.Join(ws.Dir, "STOP")); err == nil {
				status = "stopped"
			}
			if snapshot, err := ws.Store.Snapshot(context.Background()); err == nil && status == "complete" {
				for _, task := range snapshot.Tasks {
					if task.Status == engagement.StatusTodo || task.Status == engagement.StatusActive || task.Status == engagement.StatusBlocked {
						status = "paused"
						break
					}
				}
			}
			webMetadata.Status = status
			webMetadata.CommandAttempts = gate.PolicyUsage()
			webMetadata.ByteUsage = gate.PolicyByteUsage()
			if err := writeEngageMetadata(ws.Dir, webMetadata); err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("web checkpoint write failed: %w", err))
			}
			if err := writer.Flush(status); err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("web report write failed: %w", err))
			}
			if !o.asJSON {
				md, js := reportPaths(ws.Dir)
				output = actionView.String() + output + "\nReport: " + md + "\n        " + js + "\nTranscript: " + trace.path + "\n"
			}
		}()
		stopReport := watchEngageStop(ctx, ws.Dir, stopWeb)
		defer stopReport()
	}
	armed := func() bool { return false }
	if o.task != "" {
		snap, e := ws.Store.Snapshot(ctx)
		if e != nil {
			return "", e
		}
		found := false
		for _, t := range snap.Tasks {
			if t.ID == o.task {
				found = true
				task := t
				armed = func() bool { return task.Armed }
			}
		}
		if !found {
			return "", errors.New("web: engagement task not found")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	svc := webcollect.New(ws.Store, newWebBroker(gate, armed), webParseWorker)
	if command == "import" && gate.Policy != nil {
		svc.AccountArtifactBytes = gate.ClaimPolicyBytes
	}
	svc.DiscoveryAllowed = webRedirectOK(gate)
	svc.SetTask(o.task)
	for _, g := range targets.Gaps {
		svc.Gap(g.Stage, g.URL, g.Reason)
	}
	switch command {
	case "collect", "archive":
		if len(targets.URLs) == 0 {
			return "", usageErr("web: supply domains, IPs, a target list, or engagement.md")
		}
		roles, e := webLoadSessions(o.session)
		if e != nil {
			return "", e
		}
		if o.role != "" && o.session == "" && o.role != "anonymous" {
			if err := svc.RecordGap(ctx, o.role, "role", "", "Requested role has no supplied session"); err != nil {
				return "", err
			}
			return "", errors.New("requested role requires a supplied session")
		}
		found := false
		available := 0
		for _, r := range roles {
			if o.role != "" && r.Name != o.role {
				continue
			}
			found = true
			collector := webcollect.New(ws.Store, svc.Broker, webParseWorker)
			collector.DiscoveryAllowed = svc.DiscoveryAllowed
			collector.SetTask(o.task)
			headers, e := webRoleHeaders(r)
			if e == nil {
				e = webRoleStateAvailable(r)
			}
			if e != nil {
				if err := svc.RecordGap(ctx, r.Name, "role", r.Origin, e.Error()); err != nil {
					return "", err
				}
				continue
			}
			if (r.Login != nil || len(r.Storage) > 0) && !o.browser && !o.headed && command != "archive" {
				if err := svc.RecordGap(ctx, r.Name, "state", r.Origin, "Supplied login or storage state requires browser collection"); err != nil {
					return "", err
				}
				continue
			}
			available++
			if r.Origin != "" && !webTargetMatches(r.Origin, targets.URLs) {
				return "", errors.New("session origin is not a supplied target")
			}
			opt := webcollect.Options{Role: r.Name, Headers: headers, CredentialOrigin: r.Origin, MaxDepth: o.depth, MaxStates: o.states, Historical: command == "archive", Interactions: o.interactions}
			if command == "archive" {
				collector.Archive = webcollect.NewArchive(collector.DiscoveryAllowed)
				collector.Archive.Resume = o.resume
			}
			if (o.browser || o.headed) && command != "archive" {
				b, e := webNewJobBrowser(gate, armed, collector, r, o.headed)
				if e != nil {
					return "", e
				}
				if o.headed {
					seconds := o.assistSeconds
					if seconds == 0 {
						seconds = 30
					}
					b.Assist = time.Duration(seconds) * time.Second
				}
				opt.Browser = b
			}
			for _, g := range targets.Gaps {
				collector.Gap(g.Stage, g.URL, g.Reason)
			}
			coverage, collectErr := collector.Collect(ctx, targets.URLs, opt)
			if collectErr != nil {
				return "", collectErr
			}
			for _, gap := range coverage.Gaps {
				if gap.Stage != "fetch" && gap.Stage != "storage" && gap.Stage != "scope" {
					continue
				}
				webIncomplete = true
				for _, target := range targets.URLs {
					if gap.URL == target {
						return "", errors.New("web: target request was denied or incomplete; see report coverage and audit")
					}
				}
			}
		}
		if !found {
			if err := svc.RecordGap(ctx, o.role, "role", "", "Requested role is absent from supplied sessions"); err != nil {
				return "", err
			}
			return "", errors.New("supplied session role not found")
		}
		if available == 0 {
			return "", errors.New("no supplied role has usable session state; see coverage gaps")
		}
		if e = webScanLibraries(ctx, svc); e != nil {
			return "", e
		}
	case "analyze":
		if e = svc.AnalyzeStored(ctx); e != nil {
			return "", e
		}
		if e = webScanLibraries(ctx, svc); e != nil {
			return "", e
		}
	case "import":
		if o.file == "" {
			return "", usageErr("web import requires --file traffic.har")
		}
		b, e := webReadFile(o.file, 16<<20)
		if e != nil {
			return "", e
		}
		role := o.role
		if role == "" {
			role = "imported"
		}
		if scope == nil || scope.Empty() {
			return "", errors.New("web import requires engagement discovery scope")
		}
		if e = svc.ImportHAR(ctx, strings.NewReader(string(b)), role); e != nil {
			return "", e
		}
	case "export":
		snap, e := ws.Store.WebSnapshot(ctx)
		if e != nil {
			return "", e
		}
		snap = webFilter(snap, targets.URLs)
		if e = webWriteExports(ctx, ws, snap, o.operation); e != nil {
			return "", e
		}
	case "replay":
		if e = webReplay(ctx, svc, gate, armed, o); e != nil {
			return "", e
		}
	}
	snap, e := ws.Store.WebSnapshot(ctx)
	if e != nil {
		return "", e
	}
	snap = webFilter(snap, targets.URLs)
	if o.role != "" {
		ops := []webanalysis.Operation{}
		for _, v := range snap.Operations {
			for _, r := range v.Roles {
				if r == o.role {
					ops = append(ops, v)
					break
				}
			}
		}
		snap.Operations = ops
	}
	if o.asJSON {
		b, e := json.MarshalIndent(webanalysis.Display(snap), "", "  ")
		return string(b) + "\n", e
	}
	output = webView(snap, o.view, interactive, width)
	if command == "export" {
		output += "Export directory: " + webanalysis.SafeText(filepath.Join(ws.EvidenceDir(), "web", "exports")) + "\n"
	}
	return output, nil
}
func webWriteExports(ctx context.Context, ws *engagement.Workspace, s webanalysis.Snapshot, only string) error {
	dir := filepath.Join(ws.EvidenceDir(), "web", "exports")
	if e := webExportDir(dir); e != nil {
		return e
	}
	display := webanalysis.Display(s)
	data, e := json.MarshalIndent(display, "", "  ")
	if e != nil {
		return e
	}
	name := webanalysis.Hash(data) + ".json"
	if e = webExportFile(filepath.Join(dir, name), data); e != nil {
		return e
	}
	found := only == ""
	for _, op := range display.Operations {
		if only != "" && op.ID != only {
			continue
		}
		found = true
		t, e := webanalysis.CurlTemplate(op)
		if e != nil {
			return e
		}
		if t.Body != "" {
			if e = webExportFile(filepath.Join(dir, t.BodyFile), []byte(t.Body)); e != nil {
				return e
			}
		}
		output := t.Command + "\n# " + strings.Join(t.Gaps, "; ") + "\n"
		if e = webExportFile(filepath.Join(dir, webanalysis.Hash([]byte(output))+".curl.txt"), []byte(output)); e != nil {
			return e
		}
		if e = ws.Store.PutWeb(ctx, "export", op.ID, "", t); e != nil {
			return e
		}
	}
	if !found {
		return errors.New("operation not found")
	}
	return nil
}
func webExportDir(dir string) error {
	for _, p := range []string{filepath.Dir(dir), dir} {
		if e := os.MkdirAll(p, 0700); e != nil {
			return e
		}
		st, e := os.Lstat(p)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid export directory")
		}
		if e = os.Chmod(p, 0700); e != nil {
			return e
		}
	}
	return nil
}
func webExportFile(path string, data []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(e) {
		st, e := os.Lstat(path)
		if e != nil || !st.Mode().IsRegular() {
			return errors.New("invalid export file")
		}
		b, e := webReadFile(path, 32<<20)
		if e != nil || webanalysis.Hash(b) != webanalysis.Hash(data) {
			return errors.New("export file already exists with different contents")
		}
		return nil
	}
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	closeErr := f.Close()
	if e != nil {
		return e
	}
	return closeErr
}
func webReplay(ctx context.Context, svc *webcollect.Service, g *secgate.Gate, armed webArmedFunc, o webOpts) error {
	if o.operation == "" {
		return usageErr("web replay requires --operation and explicit --values for unresolved fields")
	}
	snap, e := svc.Store.WebSnapshot(ctx)
	if e != nil {
		return e
	}
	var op webanalysis.Operation
	for _, v := range snap.Operations {
		if v.ID == o.operation {
			op = v
		}
	}
	if op.ID == "" {
		return errors.New("operation not found")
	}
	if op.Protocol == "websocket" {
		return webReplaySocket(ctx, svc, op, o)
	}
	if op.Protocol != "http" {
		return errors.New("protocol requires specialized replay")
	}
	values := map[string]string{}
	if o.values != "" {
		b, e := webReadFile(o.values, 1<<20)
		if e != nil {
			return e
		}
		if json.Unmarshal(b, &values) != nil {
			return errors.New("invalid replay values")
		}
	}
	var request webAPIRequest
	selectedRole := ""
	if o.example > 0 {
		request, selectedRole, e = webReplayExample(op, o.example)
	} else {
		request, e = webReplayRequest(op, values)
	}
	if e != nil {
		if err := svc.RecordGap(ctx, o.role, "replay", op.Origin+op.Path, e.Error()); err != nil {
			return err
		}
		return e
	}
	raw := request.URL
	headers := map[string]string{}
	for _, line := range request.Headers {
		k, v, _ := strings.Cut(line, ": ")
		headers[k] = v
	}
	roles, e := webLoadSessions(o.session)
	if e != nil {
		return e
	}
	role := roles[0]
	if o.role == "" && selectedRole != "" {
		o.role = selectedRole
	}
	if o.role != "" {
		found := false
		for _, r := range roles {
			if r.Name == o.role {
				role = r
				found = true
			}
		}
		if !found {
			if err := svc.RecordGap(ctx, o.role, "role", op.Origin, "Replay role has no supplied session"); err != nil {
				return err
			}
			return errors.New("replay role missing")
		}
	}
	if role.Origin != "" && !webSameOrigin(raw, role.Origin) {
		return errors.New("replay origin differs from session")
	}
	if len(role.Storage) == 0 && role.Login == nil {
		hs, err := webRoleHeaders(role)
		if err != nil {
			if e := svc.RecordGap(ctx, role.Name, "role", raw, err.Error()); e != nil {
				return e
			}
			return err
		}
		h := webHeaders(headers)
		for k, vs := range hs {
			h[k] = vs
		}
		out, err := svc.Broker.Fetch(ctx, webacquire.Request{Method: request.Method, URL: raw, Headers: h, Body: []byte(request.Body)})
		a, saveErr := svc.Accept(ctx, webanalysis.Artifact{Kind: "api-response", URL: raw, FinalURL: out.FinalURL, Role: role.Name, Status: out.Status, Headers: out.Headers, MIME: out.Headers.Get("Content-Type"), Complete: out.Complete, Gap: out.Gap}, out.Body, 0)
		if saveErr != nil {
			return saveErr
		}
		example := webanalysis.RequestExample{URL: raw, Method: request.Method, Headers: h, Role: role.Name, Status: out.Status, Artifact: a.ID, Denied: err != nil}
		webanalysis.SetRequestBody(&example, []byte(request.Body))
		if saveErr = svc.Observe(ctx, example); saveErr != nil {
			return saveErr
		}
		if err != nil {
			if e := svc.RecordGap(ctx, role.Name, "replay", raw, err.Error()); e != nil {
				return e
			}
		}
		return err
	}
	b, e := webNewJobBrowser(g, armed, svc, role, false)
	if e != nil {
		return e
	}
	defer b.Close()
	if e = b.prepare(ctx); e != nil {
		return e
	}
	hs, e := webRoleHeaders(role)
	if e != nil {
		return e
	}
	for k, vs := range hs {
		headers[k] = strings.Join(vs, "; ")
	}
	lines := []string{}
	for k, v := range headers {
		lines = append(lines, k+": "+v)
	}
	_, e = b.Driver.DoAPIRequest(ctx, webAPIRequest{URL: raw, Method: op.Method, Headers: lines, Body: request.Body}, webRedirectOK(g))
	if de := b.drain(ctx); de != nil {
		return de
	}
	return e
}
