package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/webanalysis"
	"blkchain/cli/internal/webcollect"
)

var webPlaceholder = regexp.MustCompile(`\{([^{}]+)\}`)

type webOpts struct {
	workspace, scope, roe, file, role, session, view, task, operation, values, resume string
	asJSON, auto, browser, headed, noRDNS                                             bool
	depth, states                                                                     int
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
	fs.StringVar(&o.scope, "scope", "", "line-based engagement scope file")
	fs.StringVar(&o.roe, "roe", "", "engagement Markdown scope file")
	fs.StringVar(&o.file, "file", "", "target list or HAR input")
	fs.StringVar(&o.role, "role", "", "supplied session role (default: all supplied roles)")
	fs.StringVar(&o.session, "session", "", "isolated role sessions with environment references")
	fs.StringVar(&o.view, "view", "summary", "summary, apis, artifacts, functions, features, findings, coverage, exports, all")
	fs.StringVar(&o.task, "task", "", "existing engagement task for active actions")
	fs.StringVar(&o.operation, "operation", "", "API operation id for export or replay")
	fs.StringVar(&o.values, "values", "", "JSON file of replay parameter values")
	fs.StringVar(&o.resume, "resume", "", "archive resume key")
	fs.BoolVar(&o.asJSON, "json", false, "emit structured JSON with exact operation records")
	fs.BoolVar(&o.auto, "auto", false, "apply existing unattended engagement policy")
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
	var confirm secgate.Confirmer
	if isTerminalFile(os.Stdin) {
		confirm = newTerminalConfirmer(os.Stdin, os.Stdout)
	}
	out, e := webExecute(ctx, args, secgate.Safe, confirm, false, 100)
	if out != "" {
		fmt.Fprint(os.Stdout, out)
	}
	return e
}
func webExecute(ctx context.Context, args []string, mode secgate.Mode, confirm secgate.Confirmer, interactive bool, width int) (string, error) {
	if helpRequested(args) || len(args) > 0 && args[0] == "help" {
		var b strings.Builder
		c, _ := lookupCommand("web")
		printCommandHelp(&b, c)
		return b.String(), nil
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
	fs := newFlagSet("web")
	var o webOpts
	defineWebFlags(fs, &o)
	valueFlags := map[string]bool{}
	for _, k := range []string{"workspace", "scope", "roe", "file", "role", "session", "view", "task", "operation", "values", "depth", "states", "interaction", "resume", "assist-seconds"} {
		valueFlags[k] = true
	}
	if e := parseFlags(fs, reorder(args, valueFlags)); e != nil {
		return "", e
	}
	views := map[string]bool{"summary": true, "apis": true, "artifacts": true, "functions": true, "features": true, "findings": true, "coverage": true, "exports": true, "all": true}
	if !views[o.view] || o.depth < 1 || o.depth > 8 || o.states < 1 || o.states > 100 || o.assistSeconds < 0 || o.assistSeconds > 120 || o.assistSeconds > 0 && !o.headed {
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
	cwd, _ := os.Getwd()
	scope := targets.Scope
	if o.roe != "" {
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
	if scope == nil || o.scope != "" {
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
	policy, e := resolveEngageConfigPolicy(engageOpts{}, cwd)
	if e != nil {
		return "", e
	}
	gate := buildEngageGate(ws, scope, mode, confirm, secgate.NewSessionApprovals(), "", policy, func(a, d string) { _ = ws.AuditLine("secgate", a, webanalysis.RedactText(d)) })
	if e = gate.Start(); e != nil {
		return "", e
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
		if o.role != "" && o.session == "" {
			roles[0].Name = o.role
		}
		found := false
		for _, r := range roles {
			if o.role != "" && r.Name != o.role {
				continue
			}
			found = true
			collector := webcollect.New(ws.Store, svc.Broker, webParseWorker)
			collector.DiscoveryAllowed = svc.DiscoveryAllowed
			collector.SetTask(o.task)
			headers, e := webRoleHeaders(r)
			if e != nil {
				return "", e
			}
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
			_, e = collector.Collect(ctx, targets.URLs, opt)
			if e != nil {
				return "", e
			}
		}
		if !found {
			return "", errors.New("supplied session role not found")
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
	output := webView(snap, o.view, interactive, width)
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
	request, e := webReplayRequest(op, values)
	if e != nil {
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
	if o.role != "" {
		found := false
		for _, r := range roles {
			if r.Name == o.role {
				role = r
				found = true
			}
		}
		if !found {
			return errors.New("replay role missing")
		}
	}
	if role.Origin != "" && !webSameOrigin(raw, role.Origin) {
		return errors.New("replay origin differs from session")
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
