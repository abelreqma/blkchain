package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"blkchain/cli/internal/engagement"
)

type storeOptions struct {
	id          string
	workspace   string
	surface     string
	kind        string
	status      string
	severity    string
	findingID   string
	task        string
	asset       string
	title       string
	impact      string
	confidence  string
	detail      string
	json        bool
	offset      int
	limit       int
	evidence    string
	search      string
	interactive bool
}

func storeFlags(fs *flag.FlagSet, o *storeOptions) {
	fs.StringVar(&o.id, "id", "", "engagement id from blk store list")
	fs.StringVar(&o.workspace, "workspace", "", "engagement workspace directory")
	fs.StringVar(&o.surface, "surface", "", "surface name")
	fs.StringVar(&o.kind, "kind", "", "record kind")
	fs.StringVar(&o.status, "status", "", "finding status")
	fs.StringVar(&o.severity, "severity", "", "finding severity")
	fs.StringVar(&o.findingID, "finding", "", "finding id")
	fs.StringVar(&o.task, "task", "", "task id")
	fs.StringVar(&o.asset, "asset", "", "affected asset")
	fs.StringVar(&o.title, "title", "", "finding title")
	fs.StringVar(&o.impact, "impact", "", "observed impact")
	fs.StringVar(&o.confidence, "confidence", "", "confidence description")
	fs.StringVar(&o.detail, "detail", "", "finding detail")
	fs.StringVar(&o.evidence, "evidence", "", "comma-separated exact evidence row ids")
	fs.StringVar(&o.search, "search", "", "find earlier engagements by id, name, target, or surface")
	fs.BoolVar(&o.json, "json", false, "print JSON")
	fs.BoolVar(&o.interactive, "interactive", false, "open the interactive engagement store")
	fs.IntVar(&o.offset, "offset", 0, "record page offset")
	fs.IntVar(&o.limit, "limit", 20, "record page size (1-100)")
}

func parseStoreArgs(args []string) (string, storeOptions, []string, error) {
	if len(args) == 0 {
		return "", storeOptions{}, nil, missingArg("store", "choose list, show, records, findings, ask, add, or review", "blk store list")
	}
	verb := args[0]
	switch verb {
	case "list", "show", "records", "findings", "ask", "add", "review":
	default:
		return "", storeOptions{}, nil, fmt.Errorf("store: unknown action %q", verb)
	}
	fs := newFlagSet("store " + verb)
	o := storeOptions{}
	storeFlags(fs, &o)
	valueFlags := map[string]bool{}
	for _, name := range []string{"id", "workspace", "surface", "kind", "status", "severity", "finding", "task", "asset", "title", "impact", "confidence", "detail", "evidence", "search", "offset", "limit"} {
		valueFlags[name] = true
	}
	if err := parseFlags(fs, reorder(args[1:], valueFlags)); err != nil {
		return "", o, nil, err
	}
	if o.interactive {
		return "", o, nil, errors.New("use blk store --interactive before an action")
	}
	if o.limit < 1 || o.limit > 100 || o.offset < 0 || o.offset > 1000000 {
		return "", o, nil, errors.New("store: limit must be 1-100 and offset must be non-negative")
	}
	if len(o.search) > 256 || len(o.id) > 256 {
		return "", o, nil, errors.New("store: search and id must be at most 256 bytes")
	}
	if o.surface != "" && o.surface != "unclassified" {
		valid := false
		for _, s := range engagement.AllSurfaces() {
			if string(s) == o.surface {
				valid = true
				break
			}
		}
		if !valid {
			return "", o, nil, fmt.Errorf("store: unknown surface %q", o.surface)
		}
	}
	if o.status != "" {
		switch engagement.FindingStatus(o.status) {
		case engagement.FindingLead, engagement.FindingObserved, engagement.FindingValidated, engagement.FindingDismissed:
		default:
			return "", o, nil, fmt.Errorf("store: unknown finding status %q", o.status)
		}
	}
	if o.severity != "" {
		switch o.severity {
		case "info", "low", "medium", "high", "critical":
		default:
			return "", o, nil, fmt.Errorf("store: unknown severity %q", o.severity)
		}
	}
	return verb, o, fs.Args(), nil
}

func storeEvidenceIDs(raw string) ([]int64, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 32 {
		return nil, errors.New("too many evidence ids")
	}
	ids := make([]int64, 0, len(parts))
	seen := map[int64]bool{}
	for _, part := range parts {
		id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err != nil || id <= 0 {
			return nil, errors.New("evidence ids must be positive integers")
		}
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	return ids, nil
}

func writeStoreJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func storeIcon(kind string) string {
	if !useUnicode {
		return "*"
	}
	switch kind {
	case "engagement":
		return "📁"
	case "finding":
		return "🔎"
	case "question":
		return "💬"
	default:
		return "•"
	}
}

func storeSurfaceIcon(surface engagement.Surface) string {
	if !useUnicode {
		return "-"
	}
	switch surface {
	case engagement.SurfaceWeb:
		return "🌐"
	case engagement.SurfaceNetwork:
		return "🔌"
	case engagement.SurfaceLocal:
		return "💻"
	case engagement.SurfaceAD:
		return "🏢"
	case engagement.SurfaceContainer:
		return "📦"
	case engagement.SurfaceAISecurity:
		return "🤖"
	default:
		return "•"
	}
}

func storeStatusIcon(status engagement.FindingStatus) string {
	if !useUnicode {
		return "*"
	}
	switch status {
	case engagement.FindingValidated:
		return "✅"
	case engagement.FindingObserved:
		return "👁"
	case engagement.FindingDismissed:
		return "✕"
	default:
		return "🔎"
	}
}

func storeLocalModelURL() error {
	u, err := url.Parse(omlxBaseURL())
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("store ask requires an HTTP(S) local model URL")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("store ask requires a loopback model endpoint for engagement evidence")
}

type storeOverview struct {
	ID        string                                                `json:"id"`
	Name      string                                                `json:"name"`
	Workspace string                                                `json:"workspace"`
	Revision  int64                                                 `json:"revision"`
	Vantage   engagement.Vantage                                    `json:"vantage"`
	Surfaces  map[engagement.Surface]map[string]int                 `json:"surfaces"`
	Global    map[string]int                                        `json:"global"`
	Files     map[string]string                                     `json:"files"`
	Sample    map[engagement.Surface]map[string][]engagement.Record `json:"sample"`
}

func storeOverviewFor(ctx context.Context, ws *engagement.Workspace, id string, filter engagement.Surface, sampleLimit int) (storeOverview, error) {
	snap, _, err := ws.Store.ReportSnapshot(ctx, 1)
	if err != nil {
		return storeOverview{}, err
	}
	o := storeOverview{ID: id, Name: snap.Name, Workspace: ws.Dir, Revision: snap.Revision, Vantage: snap.Vantage,
		Surfaces: map[engagement.Surface]map[string]int{}, Global: map[string]int{}, Files: map[string]string{}, Sample: map[engagement.Surface]map[string][]engagement.Record{}}
	allFindings, err := ws.Store.Findings(ctx, "")
	if err != nil {
		return storeOverview{}, err
	}
	findingsBySurface := map[engagement.Surface][]engagement.Finding{}
	for _, finding := range allFindings {
		findingsBySurface[finding.Surface] = append(findingsBySurface[finding.Surface], finding)
	}
	for _, file := range []string{"engagement.db", "run.json", "audit.jsonl", "actions.jsonl", "report.md"} {
		path := filepath.Join(ws.Dir, file)
		if st, err := os.Lstat(path); err == nil && st.Mode().IsRegular() {
			o.Files[file] = path
		}
	}
	surfaces := append(engagement.AllSurfaces(), engagement.Surface("unclassified"))
	for _, surface := range surfaces {
		if filter != "" && surface != filter {
			continue
		}
		o.Surfaces[surface] = map[string]int{}
		o.Sample[surface] = map[string][]engagement.Record{}
		for _, kind := range []string{"task", "finding", "finding-event", "evidence", "receipt", "coverage", "web", "action"} {
			if kind == "finding" {
				found := findingsBySurface[surface]
				o.Surfaces[surface][kind] = len(found)
				start := len(found) - sampleLimit
				if start < 0 {
					start = 0
				}
				for _, f := range found[start:] {
					data, err := json.Marshal(f)
					if err != nil {
						return storeOverview{}, err
					}
					o.Sample[surface][kind] = append(o.Sample[surface][kind], engagement.Record{ID: f.ID, Kind: kind, Surface: f.Surface, TaskID: f.TaskID, Document: data})
				}
				continue
			}
			if kind == "web" && surface != engagement.SurfaceWeb {
				continue
			}
			if kind == "action" {
				count, err := ws.Store.ActionCount(ctx, surface)
				if err != nil {
					return storeOverview{}, err
				}
				o.Surfaces[surface][kind] = count
				continue
			}
			page, err := ws.Store.Records(ctx, kind, surface, 0, sampleLimit)
			if err != nil {
				return storeOverview{}, err
			}
			o.Surfaces[surface][kind] = page.Total
			if len(page.Records) > 0 {
				o.Sample[surface][kind] = page.Records
			}
		}
	}
	for _, kind := range []string{"audit", "transition"} {
		page, err := ws.Store.Records(ctx, kind, "", 0, sampleLimit)
		if err != nil {
			return storeOverview{}, err
		}
		o.Global[kind] = page.Total
	}
	return o, nil
}

func runStore(args []string) error {
	if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		fs := newFlagSet("store --interactive")
		o := storeOptions{}
		storeFlags(fs, &o)
		if err := parseFlags(fs, reorder(args, map[string]bool{"id": true, "workspace": true})); err != nil {
			return err
		}
		if !o.interactive || len(fs.Args()) != 0 {
			return errors.New("store --interactive takes no action")
		}
		if !isInteractive() {
			return errors.New("store --interactive requires a terminal")
		}
		return runStoreInteractive(context.Background(), os.Stdin, os.Stdout, o.id, o.workspace)
	}
	return runStoreTo(context.Background(), args, os.Stdout, nil, "")
}

func runStoreTo(ctx context.Context, args []string, w io.Writer, model toolLoopModel, modelID string) error {
	verb, o, rest, err := parseStoreArgs(args)
	if err != nil {
		return err
	}
	if verb == "list" {
		if len(rest) != 0 {
			return errors.New("store list takes no arguments")
		}
		if o.id != "" || o.workspace != "" || o.surface != "" {
			return errors.New("store list does not select a workspace or surface")
		}
		items, err := listStoredEngagements(ctx)
		if err != nil {
			return err
		}
		if o.search != "" {
			needle := strings.ToLower(o.search)
			filtered := make([]storedEngagement, 0, len(items))
			for _, item := range items {
				haystack := item.ID + " " + item.Name + " " + strings.Join(item.Targets, " ")
				for surface := range item.Surfaces {
					haystack += " " + surface
				}
				for surface := range item.Findings {
					haystack += " " + surface
				}
				if strings.Contains(strings.ToLower(haystack), needle) {
					filtered = append(filtered, item)
				}
			}
			items = filtered
		}
		if o.json {
			return writeStoreJSON(w, items)
		}
		if len(items) == 0 {
			message := "No stored engagements. Run blk engage first."
			if o.search != "" {
				message = "No matching engagements."
			}
			_, err = fmt.Fprintln(w, message)
			return err
		}
		for _, item := range items {
			if item.Error != "" {
				if _, err := fmt.Fprintf(w, "%s %s  unavailable: %s\n", storeIcon("engagement"), terminalSafe(item.ID), terminalSafe(item.Error)); err != nil {
					return err
				}
				continue
			}
			surfaces := make([]string, 0, len(item.Surfaces))
			for surface, count := range item.Surfaces {
				surfaces = append(surfaces, fmt.Sprintf("%s:%d", surface, count))
			}
			sort.Strings(surfaces)
			findingCount := 0
			for _, n := range item.Findings {
				findingCount += n
			}
			if _, err := fmt.Fprintf(w, "%s %s  %s\n   surfaces: %s\n   findings: %d  targets: %s\n", storeIcon("engagement"), terminalSafe(item.ID), terminalSafe(capRunes(item.Name, 48)), strings.Join(surfaces, ", "), findingCount, terminalSafe(capRunes(strings.Join(item.Targets, ", "), 80))); err != nil {
				return err
			}
		}
		return nil
	}
	ws, id, err := selectStoredWorkspace(ctx, o.id, o.workspace)
	if err != nil {
		return err
	}
	defer ws.Close()
	surface := engagement.Surface(o.surface)
	switch verb {
	case "show":
		if len(rest) != 0 {
			return errors.New("store show takes no arguments")
		}
		overview, err := storeOverviewFor(ctx, ws, id, surface, o.limit)
		if err != nil {
			return err
		}
		if o.json {
			return writeStoreJSON(w, overview)
		}
		if _, err := fmt.Fprintf(w, "%s %s  %s\n", storeIcon("engagement"), terminalSafe(id), terminalSafe(overview.Name)); err != nil {
			return err
		}
		for _, s := range append(engagement.AllSurfaces(), engagement.Surface("unclassified")) {
			counts, ok := overview.Surfaces[s]
			if !ok {
				continue
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n    tasks %d  findings %d  reviews %d\n    evidence %d  actions %d\n    coverage %d  web %d\n", storeSurfaceIcon(s), s, counts["task"], counts["finding"], counts["finding-event"], counts["evidence"], counts["action"], counts["coverage"], counts["web"]); err != nil {
				return err
			}
		}
		_, err = fmt.Fprintln(w, "Records: blk store records --kind KIND\nUse --surface and --offset to page.")
		return err
	case "records":
		if len(rest) != 0 || o.kind == "" {
			return errors.New("store records requires --kind and no positional arguments")
		}
		validKind := false
		for _, kind := range engagement.RecordKinds() {
			if o.kind == kind {
				validKind = true
				break
			}
		}
		if !validKind {
			return fmt.Errorf("unknown record kind %q; use %s", o.kind, strings.Join(engagement.RecordKinds(), ", "))
		}
		page, err := ws.Store.Records(ctx, o.kind, surface, o.offset, o.limit)
		if err != nil {
			return err
		}
		if o.json {
			return writeStoreJSON(w, page)
		}
		if _, err := fmt.Fprintf(w, "%s %s: %s/%s  %d of %d from offset %d\n", storeIcon("engagement"), id, o.kind, o.surface, len(page.Records), page.Total, page.Offset); err != nil {
			return err
		}
		for _, rec := range page.Records {
			if _, err := fmt.Fprintf(w, "[%s] %s %s\n", terminalSafe(rec.ID), rec.Surface, terminalSafe(string(rec.Document))); err != nil {
				return err
			}
		}
		return nil
	case "findings":
		if len(rest) != 0 {
			return errors.New("store findings takes no arguments")
		}
		if surface == "unclassified" {
			if o.json {
				return writeStoreJSON(w, []engagement.Finding{})
			}
			_, err := fmt.Fprintln(w, "No matching findings.")
			return err
		}
		fs, err := ws.Store.Findings(ctx, surface)
		if err != nil {
			return err
		}
		filtered := make([]engagement.Finding, 0, len(fs))
		for _, f := range fs {
			if o.status == "" || string(f.Status) == o.status {
				filtered = append(filtered, f)
			}
		}
		if o.offset >= len(filtered) {
			filtered = []engagement.Finding{}
		} else {
			end := o.offset + o.limit
			if end > len(filtered) {
				end = len(filtered)
			}
			filtered = filtered[o.offset:end]
		}
		if o.json {
			return writeStoreJSON(w, filtered)
		}
		for _, f := range filtered {
			if _, err := fmt.Fprintf(w, "%s [%s/%s] %s  %s  %s  %s\n", storeStatusIcon(f.Status), f.Status, f.Severity, terminalSafe(f.ID), f.Surface, terminalSafe(f.Title), terminalSafe(f.Asset)); err != nil {
				return err
			}
		}
		if len(filtered) == 0 {
			_, err = fmt.Fprintln(w, "No matching findings.")
		}
		return err
	case "add", "review":
		if len(rest) != 0 {
			return errors.New("store add and review take flags only")
		}
		if verb == "add" && (surface == "" || o.task == "" || o.asset == "" || o.title == "" || o.evidence == "") {
			return errors.New("store add requires --surface, --task, --asset, --title, and --evidence")
		}
		ids, err := storeEvidenceIDs(o.evidence)
		if err != nil {
			return err
		}
		var f engagement.Finding
		if verb == "review" {
			if o.findingID == "" {
				return errors.New("store review requires --finding")
			}
			f, err = ws.Store.Finding(ctx, o.findingID)
			if err != nil {
				return err
			}
			if surface != "" && surface != f.Surface {
				return errors.New("review surface differs from the stored finding")
			}
		} else {
			f = engagement.Finding{Surface: surface, TaskID: o.task, Asset: o.asset, Title: o.title, Status: engagement.FindingLead}
		}
		if o.status != "" {
			f.Status = engagement.FindingStatus(o.status)
		}
		if o.severity != "" {
			f.Severity = o.severity
		}
		if o.task != "" {
			f.TaskID = o.task
		}
		if o.asset != "" {
			f.Asset = o.asset
		}
		if o.title != "" {
			f.Title = o.title
		}
		if o.impact != "" {
			f.Impact = o.impact
		}
		if o.confidence != "" {
			f.Confidence = o.confidence
		}
		if o.detail != "" {
			f.Detail = o.detail
		}
		if len(ids) > 0 {
			f.EvidenceIDs = ids
		}
		f, err = ws.Store.SaveFinding(ctx, f)
		if err != nil {
			return err
		}
		if o.json {
			return writeStoreJSON(w, f)
		}
		_, err = fmt.Fprintf(w, "%s [%s] %s  %s\n", storeStatusIcon(f.Status), f.Status, terminalSafe(f.ID), terminalSafe(f.Title))
		return err
	case "ask":
		question := strings.Join(rest, " ")
		if strings.TrimSpace(question) == "" {
			return errors.New("store ask requires a question")
		}
		if model == nil {
			if err := storeLocalModelURL(); err != nil {
				return err
			}
			client, err := newOMLX(loadConfig(), modelID)
			if err != nil {
				return err
			}
			model = client
			modelID = client.model
		}
		answer, err := answerStore(ctx, ws.Store, id, surface, question, model, modelID)
		if err != nil {
			return err
		}
		if o.json {
			return writeStoreJSON(w, answer)
		}
		if _, err := fmt.Fprintf(w, "%s %s\n\n%s\n", storeIcon("question"), terminalSafe(id), terminalSafe(answer.Answer)); err != nil {
			return err
		}
		if answer.Partial {
			if _, err := fmt.Fprintln(w, "Record selection was partial; use store records to inspect the rest."); err != nil {
				return err
			}
		}
		for _, c := range answer.Citations {
			if _, err := fmt.Fprintf(w, "[%s] %s %s: %s\n", c.Ref, c.Surface, c.Kind, terminalSafe(capRunes(c.Text, 240))); err != nil {
				return err
			}
		}
		return nil
	}
	return errors.New("store action unavailable")
}
