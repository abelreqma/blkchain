package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webanalysis"
	"github.com/tmc/langchaingo/llms"
)

func fixtureStoreWorkspace(t *testing.T, path string) (*engagement.Workspace, int64) {
	t.Helper()
	ws, err := engagement.OpenWorkspace(path)
	if err != nil {
		t.Fatal(err)
	}
	name := "Fixture assessment"
	_, err = ws.Store.Apply(engagement.Delta{SetName: &name, Kind: "fixture", Upserts: []engagement.Task{
		{ID: "network-task", Kind: "recon", Target: "192.0.2.1", Objective: "observe service", DoneWhen: "banner saved", Status: engagement.StatusDone, Surface: engagement.SurfaceNetwork},
		{ID: "web-task", Kind: "web", Target: "https://example.test/", Objective: "inspect application", DoneWhen: "routes captured", Status: engagement.StatusTodo, Surface: engagement.SurfaceWeb},
	}})
	if err != nil {
		ws.Close()
		t.Fatal(err)
	}
	id, err := ws.Store.RecordEvidence("network-task", "fixture service banner")
	if err != nil {
		ws.Close()
		t.Fatal(err)
	}
	return ws, id
}

func TestStoreCatalogSelectsEarlierEngagementByID(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root, err := storeRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"20260101-000000", "20260102-000000"} {
		ws, _ := fixtureStoreWorkspace(t, filepath.Join(root, id))
		ws.Close()
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "symlink")); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(root, "20260103-000000")
	if err := os.MkdirAll(bad, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "engagement.db"), []byte("invalid sqlite fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	items, err := listStoredEngagements(context.Background())
	if err != nil || len(items) != 3 || items[0].Error == "" || items[1].ID != "20260102-000000" || items[2].Surfaces["network"] != 1 {
		t.Fatalf("catalog: %+v %v", items, err)
	}
	var searched bytes.Buffer
	if err := runStoreTo(context.Background(), []string{"list", "--search", "192.0.2.1", "--json"}, &searched, nil, ""); err != nil {
		t.Fatal(err)
	}
	var matches []storedEngagement
	if err := json.Unmarshal(searched.Bytes(), &matches); err != nil || len(matches) != 2 {
		t.Fatalf("catalog target search: %+v %v", matches, err)
	}
	var b bytes.Buffer
	if err := runStoreTo(context.Background(), []string{"show", "--id", items[2].ID, "--surface", "network", "--json"}, &b, nil, ""); err != nil {
		t.Fatal(err)
	}
	var overview storeOverview
	if err := json.Unmarshal(b.Bytes(), &overview); err != nil || overview.ID != items[2].ID || overview.Surfaces[engagement.SurfaceWeb] != nil || overview.Surfaces[engagement.SurfaceNetwork]["evidence"] != 1 {
		t.Fatalf("selected overview: %+v %v", overview, err)
	}
	b.Reset()
	if err := runStoreTo(context.Background(), []string{"show", "--json"}, &b, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b.Bytes(), &overview); err != nil || overview.ID != items[1].ID {
		t.Fatalf("default selection: %+v %v", overview, err)
	}
}

func TestStoreCatalogListsEarlierSchemaWithoutSurfaceColumn(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root, err := storeRoot()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "20250101-000000")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "engagement.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE meta(k TEXT PRIMARY KEY,v TEXT)`,
		`INSERT INTO meta(k,v) VALUES('name','Earlier fixture'),('revision','1')`,
		`CREATE TABLE task(id TEXT,target TEXT)`,
		`INSERT INTO task(id,target) VALUES('old-task','192.0.2.9')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	db.Close()
	items, err := listStoredEngagements(context.Background())
	if err != nil || len(items) != 1 || items[0].Error != "" || items[0].Surfaces["unclassified"] != 1 {
		t.Fatalf("earlier schema catalog: %+v %v", items, err)
	}
}

func TestStoreFindingsAndCitedAnswerShareStoredEvidence(t *testing.T) {
	ws, id := fixtureStoreWorkspace(t, t.TempDir())
	defer ws.Close()
	web := webanalysis.Finding{ID: webanalysis.ID("store-secret"), Kind: "secret-candidate", Value: "fixture-secret-value", Preview: "fixture-secret-value"}
	if err := ws.Store.PutWeb(context.Background(), "finding", web.ID, "", web); err != nil {
		t.Fatal(err)
	}
	path := ws.Dir
	action := []byte(`{"id":"a-000001","task":"network-task","at":"2026-01-01T00:00:00Z","status":"complete","command":"fixture"}` + "\n")
	if err := os.WriteFile(filepath.Join(path, "actions.jsonl"), action, 0600); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	add := []string{"add", "--workspace", path, "--surface", "network", "--task", "network-task", "--asset", "192.0.2.1", "--title", "Service observed", "--status", "validated", "--evidence", fmt.Sprint(id), "--json"}
	if err := runStoreTo(context.Background(), add, &b, nil, ""); err != nil {
		t.Fatal(err)
	}
	var saved engagement.Finding
	if err := json.Unmarshal(b.Bytes(), &saved); err != nil || saved.Status != engagement.FindingValidated {
		t.Fatalf("saved finding: %+v %v", saved, err)
	}
	b.Reset()
	if err := runStoreTo(context.Background(), []string{"findings", "--workspace", path, "--surface", "network", "--json"}, &b, nil, ""); err != nil {
		t.Fatal(err)
	}
	var findings []engagement.Finding
	if err := json.Unmarshal(b.Bytes(), &findings); err != nil || len(findings) != 1 || findings[0].ID != saved.ID {
		t.Fatalf("findings: %+v %v", findings, err)
	}
	b.Reset()
	if err := runStoreTo(context.Background(), []string{"show", "--workspace", path, "--surface", "network", "--json"}, &b, nil, ""); err != nil {
		t.Fatal(err)
	}
	var overview storeOverview
	if err := json.Unmarshal(b.Bytes(), &overview); err != nil || overview.Surfaces[engagement.SurfaceNetwork]["finding"] != 1 || len(overview.Sample[engagement.SurfaceNetwork]["finding"]) != 1 {
		t.Fatalf("finding overview: %+v %v", overview, err)
	}
	b.Reset()
	if err := runStoreTo(context.Background(), []string{"records", "--workspace", path, "--kind", "action", "--surface", "network", "--json"}, &b, nil, ""); err != nil {
		t.Fatal(err)
	}
	var actions engagement.RecordPage
	if err := json.Unmarshal(b.Bytes(), &actions); err != nil || actions.Total != 1 || len(actions.Records) != 1 {
		t.Fatalf("imported action records: %+v %v", actions, err)
	}
	model := &fakeModel{queue: []*llms.ContentResponse{textResp("A validated service observation was recorded [R1].")}}
	b.Reset()
	if err := runStoreTo(context.Background(), []string{"ask", "--workspace", path, "--surface", "network", "--json", "What was found?"}, &b, model, "fixture-model"); err != nil {
		t.Fatal(err)
	}
	var answer storeAnswer
	if err := json.Unmarshal(b.Bytes(), &answer); err != nil || len(answer.Citations) != 1 || answer.Citations[0].Kind != "finding" || model.calls != 1 {
		t.Fatalf("answer: %+v %v", answer, err)
	}
	webFacts, _, err := storeFacts(context.Background(), ws.Store, engagement.SurfaceWeb, "what was found")
	if err != nil {
		t.Fatal(err)
	}
	for _, fact := range webFacts {
		if strings.Contains(fact.Text, "fixture-secret-value") {
			t.Fatal("secret candidate value entered model facts")
		}
	}
}

func TestStoreImportsCodeParsedFindingsFromExactEvidence(t *testing.T) {
	ws, _ := fixtureStoreWorkspace(t, t.TempDir())
	id, err := ws.Store.RecordEvidence("network-task", "Nmap scan report for 192.0.2.1\n22/tcp open ssh OpenSSH 9.1\nTLSv1.0 enabled\n")
	if err != nil {
		ws.Close()
		t.Fatal(err)
	}
	ws.Close()
	var b bytes.Buffer
	args := []string{"findings", "--workspace", ws.Dir, "--surface", "network", "--json"}
	for pass := 0; pass < 2; pass++ {
		b.Reset()
		if err := runStoreTo(context.Background(), args, &b, nil, ""); err != nil {
			t.Fatal(err)
		}
		var findings []engagement.Finding
		if err := json.Unmarshal(b.Bytes(), &findings); err != nil || len(findings) != 3 {
			t.Fatalf("parsed findings pass %d: %+v %v", pass, findings, err)
		}
		for _, finding := range findings {
			if finding.Source != "code-parsed" || finding.Status != engagement.FindingLead || len(finding.EvidenceIDs) != 1 || finding.EvidenceIDs[0] != id {
				t.Fatalf("finding lost exact provenance: %+v", finding)
			}
		}
	}
	b.Reset()
	if err := runStoreTo(context.Background(), []string{"records", "--workspace", ws.Dir, "--kind", "finding-event", "--surface", "network", "--json"}, &b, nil, ""); err != nil {
		t.Fatal(err)
	}
	var history engagement.RecordPage
	if err := json.Unmarshal(b.Bytes(), &history); err != nil || history.Total != 3 {
		t.Fatalf("parser generated duplicate review events: %+v %v", history, err)
	}
	var event map[string]string
	if err := json.Unmarshal(history.Records[0].Document, &event); err != nil || event["actor"] != "code-parsed" {
		t.Fatalf("parsed event actor: %+v %v", event, err)
	}
}

func TestStoreAnswerRejectsInventedReferences(t *testing.T) {
	ws, _ := fixtureStoreWorkspace(t, t.TempDir())
	defer ws.Close()
	m := &fakeModel{queue: []*llms.ContentResponse{textResp("Unverified claim [R999].")}}
	answer, err := answerStore(context.Background(), ws.Store, "fixture", engagement.SurfaceNetwork, "What was found?", m, "fixture")
	if err != nil || answer.Synthesis != "records" || strings.Contains(answer.Answer, "Unverified claim") || len(answer.Citations) == 0 {
		t.Fatalf("unsupported model answer was not replaced: %+v %v", answer, err)
	}
}

func TestStorePreservesTaskCompletionBasisFromEngagement(t *testing.T) {
	ws, evidenceID := fixtureStoreWorkspace(t, t.TempDir())
	defer ws.Close()
	basis := "The captured banner meets the service observation objective."
	if _, err := ws.Store.Apply(engagement.Delta{
		Kind: "plan_complete", Completes: []string{"network-task"},
		CompletionBasis: basis, CompletionEvidenceIDs: []string{fmt.Sprint(evidenceID)},
	}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runStoreTo(context.Background(), []string{"records", "--workspace", ws.Dir, "--kind", "task", "--surface", "network", "--json"}, &output, nil, ""); err != nil {
		t.Fatal(err)
	}
	var page engagement.RecordPage
	if err := json.Unmarshal(output.Bytes(), &page); err != nil || len(page.Records) != 1 {
		t.Fatalf("task records: count=%d err=%v", len(page.Records), err)
	}
	var task engagement.Task
	if err := json.Unmarshal(page.Records[0].Document, &task); err != nil || task.CompletionBasis != basis || len(task.CompletionEvidenceIDs) != 1 || task.CompletionEvidenceIDs[0] != fmt.Sprint(evidenceID) {
		t.Fatalf("completion basis or evidence lost: err=%v", err)
	}
	model := &fakeModel{queue: []*llms.ContentResponse{textResp("The executor recorded its completion basis [R1].")}}
	if _, err := answerStore(context.Background(), ws.Store, "fixture", engagement.SurfaceNetwork, "Why was this task completed?", model, "fixture"); err != nil {
		t.Fatal(err)
	}
	prompt := fmt.Sprint(model.seen)
	if !strings.Contains(prompt, basis) || !strings.Contains(prompt, "completion_evidence_ids=["+fmt.Sprint(evidenceID)+"]") || !strings.Contains(prompt, "executor's assertion, not independent verification") {
		t.Fatal("answer path omitted or overstated the completion basis")
	}
}

func TestStoreAskRejectsRemoteModelEndpoint(t *testing.T) {
	ws, _ := fixtureStoreWorkspace(t, t.TempDir())
	defer ws.Close()
	t.Setenv("OMLX_BASE_URL", "https://model.example.test/v1")
	var b bytes.Buffer
	err := runStoreTo(context.Background(), []string{"ask", "--workspace", ws.Dir, "What was found?"}, &b, nil, "")
	if err == nil || !strings.Contains(err.Error(), "loopback") || b.Len() != 0 {
		t.Fatalf("remote model accepted: output=%q err=%v", b.String(), err)
	}
}

func TestStoreRegisteredAcrossInteractiveSurfaces(t *testing.T) {
	if _, ok := lookupCommand("store"); !ok {
		t.Fatal("CLI command missing")
	}
	if _, ok := slashCommand("store"); !ok || !isTurnVerb("store") {
		t.Fatal("interactive store command missing or not queued")
	}
	if verb, arg := parseInput("/store list"); verb != "store" || arg != "list" {
		t.Fatalf("TUI parse = %q %q", verb, arg)
	}
	m := newKeyModel(t)
	choices := m.argumentSuggestions("/store fi")
	if len(choices) != 1 || choices[0].value != "/store findings " {
		t.Fatalf("store action completion: %+v", choices)
	}
	next, cmd := m.dispatchInput("/store list")
	if !next.(model).working || cmd == nil {
		t.Fatal("TUI did not dispatch store through a bounded turn")
	}
}

func TestStoreSummaryFitsNarrowTerminal(t *testing.T) {
	ws, _ := fixtureStoreWorkspace(t, t.TempDir())
	defer ws.Close()
	old := useUnicode
	useUnicode = false
	defer func() { useUnicode = old }()
	var b bytes.Buffer
	if err := runStoreTo(context.Background(), []string{"show", "--workspace", ws.Dir, "--surface", "network"}, &b, nil, ""); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if utf8.RuneCountInString(line) > 40 {
			t.Fatalf("store summary exceeds 40 columns: %q", line)
		}
	}
}

func TestStoreInteractiveUsesSharedQueriesAndSelectsEarlierEngagement(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root, err := storeRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"20260101-000000", "20260102-000000"} {
		ws, _ := fixtureStoreWorkspace(t, filepath.Join(root, id))
		ws.Close()
	}
	input := strings.NewReader("list\nuse 20260101-000000\nshow --surface network\nfindings --surface network\nquit\n")
	var out bytes.Buffer
	if err := runStoreInteractive(context.Background(), input, &out, "", ""); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"Selected: 20260102-000000", "Selected: 20260101-000000", "network", "No matching findings."} {
		if !strings.Contains(text, want) {
			t.Fatalf("interactive store lacks %q", want)
		}
	}
}

func TestStoreLocalModelE2E(t *testing.T) {
	if os.Getenv("BLK_STORE_LLM_E2E") != "1" {
		t.Skip("set BLK_STORE_LLM_E2E=1 with a local model server")
	}
	ws, evidenceID := fixtureStoreWorkspace(t, t.TempDir())
	defer ws.Close()
	if _, err := ws.Store.SaveFinding(context.Background(), engagement.Finding{Surface: engagement.SurfaceNetwork, TaskID: "network-task", Asset: "192.0.2.1", Title: "Service banner observed", Status: engagement.FindingValidated, EvidenceIDs: []int64{evidenceID}}); err != nil {
		t.Fatal(err)
	}
	if err := storeLocalModelURL(); err != nil {
		t.Fatal(err)
	}
	client, err := newOMLX(loadConfig(), "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	answer, err := answerStore(ctx, ws.Store, "fixture", engagement.SurfaceNetwork, "What was found? Cite the stored record.", client, client.model)
	if err != nil || answer.Synthesis != "model" || len(answer.Citations) == 0 {
		t.Fatalf("local synthesis did not cite the store: synthesis=%s citations=%d err=%v", answer.Synthesis, len(answer.Citations), err)
	}
}
