package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestDomainForKnownAndUnknown(t *testing.T) {
	if d := domainFor("web"); d.Name != "web" {
		t.Errorf("domainFor(web).Name = %q", d.Name)
	}
	if d := domainFor("totally-unknown-kind"); d.Name != "generic" {
		t.Errorf("unknown kind should map to generic, got %q", d.Name)
	}
	if d := domainFor("web"); strings.TrimSpace(d.Prompt) == "" {
		t.Error("web domain has empty prompt")
	}
}

func TestProjectionTextShowsCoverageAndDiscoveries(t *testing.T) {
	st := openStore(t) // from plantools_test.go, same package
	if _, err := newPlanAddTool(st).Call(context.Background(), `{"id":"t1","kind":"recon","target":"10.0.0.5","objective":"enumerate"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := newPlanAddTool(st).Call(context.Background(), `{"id":"t2","kind":"web","target":"10.0.0.5","objective":"login flow"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := newRecordEvidenceTool(st).Call(context.Background(), `{"task_id":"t1","quote":"port 22 open"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := newPlanCompleteTool(st).Call(context.Background(), `{"id":"t1"}`); err != nil {
		t.Fatal(err)
	}
	out, err := projectionText(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "t2") {
		t.Errorf("projection missing open task t2:\n%s", out)
	}
	if !strings.Contains(out, "t1") {
		t.Errorf("projection missing discovered task t1:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "coverage") {
		t.Errorf("projection missing coverage line:\n%s", out)
	}
}

func TestProjectionTextCapsLongLists(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	n := projectionMaxPerList + 5
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("t%d", i)
		if _, err := newPlanAddTool(st).Call(ctx, fmt.Sprintf(`{"id":%q,"kind":"recon","target":"h","objective":"o"}`, id)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("d%d", i)
		if _, err := newPlanAddTool(st).Call(ctx, fmt.Sprintf(`{"id":%q,"kind":"web","target":"h","objective":"o","status":"na"}`, id)); err != nil {
			t.Fatal(err)
		}
	}
	out, err := projectionText(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out, "... (+5 more)"); got != 2 {
		t.Errorf("tail count = %d, want 2 (one per list):\n%s", got, out)
	}
	if got := strings.Count(out, "\n- "); got != 2*projectionMaxPerList {
		t.Errorf("listed lines = %d, want %d", got, 2*projectionMaxPerList)
	}
}
