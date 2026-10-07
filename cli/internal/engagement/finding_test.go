package engagement

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"blkchain/cli/internal/webanalysis"
)

func TestFindingRequiresMatchingTaskEvidence(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	id, err := s.RecordEvidence("A", "service banner observed")
	if err != nil {
		t.Fatal(err)
	}
	f := Finding{Surface: SurfaceNetwork, TaskID: "A", Asset: "192.0.2.1", Title: "Service observed", Status: FindingObserved, EvidenceIDs: []int64{id}}
	saved, err := s.SaveFinding(context.Background(), f)
	if err != nil || saved.ID == "" {
		t.Fatalf("save finding: %+v %v", saved, err)
	}
	got, err := s.Finding(context.Background(), saved.ID)
	if err != nil || got.Status != FindingObserved || len(got.EvidenceIDs) != 1 || got.EvidenceIDs[0] != id {
		t.Fatalf("read finding: %+v %v", got, err)
	}
	got.Status = FindingValidated
	updated, err := s.SaveFinding(context.Background(), got)
	if err != nil || updated.CreatedAt != got.CreatedAt {
		t.Fatalf("review finding: %+v %v", updated, err)
	}
	got.Status = FindingDismissed
	if _, err := s.SaveFinding(context.Background(), got); err == nil {
		t.Fatal("stale review overwrote a newer finding")
	}
	events, err := s.Records(context.Background(), "finding-event", SurfaceNetwork, 0, 10)
	if err != nil || events.Total != 2 {
		t.Fatalf("finding review history: %+v %v", events, err)
	}
	var event map[string]string
	if err := json.Unmarshal(events.Records[1].Document, &event); err != nil || event["actor"] != "operator" {
		t.Fatalf("review actor: %+v %v", event, err)
	}
	f.EvidenceIDs = []int64{id + 1}
	if _, err := s.SaveFinding(context.Background(), f); err == nil {
		t.Fatal("accepted an evidence id from another task")
	}
	f.EvidenceIDs = []int64{id}
	f.Surface = SurfaceWeb
	if _, err := s.SaveFinding(context.Background(), f); err == nil {
		t.Fatal("accepted a surface different from its task")
	}
}

func TestWebFindingProjectsAsLeadWithoutCredentialValue(t *testing.T) {
	s := openTemp(t)
	w := webanalysis.Finding{ID: webanalysis.ID("credential-fixture"), Kind: "secret-candidate", Name: "token", Value: "fixture-secret", Preview: "fixture-secret"}
	if err := s.PutWeb(context.Background(), "finding", w.ID, "", w); err != nil {
		t.Fatal(err)
	}
	fs, err := s.Findings(context.Background(), SurfaceWeb)
	if err != nil || len(fs) != 1 || fs[0].Status != FindingLead || strings.Contains(fs[0].Detail, "fixture-secret") {
		t.Fatalf("web lead: %+v %v", fs, err)
	}
	if _, err := s.SaveFinding(context.Background(), Finding{ID: fs[0].ID, Surface: SurfaceWeb, Asset: fs[0].Asset, Title: fs[0].Title, Status: FindingValidated}); err == nil {
		t.Fatal("validated an unproven detector match")
	}
	fs[0].Status = FindingDismissed
	if _, err := s.SaveFinding(context.Background(), fs[0]); err != nil {
		t.Fatal(err)
	}
	got, err := s.Findings(context.Background(), SurfaceWeb)
	if err != nil || len(got) != 1 || got[0].Status != FindingDismissed {
		t.Fatalf("reviewed web lead: %+v %v", got, err)
	}
	events, err := s.Records(context.Background(), "finding-event", SurfaceWeb, 0, 10)
	if err != nil || events.Total != 1 || len(events.Records) != 1 {
		t.Fatalf("review history: %+v %v", events, err)
	}
}
