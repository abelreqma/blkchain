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

func TestFindingNotificationsObserveOnlyCommittedChanges(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	id, err := s.RecordEvidence("A", "fixture observation")
	if err != nil {
		t.Fatal(err)
	}
	observed := 0
	remove := s.AddOnFinding(func() {
		if !s.wmu.TryLock() {
			t.Error("finding callback ran under the write lock")
			return
		}
		s.wmu.Unlock()
		findings, _, err := s.ReportFindings(context.Background(), 10)
		if err != nil || len(findings) != 1 {
			t.Errorf("callback could not read committed finding: %v %v", findings, err)
		}
		observed++
	})
	f := Finding{Surface: SurfaceNetwork, TaskID: "A", Asset: "192.0.2.1", Title: "Fixture", Status: FindingObserved, EvidenceIDs: []int64{id}}
	saved, err := s.SaveFinding(context.Background(), f)
	if err != nil || observed != 1 {
		t.Fatalf("committed notification: %d %v", observed, err)
	}
	f.EvidenceIDs = []int64{id + 1}
	if _, err := s.SaveFinding(context.Background(), f); err == nil || observed != 1 {
		t.Fatalf("invalid save notified: %d %v", observed, err)
	}
	remove()
	saved.Status = FindingDismissed
	if _, err := s.SaveFinding(context.Background(), saved); err != nil || observed != 1 {
		t.Fatalf("removed observer notified: %d %v", observed, err)
	}
}

func TestReportFindingsSignalsTruncation(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	id, err := s.RecordEvidence("A", "fixture observation")
	if err != nil {
		t.Fatal(err)
	}
	for _, title := range []string{"First", "Second"} {
		_, err := s.SaveFinding(context.Background(), Finding{Surface: SurfaceNetwork, TaskID: "A", Asset: "192.0.2.1", Title: title, Status: FindingObserved, EvidenceIDs: []int64{id}})
		if err != nil {
			t.Fatal(err)
		}
	}
	findings, partial, err := s.ReportFindings(context.Background(), 1)
	if err != nil || len(findings) != 1 || findings[0].Title != "First" || !partial {
		t.Fatalf("bounded findings: %+v partial=%v err=%v", findings, partial, err)
	}
	findings, partial, err = s.ReportFindings(context.Background(), 2)
	if err != nil || len(findings) != 2 || partial {
		t.Fatalf("complete findings: %+v partial=%v err=%v", findings, partial, err)
	}
	if _, _, err := s.ReportFindings(context.Background(), 1001); err == nil {
		t.Fatal("accepted an unbounded report limit")
	}
}
