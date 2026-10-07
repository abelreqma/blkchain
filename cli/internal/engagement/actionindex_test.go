package engagement

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestActionTranscriptImportIsIdempotentAndSurfaceScoped(t *testing.T) {
	s := openTemp(t)
	seedAB(t, s)
	path := filepath.Join(t.TempDir(), "actions.jsonl")
	line := []byte(`{"id":"a-000001","task":"A","at":"2026-01-01T00:00:00Z","status":"complete","command":"fixture"}` + "\n")
	if err := os.WriteFile(path, line, 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.ImportActionTranscript(context.Background(), path); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.Records(context.Background(), "action", SurfaceNetwork, 0, 10)
	if err != nil || page.Total != 1 || len(page.Records) != 1 || page.Records[0].TaskID != "A" {
		t.Fatalf("indexed actions: %+v %v", page, err)
	}
	if err := os.WriteFile(path, append(line, []byte(`{"id":"a-000002","task":"A","at":"2026-01-01T00:00:01Z","status":"complete"}`)...), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportActionTranscript(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	page, err = s.Records(context.Background(), "action", SurfaceNetwork, 0, 10)
	if err != nil || page.Total != 1 {
		t.Fatalf("partial action line imported: %+v %v", page, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("\n")); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if err := s.ImportActionTranscript(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	page, err = s.Records(context.Background(), "action", SurfaceNetwork, 0, 10)
	if err != nil || page.Total != 2 {
		t.Fatalf("complete action line missing: %+v %v", page, err)
	}
	if err := os.WriteFile(path, line, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportActionTranscript(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	page, err = s.Records(context.Background(), "action", SurfaceNetwork, 0, 10)
	if err != nil || page.Total != 2 {
		t.Fatalf("indexed action history was lost: %+v %v", page, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportActionTranscript(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	page, err = s.Records(context.Background(), "action", SurfaceNetwork, 0, 10)
	if err != nil || page.Total != 2 {
		t.Fatalf("indexed actions depended on the raw file: %+v %v", page, err)
	}
}

func TestActionTranscriptImportRejectsSymlinkAndRollsBack(t *testing.T) {
	s := openTemp(t)
	root := t.TempDir()
	path := filepath.Join(root, "actions.jsonl")
	if err := os.WriteFile(path, []byte(`{"at":"2026-01-01T00:00:00Z","status":"complete"}`+"\n"+`{"bad":`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportActionTranscript(context.Background(), path); err == nil {
		t.Fatal("accepted invalid action line")
	}
	page, err := s.Records(context.Background(), "action", "", 0, 10)
	if err != nil || page.Total != 0 {
		t.Fatalf("failed import committed rows: %+v %v", page, err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportActionTranscript(context.Background(), link); err == nil {
		t.Fatal("followed transcript symlink")
	}
}
