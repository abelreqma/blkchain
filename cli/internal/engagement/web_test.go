package engagement

import (
	"blkchain/cli/internal/webanalysis"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestWebArtifactExactConcurrentDedupAndVersions(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "engagement.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	body := []byte("exact\x00source\nbytes")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := s.SaveWebArtifact(context.Background(), webanalysis.Artifact{Kind: "script", URL: "https://fixture.test/a", Complete: true}, body); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	snap, e := s.WebSnapshot(context.Background())
	if e != nil || len(snap.Artifacts) != 8 {
		t.Fatal(len(snap.Artifacts), e)
	}
	entries, e := os.ReadDir(filepath.Join(s.EvidenceDir(), "web", "blobs"))
	if e != nil || len(entries) != 1 {
		t.Fatal(entries, e)
	}
	for _, a := range snap.Artifacts {
		b, e := s.WebBlob(a.Hash)
		if e != nil || string(b) != string(body) {
			t.Fatal("exact bytes lost")
		}
	}
	st, _ := os.Stat(filepath.Join(s.EvidenceDir(), "web", "blobs", entries[0].Name()))
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
}
func TestWebArtifactRejectSymlinkAndHostileHash(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "engagement.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.WebBlob("../../etc/passwd"); e == nil {
		t.Fatal("path traversal")
	}
	if e = os.MkdirAll(s.EvidenceDir(), 0700); e != nil {
		t.Fatal(e)
	}
	outside := t.TempDir()
	if e = os.Symlink(outside, filepath.Join(s.EvidenceDir(), "web")); e != nil {
		t.Fatal(e)
	}
	if _, e = s.SaveWebArtifact(context.Background(), webanalysis.Artifact{}, []byte("test")); e == nil {
		t.Fatal("followed symlink")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("wrote through symlink")
	}
}

func TestWebMetadataAggregateLimit(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "engagement.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	data := strings.Repeat("x", 1<<20)
	for i := 0; i < 33; i++ {
		if _, e = s.db.Exec(`INSERT INTO web_record(kind,id,task_id,document,at) VALUES('fixture',?,'',?,'')`, fmt.Sprint(i), data); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.PutWeb(context.Background(), "finding", webanalysis.ID("beyond-limit"), "", webanalysis.Finding{}); e == nil {
		t.Fatal("metadata limit ignored")
	}
}
