package engagement

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"blkchain/cli/internal/webanalysis"
)

func TestWebCredentialEventsConcurrentAndFailure(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "engagement.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var events atomic.Int32
	remove := store.AddOnWebFinding(func([]byte) error { events.Add(1); return nil })
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			f := webanalysis.Finding{ID: webanalysis.ID("credential", string(rune('a'+i))), Kind: "secret-candidate", Value: "fixture-password"}
			if err := store.PutWeb(context.Background(), "finding", f.ID, "fixture-task", f); err != nil {
				t.Error(err)
			}
		}(i)
	}
	group.Wait()
	remove()
	if events.Load() != 8 {
		t.Fatal("credential event missing", events.Load())
	}
	failure := errors.New("stdout unavailable")
	stop := store.AddOnWebFinding(func([]byte) error { return failure })
	defer stop()
	f := webanalysis.Finding{ID: webanalysis.ID("output-failure"), Kind: "secret-candidate", Value: "fixture-value"}
	if err := store.PutWeb(context.Background(), "finding", f.ID, "", f); !errors.Is(err, failure) {
		t.Fatal("output failure was hidden", err)
	}
	snapshot, err := store.WebSnapshot(context.Background())
	if err != nil || len(snapshot.Findings) != 9 {
		t.Fatal("output failure discarded persisted finding", err)
	}
}

func TestWebCredentialLogRejectsSymlinkAndBounds(t *testing.T) {
	for _, test := range []string{"symlink", "limit"} {
		t.Run(test, func(t *testing.T) {
			root := t.TempDir()
			store, err := Open(filepath.Join(root, "engagement.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err = store.webBlobDir(); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(store.EvidenceDir(), "web", "findings.jsonl")
			if test == "symlink" {
				sentinel := filepath.Join(root, "sentinel")
				if err = os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(sentinel, logPath); err != nil {
					t.Fatal(err)
				}
				defer func() {
					data, err := os.ReadFile(sentinel)
					if err != nil || string(data) != "unchanged" {
						t.Fatal("finding log followed symlink")
					}
				}()
			} else {
				file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if err = file.Truncate(32 << 20); err != nil {
					t.Fatal(err)
				}
				file.Close()
			}
			if err = store.appendWebFinding([]byte(`{"finding":"fixture"}`)); err == nil {
				t.Fatal("invalid finding log accepted")
			}
		})
	}
}
