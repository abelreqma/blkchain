package engagement

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEngagementWorkBudgetPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engagement.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 4, 18, 0, 0, 0, time.UTC)
	got, err := first.EnsureEngagementStart(start)
	if err != nil || !got.Equal(start) {
		t.Fatalf("start=%s err=%v", got, err)
	}
	for i := 0; i < 2; i++ {
		ok, err := first.ReserveEngagementAction(2)
		if err != nil || !ok {
			t.Fatalf("action %d allowed=%t err=%v", i+1, ok, err)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	resumed, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	got, err = resumed.EnsureEngagementStart(start.Add(time.Hour))
	if err != nil || !got.Equal(start) {
		t.Fatalf("resumed start=%s err=%v", got, err)
	}
	if ok, err := resumed.ReserveEngagementAction(2); err != nil || ok {
		t.Fatalf("resumed action allowed=%t err=%v", ok, err)
	}
}

func TestEngagementWorkBudgetConcurrentExactCap(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "engagement.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var allowed atomic.Int32
	var wg sync.WaitGroup
	errorsSeen := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.ReserveEngagementAction(5)
			if err != nil {
				errorsSeen <- err
			} else if ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Errorf("reserve: %v", err)
	}
	if allowed.Load() != 5 {
		t.Fatalf("allowed=%d, want 5", allowed.Load())
	}
}
