package webcollect

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestArchiveRateSharedAcrossQueriesCapturesAndRetries(t *testing.T) {
	var mu sync.Mutex
	starts := []time.Time{}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		starts = append(starts, time.Now())
		requests++
		count := requests
		mu.Unlock()
		if count == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		if r.URL.Path == "/cdx/search/cdx" {
			fmt.Fprint(w, `[["timestamp","original","statuscode","mimetype","digest"],["20200101000000","https://fixture.test/app.js","200","application/javascript","fixture"]]`)
			return
		}
		fmt.Fprint(w, "fixture body")
	}))
	defer server.Close()
	first := &Archive{Base: server.URL, Broker: fixtureBroker(server), Allowed: func(string) bool { return true }}
	second := &Archive{Base: server.URL, Broker: fixtureBroker(server), Allowed: func(string) bool { return true }}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		if _, _, err := first.Query(ctx, "https://fixture.test/app.js", "exact", "", ""); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer group.Done()
		if _, err := second.Fetch(ctx, Capture{Timestamp: "20200101000000", Original: "https://fixture.test/app.js"}); err != nil {
			t.Error(err)
		}
	}()
	group.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(starts) != 3 {
		t.Fatalf("got %d requests; want initial attempt, retry and other archive request", len(starts))
	}
	for i := 1; i < len(starts); i++ {
		if delta := starts[i].Sub(starts[i-1]); delta < time.Second {
			t.Fatalf("Wayback requests %d and %d were only %v apart; need at least one second", i-1, i, delta)
		}
	}
}

func TestArchiveRateCancelledWaitDoesNotSend(t *testing.T) {
	var mu sync.Mutex
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		fmt.Fprint(w, `[["timestamp","original","statuscode","mimetype","digest"]]`)
	}))
	defer server.Close()
	archive := &Archive{Base: server.URL, Broker: fixtureBroker(server), Allowed: func(string) bool { return true }}
	if _, _, err := archive.Query(context.Background(), "https://fixture.test/app.js", "exact", "", ""); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, _, err := archive.Query(ctx, "https://fixture.test/app.js", "exact", "", ""); err == nil {
		t.Fatal("rate wait ignored cancellation")
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("cancelled rate wait blocked")
	}
	mu.Lock()
	defer mu.Unlock()
	if count != 1 {
		t.Fatal("cancelled wait sent another request", count)
	}
}
