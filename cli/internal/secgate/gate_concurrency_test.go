package secgate

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestConcurrentAuthorizeSharedBudget asserts the shared episode command budget
// is exact under concurrent Authorize: exactly MaxCommands calls are allowed
// and the rest hit the cap, with no data race.
func TestConcurrentAuthorizeSharedBudget(t *testing.T) {
	s, err := ParseScope(strings.NewReader("local\n"))
	if err != nil {
		t.Fatal(err)
	}
	const capN, n = 40, 100
	// Local scope requires per-command confirmation; an approving confirmer lets
	// commands through so the episode budget (the subject here) is what bounds them.
	g := &Gate{
		Mode:    Auto,
		Scope:   s,
		Allow:   NewAllowlist("id"),
		Confirm: stubConfirmer{true},
		Episode: NewEpisode(Caps{MaxCommands: capN}, nil),
	}
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	var allowed, denied atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.Authorize(context.Background(), Command{Binary: "id"}).Allowed {
				allowed.Add(1)
			} else {
				denied.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != capN || denied.Load() != n-capN {
		t.Errorf("allowed=%d denied=%d, want %d and %d", allowed.Load(), denied.Load(), capN, n-capN)
	}
	if g.Episode.count != capN {
		t.Errorf("episode count = %d, want %d", g.Episode.count, capN)
	}
}

// TestConcurrentAuthorizeSafeApprovals drives the SessionApprovals map from many
// goroutines through the Safe confirmation path.
func TestConcurrentAuthorizeSafeApprovals(t *testing.T) {
	const n = 100
	g := &Gate{
		Mode:      Safe,
		Allow:     NewAllowlist("id"),
		Confirm:   stubConfirmer{true},
		Approvals: NewSessionApprovals(),
		Episode:   NewEpisode(Caps{MaxCommands: 1000}, nil),
	}
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := Command{Binary: "id", Args: []string{fmt.Sprintf("u%d", i%10)}}
			if !g.Authorize(context.Background(), c).Allowed {
				bad.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Errorf("%d commands denied, want 0", bad.Load())
	}
	if got := len(g.Approvals.approved); got != 10 {
		t.Errorf("approvals = %d, want 10", got)
	}
}
