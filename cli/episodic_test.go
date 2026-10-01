package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/histstore"
)

// newTestEpisodicDB opens the shared history database at a temp path and returns
// its handle, the seam the episodic store writes its own table onto.
func newTestEpisodicDB(t *testing.T) *sql.DB {
	t.Helper()
	hs, err := histstore.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatalf("histstore.Open: %v", err)
	}
	t.Cleanup(func() { hs.Close() })
	return hs.DB()
}

// Slice 1 seam: the episodicStore public methods (record, priorFor), backed by
// the blk_episodic table on the shared history database. We observe behavior
// only through those methods, never the raw table.
func TestEpisodicStoreRecordAndQueryByProduct(t *testing.T) {
	ctx := context.Background()
	es, err := newEpisodicStore(newTestEpisodicDB(t))
	if err != nil {
		t.Fatalf("newEpisodicStore: %v", err)
	}

	eps := []episode{
		{Kind: "correlate", Engagement: "e1", Product: "openssh", Technique: "known-CVE exploitation of OpenSSH", Target: "10.0.0.1:22", Rev: 3},
		{Kind: "vantage-advance", Engagement: "e1", Outcome: "internal-foothold", Product: "openssh", Technique: "known-CVE exploitation of OpenSSH", Target: "10.0.0.1:22", Rev: 5},
		{Kind: "correlate", Engagement: "e1", Product: "nginx", Technique: "known-CVE exploitation of nginx", Target: "10.0.0.2:80", Rev: 4},
	}
	for _, ep := range eps {
		if err := es.record(ctx, ep); err != nil {
			t.Fatalf("record %+v: %v", ep, err)
		}
	}

	// Case-insensitive product match, newest first (highest id first).
	got, err := es.priorFor(ctx, "OpenSSH", 5)
	if err != nil {
		t.Fatalf("priorFor: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("priorFor(OpenSSH) returned %d episodes, want 2: %+v", len(got), got)
	}
	if got[0].Kind != "vantage-advance" || got[0].Outcome != "internal-foothold" {
		t.Fatalf("newest episode = %+v, want the vantage-advance recorded last", got[0])
	}
	if got[1].Technique != "known-CVE exploitation of OpenSSH" {
		t.Fatalf("second episode technique = %q", got[1].Technique)
	}

	// A product with no episodes yields none, not an error.
	none, err := es.priorFor(ctx, "vsftpd", 5)
	if err != nil {
		t.Fatalf("priorFor(vsftpd): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("priorFor(vsftpd) = %+v, want none", none)
	}
}

// Slice 2a seam: the AddOnApply listener. We attach it to a real engagement
// store, drive committed transitions, and observe the episodes it writes through
// the episodicStore. A correlate transition (a new exploit candidate task) and a
// vantage advance each produce a product-keyed episode; the first snapshot is a
// baseline that records nothing.
func TestEpisodicListenerRecordsCorrelateAndVantage(t *testing.T) {
	ctx := context.Background()
	es, err := newEpisodicStore(newTestEpisodicDB(t))
	if err != nil {
		t.Fatalf("newEpisodicStore: %v", err)
	}
	st, err := engagement.Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatalf("engagement.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	remove := st.AddOnApply(newEpisodicApplyListener(es))
	defer remove()

	// #1 baseline: name only, no exploit task, no vantage -> records nothing.
	name := "eng-alpha"
	if _, err := st.Apply(engagement.Delta{SetName: &name, Kind: "init"}); err != nil {
		t.Fatalf("apply init: %v", err)
	}
	// #2 correlate: a new exploit candidate task appears.
	exploit := engagement.Task{
		ID:        "exploit-10.0.0.1-22-openssh",
		Kind:      "exploit",
		Target:    "10.0.0.1:22",
		Objective: "known-CVE exploitation of OpenSSH against OpenSSH 7.2",
		Status:    engagement.StatusTodo,
		Phase:     engagement.PhaseExploit,
		Surface:   engagement.SurfaceNetwork,
		Citation:  engagement.Citation{Source: "offensive-rce", Path: "ssh.md", Origin: "trusted"},
	}
	if _, err := st.Apply(engagement.Delta{Upserts: []engagement.Task{exploit}, Kind: "correlate"}); err != nil {
		t.Fatalf("apply correlate: %v", err)
	}
	// #3 vantage advance, with the exploit task now done.
	exploit.Status = engagement.StatusDone
	v := engagement.VantageInternalFoothold
	if _, err := st.Apply(engagement.Delta{Upserts: []engagement.Task{exploit}, SetVantage: &v, Kind: "advance"}); err != nil {
		t.Fatalf("apply advance: %v", err)
	}

	got, err := es.priorFor(ctx, "OpenSSH", 10)
	if err != nil {
		t.Fatalf("priorFor: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("recorded %d episodes, want 2 (correlate + vantage-advance): %+v", len(got), got)
	}
	if got[0].Kind != "vantage-advance" || got[0].Outcome != "internal-foothold" {
		t.Fatalf("newest episode = %+v, want vantage-advance internal-foothold", got[0])
	}
	if got[0].Engagement != "eng-alpha" {
		t.Fatalf("episode engagement = %q, want eng-alpha", got[0].Engagement)
	}
	if got[1].Kind != "correlate" || got[1].Citation.Source != "offensive-rce" {
		t.Fatalf("oldest episode = %+v, want correlate with citation", got[1])
	}
}

// The first snapshot the listener sees is a baseline: pre-existing tasks and an
// already-set vantage are NOT recorded as transitions.
func TestEpisodicListenerBaselineRecordsNothing(t *testing.T) {
	ctx := context.Background()
	es, err := newEpisodicStore(newTestEpisodicDB(t))
	if err != nil {
		t.Fatalf("newEpisodicStore: %v", err)
	}
	l := newEpisodicApplyListener(es)
	exploit := engagement.Task{ID: "exploit-h-22-openssh", Kind: "exploit", Objective: "x against OpenSSH 7.2", Status: engagement.StatusDone}
	// First call: an engagement that already has an exploit task and a vantage.
	l(5, engagement.Engagement{Revision: 5, Name: "e", Tasks: []engagement.Task{exploit}, Vantage: engagement.VantageInternalFoothold})
	got, err := es.priorFor(ctx, "OpenSSH", 10)
	if err != nil {
		t.Fatalf("priorFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("baseline recorded %d episodes, want 0: %+v", len(got), got)
	}
}

// A snapshot delivered out of order (a lower revision than one already seen) does
// not record a vantage transition; listeners may fire from multiple goroutines
// and out of order.
func TestEpisodicListenerVantageIgnoresStaleRev(t *testing.T) {
	ctx := context.Background()
	es, err := newEpisodicStore(newTestEpisodicDB(t))
	if err != nil {
		t.Fatalf("newEpisodicStore: %v", err)
	}
	l := newEpisodicApplyListener(es)
	exploit := engagement.Task{ID: "exploit-h-22-openssh", Kind: "exploit", Objective: "x against OpenSSH 7.2", Status: engagement.StatusDone}
	// Baseline at rev 1 (no vantage).
	l(1, engagement.Engagement{Revision: 1, Name: "e", Tasks: []engagement.Task{exploit}})
	// Advance at rev 3: records a vantage-advance episode.
	l(3, engagement.Engagement{Revision: 3, Name: "e", Tasks: []engagement.Task{exploit}, Vantage: engagement.VantageInternalFoothold})
	// Stale delivery at rev 2 (< max seen 3): must be ignored for vantage.
	l(2, engagement.Engagement{Revision: 2, Name: "e", Tasks: []engagement.Task{exploit}, Vantage: engagement.VantageExternalAuth})

	got, err := es.priorFor(ctx, "OpenSSH", 10)
	if err != nil {
		t.Fatalf("priorFor: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("recorded %d vantage episodes, want 1 (stale rev ignored): %+v", len(got), got)
	}
	if got[0].Outcome != "internal-foothold" {
		t.Fatalf("episode outcome = %q, want internal-foothold", got[0].Outcome)
	}
}

// The listener is safe to fire from multiple goroutines, as AddOnApply may do
// under concurrent writers. Run under -race.
func TestEpisodicListenerConcurrentApply(t *testing.T) {
	ctx := context.Background()
	es, err := newEpisodicStore(newTestEpisodicDB(t))
	if err != nil {
		t.Fatalf("newEpisodicStore: %v", err)
	}
	l := newEpisodicApplyListener(es)
	l(1, engagement.Engagement{Revision: 1, Name: "e"}) // baseline

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			task := engagement.Task{ID: "exploit-h-22-openssh-" + strconv.Itoa(k), Kind: "exploit", Objective: "t against OpenSSH 7.2"}
			l(int64(k+2), engagement.Engagement{Revision: int64(k + 2), Name: "e", Tasks: []engagement.Task{task}})
		}(i)
	}
	wg.Wait()

	got, err := es.priorFor(ctx, "OpenSSH", 100)
	if err != nil {
		t.Fatalf("priorFor: %v", err)
	}
	if len(got) != n {
		t.Fatalf("recorded %d correlate episodes, want %d (one per unique task)", len(got), n)
	}
}

// The limit bounds the number of episodes returned.
func TestEpisodicStorePriorForLimit(t *testing.T) {
	ctx := context.Background()
	es, err := newEpisodicStore(newTestEpisodicDB(t))
	if err != nil {
		t.Fatalf("newEpisodicStore: %v", err)
	}
	for i := 0; i < 10; i++ {
		if err := es.record(ctx, episode{Kind: "correlate", Engagement: "e1", Product: "openssh", Technique: "t", Rev: int64(i)}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	got, err := es.priorFor(ctx, "openssh", 3)
	if err != nil {
		t.Fatalf("priorFor: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("priorFor limit 3 returned %d, want 3", len(got))
	}
}

// The init() registration wires the episodic listener into the foundation
// multi-flow registry, so runOrchestrator attaches it on every engage flow.
func TestEpisodicRegisteredWithOnApply(t *testing.T) {
	if len(onApplyListeners) == 0 {
		t.Fatal("episodic listener was not registered via registerOnApply init()")
	}
}

// The lazy wrapper activates at most once and then delegates every apply; the
// read-hint is installed on that first activation.
func TestLazyEpisodicActivatesOnceAndDelegates(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	priorEpisodeHint = nil
	t.Cleanup(func() { priorEpisodeHint = nil })

	calls := 0
	le := &lazyEpisodic{activate: func() (func(rev int64, e engagement.Engagement), func()) {
		calls++
		return activateEpisodicMemory()
	}}
	exploit := engagement.Task{ID: "exploit-h-22-openssh", Kind: "exploit", Objective: "t against OpenSSH 7.2", Status: engagement.StatusDone}
	le.onApply(1, engagement.Engagement{Revision: 1, Name: "e", Tasks: []engagement.Task{exploit}}) // baseline, activates
	le.onApply(2, engagement.Engagement{Revision: 2, Name: "e", Tasks: []engagement.Task{exploit}, Vantage: engagement.VantageInternalFoothold})

	if calls != 1 {
		t.Fatalf("activate ran %d times, want exactly once", calls)
	}
	if priorEpisodeHint == nil {
		t.Fatal("lazy activation did not install the read-hint")
	}
	if lines := priorEpisodeHint(Service{Product: "OpenSSH"}); len(lines) == 0 {
		t.Fatal("no advisory lines after lazy activation and a vantage advance")
	}
}

// Slice 2b seam: activateEpisodicMemory, the production entry the held init()
// registration line will call. It opens the shared history db (under a temp
// XDG_DATA_HOME here), installs the read-hint, and returns the listener; driving
// a vantage advance through the listener makes the hint surface it. cleanup
// clears the hint.
func TestActivateEpisodicMemoryInstallsHintAndListener(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	priorEpisodeHint = nil
	t.Cleanup(func() { priorEpisodeHint = nil })

	listener, cleanup := activateEpisodicMemory()
	if listener == nil {
		t.Fatal("listener is nil; the history db should open under a temp XDG_DATA_HOME")
	}
	if priorEpisodeHint == nil {
		t.Fatal("activate did not install the read-hint")
	}

	exploit := engagement.Task{ID: "exploit-h-22-openssh", Kind: "exploit", Objective: "known-CVE exploitation of OpenSSH against OpenSSH 7.2", Target: "h:22", Status: engagement.StatusDone}
	listener(1, engagement.Engagement{Revision: 1, Name: "e", Tasks: []engagement.Task{exploit}}) // baseline
	listener(2, engagement.Engagement{Revision: 2, Name: "e", Tasks: []engagement.Task{exploit}, Vantage: engagement.VantageInternalFoothold})

	lines := priorEpisodeHint(Service{Product: "OpenSSH", Version: "7.2"})
	if len(lines) == 0 {
		t.Fatal("hint returned no advisory lines for a product with a recorded episode")
	}
	if joined := strings.Join(lines, "\n"); !strings.Contains(joined, "internal-foothold") {
		t.Fatalf("advisory line missing the reached vantage: %q", joined)
	}

	cleanup()
	if priorEpisodeHint != nil {
		t.Fatal("cleanup did not clear the read-hint")
	}
}

// Slice 3 (decoupled) seam: the read side's OWN contract, hintFor(), tested
// DIRECTLY and independently of any consumer. This replaces the earlier tests
// that asserted surfacing into the exploit-selector's model prompt, so the read
// side stays pinned whether its consumer is the selector prompt or (after the
// deterministic drift fix removes that model call) an operator-facing advisory in
// correlateNewEvidence. The NON-BINDING property is inherently consumer-specific
// (it needs the consumer to express "the hint never changes the decision"), so it
// is owned by each consumer's own test, not here - today the selector's model
// path, and after the drift fix the deterministic path's own non-binding test.

// hintFor returns advisory lines for a product with recorded episodes, newest
// first, naming the reached vantage for a vantage-advance episode and the
// candidate form for a correlate episode. It is reference-only prose, never a
// command.
func TestHintForReturnsAdvisoryLinesNewestFirst(t *testing.T) {
	ctx := context.Background()
	es, err := newEpisodicStore(newTestEpisodicDB(t))
	if err != nil {
		t.Fatalf("newEpisodicStore: %v", err)
	}
	if err := es.record(ctx, episode{Kind: "correlate", Engagement: "e1", Product: "openssh", Technique: "known-CVE exploitation of OpenSSH"}); err != nil {
		t.Fatalf("record correlate: %v", err)
	}
	if err := es.record(ctx, episode{Kind: "vantage-advance", Engagement: "e1", Outcome: "internal-foothold", Product: "openssh", Technique: "known-CVE exploitation of OpenSSH"}); err != nil {
		t.Fatalf("record vantage: %v", err)
	}

	lines := es.hintFor(ctx, Service{Product: "OpenSSH"})
	if len(lines) != 2 {
		t.Fatalf("hintFor returned %d lines, want 2: %+v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "internal-foothold") || !strings.Contains(lines[0], "engagement e1") {
		t.Fatalf("newest line = %q, want the vantage-advance naming the reached vantage + engagement", lines[0])
	}
	if !strings.Contains(lines[1], "prior candidate") {
		t.Fatalf("oldest line = %q, want the correlate candidate form", lines[1])
	}
}

// hintFor is bounded to maxEpisodeHints regardless of how many episodes match.
func TestHintForBounded(t *testing.T) {
	ctx := context.Background()
	es, err := newEpisodicStore(newTestEpisodicDB(t))
	if err != nil {
		t.Fatalf("newEpisodicStore: %v", err)
	}
	for i := 0; i < maxEpisodeHints+5; i++ {
		if err := es.record(ctx, episode{Kind: "correlate", Engagement: "e1", Product: "openssh", Technique: "t", Rev: int64(i)}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	if lines := es.hintFor(ctx, Service{Product: "OpenSSH"}); len(lines) != maxEpisodeHints {
		t.Fatalf("hintFor returned %d lines, want capped at %d", len(lines), maxEpisodeHints)
	}
}

// hintFor returns nothing for a product with no episodes or an empty product -
// the read side fails closed, mirroring the selector's empty path.
func TestHintForEmptyWhenNoMatch(t *testing.T) {
	ctx := context.Background()
	es, err := newEpisodicStore(newTestEpisodicDB(t))
	if err != nil {
		t.Fatalf("newEpisodicStore: %v", err)
	}
	if err := es.record(ctx, episode{Kind: "correlate", Engagement: "e1", Product: "openssh", Technique: "t"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if lines := es.hintFor(ctx, Service{Product: "vsftpd"}); len(lines) != 0 {
		t.Fatalf("hintFor(vsftpd) = %+v, want none", lines)
	}
	if lines := es.hintFor(ctx, Service{Product: "   "}); len(lines) != 0 {
		t.Fatalf("hintFor(blank) = %+v, want none", lines)
	}
}

// Citation round-trips through the stored JSON so provenance survives recall.
func TestEpisodicStoreCitationRoundTrip(t *testing.T) {
	ctx := context.Background()
	es, err := newEpisodicStore(newTestEpisodicDB(t))
	if err != nil {
		t.Fatalf("newEpisodicStore: %v", err)
	}
	cit := engagement.Citation{Source: "offensive-rce", Path: "ssh.md", Section: "SSH", CWEClass: "CWE-78", Origin: "trusted"}
	if err := es.record(ctx, episode{Kind: "correlate", Engagement: "e1", Product: "openssh", Technique: "t", Citation: cit}); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, err := es.priorFor(ctx, "openssh", 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("priorFor: %v (%d rows)", err, len(got))
	}
	if got[0].Citation != cit {
		t.Fatalf("citation = %+v, want %+v", got[0].Citation, cit)
	}
}
