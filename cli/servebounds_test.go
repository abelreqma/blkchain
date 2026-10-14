package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

// servebounds_test.go covers what bounds `blk serve`: the turns in flight, one
// turn's wall clock, one stream's bytes, and the request rate. No model runs;
// adaptiveAnswerFn is replaced, here by a router a test can hold in flight so
// the bound is reached with a turn that is still running.

// serveHeldTurns is a router that blocks every turn until the test lets it
// finish, so a test holds real turns in flight while it sends another request.
type serveHeldTurns struct {
	started chan struct{}
	done    chan struct{}
	once    sync.Once
	ran     atomic.Int32
}

// finish lets every held turn return. It is idempotent, so a test that calls it
// and the cleanup that calls it again both work.
func (h *serveHeldTurns) finish() {
	h.once.Do(func() { close(h.done) })
}

// installServeHeldRouter replaces the router with one that reports each turn as
// started and then blocks. hold is how many turns may be in flight at once,
// which is the depth of the started channel.
func installServeHeldRouter(t *testing.T, hold int) *serveHeldTurns {
	t.Helper()
	h := &serveHeldTurns{started: make(chan struct{}, hold), done: make(chan struct{})}
	prev := adaptiveAnswerFn
	t.Cleanup(func() {
		h.finish()
		adaptiveAnswerFn = prev
	})
	adaptiveAnswerFn = func(ctx context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		h.ran.Add(1)
		h.started <- struct{}{}
		select {
		case <-h.done:
		case <-ctx.Done():
			return "", []citation{}, false, []retrieval.Result{}, 0, "rag", ctx.Err()
		}
		if opts.Stream != nil {
			opts.Stream([]byte("an answer"))
		}
		return "an answer", []citation{}, false, []retrieval.Result{}, 7, "rag", nil
	}
	return h
}

// serveBoundsTurnPath is one owned session's turn path.
func serveBoundsTurnPath(id, suffix string) string {
	return serveSessionsPath + "/" + id + suffix
}

func TestServeRefusesASecondTurnOnTheSameSession(t *testing.T) {
	s, id := serveTurnServer(t, serveOpts{}, "")
	h := installServeHeldRouter(t, 1)
	path := serveBoundsTurnPath(id, serveTurnsSuffix)

	var first *httptest.ResponseRecorder
	ran := make(chan struct{})
	go func() {
		defer close(ran)
		first = serveTurnDo(s, serveTurnPost(t, path, "127.0.0.1:54321", `{"message":"q"}`))
	}()
	<-h.started

	// A second turn on the session the first one holds is refused, not queued:
	// runNativeTurn holds that session's turn lock for the whole turn, so
	// queueing would hold a connection on a lock instead.
	second := serveTurnDo(s, serveTurnPost(t, path, "127.0.0.1:54321", `{"message":"q"}`))
	if second.Code != http.StatusConflict {
		t.Fatalf("a second turn on the same session: status = %d, want %d; body %q", second.Code, http.StatusConflict, second.Body.String())
	}
	if !strings.Contains(second.Body.String(), "already in flight") {
		t.Errorf("the refusal body = %q, want it to name the turn in flight", second.Body.String())
	}

	// The first one still completes, so the gate refused the second request and
	// did not disturb the turn it was holding.
	h.finish()
	<-ran
	if first.Code != http.StatusOK {
		t.Fatalf("the held turn: status = %d, want %d; body %q", first.Code, http.StatusOK, first.Body.String())
	}
	var got turnResult
	if err := json.Unmarshal(first.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode the held turn %q: %v", first.Body.String(), err)
	}
	if got.Answer != "an answer" {
		t.Errorf("the held turn's answer = %q, want %q", got.Answer, "an answer")
	}
	if h.ran.Load() != 1 {
		t.Errorf("the router ran %d turns, want 1: the refused request ran one too", h.ran.Load())
	}

	// And the session takes a turn again once the first has released it.
	again := serveTurnDo(s, serveTurnPost(t, path, "127.0.0.1:54321", `{"message":"q"}`))
	if again.Code != http.StatusOK {
		t.Errorf("a turn after the first released: status = %d, want %d; body %q", again.Code, http.StatusOK, again.Body.String())
	}
}

func TestServeRefusesATurnPastTheConcurrencyCap(t *testing.T) {
	s, _ := serveTurnServer(t, serveOpts{}, "")
	h := installServeHeldRouter(t, serveMaxConcurrentTurns)

	// One session per turn, so the per-session check is not what refuses, plus
	// one past the cap.
	ids := make([]string, serveMaxConcurrentTurns+1)
	for i := range ids {
		ids[i] = writeSessionOnDisk(t, fmt.Sprintf("20260101T000000-%06x", i), turnRecord{Role: roleUser, Content: "an earlier turn"})
		s.owned.own(ids[i])
	}

	recs := make([]*httptest.ResponseRecorder, serveMaxConcurrentTurns)
	var wg sync.WaitGroup
	for i := range recs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recs[i] = serveTurnDo(s, serveTurnPost(t, serveBoundsTurnPath(ids[i], serveTurnsSuffix), "127.0.0.1:54321", `{"message":"q"}`))
		}()
	}
	for range serveMaxConcurrentTurns {
		<-h.started
	}

	over := serveTurnDo(s, serveTurnPost(t, serveBoundsTurnPath(ids[serveMaxConcurrentTurns], serveTurnsSuffix), "127.0.0.1:54321", `{"message":"q"}`))
	if over.Code != http.StatusServiceUnavailable {
		t.Fatalf("a turn past the cap of %d: status = %d, want %d; body %q", serveMaxConcurrentTurns, over.Code, http.StatusServiceUnavailable, over.Body.String())
	}
	// The server's own message, not the per-session one: "already in flight"
	// alone is satisfied by the 409 as well, so it would not tell the two
	// refusals apart.
	if want := fmt.Sprintf("%d turns are already in flight", serveMaxConcurrentTurns); !strings.Contains(over.Body.String(), want) {
		t.Errorf("the refusal body = %q, want it to name the %q bound", over.Body.String(), want)
	}

	h.finish()
	wg.Wait()
	for i, rec := range recs {
		if rec.Code != http.StatusOK {
			t.Errorf("held turn %d: status = %d, want %d; body %q", i, rec.Code, http.StatusOK, rec.Body.String())
		}
	}
	if got := h.ran.Load(); got != int32(serveMaxConcurrentTurns) {
		t.Errorf("the router ran %d turns, want %d: the refused request ran one too", got, serveMaxConcurrentTurns)
	}

	// A slot freed by a turn that finished admits the next turn, so the cap
	// bounds what runs at once and not how many a client may ever run.
	after := serveTurnDo(s, serveTurnPost(t, serveBoundsTurnPath(ids[serveMaxConcurrentTurns], serveTurnsSuffix), "127.0.0.1:54321", `{"message":"q"}`))
	if after.Code != http.StatusOK {
		t.Errorf("a turn once the cap cleared: status = %d, want %d; body %q", after.Code, http.StatusOK, after.Body.String())
	}
}

func TestServeBoundsATurnByTheRequestTimeout(t *testing.T) {
	// The turn's wall clock is the configured one, so the test sets it to its
	// floor of one second rather than waiting out the default.
	t.Setenv("BLKCHAIN_TIMEOUT_SECONDS", "1")
	isolateUserDirs(t)
	useDeadServices(t)
	cfg := loadConfig()
	if cfg.RequestTimeout() != time.Second {
		t.Fatalf("the configured timeout is %s, want 1s", cfg.RequestTimeout())
	}
	s, err := newServeServer(nil, cfg, nil, serveOpts{bind: serveDefaultBind}, "")
	if err != nil {
		t.Fatal(err)
	}
	id := writeSessionOnDisk(t, "", turnRecord{Role: roleUser, Content: "an earlier turn"})
	s.owned.own(id)

	// A router that never finishes on its own. It returns the context's error,
	// which is what a cancelled model call reports.
	installServeHeldRouter(t, 1)

	started := time.Now()
	rec := serveTurnDo(s, serveTurnPost(t, serveBoundsTurnPath(id, serveTurnsSuffix), "127.0.0.1:54321", `{"message":"q"}`))
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("a turn that never returns: status = %d, want %d; body %q", rec.Code, http.StatusGatewayTimeout, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "timed out") {
		t.Errorf("the refusal body = %q, want it to say the turn timed out", rec.Body.String())
	}
	if elapsed := time.Since(started); elapsed < cfg.RequestTimeout() {
		t.Errorf("the turn was cut after %s, before its %s bound", elapsed, cfg.RequestTimeout())
	}

	// The turn released its gate slot on the way out, so the session is usable.
	// The slot this check takes is released again, or the check would leak one.
	release, err := s.turns.acquire(id)
	if err != nil {
		t.Errorf("the session is still held after the timeout: %v", err)
	} else {
		release()
	}
}

// serveSSESink is a ResponseWriter that counts what a stream writes instead of
// buffering it, so a test can drive a stream past a 32 MiB cap without holding
// 32 MiB. It keeps each frame's event name and the tail of the last frame.
type serveSSESink struct {
	header http.Header
	code   int
	total  int
	names  []string
	tail   string
}

func (k *serveSSESink) Header() http.Header {
	if k.header == nil {
		k.header = http.Header{}
	}
	return k.header
}

func (k *serveSSESink) WriteHeader(code int) { k.code = code }

func (k *serveSSESink) Flush() {}

func (k *serveSSESink) Write(p []byte) (int, error) {
	k.total += len(p)
	name, _, _ := strings.Cut(string(p[:min(len(p), 64)]), "\n")
	k.names = append(k.names, strings.TrimSpace(strings.TrimPrefix(name, "event:")))
	k.tail = string(p[max(0, len(p)-512):])
	return len(p), nil
}

// count reports how many events carried one name.
func (k *serveSSESink) count(name string) int {
	n := 0
	for _, got := range k.names {
		if got == name {
			n++
		}
	}
	return n
}

func TestServeStopsAnSSEStreamAtItsCapAndSaysSo(t *testing.T) {
	// The real cap, not a lowered one: the deltas are sized past
	// serveMaxSSEBytes so the shipped constant is what cuts the stream.
	const (
		delta  = 1 << 20
		offers = 40
	)
	if delta*offers <= serveMaxSSEBytes {
		t.Fatalf("the test offers %d bytes, which is not past the %d cap", delta*offers, serveMaxSSEBytes)
	}
	s, id := serveTurnServer(t, serveOpts{}, "")
	chunk := strings.Repeat("a", delta)
	deltas := make([]string, offers)
	for i := range deltas {
		deltas[i] = chunk
	}
	calls := installServeTurnRouter(t, serveTurnRouter{answer: "an answer", deltas: deltas, tokens: 1})

	sink := &serveSSESink{}
	s.handler().ServeHTTP(sink, serveTurnPost(t, serveBoundsTurnPath(id, serveTurnsStreamSuffix), "127.0.0.1:54321", `{"message":"q"}`))
	if sink.code != http.StatusOK {
		t.Fatalf("status = %d, want %d", sink.code, http.StatusOK)
	}

	// Half one: the cap holds, framing included.
	if sink.total > serveMaxSSEBytes {
		t.Errorf("the stream wrote %d bytes, past its %d cap", sink.total, serveMaxSSEBytes)
	}
	// And it cut the stream rather than refusing it: the budget was spent.
	if sink.total < serveMaxSSEBytes/2 {
		t.Errorf("the stream wrote only %d bytes of its %d budget, so the cap fired early", sink.total, serveMaxSSEBytes)
	}
	if got := sink.count("assistant.delta"); got == 0 || got >= offers {
		t.Errorf("the stream carried %d of %d deltas, want some but not all", got, offers)
	}

	// Half two: the client is told, because a stream that stopped silently
	// reads as a complete answer.
	if len(sink.names) == 0 {
		t.Fatal("the stream carried no event at all")
	}
	if last := sink.names[len(sink.names)-1]; last != "run.failed" {
		t.Errorf("the stream ended on %q, want %q", last, "run.failed")
	}
	if !strings.Contains(sink.tail, serveSSECapError) {
		t.Errorf("the terminal event = %q, want it to say the stream reached its limit", sink.tail)
	}
	if got := sink.count("run.completed"); got != 0 {
		t.Errorf("a cut stream also reported run.completed %d times", got)
	}

	// Half three: the turn is cut too. Past the cap every event is dropped, so a
	// turn left running would spend the rest of its deadline producing output
	// nothing writes.
	if got := calls.streamed.Load(); got >= int32(offers) {
		t.Errorf("the router offered %d of %d deltas, so reaching the cap did not cancel the turn", got, offers)
	}
}

// serveBoundsGet is one request to a route that touches no store, which is what
// the rate bound is measured with.
func serveBoundsGet(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Host = serveTurnTestHost
	req.RemoteAddr = "127.0.0.1:54321"
	return req
}

func TestServeRateLimitRefusesABurstPastTheLimit(t *testing.T) {
	s := newServeTestServer(t, serveOpts{}, "")

	// Past the burst, not at it. The extra requests also cover the tokens the
	// bucket refills while the burst is being sent.
	codes := make([]int, 0, serveRateLimitBurst+8)
	for range serveRateLimitBurst + 8 {
		rec := serveTurnDo(s, serveBoundsGet(t))
		codes = append(codes, rec.Code)
	}
	for i := range serveRateLimitBurst {
		if codes[i] != http.StatusOK {
			t.Fatalf("request %d of the burst of %d: status = %d, want %d", i+1, serveRateLimitBurst, codes[i], http.StatusOK)
		}
	}
	last := serveTurnDo(s, serveBoundsGet(t))
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("a request past the burst: status = %d, want %d; body %q", last.Code, http.StatusTooManyRequests, last.Body.String())
	}
	if !strings.Contains(last.Body.String(), "rate limit") {
		t.Errorf("the refusal body = %q, want it to name the rate limit", last.Body.String())
	}

	// After one refill interval a request is served again, so the bound is a
	// rate and not a quota.
	time.Sleep(2 * time.Minute / serveRateLimitPerMinute)
	if rec := serveTurnDo(s, serveBoundsGet(t)); rec.Code != http.StatusOK {
		t.Errorf("a request after the window: status = %d, want %d; body %q", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// installPanickingRouter replaces the router with one that panics, which is the
// failure a handler cannot report as a status once it has sent its headers.
func installPanickingRouter(t *testing.T) {
	t.Helper()
	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	adaptiveAnswerFn = func(context.Context, searcher, ragconfig.Config, string, enabledRoutes, bool, AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		panic("the router panicked")
	}
}

func TestServeStreamEndsOnATerminalEventWhenTheTurnPanics(t *testing.T) {
	s, id := serveTurnServer(t, serveOpts{}, "")
	installPanickingRouter(t)
	path := serveBoundsTurnPath(id, serveTurnsStreamSuffix)

	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if p := recover(); p == nil {
				t.Error("the handler swallowed the panic, so net/http's own handling of it changed")
			}
		}()
		s.handler().ServeHTTP(rec, serveTurnPost(t, path, "127.0.0.1:54321", `{"message":"q"}`))
	}()

	// The status is already 200 at that point, so without a terminal event the
	// client reads a truncated chunked body it cannot tell from a cut
	// connection.
	events := parseServeSSE(t, rec.Body)
	if len(events) == 0 {
		t.Fatal("a panicking turn streamed no event at all")
	}
	last := events[len(events)-1]
	if last.name != "run.failed" {
		t.Fatalf("the stream ended on %q, want %q", last.name, "run.failed")
	}
	payload, keys := eventKeys(t, last)
	if strings.Join(keys, ",") != "error" {
		t.Errorf("run.failed keys = %v, want [error]", keys)
	}
	var msg string
	if err := json.Unmarshal(payload["error"], &msg); err != nil {
		t.Fatalf("decode the error %s: %v", payload["error"], err)
	}
	for _, leak := range []string{"panic", "goroutine ", ".go:", "runtime."} {
		if strings.Contains(msg, leak) {
			t.Errorf("run.failed carried %q from the panic: %q", leak, msg)
		}
	}

	// Both bounds release on that path: the session and a server slot are free,
	// so a panicking turn does not take the surface down with it.
	installServeTurnRouter(t, serveTurnRouter{answer: "an answer", tokens: 1})
	if ok := serveTurnDo(s, serveTurnPost(t, serveBoundsTurnPath(id, serveTurnsSuffix), "127.0.0.1:54321", `{"message":"q"}`)); ok.Code != http.StatusOK {
		t.Errorf("a turn after the panic: status = %d, want %d; body %q", ok.Code, http.StatusOK, ok.Body.String())
	}
}

func TestServeTurnReleasesItsGateWhenTheTurnPanics(t *testing.T) {
	s, id := serveTurnServer(t, serveOpts{}, "")
	installPanickingRouter(t)
	path := serveBoundsTurnPath(id, serveTurnsSuffix)

	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if p := recover(); p == nil {
				t.Error("the handler swallowed the panic, so net/http's own handling of it changed")
			}
		}()
		s.handler().ServeHTTP(rec, serveTurnPost(t, path, "127.0.0.1:54321", `{"message":"q"}`))
	}()

	installServeTurnRouter(t, serveTurnRouter{answer: "an answer", tokens: 1})
	if ok := serveTurnDo(s, serveTurnPost(t, path, "127.0.0.1:54321", `{"message":"q"}`)); ok.Code != http.StatusOK {
		t.Errorf("a turn after the panic: status = %d, want %d; body %q", ok.Code, http.StatusOK, ok.Body.String())
	}
}

func TestServeStreamSaysASkippedToolCallWasSkipped(t *testing.T) {
	// A call the loop's call cap skipped must not arrive with the key set of a
	// call that ran: a false success in this event stream is a finding a client
	// reports as made.
	for _, tc := range []struct {
		outcome ToolOutcome
		keys    string
	}{
		{ToolDone, "tool"},
		{ToolFailed, "error,tool"},
		{ToolSkipped, "error,tool"},
	} {
		t.Run(string(tc.outcome), func(t *testing.T) {
			s, id := serveTurnServer(t, serveOpts{}, "")
			installServeTurnRouter(t, serveTurnRouter{
				answer:  "an answer",
				actions: [][2]string{{"kb_search", "running"}, {"kb_search", string(tc.outcome)}},
				tokens:  1,
			})
			rec := serveTurnDo(s, serveTurnPost(t, serveBoundsTurnPath(id, serveTurnsStreamSuffix), "127.0.0.1:54321", `{"message":"q"}`))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body %q", rec.Code, http.StatusOK, rec.Body.String())
			}
			var completed serveTurnEvent
			for _, ev := range parseServeSSE(t, rec.Body) {
				if ev.name == "tool.completed" {
					completed = ev
				}
			}
			if completed.name == "" {
				t.Fatal("the stream carried no tool.completed event")
			}
			payload, keys := eventKeys(t, completed)
			if got := strings.Join(keys, ","); got != tc.keys {
				t.Fatalf("tool.completed keys = %q, want %q", got, tc.keys)
			}
			if tc.outcome == ToolDone {
				return
			}
			var msg string
			if err := json.Unmarshal(payload["error"], &msg); err != nil {
				t.Fatalf("decode the error %s: %v", payload["error"], err)
			}
			if tc.outcome == ToolSkipped && !strings.Contains(msg, "skipped") {
				t.Errorf("a skipped call reported %q, which does not say it was skipped", msg)
			}
			if tc.outcome == ToolSkipped && msg == "the tool call failed" {
				t.Errorf("a skipped call reports what a failed call reports: %q", msg)
			}
		})
	}
}

func TestServeRefusesAnEmptyMessageTheSameWayOnBothRoutes(t *testing.T) {
	// The turn raises its own missing-question error only after the stream route
	// has sent its headers, so without the gate's check the same bad request
	// answers 400 on one route and 200 plus run.failed on the other.
	for _, body := range []string{`{}`, `{"message":"   "}`} {
		var want string
		for _, suffix := range []string{serveTurnsSuffix, serveTurnsStreamSuffix} {
			s, id := serveTurnServer(t, serveOpts{}, "")
			calls := installServeTurnRouter(t, serveTurnRouter{answer: "an answer"})
			rec := serveTurnDo(s, serveTurnPost(t, serveBoundsTurnPath(id, suffix), "127.0.0.1:54321", body))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s with body %s: status = %d, want %d; body %q", suffix, body, rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("%s with body %s: Content-Type = %q, so the refusal came after the stream's headers", suffix, body, got)
			}
			if calls.ran.Load() != 0 {
				t.Errorf("%s with body %s ran %d turns", suffix, body, calls.ran.Load())
			}
			if want == "" {
				want = rec.Body.String()
				continue
			}
			if rec.Body.String() != want {
				t.Errorf("body %s is refused as %q on %s and as %q on the other route", body, rec.Body.String(), suffix, want)
			}
		}
	}
}
