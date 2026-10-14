package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
)

// serveturns_test.go covers the two turn endpoints: the shared gate, the JSON
// body, and the SSE framing. No model runs; adaptiveAnswerFn is replaced by a
// fixture that drives the callbacks the stream maps to events.

// serveTurnTestHost is the authority a legitimate client addresses the default
// bind with. On a loopback bind the Host defense refuses anything else.
const serveTurnTestHost = "127.0.0.1:8787"

// serveTurnEvent is one Server-Sent Event as a client reads it.
type serveTurnEvent struct {
	name string
	data string
}

// parseServeSSE reads a Server-Sent Events stream the way a client does: it
// accumulates event: and data: lines, dispatches on a blank line, joins several
// data lines with a newline, and skips comment lines. Asserting on this rather
// than on the raw bytes tests the framing a client has to be able to parse.
func parseServeSSE(t *testing.T, r io.Reader) []serveTurnEvent {
	t.Helper()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var out []serveTurnEvent
	var name string
	var data strings.Builder
	dispatch := func() {
		if name == "" && data.Len() == 0 {
			return
		}
		out = append(out, serveTurnEvent{name: name, data: data.String()})
		name = ""
		data.Reset()
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			dispatch()
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	dispatch()
	if err := sc.Err(); err != nil {
		t.Fatalf("scan the stream: %v", err)
	}
	return out
}

// eventKeys decodes one event's payload and returns its top-level keys with the
// payload, so a test asserts the exact JSON keys a client parses.
func eventKeys(t *testing.T, ev serveTurnEvent) (map[string]json.RawMessage, []string) {
	t.Helper()
	payload := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(ev.data), &payload); err != nil {
		t.Fatalf("event %s payload %q: %v", ev.name, ev.data, err)
	}
	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return payload, keys
}

// serveTurnRouter is one turn's fixture: what the router streams, which tool
// calls it reports with which status, what it costs, and how it ends.
type serveTurnRouter struct {
	answer  string
	deltas  []string
	actions [][2]string
	tokens  int
	err     error
}

// serveTurnCalls records what reached the router: how many turns ran, how many
// deltas the router offered, and the options the last turn carried.
type serveTurnCalls struct {
	ran      atomic.Int32
	streamed atomic.Int32
	opts     AnswerOpts
}

// installServeTurnRouter replaces the router for one test. A test asserts on
// ran to show that a refused request ran no turn at all.
func installServeTurnRouter(t *testing.T, f serveTurnRouter) *serveTurnCalls {
	t.Helper()
	calls := &serveTurnCalls{}
	prev := adaptiveAnswerFn
	t.Cleanup(func() { adaptiveAnswerFn = prev })
	adaptiveAnswerFn = func(ctx context.Context, _ searcher, _ ragconfig.Config, _ string, _ enabledRoutes, _ bool, opts AnswerOpts) (string, []citation, bool, []retrieval.Result, int, string, error) {
		calls.ran.Add(1)
		calls.opts = opts
		// A cancelled turn stops offering deltas, as a model call does, so a
		// test can tell a turn that was cut from one that ran to its end.
		for _, d := range f.deltas {
			if ctx.Err() != nil {
				break
			}
			if opts.Stream != nil {
				opts.Stream([]byte(d))
			}
			calls.streamed.Add(1)
		}
		for _, a := range f.actions {
			if opts.Action != nil {
				opts.Action(a[0], a[1])
			}
		}
		return f.answer, []citation{}, false, []retrieval.Result{}, f.tokens, "rag", f.err
	}
	return calls
}

// serveTurnServer builds a server over an isolated session store holding one
// session the server owns, which is the state a client is in after a successful
// POST to the sessions collection.
func serveTurnServer(t *testing.T, o serveOpts, tok string) (*serveServer, string) {
	t.Helper()
	isolateUserDirs(t)
	useDeadServices(t)
	s := newServeTestServer(t, o, tok)
	id := writeSessionOnDisk(t, "", turnRecord{Role: roleUser, Content: "an earlier turn"})
	s.owned.own(id)
	return s, id
}

// serveTurnPost builds one POST to a turn route the way a legitimate client
// frames it: a JSON body, the bind's own authority, and no Origin. peer is the
// request's peer address, which is what the vantage decision reads.
func serveTurnPost(t *testing.T, path, peer, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Host = serveTurnTestHost
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = peer
	return req
}

// serveTurnDo drives one request through the served tree, guard chain included,
// so a test exercises the shipped path rather than a handler in isolation.
func serveTurnDo(s *serveServer, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	return rec
}

// serveJSONKeys lists a struct's JSON field names, descending into a nested
// struct field so turnUsage's fields count as the turn's own.
func serveJSONKeys(rt reflect.Type) map[string]bool {
	out := map[string]bool{}
	for i := range rt.NumField() {
		f := rt.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if key == "-" {
			continue
		}
		if f.Type.Kind() == reflect.Struct && f.Type.PkgPath() == rt.PkgPath() {
			for k := range serveJSONKeys(f.Type) {
				out[k] = true
			}
		}
		if f.Anonymous && key == "" {
			continue
		}
		if key != "" {
			out[key] = true
		}
	}
	return out
}

func TestServeTurnReturnsTheSameShapeAsAskJSON(t *testing.T) {
	s, id := serveTurnServer(t, serveOpts{}, "")
	installServeTurnRouter(t, serveTurnRouter{answer: "an answer", deltas: []string{"an answer"}, tokens: 11})

	rec := serveTurnDo(s, serveTurnPost(t, serveSessionsPath+"/"+id+serveTurnsSuffix, "127.0.0.1:54321", `{"message":"q"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %q", rec.Code, http.StatusOK, rec.Body.String())
	}

	// The field set is read off the struct blk ask --json marshals, so a field
	// added there and not carried here fails this test instead of letting the
	// two surfaces drift apart. The turn nests under usage what ask reports
	// flat, so serveJSONKeys descends into turnUsage.
	//
	// Two drifts that does not catch: the key set is flat, so a key moved
	// between nesting levels leaves it unchanged, and the body check below
	// asserts only that no key appears which the result does not define, not
	// that a defined key is present, so a key that gained omitempty and stopped
	// being emitted still passes.
	turnKeys := serveJSONKeys(reflect.TypeFor[turnResult]())
	for key := range serveJSONKeys(reflect.TypeFor[answerResponse]()) {
		if !turnKeys[key] {
			t.Errorf("a turn does not report %q, which blk ask --json reports", key)
		}
	}

	// And the response body is that type's marshalling and nothing else.
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	outKeys := serveJSONKeys(reflect.TypeFor[mcpChatOut]())
	for key := range body {
		if !outKeys[key] {
			t.Errorf("the turn body carries %q, which the turn result does not define", key)
		}
	}
	if _, ok := body["error"]; ok {
		t.Errorf("a turn that finished reported an error: %q", rec.Body.String())
	}

	var got turnResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode as a turn result: %v", err)
	}
	if got.Answer != "an answer" {
		t.Errorf("answer = %q, want %q", got.Answer, "an answer")
	}
	if got.SessionID != id {
		t.Errorf("session_id = %q, want %q", got.SessionID, id)
	}
	if got.Usage.CompletionTokens != 11 {
		t.Errorf("usage.completion_tokens = %d, want 11", got.Usage.CompletionTokens)
	}
}

// The documented flow: a client creates a session through the collection route
// and runs a turn on the id it got back. handleCreateSession writes a listing
// row and no transcript, so the turn resolves through that row, which is a
// different path from the turn tests that seed a transcript on disk.
func TestServeRunsATurnOnASessionItJustCreated(t *testing.T) {
	isolateUserDirs(t)
	useDeadServices(t)
	s := newServeTestServer(t, serveOpts{}, "")
	installServeTurnRouter(t, serveTurnRouter{answer: "an answer", deltas: []string{"an answer"}, tokens: 9})

	create := httptest.NewRequest(http.MethodPost, serveSessionsPath, nil)
	create.Host = serveTurnTestHost
	create.RemoteAddr = "127.0.0.1:54321"
	rec := serveTurnDo(s, create)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d; body %q", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var meta sessionMeta
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("create body is not a sessionMeta: %v: %q", err, rec.Body.String())
	}
	// The control: no transcript exists yet, so the turn below resolves the id
	// through the listing row and not through a file another write left.
	if sessionExists(meta.ID) {
		t.Fatalf("the created session %q already has a transcript", meta.ID)
	}
	// mode is retired from the model, so a created session reports no mode
	// rather than an empty one.
	if strings.Contains(rec.Body.String(), `"mode"`) {
		t.Errorf("the create body carries a mode: %q", rec.Body.String())
	}

	rec = serveTurnDo(s, serveTurnPost(t, serveSessionsPath+"/"+meta.ID+serveTurnsSuffix, "127.0.0.1:54321", `{"message":"q"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("turn status = %d, want %d; body %q", rec.Code, http.StatusOK, rec.Body.String())
	}
	var got turnResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode the turn %q: %v", rec.Body.String(), err)
	}
	if got.SessionID != meta.ID {
		t.Errorf("the turn ran on session %q, want the created %q", got.SessionID, meta.ID)
	}
	if got.Answer != "an answer" {
		t.Errorf("answer = %q, want %q", got.Answer, "an answer")
	}
	// And the turn was recorded, so the created session carries the exchange a
	// later turn continues.
	if !sessionExists(meta.ID) {
		t.Errorf("the turn wrote no transcript for %q", meta.ID)
	}
}

func TestServeTurnRefusesASessionItDidNotCreate(t *testing.T) {
	s, _ := serveTurnServer(t, serveOpts{}, "")
	calls := installServeTurnRouter(t, serveTurnRouter{answer: "an answer"})
	// A session another surface wrote, which this server never created.
	foreign := writeSessionOnDisk(t, "", turnRecord{Role: roleUser, Content: "elsewhere"})
	path := serveSessionsPath + "/" + foreign + serveTurnsSuffix

	_, _, release, err := s.serveTurnGate(serveTurnPost(t, path, "127.0.0.1:54321", `{"message":"q"}`), serveTurnsSuffix)
	if release != nil {
		release()
	}
	if !errors.Is(err, errChatForeignSession) {
		t.Fatalf("gate error = %v, want errChatForeignSession", err)
	}
	if errors.Is(err, errServeBadSessionID) {
		t.Errorf("the refusal is not distinguishable from a malformed id: %v", err)
	}

	rec := serveTurnDo(s, serveTurnPost(t, path, "127.0.0.1:54321", `{"message":"q"}`))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body %q", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if calls.ran.Load() != 0 {
		t.Errorf("a foreign session ran %d turns", calls.ran.Load())
	}

	// A malformed id is its own refusal, so the two are not one branch. The id
	// is percent-encoded, so the route table neither cleans the path nor reads
	// the escape as a separator: the id reaches the validation and is refused
	// there, which is what makes the status below that refusal and not a route
	// that matched nothing.
	bad := serveTurnDo(s, serveTurnPost(t, serveSessionsPath+"/..%2F..%2Fetc%2Fpasswd"+serveTurnsSuffix, "127.0.0.1:54321", `{"message":"q"}`))
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "invalid session id") {
		t.Errorf("a malformed id answered %d %q, want 400 and the id refusal", bad.Code, bad.Body.String())
	}
}

func TestServeTurnRefusesLocalToolHostFromANonLoopbackPeer(t *testing.T) {
	const peer = "192.0.2.10:44321"
	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{"tool_host local", `{"message":"q","tool_host":"local"}`, errChatLocalHostRefused},
		{"browser_cdp", `{"message":"q","browser_cdp":"http://127.0.0.1:9222"}`, errChatBrowserCDPRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, id := serveTurnServer(t, serveOpts{}, "")
			calls := installServeTurnRouter(t, serveTurnRouter{answer: "an answer"})
			path := serveSessionsPath + "/" + id + serveTurnsSuffix

			_, _, release, err := s.serveTurnGate(serveTurnPost(t, path, peer, tc.body), serveTurnsSuffix)
			if release != nil {
				release()
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("gate error = %v, want %v", err, tc.want)
			}

			rec := serveTurnDo(s, serveTurnPost(t, path, peer, tc.body))
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d; body %q", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if calls.ran.Load() != 0 {
				t.Errorf("a refused turn reached the router %d times", calls.ran.Load())
			}

			// The same peer still gets a sandboxed turn, so the refusal is the
			// option and not the caller.
			ok := serveTurnDo(s, serveTurnPost(t, path, peer, `{"message":"q"}`))
			if ok.Code != http.StatusOK {
				t.Fatalf("a sandboxed turn from the same peer: status = %d; body %q", ok.Code, ok.Body.String())
			}
			if calls.opts.ToolHost != chatToolHostSandbox {
				t.Errorf("the admitted turn reached the router with host %q", calls.opts.ToolHost)
			}
		})
	}
}

func TestServeTurnAllowsLocalToolHostFromALoopbackPeer(t *testing.T) {
	const endpoint = "http://127.0.0.1:9222"
	s, id := serveTurnServer(t, serveOpts{}, "")
	calls := installServeTurnRouter(t, serveTurnRouter{answer: "an answer"})
	path := serveSessionsPath + "/" + id + serveTurnsSuffix

	body := `{"message":"q","tool_host":"local","browser_cdp":"` + endpoint + `"}`
	rec := serveTurnDo(s, serveTurnPost(t, path, "127.0.0.1:54321", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if calls.opts.ToolHost != chatToolHostLocal {
		t.Errorf("the router saw tool host %q, want %q", calls.opts.ToolHost, chatToolHostLocal)
	}
	if calls.opts.BrowserCDP != endpoint {
		t.Errorf("the router saw browser_cdp %q, want %q", calls.opts.BrowserCDP, endpoint)
	}
	if got := s.callerVantage(serveTurnPost(t, path, "[::1]:54321", body)); got != vantageLocal {
		t.Errorf("callerVantage for an IPv6 loopback peer = %v, want %v", got, vantageLocal)
	}
}

// TestServeTurnRequiresTheThreeDefensesBeforeTheVantageGrant pins the
// composition the grant rests on. A loopback peer is not by itself proof of a
// local process: a page in the operator's browser reaches loopback too. What
// makes vantageLocal honest on this route is that the three browser defenses
// ran in the guard chain before the handler. Each case below asks for the
// operator's reach from a loopback peer and breaks exactly one defense, so a
// chain reordered to run a handler first would grant the reach and fail here.
func TestServeTurnRequiresTheThreeDefensesBeforeTheVantageGrant(t *testing.T) {
	const body = `{"message":"q","tool_host":"local"}`
	for _, tc := range []struct {
		name  string
		want  int
		says  string
		shape func(*http.Request)
	}{
		{"a body that is not JSON", http.StatusUnsupportedMediaType, "application/json", func(r *http.Request) {
			r.Header.Set("Content-Type", "text/plain")
		}},
		{"a Host the bind does not serve", http.StatusMisdirectedRequest, "must be loopback", func(r *http.Request) {
			r.Host = "rebound.example"
		}},
		{"an Origin", http.StatusForbidden, "no browser origin", func(r *http.Request) {
			r.Header.Set("Origin", "http://evil.example")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, id := serveTurnServer(t, serveOpts{}, "")
			calls := installServeTurnRouter(t, serveTurnRouter{answer: "an answer"})
			req := serveTurnPost(t, serveSessionsPath+"/"+id+serveTurnsSuffix, "127.0.0.1:54321", body)
			tc.shape(req)
			rec := serveTurnDo(s, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d; body %q", rec.Code, tc.want, rec.Body.String())
			}
			// The message is the defense's own, so this is not another refusal
			// that happens to share a status.
			if !strings.Contains(rec.Body.String(), tc.says) {
				t.Errorf("body = %q, want the defense's own refusal naming %q", rec.Body.String(), tc.says)
			}
			if calls.ran.Load() != 0 {
				t.Errorf("the turn ran, so a handler was reached before the defense")
			}
		})
	}

	// With all three satisfied the same request runs and does get the reach, so
	// the cases above fail on their defense and not on something else.
	s, id := serveTurnServer(t, serveOpts{}, "")
	calls := installServeTurnRouter(t, serveTurnRouter{answer: "an answer"})
	rec := serveTurnDo(s, serveTurnPost(t, serveSessionsPath+"/"+id+serveTurnsSuffix, "127.0.0.1:54321", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if calls.opts.ToolHost != chatToolHostLocal {
		t.Errorf("the router saw tool host %q, want %q", calls.opts.ToolHost, chatToolHostLocal)
	}
}

func TestServeTurnRefusesTheOperatorsReachInRemoteMode(t *testing.T) {
	// A wide bind admits any Host by design, so the rebinding defense does not
	// run; and a loopback peer there is produced by any tunnel, published
	// container port or local proxy. The peer address therefore proves nothing
	// about who originated the request, and no caller gets the reach.
	s, id := serveTurnServer(t, serveOpts{bind: "0.0.0.0:8787", allowRemote: true}, serveTestToken)
	calls := installServeTurnRouter(t, serveTurnRouter{answer: "an answer"})
	path := serveSessionsPath + "/" + id + serveTurnsSuffix

	for _, peer := range []string{"127.0.0.1:54321", "[::1]:54321", "10.1.2.3:44321"} {
		if got := s.callerVantage(serveTurnPost(t, path, peer, `{}`)); got != vantageRemote {
			t.Errorf("callerVantage on a wide bind for peer %q = %v, want %v", peer, got, vantageRemote)
		}
	}

	for _, body := range []string{
		`{"message":"q","tool_host":"local"}`,
		`{"message":"q","browser_cdp":"http://127.0.0.1:9222"}`,
	} {
		req := serveTurnPost(t, path, "127.0.0.1:54321", body)
		req.Header.Set("Authorization", "Bearer "+serveTestToken)
		rec := serveTurnDo(s, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s from a loopback peer on a wide bind: status = %d, want %d; body %q", body, rec.Code, http.StatusForbidden, rec.Body.String())
		}
	}
	if calls.ran.Load() != 0 {
		t.Errorf("a refused turn reached the router %d times", calls.ran.Load())
	}

	// Remote mode keeps every retrieval and answer tool; only the two
	// operator-reach options are gone.
	req := serveTurnPost(t, path, "10.1.2.3:44321", `{"message":"q"}`)
	req.Header.Set("Authorization", "Bearer "+serveTestToken)
	if rec := serveTurnDo(s, req); rec.Code != http.StatusOK {
		t.Fatalf("a sandboxed turn in remote mode: status = %d; body %q", rec.Code, rec.Body.String())
	}
	if calls.opts.vantage != vantageRemote {
		t.Errorf("a remote-mode turn reached the router with vantage %v, want %v", calls.opts.vantage, vantageRemote)
	}
}

func TestServeTurnRequiresAJSONBody(t *testing.T) {
	// requireJSONBody returns early at ContentLength == 0, so a bodiless POST
	// passes the content-type defense entirely. Both turn routes require a body
	// of their own rather than running a turn with an empty message.
	for _, suffix := range []string{serveTurnsSuffix, serveTurnsStreamSuffix} {
		t.Run(suffix, func(t *testing.T) {
			s, id := serveTurnServer(t, serveOpts{}, "")
			calls := installServeTurnRouter(t, serveTurnRouter{answer: "an answer"})
			path := serveSessionsPath + "/" + id + suffix

			bodiless := httptest.NewRequest(http.MethodPost, path, nil)
			bodiless.Host = serveTurnTestHost
			bodiless.RemoteAddr = "127.0.0.1:54321"
			if rec := serveTurnDo(s, bodiless); rec.Code != http.StatusUnsupportedMediaType {
				t.Errorf("no body: status = %d, want %d; body %q", rec.Code, http.StatusUnsupportedMediaType, rec.Body.String())
			}
			if calls.ran.Load() != 0 {
				t.Errorf("a bodiless POST ran %d turns", calls.ran.Load())
			}

			// A body with no JSON content type is the chain's refusal.
			plain := serveTurnPost(t, path, "127.0.0.1:54321", `{"message":"q"}`)
			plain.Header.Set("Content-Type", "text/plain")
			if rec := serveTurnDo(s, plain); rec.Code != http.StatusUnsupportedMediaType {
				t.Errorf("a text/plain body: status = %d, want %d", rec.Code, http.StatusUnsupportedMediaType)
			}

			// A JSON content type with a body that is not a turn is malformed,
			// which is a different refusal from a missing body.
			if rec := serveTurnDo(s, serveTurnPost(t, path, "127.0.0.1:54321", `{"message":`)); rec.Code != http.StatusBadRequest {
				t.Errorf("a malformed body: status = %d, want %d; body %q", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			if calls.ran.Load() != 0 {
				t.Errorf("a refused body ran %d turns", calls.ran.Load())
			}
		})
	}
}

func TestServeTurnAnswers413ForAnOversizeChunkedBody(t *testing.T) {
	// The chain refuses a declared oversize Content-Length before any handler,
	// but a chunked body declares no length and fails only when the handler
	// reads past the cap. Both framings answer 413, or the same body's status
	// would depend on how the client framed it.
	s, id := serveTurnServer(t, serveOpts{}, "")
	calls := installServeTurnRouter(t, serveTurnRouter{answer: "an answer"})
	path := serveSessionsPath + "/" + id + serveTurnsSuffix
	// Past the bound, not at it.
	body := `{"message":"` + strings.Repeat("a", serveMaxBody+1) + `"}`

	chunked := serveTurnPost(t, path, "127.0.0.1:54321", body)
	chunked.ContentLength = -1
	chunked.TransferEncoding = []string{"chunked"}
	if rec := serveTurnDo(s, chunked); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a chunked oversize body: status = %d, want %d; body %q", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}

	declared := serveTurnPost(t, path, "127.0.0.1:54321", body)
	if declared.ContentLength <= serveMaxBody {
		t.Fatalf("the declared length is %d, which is not past the %d bound", declared.ContentLength, serveMaxBody)
	}
	if rec := serveTurnDo(s, declared); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a declared oversize body: status = %d, want %d; body %q", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}

	if calls.ran.Load() != 0 {
		t.Errorf("an oversize body ran %d turns", calls.ran.Load())
	}
}

func TestServeStreamEmitsTheEventNamesBlkParses(t *testing.T) {
	// One exchange carrying every event the stream emits except run.failed,
	// which has its own test: the event names in order and each event's exact
	// payload keys, so a key added or dropped is a failure rather than a change
	// a client discovers.
	s, id := serveTurnServer(t, serveOpts{}, "")
	installServeTurnRouter(t, serveTurnRouter{
		answer:  "hello",
		deltas:  []string{"hello"},
		actions: [][2]string{{"kb_search", "running"}, {"kb_search", string(ToolFailed)}},
		tokens:  42,
	})

	rec := serveTurnDo(s, serveTurnPost(t, serveSessionsPath+"/"+id+serveTurnsStreamSuffix, "127.0.0.1:54321", `{"message":"q"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %q", rec.Code, http.StatusOK, rec.Body.String())
	}
	for header, want := range map[string]string{
		"Content-Type":  "text/event-stream",
		"Cache-Control": "no-cache",
		"Connection":    "keep-alive",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	raw := rec.Body.String()
	t.Logf("one complete exchange, exactly as the client reads it:\n%q", raw)

	events := parseServeSSE(t, strings.NewReader(raw))
	wantNames := []string{"assistant.delta", "tool.started", "tool.completed", "run.completed"}
	if len(events) != len(wantNames) {
		t.Fatalf("got %d events %v, want %d %v", len(events), events, len(wantNames), wantNames)
	}
	for i, want := range wantNames {
		if events[i].name != want {
			t.Fatalf("event %d = %q, want %q", i, events[i].name, want)
		}
	}

	payload, keys := eventKeys(t, events[0])
	if strings.Join(keys, ",") != "delta" {
		t.Errorf("assistant.delta keys = %v, want [delta]", keys)
	}
	if got := string(payload["delta"]); got != `"hello"` {
		t.Errorf("delta = %s, want %q", got, "hello")
	}

	payload, keys = eventKeys(t, events[1])
	if strings.Join(keys, ",") != "tool" {
		t.Errorf("tool.started keys = %v, want [tool]", keys)
	}
	if got := string(payload["tool"]); got != `"kb_search"` {
		t.Errorf("tool = %s, want %q", got, "kb_search")
	}

	payload, keys = eventKeys(t, events[2])
	if strings.Join(keys, ",") != "error,tool" {
		t.Errorf("tool.completed keys = %v, want [error tool]", keys)
	}
	if got := string(payload["error"]); got == `""` || got == "null" {
		t.Errorf("a failed call reported error = %s, which reads as a call that succeeded", got)
	}

	payload, keys = eventKeys(t, events[3])
	if strings.Join(keys, ",") != "usage" {
		t.Errorf("run.completed keys = %v, want [usage]", keys)
	}
	var usage map[string]int
	if err := json.Unmarshal(payload["usage"], &usage); err != nil {
		t.Fatalf("decode usage %s: %v", payload["usage"], err)
	}
	if len(usage) != 1 || usage["completion_tokens"] != 42 {
		t.Errorf("usage = %v, want {completion_tokens: 42}", usage)
	}
}

func TestServeStreamEndsOnRunFailedWhenTheTurnErrors(t *testing.T) {
	s, id := serveTurnServer(t, serveOpts{}, serveTestToken)
	installServeTurnRouter(t, serveTurnRouter{err: errors.New("the model host refused the call")})

	req := serveTurnPost(t, serveSessionsPath+"/"+id+serveTurnsStreamSuffix, "127.0.0.1:54321", `{"message":"q"}`)
	req.Header.Set("Authorization", "Bearer "+serveTestToken)
	rec := serveTurnDo(s, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %q", rec.Code, http.StatusOK, rec.Body.String())
	}

	events := parseServeSSE(t, rec.Body)
	if len(events) == 0 {
		t.Fatal("a failing turn streamed no event at all")
	}
	last := events[len(events)-1]
	if last.name != "run.failed" {
		t.Fatalf("the stream ended on %q, want %q", last.name, "run.failed")
	}
	for _, ev := range events {
		if ev.name == "run.completed" {
			t.Errorf("a failing turn also reported run.completed")
		}
	}
	payload, keys := eventKeys(t, last)
	if strings.Join(keys, ",") != "error" {
		t.Errorf("run.failed keys = %v, want [error]", keys)
	}
	var msg string
	if err := json.Unmarshal(payload["error"], &msg); err != nil {
		t.Fatalf("decode the error %s: %v", payload["error"], err)
	}
	if strings.TrimSpace(msg) == "" {
		t.Error("run.failed carried an empty error")
	}
	if strings.Contains(msg, serveTestToken) {
		t.Error("run.failed carried the bearer token")
	}
	for _, trace := range []string{"goroutine ", ".go:", "runtime."} {
		if strings.Contains(msg, trace) {
			t.Errorf("run.failed carried a stack: %q", msg)
		}
	}
}

func TestServeStreamEscapesADeltaWithNewlines(t *testing.T) {
	// An SSE data line cannot carry a raw newline, and a line that began with
	// "data:" inside the text would read as a second line of the same event.
	// The payload is JSON-encoded, so both arrive intact.
	const delta = "line one\nline two\r\ndata: not an event\n\nevent: neither\n"
	s, id := serveTurnServer(t, serveOpts{}, "")
	installServeTurnRouter(t, serveTurnRouter{answer: delta, deltas: []string{delta}, tokens: 1})

	rec := serveTurnDo(s, serveTurnPost(t, serveSessionsPath+"/"+id+serveTurnsStreamSuffix, "127.0.0.1:54321", `{"message":"q"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %q", rec.Code, http.StatusOK, rec.Body.String())
	}
	events := parseServeSSE(t, rec.Body)
	if len(events) != 2 || events[0].name != "assistant.delta" || events[1].name != "run.completed" {
		t.Fatalf("events = %v, want one assistant.delta then run.completed", events)
	}
	var got struct {
		Delta string `json:"delta"`
	}
	if err := json.Unmarshal([]byte(events[0].data), &got); err != nil {
		t.Fatalf("decode %q: %v", events[0].data, err)
	}
	if got.Delta != delta {
		t.Errorf("the delta parsed back as %q, want %q", got.Delta, delta)
	}
}
