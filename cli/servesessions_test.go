package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// servesessions_test.go covers the session endpoints. Each test points the
// session store at its own temporary directory through isolateUserDirs, so no
// test reads or writes the operator's sessions.

// sessionTestServer serves the full route table behind the guard chain, with a
// token set, because reading sessions requires one. sessionDo presents it.
func sessionTestServer(t *testing.T) (*httptest.Server, *serveServer) {
	t.Helper()
	isolateUserDirs(t)
	s := newServeTestServer(t, serveOpts{}, serveTestToken)
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return srv, s
}

// sessionDo sends one request without following redirects, so a redirect the
// route table issues is visible as its own status.
func sessionDo(t *testing.T, srv *httptest.Server, method, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+serveTestToken)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 32<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if rerr != nil || sb.Len() > 2*sessionResourceMaxBytes {
			break
		}
	}
	return resp, sb.String()
}

// writeSessionOnDisk creates a session outside any serveServer, as another
// blk surface would, and writes the given turns to its transcript. An empty id
// uses a generated one.
func writeSessionOnDisk(t *testing.T, id string, turns ...turnRecord) string {
	t.Helper()
	sess, err := newSession()
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		sess.id = id
	}
	for _, rec := range turns {
		if err := sess.appendTurn(rec); err != nil {
			t.Fatal(err)
		}
	}
	sess.endTurn()
	return sess.id
}

type sessionListBody struct {
	Sessions  []sessionMeta `json:"sessions"`
	Truncated bool          `json:"truncated"`
}

func TestServeCreateSessionReturnsAnOwnedID(t *testing.T) {
	srv, s := sessionTestServer(t)

	resp, body := sessionDo(t, srv, http.MethodPost, "/v1/sessions")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", resp.StatusCode, body)
	}
	var meta sessionMeta
	if err := json.Unmarshal([]byte(body), &meta); err != nil {
		t.Fatalf("body is not a sessionMeta: %v: %s", err, body)
	}
	if meta.ID == "" || !validSessionID(meta.ID) {
		t.Fatalf("id = %q, want a non-empty valid session id", meta.ID)
	}
	if !s.owned.touch(meta.ID) {
		t.Fatalf("id %q is not in the owner set, so a later turn on it would be refused as foreign", meta.ID)
	}
	// An id this server did not create is not owned: the set is not a blanket yes.
	if s.owned.touch(writeSessionOnDisk(t, "")) {
		t.Fatal("a session created outside this server is in the owner set")
	}

	resp, body = sessionDo(t, srv, http.MethodGet, "/v1/sessions")
	var list sessionListBody
	if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &list) != nil {
		t.Fatalf("list status = %d body %s", resp.StatusCode, body)
	}
	found := false
	for _, m := range list.Sessions {
		found = found || m.ID == meta.ID
	}
	if !found {
		t.Fatalf("the created session %q is not listed", meta.ID)
	}
}

// A session this server created reads as 200 with no turns before its first
// turn, and an id that names nothing is still 404, so a client that creates a
// session and reads it back does not have to treat 404 as "it may exist".
func TestServeReadsACreatedSessionBeforeItsFirstTurn(t *testing.T) {
	srv, _ := sessionTestServer(t)

	resp, body := sessionDo(t, srv, http.MethodPost, "/v1/sessions")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body %s", resp.StatusCode, body)
	}
	var meta sessionMeta
	if err := json.Unmarshal([]byte(body), &meta); err != nil {
		t.Fatalf("body is not a sessionMeta: %v: %s", err, body)
	}
	// The control: no transcript exists yet, so this is the empty read and not
	// a read of a session some other write created.
	if sessionExists(meta.ID) {
		t.Fatalf("session %q already has a transcript, so the read below proves nothing", meta.ID)
	}

	resp, body = sessionDo(t, srv, http.MethodGet, "/v1/sessions/"+meta.ID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read status = %d, want 200; body %s", resp.StatusCode, body)
	}
	var out struct {
		ID       string            `json:"id"`
		MsgCount int               `json:"msg_count"`
		Turns    []json.RawMessage `json:"turns"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if out.ID != meta.ID || out.MsgCount != 0 {
		t.Errorf("read = id %q msg_count %d, want %q and 0", out.ID, out.MsgCount, meta.ID)
	}
	if out.Turns == nil || len(out.Turns) != 0 {
		t.Errorf("turns = %v, want an empty list and not a missing key", out.Turns)
	}
}

// The other half: an id this server did not create and the listing does not
// carry names nothing, so it is 404 and not an empty session.
func TestServeReadOfAnUnknownSessionIsNotFound(t *testing.T) {
	srv, _ := sessionTestServer(t)

	resp, body := sessionDo(t, srv, http.MethodGet, "/v1/sessions/20260101T000000-abcdef")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "session not found") {
		t.Errorf("body = %s, want the refusal to say the session was not found", body)
	}
}

func TestServeListSessionsIsBoundedAndReadsEverySession(t *testing.T) {
	srv, s := sessionTestServer(t)
	for i := 0; i < sessionResourceListCap+5; i++ {
		writeSessionOnDisk(t, "", turnRecord{Role: roleUser, Content: "q"})
	}

	resp, body := sessionDo(t, srv, http.MethodGet, "/v1/sessions")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", resp.StatusCode, body)
	}
	var list sessionListBody
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Sessions) != sessionResourceListCap {
		t.Fatalf("listed %d sessions with %d on disk, want exactly the cap %d", len(list.Sessions), sessionResourceListCap+5, sessionResourceListCap)
	}
	if !list.Truncated {
		t.Fatal("the cap hid sessions and the response does not say so")
	}
	for _, m := range list.Sessions {
		if s.owned.touch(m.ID) {
			t.Fatalf("session %q is owned, but this server created none, so the listing is filtering by owner", m.ID)
		}
	}

	small, _ := sessionTestServer(t)
	writeSessionOnDisk(t, "", turnRecord{Role: roleUser, Content: "q"})
	_, body = sessionDo(t, small, http.MethodGet, "/v1/sessions")
	list = sessionListBody{}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Sessions) != 1 || list.Truncated {
		t.Fatalf("a listing under the cap = %d sessions, truncated %v; want 1, false", len(list.Sessions), list.Truncated)
	}
}

func TestServeReadSessionReturnsItsTranscriptBounded(t *testing.T) {
	srv, _ := sessionTestServer(t)

	// Four 100 KiB turns are about 400 KiB of content, past the 256 KiB cap, so
	// the bound has to act. The newest turn carries a distinct marker.
	chunk := strings.Repeat("x", 100<<10)
	id := writeSessionOnDisk(t, "",
		turnRecord{Role: roleUser, Content: chunk},
		turnRecord{Role: roleAssistant, Content: chunk},
		turnRecord{Role: roleUser, Content: chunk},
		turnRecord{Role: roleAssistant, Content: chunk + "NEWEST"},
	)
	resp, body := sessionDo(t, srv, http.MethodGet, "/v1/sessions/"+id)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if len(body) > sessionResourceMaxBytes {
		t.Fatalf("body is %d bytes, over the %d cap", len(body), sessionResourceMaxBytes)
	}
	var out struct {
		ID       string `json:"id"`
		MsgCount int    `json:"msg_count"`
		Trimmed  bool   `json:"trimmed"`
		Turns    []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"turns"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.ID != id || out.MsgCount != 4 {
		t.Fatalf("meta = id %q msg_count %d, want %q and 4", out.ID, out.MsgCount, id)
	}
	if !out.Trimmed {
		t.Fatal("the transcript exceeded the cap and the response does not say it was trimmed")
	}
	if len(out.Turns) == 0 || len(out.Turns) >= 4 {
		t.Fatalf("kept %d of 4 turns, want some but not all", len(out.Turns))
	}
	if last := out.Turns[len(out.Turns)-1].Content; !strings.HasSuffix(last, "NEWEST") {
		t.Fatal("trimming dropped the newest turn")
	}

	short := writeSessionOnDisk(t, "",
		turnRecord{Role: roleUser, Content: "hello"},
		turnRecord{Role: roleAssistant, Content: "world"},
	)
	_, body = sessionDo(t, srv, http.MethodGet, "/v1/sessions/"+short)
	out.Turns, out.Trimmed = nil, false
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Trimmed || len(out.Turns) != 2 || out.Turns[0].Content != "hello" || out.Turns[1].Content != "world" {
		t.Fatalf("a transcript under the cap came back as trimmed %v turns %+v", out.Trimmed, out.Turns)
	}
}

// new and last are selectors, not ids. last resolves to the operator's most
// recent session, so accepting it as an id would let a caller attach to a
// conversation it never created. Transcripts named last and new are planted
// with distinctive content: a handler that skipped the refusal would find
// them, since both names are valid filenames, and return that content.
func TestServeRefusesASessionSelectorAsAnID(t *testing.T) {
	srv, _ := sessionTestServer(t)
	writeSessionOnDisk(t, "", turnRecord{Role: roleUser, Content: "operator's most recent conversation"})
	for _, sel := range []string{sessionTargetNew, sessionTargetLast} {
		sentinel := "SENTINEL-" + sel
		writeSessionOnDisk(t, sel, turnRecord{Role: roleUser, Content: sentinel})

		if recs, err := loadMessages(sel); err != nil || len(recs) != 1 || recs[0].Content != sentinel {
			t.Fatalf("control: transcript %q is not readable (%v), so the refusal below proves nothing", sel, err)
		}
		if _, err := serveSessionIDFromPath("/v1/sessions/" + sel); !errors.Is(err, errServeBadSessionID) {
			t.Fatalf("serveSessionIDFromPath(%q) err = %v, want the bad-id class", sel, err)
		}
		resp, body := sessionDo(t, srv, http.MethodGet, "/v1/sessions/"+sel)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET %s status = %d, want 400", sel, resp.StatusCode)
		}
		if strings.Contains(body, sentinel) {
			t.Fatalf("GET %s read the transcript: %s", sel, body)
		}
	}
}

func TestServeRefusesAMalformedSessionID(t *testing.T) {
	srv, _ := sessionTestServer(t)
	over := strings.Repeat("a", mcpChatMaxSessionID+1)
	wayOver := strings.Repeat("a", 4*mcpChatMaxSessionID)

	paths := map[string]string{
		"path separator":      "/v1/sessions/a%2Fb",
		"encoded traversal":   "/v1/sessions/a%2F..%2Fb",
		"encoded escape":      "/v1/sessions/..%2F..%2Fetc%2Fpasswd",
		"backslash":           "/v1/sessions/a%5Cb",
		"dot dot inside":      "/v1/sessions/a..b",
		"empty":               "/v1/sessions/",
		"trailing slash":      "/v1/sessions/abc/",
		"one byte over cap":   "/v1/sessions/" + over,
		"far over cap":        "/v1/sessions/" + wayOver,
		"nested path":         "/v1/sessions/a/b",
		"padded selector":     "/v1/sessions/%20last",
		"selector with space": "/v1/sessions/last%20",
	}
	for name, p := range paths {
		decoded, err := url.PathUnescape(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := serveSessionIDFromPath(decoded); !errors.Is(err, errServeBadSessionID) {
			t.Errorf("%s: serveSessionIDFromPath err = %v, want the bad-id class", name, err)
		}
		resp, body := sessionDo(t, srv, http.MethodGet, p)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: GET %.60s status = %d, want 400; body %.80s", name, p, resp.StatusCode, body)
		}
	}

	if _, err := serveSessionIDFromPath("/v1/sessions/.."); !errors.Is(err, errServeBadSessionID) {
		t.Errorf("serveSessionIDFromPath(..) err = %v, want the bad-id class", err)
	}
	// A bare dot-dot segment is cleaned and redirected by the route table, so
	// it never reaches a handler.
	if resp, _ := sessionDo(t, srv, http.MethodGet, "/v1/sessions/.."); resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("bare dot-dot status = %d, want the route table's 307", resp.StatusCode)
	}

	// The boundary: an id exactly at the cap is well formed, so it reaches the
	// lookup and is reported as missing, not as malformed.
	atCap := strings.Repeat("a", mcpChatMaxSessionID)
	if id, err := serveSessionIDFromPath("/v1/sessions/" + atCap); err != nil || id != atCap {
		t.Errorf("an id at the cap = %q, %v, want it accepted", id, err)
	}
	if resp, _ := sessionDo(t, srv, http.MethodGet, "/v1/sessions/"+atCap); resp.StatusCode != http.StatusNotFound {
		t.Errorf("an id at the cap status = %d, want 404", resp.StatusCode)
	}
	if resp, _ := sessionDo(t, srv, http.MethodGet, "/v1/sessions/20260101T000000-aaaaaa"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a well-formed id naming no session status = %d, want 404", resp.StatusCode)
	}
}

// Reads are unrestricted and writes are not: a session another surface created
// is readable here, and is not in the owner set, so no turn can continue it.
func TestServeReadsASessionItDidNotCreate(t *testing.T) {
	srv, s := sessionTestServer(t)
	id := writeSessionOnDisk(t, "",
		turnRecord{Role: roleUser, Content: "asked elsewhere"},
		turnRecord{Role: roleAssistant, Content: "answered elsewhere"},
	)
	if s.owned.touch(id) {
		t.Fatal("the session is in the owner set")
	}

	resp, body := sessionDo(t, srv, http.MethodGet, "/v1/sessions/"+id)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "asked elsewhere") || !strings.Contains(body, "answered elsewhere") {
		t.Fatalf("the transcript was not returned: %s", body)
	}
	if s.owned.touch(id) {
		t.Fatal("reading a session put it in the owner set")
	}
}

// TestServeRefusesSessionReadsWithoutAToken pins that a server with no token
// does not hand out transcripts. Any process on the machine, another local
// account's included, can call a loopback server with no token, and the session
// store holds every surface's conversations. Creating a session and running a
// sandboxed turn stay open, so the server is still usable without one.
func TestServeRefusesSessionReadsWithoutAToken(t *testing.T) {
	isolateUserDirs(t)
	s := newServeTestServer(t, serveOpts{}, "")
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	other := writeSessionOnDisk(t, "", turnRecord{Role: roleUser, Content: "a question from the TUI"})

	send := func(method, path string) (int, string) {
		req, err := http.NewRequest(method, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := resp.Body.Read(buf)
			sb.Write(buf[:n])
			if rerr != nil {
				break
			}
		}
		return resp.StatusCode, sb.String()
	}
	for _, path := range []string{serveSessionsPath, serveSessionsPath + "/" + other} {
		code, body := send(http.MethodGet, path)
		if code != http.StatusForbidden || !strings.Contains(body, "BLKCHAIN_SERVE_TOKEN") {
			t.Errorf("GET %s with no token: %d %q, want 403 naming BLKCHAIN_SERVE_TOKEN", path, code, body)
		}
		if strings.Contains(body, "a question from the TUI") {
			t.Errorf("GET %s with no token returned a transcript", path)
		}
	}
	if code, body := send(http.MethodPost, serveSessionsPath); code != http.StatusCreated {
		t.Errorf("creating a session with no token: %d %q, want 201", code, body)
	}
}
