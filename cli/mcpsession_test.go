package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"
	"blkchain/cli/internal/skillcat"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestSessionResourceURIRoundTrip(t *testing.T) {
	id := "20260101T010101-abcdef"
	uri := sessionResourceURI(id)
	if uri != "session://"+id {
		t.Fatalf("uri = %q", uri)
	}
	got, err := sessionIDFromURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("id = %q", got)
	}
}

// A malformed URI must fail with the invalid-resource class, not merely fail.
// A bare error check passes whenever any later step errors, such as a lookup
// of a file that does not exist, so it cannot show the id guard is present.
func TestSessionIDFromURIRejectsHostileURIs(t *testing.T) {
	for _, uri := range []string{
		"session://../../etc/passwd",
		"session://a/b",
		"session://..",
		"session://a\\b",
		"session://",
		"file:///etc/passwd",
		"session:/..",
		"",
	} {
		id, err := sessionIDFromURI(uri)
		if !errors.Is(err, errInvalidSessionResource) {
			t.Fatalf("uri %q: id = %q, err = %v, want the invalid-resource class", uri, id, err)
		}
		if errors.Is(err, errSessionNotFound) {
			t.Fatalf("uri %q was classed as a missing session", uri)
		}
	}
}

// A well-formed id that names no session passes the URI check, so a caller can
// tell it apart from a malformed URI.
func TestSessionIDFromURIAcceptsWellFormedUnknownID(t *testing.T) {
	id, err := sessionIDFromURI("session://20260101T000000-aaaaaa")
	if err != nil || id != "20260101T000000-aaaaaa" {
		t.Fatalf("id = %q, err = %v", id, err)
	}
}

func TestMCPSessionResourceReturnsTheTranscript(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "resource answer", nil)

	res, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "resource question"})
	if err != nil {
		t.Fatal(err)
	}

	payload, err := mcpSessionResource(res.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		ID       string `json:"id"`
		MsgCount int    `json:"msg_count"`
		Turns    []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"turns"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatal(err)
	}
	if out.ID != res.SessionID {
		t.Fatalf("id = %q", out.ID)
	}
	if len(out.Turns) != 2 || out.Turns[0].Content != "resource question" {
		t.Fatalf("turns = %+v", out.Turns)
	}
}

func TestMCPSessionResourceUnknownSessionFails(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	_, err := mcpSessionResource("20260101T000000-aaaaaa")
	if !errors.Is(err, errSessionNotFound) {
		t.Fatalf("err = %v, want session not found", err)
	}
	if errors.Is(err, errInvalidSessionResource) {
		t.Fatalf("a well-formed unknown id was classed as malformed: %v", err)
	}
}

func TestMCPSessionResourceRejectsHostileIDs(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	for _, id := range []string{"../../etc/passwd", "a/b", "..", ""} {
		_, err := mcpSessionResource(id)
		if !errors.Is(err, errInvalidSessionResource) {
			t.Fatalf("id %q: err = %v, want the invalid-resource class", id, err)
		}
	}
}

func TestMCPSessionResourceIsBounded(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	// 20 turns of a 32 KiB answer is about 640 KiB of content, comfortably over
	// the 256 KiB cap, so this actually exercises the bound. Sizing the content
	// under the cap would make the assertion pass without the truncation code
	// ever running.
	stubAdaptiveAnswer(t, strings.Repeat("y", 32<<10), nil)

	res, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 19; i++ {
		if _, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q", SessionID: res.SessionID}); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := mcpSessionResource(res.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > sessionResourceMaxBytes {
		t.Fatalf("resource payload is %d bytes, over the %d cap", len(payload), sessionResourceMaxBytes)
	}
	var out struct {
		Trimmed bool `json:"trimmed"`
		Turns   []struct {
			Content string `json:"content"`
		} `json:"turns"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Trimmed {
		t.Fatal("the payload fit without trimming, so the bound was never exercised")
	}
	if len(out.Turns) == 0 {
		t.Fatal("trimming removed every turn")
	}
	// The newest turns are the ones a resuming client needs, so the kept
	// window must end at the last turn.
	if out.Turns[len(out.Turns)-1].Content != strings.Repeat("y", 32<<10) {
		t.Fatal("trimming kept the oldest turns instead of the newest")
	}
}

// JSON escaping doubles every quote, so three answers whose raw content sums to
// well under the cap still marshal to more than the cap. The bound has to hold
// on the encoded size.
func TestMCPSessionResourceBoundHoldsForEscapedContent(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	answer := strings.Repeat(`"`, 80<<10)
	stubAdaptiveAnswer(t, answer, nil)

	res, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q", SessionID: res.SessionID}); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := mcpSessionResource(res.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > sessionResourceMaxBytes {
		t.Fatalf("resource payload is %d bytes, over the %d cap", len(payload), sessionResourceMaxBytes)
	}
	var out struct {
		Trimmed bool `json:"trimmed"`
		Turns   []struct {
			Content string `json:"content"`
		} `json:"turns"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Trimmed {
		t.Fatal("the encoded payload exceeds the cap, so it must be marked trimmed")
	}
	if len(out.Turns) == 0 || out.Turns[len(out.Turns)-1].Content != answer {
		t.Fatal("the newest turn was not kept intact")
	}
}

// One turn larger than the whole cap is cut to fit rather than dropped or
// returned over the cap, and the cut lands on a rune boundary.
func TestMCPSessionResourceCutsAnOversizeNewestTurn(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, strings.Repeat("\u00e9", 300<<10), nil)

	res, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "q"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := mcpSessionResource(res.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > sessionResourceMaxBytes {
		t.Fatalf("resource payload is %d bytes, over the %d cap", len(payload), sessionResourceMaxBytes)
	}
	var out struct {
		Trimmed bool `json:"trimmed"`
		Turns   []struct {
			Content string `json:"content"`
		} `json:"turns"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Trimmed || len(out.Turns) != 1 {
		t.Fatalf("trimmed = %v, turns = %d", out.Trimmed, len(out.Turns))
	}
	c := out.Turns[0].Content
	if c == "" || strings.Trim(c, "\u00e9") != "" {
		t.Fatalf("cut content is not a whole number of runes (len %d)", len(c))
	}
}

func TestMCPServerExposesSessionsAsResources(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	stubAdaptiveAnswer(t, "listed answer", nil)

	first, err := mcpChatResult(context.Background(), nil, loadConfig(), mcpChatIn{Message: "listed question"})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	writeTestSkill(t, dir, "aaa-web", "---\nname: aaa-web\ndescription: web http attacks\n---\nWEBBODY\n")
	cat, err := skillcat.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := newMCPServer(&retrieval.Client{}, ragconfig.Config{}, cat)

	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	listed, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range listed.Resources {
		if r.URI == sessionResourceURI(first.SessionID) {
			found = true
		}
	}
	if !found {
		t.Fatalf("resources/list does not enumerate %s: %+v", first.SessionID, listed.Resources)
	}

	read, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: sessionResourceURI(first.SessionID)})
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Contents) != 1 || !strings.Contains(read.Contents[0].Text, "listed question") {
		t.Fatalf("contents = %+v", read.Contents)
	}

	// A session created after the server started is not enumerated, but the
	// template still serves it.
	second, err := mcpChatResult(ctx, nil, loadConfig(), mcpChatIn{Message: "later question"})
	if err != nil {
		t.Fatal(err)
	}
	read, err = cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: sessionResourceURI(second.SessionID)})
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Contents) != 1 || !strings.Contains(read.Contents[0].Text, "later question") {
		t.Fatalf("contents = %+v", read.Contents)
	}

	_, err = cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: sessionResourceURI("20260101T000000-aaaaaa")})
	if err == nil || !strings.Contains(err.Error(), "Resource not found") {
		t.Fatalf("unknown session err = %v, want resource not found", err)
	}
}
