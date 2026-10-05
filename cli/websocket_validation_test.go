package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
	"blkchain/cli/internal/webcollect"
	"github.com/gorilla/websocket"
)

func TestWebSocketSubscriptionValidationAndFailureEvidence(t *testing.T) {
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{Subprotocols: []string{"graphql-transport-ws"}}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for _, response := range []string{`{"type":"connection_ack"}`, `{"id":"one","type":"next","payload":{"data":{"event":"fixture"}}}`} {
			if _, _, err = conn.ReadMessage(); err != nil {
				return
			}
			writes.Add(1)
			if err = conn.WriteMessage(1, []byte(response)); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	op := webanalysis.Operation{ID: webanalysis.ID("socket-validation"), Origin: strings.Replace(server.URL, "http:", "ws:", 1), Path: "/socket", Protocol: "websocket", Method: "GET"}
	plan := webSocketPlan{Adapter: "exact-message", Protocols: []string{"graphql-transport-ws"}, Steps: []webSocketStep{
		{Send: &webSocketFrame{Opcode: 1, Body: `{"type":"connection_init"}`}},
		{Expect: &webSocketFrame{Opcode: 1, Body: `{"type":"connection_ack"}`}},
		{Send: &webSocketFrame{Opcode: 1, Body: `{"id":"one","type":"subscribe","payload":{"query":"subscription { event }"}}`}},
		{Expect: &webSocketFrame{Opcode: 1, Body: `{"id":"one","type":"next","payload":{"data":{"event":"fixture"}}}`}},
	}}
	for _, test := range []struct {
		name           string
		mismatch, deny bool
	}{{name: "matched"}, {name: "mismatch", mismatch: true}, {name: "denied", deny: true}} {
		t.Run(test.name, func(t *testing.T) {
			ws, err := engagement.OpenWorkspace(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer ws.Close()
			broker := &webacquire.Broker{Policy: webacquire.Policy{Authorize: func(_ context.Context, r webacquire.Request) error {
				if test.deny && r.Method == "WEBSOCKET" {
					return errors.New("fixture denies send")
				}
				return nil
			}, IPAllowed: func(ip net.IP) bool { return ip.IsLoopback() }}}
			svc := webcollect.New(ws.Store, broker, nil)
			data, _ := json.Marshal(plan)
			current, err := webSocketDecodePlan(data)
			if err != nil {
				t.Fatal(err)
			}
			if test.mismatch {
				current.Steps[1].Expect.Body = `{"type":"wrong"}`
			}
			err = webValidateSocket(context.Background(), svc, op, webSessionRole{Name: "anonymous"}, nil, current, "")
			if (err != nil) != (test.mismatch || test.deny) {
				t.Fatal(err)
			}
			snap, err := ws.Store.WebSnapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(snap.Artifacts) == 0 || len(snap.Requests) == 0 {
				t.Fatal("exchange evidence missing")
			}
			validated := false
			for _, record := range snap.Operations {
				validated = validated || record.Exchange != nil && record.Evidence.Grade == "exchange-validated"
			}
			if validated == (test.mismatch || test.deny) {
				t.Fatal("incorrect application validation", snap.Operations)
			}
		})
	}
	if writes.Load() != 3 {
		t.Fatalf("server received %d messages; want 3", writes.Load())
	}
}

func TestWebSocketTranscriptBoundsAndCancellation(t *testing.T) {
	for _, data := range []string{
		`{"adapter":"exact-message","steps":[]}`,
		`{"adapter":"exact-message","steps":[{"expect":{"opcode":1,"body":"x"}},{"send":{"opcode":1,"body":"x"}}]}`,
		`{"adapter":"http","steps":[{"send":{"opcode":1}},{"expect":{"opcode":1}}]}`,
		`{"adapter":"exact-message","steps":[{"send":{"opcode":9}},{"expect":{"opcode":1}}]}`,
		`{"adapter":"exact-message","steps":[{"send":{"opcode":1}},{"expect":{"opcode":1}}]} {}`,
	} {
		if _, err := webSocketDecodePlan([]byte(data)); err == nil {
			t.Fatal("invalid transcript accepted")
		}
	}
	plan := webSocketPlan{Adapter: "exact-message"}
	for i := 0; i < 21; i++ {
		plan.Steps = append(plan.Steps, webSocketStep{Send: &webSocketFrame{Opcode: 1}})
	}
	b, _ := json.Marshal(plan)
	if _, err := webSocketDecodePlan(b); err == nil {
		t.Fatal("step limit accepted")
	}
	if _, err := webSocketFrameBytes(webSocketFrame{Opcode: 1, Body: strings.Repeat("x", webacquire.MaxWSMessage+1)}); err == nil {
		t.Fatal("frame limit accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err = conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	ws, err := engagement.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	svc := webcollect.New(ws.Store, &webacquire.Broker{Policy: webacquire.Policy{Authorize: func(context.Context, webacquire.Request) error { return nil }, IPAllowed: func(ip net.IP) bool { return ip.IsLoopback() }}}, nil)
	op := webanalysis.Operation{ID: webanalysis.ID("cancel-socket"), Origin: strings.Replace(server.URL, "http:", "ws:", 1), Protocol: "websocket", Method: "GET"}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	plan.Steps = []webSocketStep{{Send: &webSocketFrame{Opcode: 1, Body: "wait"}}, {Expect: &webSocketFrame{Opcode: 1, Body: "response"}}}
	started := time.Now()
	if err = webValidateSocket(ctx, svc, op, webSessionRole{Name: "anonymous"}, nil, plan, ""); err == nil || time.Since(started) > time.Second {
		t.Fatal("socket cancellation failed", err)
	}
}

func TestExactReplaySelectedBodyAndRoles(t *testing.T) {
	for _, test := range []struct{ mime, body string }{{"text/plain", "text\r\n"}, {"application/json", " [1,2] "}, {"multipart/form-data; boundary=x", "--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\n\xff\x00\r\n--x--\r\n"}, {"application/octet-stream", "\xff\x00"}} {
		e := webanalysis.RequestExample{URL: "https://fixture.test/upload?a=%2f+", Method: "POST", Role: "writer", Headers: http.Header{"Content-Type": []string{test.mime}, "Authorization": []string{"stale"}}}
		webanalysis.SetRequestBody(&e, []byte(test.body))
		op, _ := webanalysis.FromObserved(e)
		request, role, err := webReplayExample(op, 1)
		if err != nil || request.Body != test.body || request.URL != e.URL || role != "writer" || strings.Contains(strings.Join(request.Headers, ","), "stale") {
			t.Fatal(request, role, err)
		}
		if _, _, err = webReplayExample(op, 2); err == nil {
			t.Fatal("missing example accepted")
		}
		op.Examples[0].BodyOmitted = true
		if _, _, err = webReplayExample(op, 1); err == nil {
			t.Fatal("omitted body accepted")
		}
	}
}
