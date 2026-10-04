package webacquire

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func wsBroker() *Broker {
	return &Broker{Policy: Policy{Authorize: func(context.Context, Request) error { return nil }, IPAllowed: func(ip net.IP) bool { return ip.IsLoopback() }}}
}
func TestWebSocketPinnedMessagesPoliciesAndCancellation(t *testing.T) {
	var headers http.Header
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = r.Header.Clone()
		conn, err := (&websocket.Upgrader{Subprotocols: []string{"fixture"}, CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			kind, body, err := conn.ReadMessage()
			if err != nil {
				return
			}
			writes.Add(1)
			if err = conn.WriteMessage(kind, body); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	target := "ws" + strings.TrimPrefix(server.URL, "http") + "/stream"
	broker := wsBroker()
	broker.Policy.Resolve = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1")}, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	socket, response, err := broker.OpenWebSocket(ctx, target, http.Header{"Cookie": []string{"session=fixture"}, "Origin": []string{server.URL}}, []string{"fixture"})
	if err != nil || response.Status != 101 || socket.Conn.Subprotocol() != "fixture" {
		t.Fatal(response, err)
	}
	defer socket.Close()
	received := make(chan error, 1)
	go func() {
		kind, body, err := socket.Receive()
		if err == nil && (kind != websocket.BinaryMessage || string(body) != "\x00\xfffixture") {
			err = ErrLimit
		}
		received <- err
	}()
	if err = socket.Send(ctx, websocket.BinaryMessage, []byte("\x00\xfffixture")); err != nil {
		t.Fatal(err)
	}
	if err = <-received; err != nil {
		t.Fatal(err)
	}
	if headers.Get("Cookie") != "session=fixture" {
		t.Fatal("credentials lost")
	}
	broker.Policy.Authorize = func(_ context.Context, r Request) error {
		if r.Method == "WEBSOCKET" {
			return ErrLimit
		}
		return nil
	}
	if err = socket.Send(ctx, websocket.TextMessage, []byte("denied")); err == nil {
		t.Fatal("message policy bypass")
	}
	if writes.Load() != 1 {
		t.Fatal("denied message reached target")
	}
	cancel()
	if _, _, err = socket.Receive(); err == nil {
		t.Fatal("cancellation did not close socket")
	}
	broker = wsBroker()
	broker.Policy.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.0.2.1")}, nil
	}
	if _, _, err = broker.OpenWebSocket(context.Background(), target, nil, nil); err == nil {
		t.Fatal("mixed DNS scope bypass")
	}
}
func TestWebSocketLimitsRedirectsAndTLSVerification(t *testing.T) {
	var reached atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer source.Close()
	broker := wsBroker()
	_, response, err := broker.OpenWebSocket(context.Background(), "ws"+strings.TrimPrefix(source.URL, "http"), nil, nil)
	if err == nil || response.Status != 302 || reached.Load() != 0 {
		t.Fatal("WebSocket redirect followed", response, err)
	}
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer secure.Close()
	if _, _, err = broker.OpenWebSocket(context.Background(), "wss"+strings.TrimPrefix(secure.URL, "https"), nil, nil); err == nil {
		t.Fatal("untrusted target TLS accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, e := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.BinaryMessage, make([]byte, MaxWSMessage+1))
	}))
	defer server.Close()
	socket, _, err := broker.OpenWebSocket(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if _, _, err = socket.Receive(); err == nil {
		t.Fatal("message limit ignored")
	}
	if err = socket.Send(context.Background(), websocket.TextMessage, make([]byte, MaxWSMessage+1)); err == nil {
		t.Fatal("outbound message limit ignored")
	}
	if _, _, err = WebSocketURL("ws://fixture.test/stream#x"); err == nil {
		t.Fatal("fragment accepted")
	}
	if _, _, err = broker.OpenWebSocket(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), http.Header{"X-Note": []string{"x\r\nCookie: stolen"}}, nil); err == nil {
		t.Fatal("header injection accepted")
	}
}
