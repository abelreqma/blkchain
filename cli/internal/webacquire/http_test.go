package webacquire

import (
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fixtureBroker() *Broker {
	return &Broker{Policy: Policy{Authorize: func(context.Context, Request) error { return nil }, IPAllowed: func(ip net.IP) bool { return ip.IsLoopback() }}}
}
func TestPinnedResolutionAndRedirectCredentials(t *testing.T) {
	leaked := false
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") != ""
		w.Write([]byte("body"))
	}))
	defer dst.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, dst.URL, 302) }))
	defer src.Close()
	b := fixtureBroker()
	out, e := b.Fetch(context.Background(), Request{Method: "GET", URL: src.URL, Headers: http.Header{"Authorization": []string{"test-only"}}})
	if e != nil || string(out.Body) != "body" || leaked {
		t.Fatalf("redirect policy: %v complete=%v leaked=%v", e, out.Complete, leaked)
	}
	b.Policy.Resolve = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("8.8.8.8")}, nil
	}
	if _, e = b.Fetch(context.Background(), Request{Method: "GET", URL: src.URL}); e == nil {
		t.Fatal("mixed DNS accepted")
	}
}
func TestCompressedBombCancellationAndBudget(t *testing.T) {
	var z bytes.Buffer
	gz := gzip.NewWriter(&z)
	gz.Write(bytes.Repeat([]byte("x"), MaxBody+1))
	gz.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(z.Bytes())
	}))
	defer s.Close()
	b := fixtureBroker()
	o, e := b.Fetch(context.Background(), Request{Method: "GET", URL: s.URL})
	if e == nil || o.Complete || !strings.Contains(o.Gap, "decompressed") {
		t.Fatal("bomb accepted")
	}
	ctx, c := context.WithCancel(context.Background())
	c()
	if _, e = b.Fetch(ctx, Request{Method: "GET", URL: s.URL}); e == nil {
		t.Fatal("cancellation ignored")
	}
	b.requests = MaxRequests
	if _, e = b.Fetch(context.Background(), Request{Method: "GET", URL: s.URL}); e == nil {
		t.Fatal("budget ignored")
	}
}
func TestURLBoundary(t *testing.T) {
	for _, s := range []string{"file:///tmp/a", "http://a@127.0.0.1/", "http://host\n/x", "http://host%2f.evil/"} {
		if _, e := URL(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

func TestDiscardedTransfersConsumeAggregateBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "unsupported")
		w.Write([]byte("discarded"))
	}))
	defer server.Close()
	b := fixtureBroker()
	b.wireBytes = MaxTotal - 3
	if _, e := b.Fetch(context.Background(), Request{URL: server.URL}); e == nil {
		t.Fatal("oversized aggregate transfer accepted")
	}
	if b.wireBytes != MaxTotal {
		t.Fatal(b.wireBytes)
	}
	if _, e := b.Fetch(context.Background(), Request{URL: server.URL}); e == nil {
		t.Fatal("discarded transfer did not exhaust budget")
	}
}
