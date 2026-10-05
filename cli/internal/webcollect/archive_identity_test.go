package webcollect

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"blkchain/cli/internal/webacquire"
)

func TestArchiveIdentifiesQueriesCapturesAndRetries(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.UserAgent() != "blkChain/1.0 (Wayback archive collection)" {
			t.Errorf("archive User-Agent = %q", r.UserAgent())
			w.WriteHeader(429)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("archive request carries credentials")
		}
		if calls == 1 {
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
	a := &Archive{Base: server.URL, Broker: fixtureBroker(server), Allowed: func(string) bool { return true }}
	rows, _, err := a.Query(context.Background(), "https://fixture.test/app.js", "exact", "", "")
	if err != nil || len(rows) != 1 {
		t.Fatalf("query captures=%d err=%v", len(rows), err)
	}
	if _, err := a.Fetch(context.Background(), rows[0]); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("requests=%d want=3", calls)
	}
}

func TestArchiveInfrastructureHeadersRemainRestricted(t *testing.T) {
	a := NewArchive(func(string) bool { return true })
	for _, tc := range []struct {
		name    string
		headers http.Header
		allowed bool
	}{
		{"identity", http.Header{"User-Agent": {"blkChain/1.0 (Wayback archive collection)"}}, true},
		{"missing", nil, false},
		{"other-identity", http.Header{"User-Agent": {"browser"}}, false},
		{"multiple-identities", http.Header{"User-Agent": {"blkChain/1.0 (Wayback archive collection)", "browser"}}, false},
		{"authorization", http.Header{"User-Agent": {"blkChain/1.0 (Wayback archive collection)"}, "Authorization": {"fixture"}}, false},
		{"cookie", http.Header{"User-Agent": {"blkChain/1.0 (Wayback archive collection)"}, "Cookie": {"fixture"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := a.Broker.Policy.Authorize(context.Background(), webacquire.Request{Method: "GET", URL: "https://web.archive.org/cdx/search/cdx", Headers: tc.headers})
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%t err=%v", tc.allowed, err)
			}
		})
	}
}
