package webcollect

import (
	"blkchain/cli/internal/webanalysis"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestArchiveJSONResumeRows(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[["timestamp","original","statuscode","mimetype","digest"],["20200101000000","https://fixture.test/app.js","200","application/javascript","old"],[],["next%2Bkey"]]`)
	}))
	defer server.Close()
	a := &Archive{Base: server.URL, Broker: fixtureBroker(server), Allowed: func(string) bool { return true }}
	captures, next, err := a.Query(context.Background(), "https://fixture.test/app.js", "exact", "", "")
	if err != nil || len(captures) != 1 || next != "next%2Bkey" {
		t.Fatalf("captures=%v next=%q err=%v", captures, next, err)
	}
}

func TestArchiveThrottlingAndMissingCaptures(t *testing.T) {
	for _, test := range []struct {
		status int
		after  string
		want   int
	}{{429, "0", 2}, {503, "60", 1}, {404, "", 1}} {
		t.Run(fmt.Sprint(test.status), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Retry-After", test.after)
				w.WriteHeader(test.status)
			}))
			defer server.Close()
			a := &Archive{Base: server.URL, Broker: fixtureBroker(server), Allowed: func(string) bool { return true }}
			if _, err := a.Fetch(context.Background(), Capture{Timestamp: "20200101000000", Original: "https://fixture.test/missing.js"}); err == nil {
				t.Fatal("unavailable capture accepted")
			}
			if calls != test.want {
				t.Fatalf("got %d requests; want %d", calls, test.want)
			}
		})
	}
}

func TestArchiveMalformedResumeAndLimits(t *testing.T) {
	for _, body := range []string{
		`[["timestamp","original","statuscode","mimetype","digest"],[],["bad key"]]`,
		`[["wrong","header"]]`,
		`[["timestamp","original","statuscode","mimetype","digest"],[]]`,
		`[["timestamp","original","statuscode","mimetype","digest"],[],["key"]] ["duplicate"]`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		a := &Archive{Base: server.URL, Broker: fixtureBroker(server), Allowed: func(string) bool { return true }}
		if _, _, err := a.Query(context.Background(), "https://fixture.test/x", "exact", "", ""); err == nil {
			t.Fatal("invalid CDX accepted", body)
		}
		server.Close()
	}
	if validArchiveResume(strings.Repeat("x", 4097)) || validArchiveResume("line\nkey") {
		t.Fatal("resume limit accepted")
	}
}

func TestHARBodyBytesOmittedAndBinary(t *testing.T) {
	svc := New(fixtureStore(t), nil, nil)
	svc.DiscoveryAllowed = func(string) bool { return true }
	har := `{"log":{"entries":[{"request":{"url":"https://fixture.test/upload","method":"POST","postData":{"mimeType":"multipart/form-data; boundary=x","params":[{"name":"file","fileName":"missing.bin"}]}},"response":{"status":200,"content":{"size":0}}},{"request":{"url":"https://fixture.test/binary","method":"POST","postData":{"mimeType":"application/octet-stream","text":"AP8=","_encoding":"base64"}},"response":{"status":200,"content":{"size":0}}},{"request":{"url":"https://fixture.test/json","method":"POST","postData":{"mimeType":"application/json"}},"response":{"status":200,"content":{"size":0}}}]}}`
	if err := svc.ImportHAR(context.Background(), strings.NewReader(har), "writer"); err != nil {
		t.Fatal(err)
	}
	snap, err := svc.Store.WebSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	omitted, binary := 0, false
	for _, r := range snap.Requests {
		if r.BodyOmitted {
			omitted++
		}
		if r.URL == "https://fixture.test/binary" {
			kind, body, err := webanalysis.ReplayBody(r)
			binary = err == nil && kind == "binary" && string(body) == "\x00\xff"
		}
	}
	if omitted != 2 || !binary || len(snap.Coverage) == 0 || len(snap.Coverage[0].Gaps) != 2 {
		t.Fatal("HAR replay gaps or bytes lost", snap.Coverage)
	}
}
