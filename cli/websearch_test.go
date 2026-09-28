package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTavilySearchMapsResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"title":"NVD CVE","url":"https://nvd.nist.gov/x","content":"body","score":0.9}]}`))
	}))
	defer srv.Close()
	got, err := tavilySearchAt(context.Background(), srv.URL, "k", "cve-2024-1", 5, []string{"nvd.nist.gov"})
	if err != nil || len(got) != 1 || got[0].Payload.Source != "web" || got[0].Payload.Path != "https://nvd.nist.gov/x" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestTavilyKeyAbsentSkips(t *testing.T) {
	t.Setenv("TAVILY_SETUP_TOKEN", "")
	if tavilyKey() != "" {
		t.Errorf("expected empty key")
	}
}
