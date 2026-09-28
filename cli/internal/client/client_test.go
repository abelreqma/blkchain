package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	c := &Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	return c, srv.Close
}

func TestHealth(t *testing.T) {
	c, closeSrv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/health" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
	})
	defer closeSrv()

	h, err := c.Health()
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if h.Status != "ok" {
		t.Errorf("Status = %q, want %q", h.Status, "ok")
	}
}

func TestSearch(t *testing.T) {
	canned := SearchResponse{
		Results: []SearchResult{
			{
				ID:    "doc-1",
				Score: 0.9321,
				Payload: Payload{
					Source:  "ledger-spec",
					Path:    "docs/ledger.md",
					Section: "Consensus",
					Type:    "markdown",
					Text:    "The consensus algorithm reaches finality after two rounds of voting.",
				},
			},
			{
				ID:    "doc-2",
				Score: 0.5001,
				Payload: Payload{
					Source:  "whitepaper",
					Path:    "docs/whitepaper.pdf",
					Section: "Introduction",
					Type:    "pdf",
					Text:    "blkChain is a research RAG system.",
				},
			},
		},
	}

	var gotReq SearchRequest
	c, closeSrv := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/search" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Fatalf("decoding request body: %v", err)
		}
		json.NewEncoder(w).Encode(canned)
	})
	defer closeSrv()

	resp, err := c.Search("how does consensus work", 5, nil)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	if gotReq.Query != "how does consensus work" {
		t.Errorf("request Query = %q, want %q", gotReq.Query, "how does consensus work")
	}
	if gotReq.TopK != 5 {
		t.Errorf("request TopK = %d, want 5", gotReq.TopK)
	}

	if len(resp.Results) != 2 {
		t.Fatalf("len(Results) = %d, want 2", len(resp.Results))
	}
	if resp.Results[0].ID != "doc-1" || resp.Results[0].Score != 0.9321 {
		t.Errorf("Results[0] = %+v, unexpected", resp.Results[0])
	}
	if resp.Results[0].Payload.Source != "ledger-spec" {
		t.Errorf("Results[0].Payload.Source = %q, want %q", resp.Results[0].Payload.Source, "ledger-spec")
	}
	if resp.Results[1].Payload.Type != "pdf" {
		t.Errorf("Results[1].Payload.Type = %q, want %q", resp.Results[1].Payload.Type, "pdf")
	}
}

func TestUnreachable(t *testing.T) {
	// Point at a port nothing is listening on.
	c := &Client{BaseURL: "http://127.0.0.1:1", HTTPClient: http.DefaultClient}

	_, err := c.Health()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var unreachable *UnreachableError
	if _, ok := err.(*UnreachableError); !ok {
		t.Fatalf("err = %v (%T), want *UnreachableError", err, err)
	} else {
		unreachable = err.(*UnreachableError)
	}
	if unreachable.URL != c.BaseURL {
		t.Errorf("UnreachableError.URL = %q, want %q", unreachable.URL, c.BaseURL)
	}
}
