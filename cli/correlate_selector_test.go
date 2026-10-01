package main

import (
	"context"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

func TestParseExploitSelection(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{"valid", `{"technique": "CVE-2021-41773 path traversal"}`, "CVE-2021-41773 path traversal"},
		{"tolerates chatter", `sure: {"technique": "SambaCry"} done`, "SambaCry"},
		{"no braces", `SambaCry`, ""},
		{"malformed", `{"technique":`, ""},
		{"wrong type", `{"technique": 7}`, ""},
		{"missing field", `{"foo": "bar"}`, ""},
		{"empty", `{"technique": "  "}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseExploitSelection(tc.raw); got != tc.want {
				t.Fatalf("parseExploitSelection(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestKBExploitSelectorParsesAndSetsBasis(t *testing.T) {
	rc := &recSearcher{results: []retrieval.Result{
		chunk("offensive-rce", "ssh.md", "SSH", "OpenSSH known CVEs and exploitation."),
	}}
	m := &fakeModel{queue: []*llms.ContentResponse{textResp(`{"technique": "CVE-2020-15778"}`)}}
	sel := newKBExploitSelector(m, rc, ragconfig.Config{TopK: 5})
	tech, basis := sel(context.Background(), Service{Product: "OpenSSH", Version: "8.2p1", Port: 22})
	if tech != "CVE-2020-15778" {
		t.Fatalf("technique = %q, want CVE-2020-15778", tech)
	}
	if basis != "kb_search:offensive-rce" {
		t.Fatalf("basis = %q, want kb_search:offensive-rce (provenance)", basis)
	}
}

func TestKBExploitSelectorFailsClosed(t *testing.T) {
	cfg := ragconfig.Config{TopK: 5}
	oneResult := []retrieval.Result{chunk("s", "p.md", "x", "note")}

	t.Run("nil model", func(t *testing.T) {
		sel := newKBExploitSelector(nil, &recSearcher{results: oneResult}, cfg)
		if tech, _ := sel(context.Background(), Service{Product: "OpenSSH"}); tech != "" {
			t.Fatalf("nil model must fail closed, got %q", tech)
		}
	})
	t.Run("malformed reply", func(t *testing.T) {
		m := &fakeModel{queue: []*llms.ContentResponse{textResp(`not json at all`)}}
		sel := newKBExploitSelector(m, &recSearcher{results: oneResult}, cfg)
		if tech, _ := sel(context.Background(), Service{Product: "OpenSSH"}); tech != "" {
			t.Fatalf("malformed reply must fail closed, got %q", tech)
		}
	})
	t.Run("empty product", func(t *testing.T) {
		m := &fakeModel{queue: []*llms.ContentResponse{textResp(`{"technique":"x"}`)}}
		sel := newKBExploitSelector(m, &recSearcher{results: oneResult}, cfg)
		if tech, _ := sel(context.Background(), Service{Product: "   "}); tech != "" {
			t.Fatalf("empty product must fail closed, got %q", tech)
		}
	})
}
