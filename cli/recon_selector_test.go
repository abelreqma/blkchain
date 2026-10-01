package main

import (
	"context"
	"errors"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

func TestParseReconSelection(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want reconSelection
	}{
		{"valid", `{"action": "ping sweep"}`, reconSelection{Action: "ping sweep", Parsed: true}},
		{"tolerates chatter", `pick: {"action": "service scan"} ok`, reconSelection{Action: "service scan", Parsed: true}},
		{"no braces", `ping sweep`, reconSelection{}},
		{"malformed", `{"action":`, reconSelection{}},
		{"wrong type", `{"action": 5}`, reconSelection{}},
		{"missing field", `{"foo": "bar"}`, reconSelection{}},
		{"empty action", `{"action": "  "}`, reconSelection{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseReconSelection(tc.raw); got != tc.want {
				t.Fatalf("parseReconSelection(%q) = %+v, want %+v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestKBReconSelectorParsesAndSetsBasis(t *testing.T) {
	rc := &recSearcher{results: []retrieval.Result{
		chunk("offensive-network-attacks", "recon/host.md", "Discovery", "Use an ICMP echo sweep for host discovery."),
	}}
	m := &fakeModel{queue: []*llms.ContentResponse{textResp(`{"action": "icmp echo sweep"}`)}}
	sel := newKBReconSelector(m, rc, ragconfig.Config{TopK: 5})
	got := sel(context.Background(), engagement.SurfaceNetwork, "10.0.0.1", reconTier{Index: 0, Name: "host-discovery", Dimensions: []string{"hosts"}}, engagement.ReconCoverage{})
	if !got.Parsed || got.Action != "icmp echo sweep" {
		t.Fatalf("selection = %+v, want parsed action 'icmp echo sweep'", got)
	}
	if got.Basis != "kb_search:offensive-network-attacks" {
		t.Fatalf("Basis = %q, want kb_search:offensive-network-attacks (provenance)", got.Basis)
	}
}

func TestKBReconSelectorFailsClosed(t *testing.T) {
	netTier := reconTier{Index: 0, Name: "host-discovery", Dimensions: []string{"hosts"}}
	cfg := ragconfig.Config{TopK: 5}
	oneResult := []retrieval.Result{chunk("src", "p.md", "s", "note")}

	t.Run("nil searcher", func(t *testing.T) {
		sel := newKBReconSelector(&fakeModel{queue: []*llms.ContentResponse{textResp(`{"action":"x"}`)}}, nil, cfg)
		if got := sel(context.Background(), engagement.SurfaceNetwork, "a", netTier, engagement.ReconCoverage{}); got.Parsed {
			t.Fatalf("nil searcher = %+v, want unparsed (ladder fallback)", got)
		}
	})
	t.Run("corpus error", func(t *testing.T) {
		rc := &recSearcher{err: errors.New("down")}
		sel := newKBReconSelector(&fakeModel{queue: []*llms.ContentResponse{textResp(`{"action":"x"}`)}}, rc, cfg)
		if got := sel(context.Background(), engagement.SurfaceNetwork, "a", netTier, engagement.ReconCoverage{}); got.Parsed {
			t.Fatalf("corpus error = %+v, want unparsed", got)
		}
	})
	t.Run("empty corpus", func(t *testing.T) {
		rc := &recSearcher{results: nil}
		sel := newKBReconSelector(&fakeModel{queue: []*llms.ContentResponse{textResp(`{"action":"x"}`)}}, rc, cfg)
		if got := sel(context.Background(), engagement.SurfaceNetwork, "a", netTier, engagement.ReconCoverage{}); got.Parsed {
			t.Fatalf("empty corpus = %+v, want unparsed", got)
		}
	})
	t.Run("model error", func(t *testing.T) {
		rc := &recSearcher{results: oneResult}
		sel := newKBReconSelector(errModel{}, rc, cfg)
		if got := sel(context.Background(), engagement.SurfaceNetwork, "a", netTier, engagement.ReconCoverage{}); got.Parsed {
			t.Fatalf("model error = %+v, want unparsed", got)
		}
	})
	t.Run("malformed model reply", func(t *testing.T) {
		rc := &recSearcher{results: oneResult}
		sel := newKBReconSelector(&fakeModel{queue: []*llms.ContentResponse{textResp("not json")}}, rc, cfg)
		if got := sel(context.Background(), engagement.SurfaceNetwork, "a", netTier, engagement.ReconCoverage{}); got.Parsed {
			t.Fatalf("malformed reply = %+v, want unparsed", got)
		}
	})
}

// countingSearcher returns results on the first call and an error afterward, so a
// second selection for the same (asset, tier) only succeeds if it is served from
// cache.
type countingSearcher struct {
	calls int
}

func (c *countingSearcher) Search(_ context.Context, _ string, _ int, _ map[string]any) ([]retrieval.Result, error) {
	c.calls++
	if c.calls == 1 {
		return []retrieval.Result{chunk("src", "p.md", "s", "note")}, nil
	}
	return nil, errors.New("second call should have been cached")
}

func TestKBReconSelectorCachesPerAssetTier(t *testing.T) {
	rc := &countingSearcher{}
	m := &fakeModel{queue: []*llms.ContentResponse{textResp(`{"action": "ping sweep"}`)}}
	sel := newKBReconSelector(m, rc, ragconfig.Config{TopK: 5})
	tier := reconTier{Index: 0, Name: "host-discovery", Dimensions: []string{"hosts"}}

	first := sel(context.Background(), engagement.SurfaceNetwork, "10.0.0.1", tier, engagement.ReconCoverage{})
	second := sel(context.Background(), engagement.SurfaceNetwork, "10.0.0.1", tier, engagement.ReconCoverage{})
	if first != second {
		t.Fatalf("second selection %+v != first %+v; per-(asset,tier) cache not applied", second, first)
	}
	if rc.calls != 1 {
		t.Fatalf("searcher called %d times, want 1 (cached)", rc.calls)
	}
}
