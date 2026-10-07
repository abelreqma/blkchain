package main

import (
	"context"
	"strings"
	"testing"

	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/retrieval"

	"github.com/tmc/langchaingo/llms"
)

// correlate_selector_cachekey_test.go pins that the selection cache is keyed by
// the subject it actually selected for. buildExploitQueries issues a
// version-bearing query first, so two versions of one product can retrieve
// different pages; serving the first version's technique and citation to every
// later version reuses a selection made for a different build.

func TestSelectionKeySeparatesVersionsOfOneProduct(t *testing.T) {
	a := newKBExploitSelectionKey(Service{Product: "Apache httpd", Version: "2.4.49"})
	b := newKBExploitSelectionKey(Service{Product: "Apache httpd", Version: "2.4.58"})
	if a == b {
		t.Fatalf("two versions of one product share key %q", a)
	}
	if none := newKBExploitSelectionKey(Service{Product: "Apache httpd"}); none == a || none == b {
		t.Errorf("an absent version must not share a key with a specific one: %q", none)
	}
}

func TestSelectionKeyNormalizesCaseAndSpacing(t *testing.T) {
	want := newKBExploitSelectionKey(Service{Product: "Apache httpd", Version: "2.4.49"})
	for _, svc := range []Service{
		{Product: "APACHE HTTPD", Version: "2.4.49"},
		{Product: "  Apache   httpd ", Version: " 2.4.49 "},
		{Product: "apache httpd", Version: "2.4.49"},
	} {
		if got := newKBExploitSelectionKey(svc); got != want {
			t.Errorf("%+v keyed %q, want %q", svc, got, want)
		}
	}
	if got := newKBExploitSelectionKey(Service{Product: "   "}); got != "" {
		t.Errorf("an empty product must key to empty, got %q", got)
	}
}

// A product name ending where a version begins must not collide through the
// separator, which a plain concatenation would allow.
func TestSelectionKeyCannotCollideAcrossTheSeparator(t *testing.T) {
	if a, b := newKBExploitSelectionKey(Service{Product: "foo", Version: "bar"}),
		newKBExploitSelectionKey(Service{Product: "foobar"}); a == b {
		t.Fatalf("the product/version boundary collides: %q", a)
	}
}

// queryRecorder is a searcher that records every query it is asked and returns a
// hit whose path, section and text name product, so acceptCitation grounds.
type queryRecorder struct {
	queries []string
	product string
}

func (q *queryRecorder) Search(_ context.Context, query string, _ int, _ map[string]any) ([]retrieval.Result, error) {
	q.queries = append(q.queries, query)
	return []retrieval.Result{chunk("hacktricks", q.product+".md", q.product, q.product+" exploit notes")}, nil
}

// TestSelectorReconsultsForANewVersion drives the real selector. Two services
// differing only in version must each reach the corpus; keying on the product
// alone served the second from the first one's entry.
func TestSelectorReconsultsForANewVersion(t *testing.T) {
	rc := &queryRecorder{product: "zabbix"}
	m := &fakeModel{queue: []*llms.ContentResponse{
		textResp(`{"technique": "authenticated-rce"}`),
		textResp(`{"technique": "authenticated-rce"}`),
	}}
	sel := newKBExploitSelector(m, rc, ragconfig.Config{TopK: 5})

	if _, cit := sel(context.Background(), Service{Product: "zabbix", Version: "5.0.17"}); cit.Source == "" {
		t.Fatal("the first selection did not ground")
	}
	afterFirst := len(rc.queries)
	if afterFirst == 0 {
		t.Fatal("the first selection never reached the corpus")
	}

	// Same product and version: served from the cache, no new query.
	sel(context.Background(), Service{Product: "zabbix", Version: "5.0.17"})
	if len(rc.queries) != afterFirst {
		t.Errorf("an identical service re-queried the corpus: %v", rc.queries)
	}

	// Same product, a different version: the corpus is consulted again, and the
	// new version reaches the query.
	sel(context.Background(), Service{Product: "zabbix", Version: "6.0.1"})
	if len(rc.queries) == afterFirst {
		t.Fatalf("a different version reused the cached selection; queries: %v", rc.queries)
	}
	var sawNewVersion bool
	for _, q := range rc.queries[afterFirst:] {
		if strings.Contains(q, "6.0.1") {
			sawNewVersion = true
		}
	}
	if !sawNewVersion {
		t.Errorf("the new version was never queried: %v", rc.queries[afterFirst:])
	}
}
