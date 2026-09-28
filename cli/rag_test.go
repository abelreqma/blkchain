package main

import "testing"

func TestNextAction(t *testing.T) {
	cases := []struct {
		suff, web, tav, cve bool
		res                 int
		want                string
	}{
		{true, false, true, false, 3, "sufficient"},
		{false, true, true, false, 3, "web"},
		{false, false, true, true, 3, "web"},      // CVE heuristic forces web
		{false, true, false, false, 3, "rewrite"}, // no tavily key -> rewrite
		{false, false, false, false, 0, "rewrite"},
	}
	for i, c := range cases {
		if got := nextAction(grade{Sufficient: c.suff, UseWeb: c.web}, c.tav, c.cve, c.res); got != c.want {
			t.Errorf("case %d: got %s want %s", i, got, c.want)
		}
	}
}

func TestLooksLikeCVEorPoC(t *testing.T) {
	yes := []string{
		"CVE-2024-1234",
		"cve-2021-44228 details",
		"is there a poc for this bug",
		"proof-of-concept exploit",
		"proof of concept code",
		"any known exploit for this",
	}
	for _, q := range yes {
		if !looksLikeCVEorPoC(q) {
			t.Errorf("looksLikeCVEorPoC(%q) = false, want true", q)
		}
	}

	no := []string{
		"what is SSRF",
		"how does XSS work",
		"pocket knife safety",
	}
	for _, q := range no {
		if looksLikeCVEorPoC(q) {
			t.Errorf("looksLikeCVEorPoC(%q) = true, want false", q)
		}
	}
}
