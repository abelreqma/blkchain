package main

import "testing"

func TestParseGrade(t *testing.T) {
	g := parseGrade("chatter {\"sufficient\": true, \"rewrite\": \"x\", \"use_web\": false} tail")
	if !g.Sufficient || g.Rewrite != "x" || g.UseWeb {
		t.Fatalf("got %+v", g)
	}
	bad := parseGrade("no json here")
	if bad.Sufficient || bad.UseWeb || bad.Rewrite != "" {
		t.Fatalf("default should be all-false/empty, got %+v", bad)
	}
}
