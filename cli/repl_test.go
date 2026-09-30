package main

import (
	"bufio"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPlainClarifyNumberedChoice(t *testing.T) {
	c := Clarification{Question: "pick", Options: []ClarifyOption{{Label: "a", Value: "va"}, {Label: "b", Value: "vb"}}}
	in := bufio.NewScanner(strings.NewReader("2\n"))
	var out strings.Builder
	if res := plainClarify(in, &out, c); res.Value != "vb" || res.Canceled {
		t.Fatalf("numbered = %+v; want vb", res)
	}
	in2 := bufio.NewScanner(strings.NewReader("\n"))
	if r := plainClarify(in2, &out, c); !r.Canceled {
		t.Fatalf("empty should cancel")
	}
	in3 := bufio.NewScanner(strings.NewReader("do something else\n"))
	if r := plainClarify(in3, &out, c); r.Custom != "do something else" {
		t.Fatalf("non-numeric should be custom; got %+v", r)
	}
}

func TestPlainClarifyEdgeCases(t *testing.T) {
	c := Clarification{Question: "pick", Detail: "some detail", Options: []ClarifyOption{{Label: "a", Value: "va"}}}
	var out strings.Builder
	if r := plainClarify(bufio.NewScanner(strings.NewReader("9\n")), &out, c); r.Custom != "9" || r.Value != "" || r.Canceled {
		t.Fatalf("out-of-range = %+v; want Custom 9", r)
	}
	if r := plainClarify(bufio.NewScanner(strings.NewReader("0\n")), &out, c); r.Custom != "0" {
		t.Fatalf("zero = %+v; want Custom 0", r)
	}
	if r := plainClarify(bufio.NewScanner(strings.NewReader("   \t \n")), &out, c); !r.Canceled {
		t.Fatalf("whitespace-only should cancel; got %+v", r)
	}
	if r := plainClarify(bufio.NewScanner(strings.NewReader("")), &out, c); !r.Canceled {
		t.Fatalf("EOF should cancel; got %+v", r)
	}
	text := stripANSI(out.String())
	for _, want := range []string{"pick", "some detail", "1) a", "choose>"} {
		if !strings.Contains(text, want) {
			t.Fatalf("prompt output missing %q: %q", want, text)
		}
	}
}

func TestPlainVizSnapshotWritesBlock(t *testing.T) {
	fr := &fakeRunner{out: "recon: enumerate host\nweb: SQLi on /login"}
	stub := newStubEngagement("acme")
	stub.setSnapshot(sampleEngagement(0))
	var out strings.Builder
	plainVizSnapshot(&out, newVizRenderer(fr), stub)
	if !strings.Contains(out.String(), "SQLi on /login") {
		t.Fatalf("snapshot missing block: %q", out.String())
	}
}

type failingView struct{}

func (failingView) Revision(context.Context) (int64, error) { return 0, errors.New("boom") }
func (failingView) Snapshot(context.Context) (Engagement, error) {
	return Engagement{}, errors.New("boom")
}

func TestPlainVizSnapshotSilentOnError(t *testing.T) {
	var out strings.Builder
	plainVizSnapshot(&out, newVizRenderer(&fakeRunner{out: "x"}), failingView{})
	if out.Len() != 0 {
		t.Fatalf("view error should write nothing; got %q", out.String())
	}
}
