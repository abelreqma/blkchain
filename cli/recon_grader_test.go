package main

import (
	"context"
	"testing"

	"blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"

	"github.com/tmc/langchaingo/llms"
)

// errModel (toolloop_test.go) always fails the generate call, exercising the
// grader's fail-closed path.

func TestParseReconGrade(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want reconVerdict
	}{
		{"continue true", `{"continue": true}`, reconVerdict{Continue: true, Parsed: true}},
		{"continue false", `{"continue": false}`, reconVerdict{Continue: false, Parsed: true}},
		{"tolerates chatter", `sure: {"continue": false} ok`, reconVerdict{Continue: false, Parsed: true}},
		{"not json", `not json`, reconVerdict{Parsed: false}},
		{"empty", ``, reconVerdict{Parsed: false}},
		{"open brace only", `{`, reconVerdict{Parsed: false}},
		{"wrong type", `{"continue": "yes"}`, reconVerdict{Parsed: false}},
		{"missing field", `{}`, reconVerdict{Parsed: false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseReconGrade(tc.raw)
			if got != tc.want {
				t.Fatalf("parseReconGrade(%q) = %+v, want %+v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestLLMReconGraderErrorFailsClosed(t *testing.T) {
	g := newLLMReconGrader(errModel{}, ragconfig.Config{})
	v := g(context.Background(), engagement.SurfaceNetwork, "10.0.0.1", "hosts: covered")
	if v.Parsed {
		t.Fatalf("grader on a call error = %+v, want Parsed=false (fail closed -> stop)", v)
	}
}

func TestLLMReconGraderNoChoicesFailsClosed(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{emptyChoices()}}
	g := newLLMReconGrader(m, ragconfig.Config{})
	v := g(context.Background(), engagement.SurfaceNetwork, "10.0.0.1", "hosts: covered")
	if v.Parsed {
		t.Fatalf("grader on no choices = %+v, want Parsed=false (fail closed -> stop)", v)
	}
}

func TestLLMReconGraderParsesContinue(t *testing.T) {
	m := &fakeModel{queue: []*llms.ContentResponse{textResp(`{"continue": true}`)}}
	g := newLLMReconGrader(m, ragconfig.Config{})
	v := g(context.Background(), engagement.SurfaceNetwork, "10.0.0.1", "hosts: covered")
	if !v.Parsed || !v.Continue {
		t.Fatalf("grader on a valid continue reply = %+v, want {Continue:true, Parsed:true}", v)
	}
}
