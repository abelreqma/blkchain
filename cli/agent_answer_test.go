package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"blkchain/cli/internal/retrieval"
	"github.com/tmc/langchaingo/llms"
)

func TestGroundedAgentOverrideChangesActualPromptAndCue(t *testing.T) {
	for _, tc := range []struct{ choice, want, marker string }{{"", "web", "browser-to-server trust boundary"}, {"cloud", "cloud", "AWS, Azure, and GCP"}, {"general", "", "generalist"}} {
		t.Run(tc.choice, func(t *testing.T) {
			fake := &fakeModel{queue: []*llms.ContentResponse{{Choices: []*llms.ContentChoice{{Content: "fixture [1]"}}}}}
			cue := "missing"
			_, _, _, err := synthesize(context.Background(), fake, kbTestCfg(), "explain this setting", []retrieval.Result{chunk("wstg", "web/application.md", "Configuration", "a documented setting")}, AnswerOpts{Agent: tc.choice, Persona: func(domain string) { cue = domain }})
			if err != nil {
				t.Fatal(err)
			}
			if cue != tc.want || len(fake.seen) != 1 || !strings.Contains(renderMessages(fake.seen[0]), tc.marker) {
				t.Fatalf("override did not reach prompt/cue: cue=%q calls=%d", cue, len(fake.seen))
			}
		})
	}
}

func TestDirectAgentOverrideReachesProviderRequest(t *testing.T) {
	systemMessages := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct{ Role, Content string }
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		for _, message := range body.Messages {
			if message.Role == "system" {
				systemMessages <- message.Content
			}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"fixture\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "sample-model")
	t.Setenv("OMLX_API_KEY", "fixture-key")
	cue := ""
	_, _, err := directAnswer(context.Background(), kbTestCfg(), "explain a configuration setting", AnswerOpts{Agent: "cloud", Persona: func(domain string) { cue = domain }})
	if err != nil {
		t.Fatal(err)
	}
	system := <-systemMessages
	if cue != "cloud" || !strings.Contains(system, "AWS, Azure, and GCP") {
		t.Fatal("direct answer ignored the chosen specialist")
	}
}

func TestAdvisoryAgentOverrideChangesActualPrompt(t *testing.T) {
	fake := &fakeModel{queue: []*llms.ContentResponse{{Choices: []*llms.ContentChoice{{Content: "fixture advisory answer"}}}}}
	cue := ""
	_, _, err := adviseLoop(context.Background(), fake, fakeSearcher{}, kbTestCfg(), nil, "explain the documented setting", AnswerOpts{Agent: "api", Persona: func(domain string) { cue = domain }})
	if err != nil {
		t.Fatal(err)
	}
	if cue != "api" || len(fake.seen) != 1 || !strings.Contains(renderMessages(fake.seen[0]), "endpoint permissions") {
		t.Fatal("advisory answer ignored the chosen specialist")
	}
}
