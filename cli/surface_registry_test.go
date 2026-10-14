package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"blkchain/cli/internal/tooldef"
)

// This file pins that a surface cannot change which tools a turn can call.
//
// The tools a turn gets come from newChatToolRegistry, which reads the action
// the router classified (AnswerOpts.requiredAction), the tool host, the browser
// endpoint, the question and the history. No surface sets the classified
// action: it is assigned inside adaptiveAnswer from the model's classification.
// What a surface can change is the tool host, the browser endpoint and the
// question it hands to runNativeTurn, and the tests below start from each
// surface's own adapter so a dropped field shows up as a different tool set.
//
// The model is a local HTTP server that classifies a question by lookup and
// records the tool names of every tool-bearing request. Nothing between the
// adapter and that request is replaced, so the names compared are the ones the
// real adviseLoop offered to the model. The turn then fails with "was not
// performed" because the model never calls the required tool; that error is
// asserted so any other failure cannot pass as a match.

// parityCase is one classified action with the surface settings that reach it.
// An empty host is the unset default, which must resolve to the sandbox on every
// surface.
type parityCase struct {
	name     string
	question string
	word     string
	action   string
	host     string
	cdp      string
}

var parityCases = []parityCase{
	{name: "terminal on the default host", question: "Run ls in the workspace shell", word: "TERMINAL", action: "terminal"},
	{name: "terminal on the local host", question: "Run ls in the workspace shell", word: "TERMINAL", action: "terminal", host: chatToolHostLocal},
	{name: "file write on the default host", question: "Write a summary into the workspace", word: "FILE_WRITE", action: "file_write"},
	{name: "browser with a CDP endpoint", question: "Open the page in the browser", word: "BROWSER", action: "browser_control", cdp: "http://127.0.0.1:9222"},
}

// paritySurface runs one turn through a surface's own adapter and returns the
// error the surface reported for it.
type paritySurface struct {
	name string
	run  func(t *testing.T, c parityCase) error
}

// pendingParitySurfaces are surfaces specified but not yet built. Each is
// reported as skipped so it is extended into paritySurfaces when it lands.
var pendingParitySurfaces = []string{"blk serve"}

// parityModel is the fake model server. It answers a request without tools with
// the classification word for the question, and records the tool names of every
// request that carries tools.
type parityModel struct {
	mu        sync.Mutex
	byContent map[string]string
	toolSets  [][]string
}

func newParityModel(t *testing.T) *parityModel {
	t.Helper()
	pm := &parityModel{byContent: map[string]string{}}
	for _, c := range parityCases {
		pm.byContent[c.question] = c.word
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req struct {
			Messages []struct {
				Role    string          `json:"role"`
				Content json.RawMessage `json:"content"`
			} `json:"messages"`
			Tools []struct {
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		content := "done"
		if len(req.Tools) > 0 {
			names := make([]string, 0, len(req.Tools))
			for _, tool := range req.Tools {
				names = append(names, tool.Function.Name)
			}
			slices.Sort(names)
			pm.mu.Lock()
			pm.toolSets = append(pm.toolSets, names)
			pm.mu.Unlock()
		} else {
			content = "ADVICE"
			last := ""
			for _, m := range req.Messages {
				if m.Role == "user" {
					last = string(m.Content)
				}
			}
			for question, word := range pm.byContent {
				if strings.Contains(last, question) {
					content = word
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"c","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`, content)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OMLX_BASE_URL", srv.URL)
	t.Setenv("OMLX_MODEL", "registry-parity")
	t.Setenv("OMLX_API_KEY", "test-key")
	return pm
}

func (pm *parityModel) reset() {
	pm.mu.Lock()
	pm.toolSets = nil
	pm.mu.Unlock()
}

// take returns the tool names the model was offered since the last take, and
// requires every tool-bearing request in that span to carry the same set.
func (pm *parityModel) take(t *testing.T, label string) []string {
	t.Helper()
	pm.mu.Lock()
	sets := pm.toolSets
	pm.toolSets = nil
	pm.mu.Unlock()
	if len(sets) == 0 {
		t.Fatalf("%s: the model was offered no tools; the turn never reached the advise loop", label)
	}
	for _, s := range sets[1:] {
		if !slices.Equal(s, sets[0]) {
			t.Fatalf("%s: one turn offered two different tool sets: %v and %v", label, sets[0], s)
		}
	}
	return sets[0]
}

// wantRegistry is the independent expectation: the registry newChatToolRegistry
// builds for the case's classified action, host and endpoint.
func wantRegistry(t *testing.T, c parityCase) []string {
	t.Helper()
	host := c.host
	if host == "" {
		host = chatToolHostSandbox
	}
	reg, closeTools, err := newChatToolRegistry(context.Background(), nil, loadConfig(), nil, c.question, nil,
		AnswerOpts{ToolHost: host, BrowserCDP: c.cdp, requiredAction: c.action})
	if err != nil {
		t.Fatalf("%s: registry: %v", c.name, err)
	}
	defer closeTools()
	return reg.Names()
}

func requireNotPerformed(t *testing.T, surface string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "was not performed") {
		t.Fatalf("%s: turn error = %v, want the required-tool-not-called error from the advise loop", surface, err)
	}
}

func paritySurfaces(t *testing.T) []paritySurface {
	return []paritySurface{
		{name: "blk ask", run: func(t *testing.T, c parityCase) error {
			args := []string{c.question}
			if c.host != "" {
				args = append([]string{"--tool-host", c.host}, args...)
			}
			if c.cdp != "" {
				args = append([]string{"--browser-cdp", c.cdp}, args...)
			}
			var err error
			captureStdout(t, func() { _, err = askWith(nil, nil, args) })
			return err
		}},
		{name: "plain REPL", run: func(t *testing.T, c parityCase) error {
			m := newKeyModel(t)
			client := &replClient{toolHost: c.host, browserCDP: c.cdp}
			defer client.close()
			var err error
			captureStdout(t, func() { _, err = plainAsk(&m, c.question, client, nil, "", false) })
			return err
		}},
		{name: "TUI", run: func(t *testing.T, c parityCase) error {
			m := newKeyModel(t)
			m.toolHost, m.browserCDP = c.host, c.cdp
			msg := m.streamCmd(context.Background(), c.question, "", m.turnStart, false)()
			switch v := msg.(type) {
			case errMsg:
				return v.err
			case streamDoneMsg:
				return v.err
			}
			return fmt.Errorf("unexpected TUI message %T", msg)
		}},
		{name: "MCP chat", run: func(t *testing.T, c parityCase) error {
			_, err := mcpChatResult(context.Background(), nil, loadConfig(), newChatSessionOwner(),
				mcpChatIn{Message: c.question, ToolHost: c.host, BrowserCDP: c.cdp}, vantageLocal)
			return err
		}},
	}
}

func TestEverySurfaceOffersTheToolsOfTheClassifiedAction(t *testing.T) {
	useDeadServices(t)
	isolateUserDirs(t)
	t.Setenv("BLKCHAIN_MCP_CLIENT_CONFIG", t.TempDir()+"/absent.json")
	pm := newParityModel(t)

	for _, name := range pendingParitySurfaces {
		t.Run(name, func(t *testing.T) {
			t.Skipf("%s does not exist yet; add its adapter to paritySurfaces when it lands", name)
		})
	}

	want := map[string][]string{}
	for _, c := range parityCases {
		want[c.name] = wantRegistry(t, c)
		for _, s := range paritySurfaces(t) {
			t.Run(c.name+"/"+s.name, func(t *testing.T) {
				pm.reset()
				err := s.run(t, c)
				requireNotPerformed(t, s.name, err)
				if got := pm.take(t, s.name); !slices.Equal(got, want[c.name]) {
					t.Fatalf("%s offered %v, the registry for %s is %v", s.name, got, c.action, want[c.name])
				}
			})
		}
	}

	// The comparison above can only fail if the tool set is sensitive to what a
	// surface passes through: the host and the classified action must each change it.
	if slices.Equal(want[parityCases[0].name], want[parityCases[1].name]) {
		t.Error("the tool host does not change the terminal registry, so a surface dropping it would go unnoticed")
	}
	if slices.Equal(want[parityCases[0].name], want[parityCases[2].name]) {
		t.Error("the classified action does not change the registry, so the router outcome would go unnoticed")
	}
}

// No input a surface can fill carries the classified action or a prebuilt
// registry, so the router is the only place the action is decided.
func TestNoSurfaceInputCarriesTheClassifiedAction(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(turnRequest{}), reflect.TypeOf(mcpChatIn{})} {
		for i := range typ.NumField() {
			f := typ.Field(i)
			name := strings.ToLower(f.Name)
			if strings.Contains(name, "requiredaction") || strings.Contains(name, "registry") ||
				f.Type == reflect.TypeOf(AnswerOpts{}) || f.Type == reflect.TypeOf((*tooldef.Registry)(nil)) {
				t.Errorf("%s.%s lets a surface choose the tools of a turn", typ.Name(), f.Name)
			}
		}
	}
}
