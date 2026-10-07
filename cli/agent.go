package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// agent.go is the AGENT-mode client. It connects blk directly to the hermes-agent for full
// agentic turns (tools, web, memory, skills), preferring the HTTP+SSE gateway
// and falling back to the `hermes chat --format stream-json` subprocess when the
// gateway is not running. RAG mode (llm.go) is untouched.

const (
	// defaultHermesAPIURL is the local hermes gateway.
	defaultHermesAPIURL = "http://127.0.0.1:8642"
	// agentHealthTimeout bounds the gateway /health probe so a down gateway is
	// detected quickly rather than stalling the turn.
	agentHealthTimeout = 2 * time.Second
	// agentSessionTimeout bounds session create/model-options calls.
	agentSessionTimeout = 10 * time.Second
)

// errHermesMissing is the sentinel for "no hermes CLI on PATH", so the caller
// can render the install/gateway guidance instead of a raw exec error.
var errHermesMissing = errors.New("hermes CLI not found on PATH")

// --- events ---

// agentEventKind classifies a mapped agent event. Both the SSE parser (gateway)
// and the JSONL parser (subprocess) produce these, so the TUI wiring is shared.
type agentEventKind int

const (
	agentText       agentEventKind = iota // assistant answer delta (append to answer)
	agentCommentary                       // progress narration (not the answer)
	agentToolActivity
	agentModelInfo // carries the model id in text (subprocess init)
	agentTerminal  // run finished; err set on failure/cancel
)

// agentEvent is the normalized event both transports emit. text carries answer
// deltas / commentary / the model id / the terminal final text; tool carries the
// tool name for tool activity (with text = "running"|"done"|"failed").
type agentEvent struct {
	kind   agentEventKind
	text   string
	tool   string
	err    error
	tokens int // completion tokens from run.completed usage (0 if absent)
}

// --- config ---

func hermesAPIURL() string {
	if v := strings.TrimSpace(os.Getenv("HERMES_API_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultHermesAPIURL
}

func hermesAPIKey() string { return strings.TrimSpace(os.Getenv("API_SERVER_KEY")) }

// agentAuth sets the Bearer header when API_SERVER_KEY is configured. Never
// hard-code the secret; it comes only from the environment.
func agentAuth(req *http.Request) {
	if k := hermesAPIKey(); k != "" {
		req.Header.Set("Authorization", "Bearer "+k)
	}
}

// hermesBinAvailable reports whether the hermes CLI is on PATH (subprocess
// fallback is possible).
func hermesBinAvailable() bool {
	_, err := exec.LookPath(hermesBin)
	return err == nil
}

// --- gateway client ---

// hermesAvailable probes GET {url}/health with the Bearer header and a short
// timeout. A reachable, authorized gateway returns 200.
func hermesAvailable(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hermesAPIURL()+"/health", nil)
	if err != nil {
		return false
	}
	agentAuth(req)
	hc := &http.Client{Timeout: agentHealthTimeout}
	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode == http.StatusOK
}

// ensureSession creates a hermes session and returns its id, which blk caches as
// the conversation handle for subsequent turns.
func ensureSession(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hermesAPIURL()+"/api/sessions", bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	agentAuth(req)
	hc := &http.Client{Timeout: agentSessionTimeout}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("hermes gateway: create session returned %s", resp.Status)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("hermes gateway: decode session: %w", err)
	}
	if out.ID == "" {
		return "", errors.New("hermes gateway: session response had no id")
	}
	return out.ID, nil
}

// StreamAgent runs one agentic turn over the gateway: POST the message to the
// session chat/stream endpoint and read the text/event-stream response, calling
// onEvent for each mapped (non-terminal) event. It returns the terminal event's
// error (nil on run.completed) or any transport error. ctx cancels the turn:
// cancelling ctx aborts the in-flight request so Body.Read unblocks.
func StreamAgent(ctx context.Context, sessionID, message, model, reasoning string, onEvent func(agentEvent)) error {
	body := map[string]any{"message": message}
	if strings.TrimSpace(model) != "" {
		body["model"] = model
	}
	if strings.TrimSpace(reasoning) != "" {
		body["model_options"] = map[string]string{"reasoning_effort": reasoning}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/api/sessions/%s/chat/stream", hermesAPIURL(), sessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	agentAuth(req)

	// No client timeout: an agent turn is long-lived; ctx governs its lifetime.
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hermes gateway: chat stream returned %s", resp.Status)
	}

	terminal := false
	var termErr error
	limited := &io.LimitedReader{R: resp.Body, N: 32 << 20}
	perr := parseAgentSSE(limited, func(ev agentEvent) {
		if ev.kind == agentTerminal {
			terminal = true
			termErr = ev.err
			onEvent(ev)       // surface usage/final text to the caller
			resp.Body.Close() // break the scan loop; server may hold the stream open
			return
		}
		onEvent(ev)
	})
	if terminal {
		return termErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if perr != nil {
		return perr
	}
	if limited.N == 0 {
		return errors.New("hermes gateway: stream exceeded the response size limit")
	}
	return errors.New("hermes gateway: stream ended before a completion event")
}

// parseAgentSSE reads a Server-Sent Events stream and calls onEvent for each
// mapped event. It is pure with respect to IO (reads from r), so it is unit
// tested with synthetic streams. Per the SSE spec it accumulates
// event:/data: lines, dispatches on a blank line, and skips lines starting with
// ':' (keepalive comments).
func parseAgentSSE(r io.Reader, onEvent func(agentEvent)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var event string
	var data strings.Builder
	dispatch := func() {
		if event == "" && data.Len() == 0 {
			return
		}
		ev, ok := mapAgentEvent(event, data.String())
		event = ""
		data.Reset()
		if ok {
			onEvent(ev)
		}
	}

	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			dispatch()
		case strings.HasPrefix(line, ":"):
			// keepalive comment — ignore
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:"):
			d := strings.TrimPrefix(line[len("data:"):], " ")
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(d)
		}
	}
	dispatch()
	return sc.Err()
}

// mapAgentEvent maps one dispatched SSE (event name, data payload) to an
// agentEvent. It is the pure core the parser tests target. Unknown or
// answer-irrelevant events (run.started, subagent.*) return ok=false.
func mapAgentEvent(event, data string) (agentEvent, bool) {
	switch event {
	case "assistant.delta":
		var d struct {
			Delta string `json:"delta"`
		}
		_ = json.Unmarshal([]byte(data), &d)
		if d.Delta == "" {
			return agentEvent{}, false
		}
		return agentEvent{kind: agentText, text: d.Delta}, true

	case "assistant.commentary":
		var d struct {
			Text  string `json:"text"`
			Delta string `json:"delta"`
		}
		_ = json.Unmarshal([]byte(data), &d)
		text := firstNonEmpty(d.Text, d.Delta)
		if text == "" {
			return agentEvent{}, false
		}
		return agentEvent{kind: agentCommentary, text: text}, true

	case "tool.started":
		var d struct {
			Tool    string `json:"tool"`
			Preview string `json:"preview"`
		}
		_ = json.Unmarshal([]byte(data), &d)
		return agentEvent{kind: agentToolActivity, text: "running", tool: firstNonEmpty(d.Tool, "tool")}, true

	case "tool.completed":
		var d struct {
			Tool  string `json:"tool"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal([]byte(data), &d)
		verb := "done"
		if d.Error != "" {
			verb = "failed"
		}
		return agentEvent{kind: agentToolActivity, text: verb, tool: firstNonEmpty(d.Tool, "tool")}, true

	case "tool.failed":
		var d struct {
			Tool string `json:"tool"`
		}
		_ = json.Unmarshal([]byte(data), &d)
		return agentEvent{kind: agentToolActivity, text: "failed", tool: firstNonEmpty(d.Tool, "tool")}, true

	case "run.completed":
		var d struct {
			Usage struct {
				CompletionTokens int `json:"completion_tokens"`
				OutputTokens     int `json:"output_tokens"`
			} `json:"usage"`
		}
		_ = json.Unmarshal([]byte(data), &d)
		ct := d.Usage.CompletionTokens
		if ct == 0 {
			ct = d.Usage.OutputTokens
		}
		return agentEvent{kind: agentTerminal, tokens: ct}, true

	case "run.failed":
		var d struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal([]byte(data), &d)
		return agentEvent{kind: agentTerminal, err: errors.New(firstNonEmpty(d.Error, "hermes run failed"))}, true

	case "run.cancelled":
		return agentEvent{kind: agentTerminal, err: context.Canceled}, true
	}
	return agentEvent{}, false
}

// modelOptions fetches GET /api/model/options for later model pickers. It parses
// the common id-carrying shapes defensively and returns the model ids (best
// effort; an empty list is not an error the caller must handle).
func modelOptions(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hermesAPIURL()+"/api/model/options", nil)
	if err != nil {
		return nil, err
	}
	agentAuth(req)
	hc := &http.Client{Timeout: agentSessionTimeout}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hermes gateway: model options returned %s", resp.Status)
	}
	var out struct {
		Options []struct {
			ID    string `json:"id"`
			Model string `json:"model"`
			Name  string `json:"name"`
		} `json:"options"`
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []string `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	var ids []string
	for _, o := range out.Options {
		if id := firstNonEmpty(o.ID, o.Model, o.Name); id != "" {
			ids = append(ids, id)
		}
	}
	for _, d := range out.Data {
		if d.ID != "" {
			ids = append(ids, d.ID)
		}
	}
	ids = append(ids, out.Models...)
	return ids, nil
}

// currentAgentModel returns a best-effort display model id from the gateway
// (first model option), or "" when none is discoverable.
func currentAgentModel(ctx context.Context) string {
	ids, err := modelOptions(ctx)
	if err != nil || len(ids) == 0 {
		return ""
	}
	return ids[0]
}

// --- subprocess fallback ---

// StreamAgentSubprocess runs one agent turn via `hermes chat -q <message>
// --format stream-json`, scanning the JSONL on stdout and calling onEvent for
// each mapped event (including the terminal result). stdin is closed. ctx
// cancels the turn by killing the process (exec.CommandContext).
func StreamAgentSubprocess(ctx context.Context, message string, onEvent func(agentEvent)) error {
	path, err := exec.LookPath(hermesBin)
	if err != nil {
		return errHermesMissing
	}
	cmd := exec.CommandContext(ctx, path, "chat", "-q", message, "--format", "stream-json")
	cmd.Stdin = nil // no stdin: one-shot, non-interactive
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if ev, ok := parseAgentJSONLine(sc.Text()); ok {
			onEvent(ev)
		}
	}
	scanErr := sc.Err()
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if scanErr != nil {
		return scanErr
	}
	return waitErr
}

// parseAgentJSONLine maps one stream-json line to an agentEvent. It is the pure
// core the subprocess tests target. Blank lines and unknown types return
// ok=false.
func parseAgentJSONLine(line string) (agentEvent, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return agentEvent{}, false
	}
	var raw struct {
		Type          string `json:"type"`
		Subtype       string `json:"subtype"`
		Text          string `json:"text"`
		Model         string `json:"model"`
		Name          string `json:"name"`
		FinalResponse string `json:"final_response"`
		ExitCode      int    `json:"exit_code"`
	}
	if json.Unmarshal([]byte(line), &raw) != nil {
		return agentEvent{}, false
	}
	switch raw.Type {
	case "system":
		if raw.Subtype == "init" && raw.Model != "" {
			return agentEvent{kind: agentModelInfo, text: raw.Model}, true
		}
		return agentEvent{}, false
	case "text":
		if raw.Text == "" {
			return agentEvent{}, false
		}
		return agentEvent{kind: agentText, text: raw.Text}, true
	case "tool_use":
		return agentEvent{kind: agentToolActivity, text: "running", tool: firstNonEmpty(raw.Name, "tool")}, true
	case "tool_result":
		return agentEvent{kind: agentToolActivity, text: "done", tool: firstNonEmpty(raw.Name, "tool")}, true
	case "result":
		var e error
		if raw.ExitCode != 0 {
			e = fmt.Errorf("hermes exited with code %d", raw.ExitCode)
		}
		// hermes emits the final answer as "text"; "final_response" is honored
		// too. The caller uses this only when no text streamed, so
		// duplicating the streamed answer here is harmless.
		return agentEvent{kind: agentTerminal, text: firstNonEmpty(raw.FinalResponse, raw.Text), err: e}, true
	}
	return agentEvent{}, false
}
