package main

import (
	"blkchain/cli/internal/modeleval"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// llmadmin.go talks to the LLM server's admin API (oMLX): list the chat models
// with their loaded state, and load or unload one. A server without the admin
// API still lists its models through the OpenAI-style list (llmModels), with
// the loaded state unknown.

const (
	// llmAdminMaxBytes caps every admin response body read.
	llmAdminMaxBytes = 1 << 20
	// modelsListTimeout bounds listing the models.
	modelsListTimeout = 5 * time.Second
	// modelLoadTimeout and modelUnloadTimeout bound one load or unload request.
	modelLoadTimeout   = 180 * time.Second
	modelUnloadTimeout = 30 * time.Second
)

// localHTTP is the one client for short calls to the local services: the
// health probes and the model lists. Each call bounds itself with a context
// deadline.
var localHTTP = &http.Client{}

// llmAdminHTTP is the client for the LLM admin API. It never follows a
// redirect, so the API key goes only to the origin of OMLX_BASE_URL. Each call
// bounds itself with a context deadline.
var llmAdminHTTP = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

var (
	errLLMAuth        = errors.New("the LLM server refused the request: set OMLX_API_KEY to its API key")
	errLLMUnsupported = errors.New("not supported by this LLM server")
	errLLMRedirect    = errors.New("the LLM server redirected the request, which blk does not follow")
)

// llmWarn prints a one-line warning about the LLM server. The TUI points it at
// its own output so the line lands above the input.
var llmWarn = func(line string) { fmt.Fprintln(os.Stderr, line) }

// insecureKeyOnce limits warnInsecureKey to one warning per process.
var insecureKeyOnce sync.Once

// warnInsecureKey warns, once per process, when the API key is about to go
// over plain http to a host that is not loopback. It never blocks the request.
func warnInsecureKey(base, key string) {
	u, err := url.Parse(base)
	if key == "" || err != nil || u.Scheme != "http" {
		return
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback()) {
		return
	}
	insecureKeyOnce.Do(func() {
		llmWarn(Caut.Render(Glyph(GlyphWarn)) + " " + Meta.Render("OMLX_API_KEY is being sent unencrypted to "+oneLine(sanitizeTerminal(host))))
	})
}

// chatModel is one chat model the LLM server serves. Known is false when the
// server has no admin API, so Loaded and Loading say nothing.
type chatModel struct {
	ID              string
	Loaded, Loading bool
	Default         bool
	Size            string
	Context         int
	Known           bool
}

// llmAdminBase is the origin of OMLX_BASE_URL (scheme and host), which drops the
// /v1 path along with any credentials, query, or fragment.
func llmAdminBase() string {
	u, err := url.Parse(omlxBaseURL())
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// llmAdminDo sends one admin request and returns the capped body of a 2xx
// reply. A 401 or 403 is errLLMAuth, a 404 is errLLMUnsupported, a 3xx is
// errLLMRedirect, and any other status is one sanitized line with the start of
// the body, the API key in it replaced by [redacted].
func llmAdminDo(ctx context.Context, method, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, llmAdminBase()+path, nil)
	if err != nil {
		return nil, err
	}
	key := omlxAPIKey()
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	warnInsecureKey(omlxBaseURL(), key)
	resp, err := llmAdminHTTP.Do(req)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("LLM server at %s did not answer in time", llmAdminBase())
	}
	if err != nil {
		return nil, mapLLMError(err, omlxBaseURL())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, llmAdminMaxBytes+1))
	if err != nil {
		return nil, mapLLMError(err, omlxBaseURL())
	}
	if len(body) > llmAdminMaxBytes {
		return nil, errors.New("LLM server response too large (over 1 MiB)")
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, errLLMAuth
	case resp.StatusCode == http.StatusNotFound:
		return nil, errLLMUnsupported
	case resp.StatusCode >= 300 && resp.StatusCode <= 399:
		return nil, errLLMRedirect
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		text := string(body)
		if key != "" {
			text = strings.ReplaceAll(text, key, "[redacted]")
		}
		detail := ellipsize(strings.Join(strings.Fields(sanitizeTerminal(text)), " "), 120)
		return nil, fmt.Errorf("LLM server error %d: %s", resp.StatusCode, detail)
	}
	return body, nil
}

// fetchChatModels lists the chat models. admin reports whether the admin API
// answered; without it the list comes from the OpenAI-style list with the
// state unknown.
// Models of other types (embedding and so on) are left out.
func fetchChatModels(ctx context.Context) (models []chatModel, admin bool, err error) {
	body, err := llmAdminDo(ctx, http.MethodGet, "/admin/api/models")
	var out struct {
		Models *[]struct {
			ID        string `json:"id"`
			Loaded    bool   `json:"loaded"`
			IsLoading bool   `json:"is_loading"`
			IsDefault bool   `json:"is_default"`
			ModelType string `json:"model_type"`
			Size      string `json:"estimated_size_formatted"`
			Context   int    `json:"model_context_length"`
		} `json:"models"`
	}
	if err == nil && (json.Unmarshal(body, &out) != nil || out.Models == nil) {
		err = errLLMUnsupported // answered, but not with the oMLX admin shape
	}
	if errors.Is(err, errLLMUnsupported) {
		ids, _ := modeleval.ListModels(ctx, llmAdminHTTP, omlxBaseURL(), omlxAPIKey())
		for _, id := range ids {
			models = append(models, chatModel{ID: id})
		}
		return models, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	for _, m := range *out.Models {
		if m.ID == "" || (m.ModelType != "" && m.ModelType != "llm") {
			continue
		}
		models = append(models, chatModel{
			ID: m.ID, Loaded: m.Loaded, Loading: m.IsLoading, Default: m.IsDefault,
			Size: m.Size, Context: m.Context, Known: true,
		})
	}
	return models, true, nil
}

// llmModelAction asks the LLM server to "load" or "unload" a model. The id is
// untrusted, so it is escaped as one path segment, and an id that is empty or a
// dot segment is refused.
func llmModelAction(ctx context.Context, id, action string) error {
	if id == "" || id == "." || id == ".." {
		return fmt.Errorf("%q is not a model id", id)
	}
	_, err := llmAdminDo(ctx, http.MethodPost, "/admin/api/models/"+url.PathEscape(id)+"/"+action)
	return err
}
