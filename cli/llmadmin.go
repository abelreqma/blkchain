package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// llmadmin.go talks to the LLM server's admin API (oMLX): list the chat models
// with their loaded state, and load or unload one. A server without the admin
// API still lists its models through the OpenAI-style list (omlxModels), with
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

// modelsHTTP is the one client for the /models calls: the LLM admin API and
// embed_server's health. Each call bounds itself with a context deadline.
var modelsHTTP = &http.Client{}

var (
	errLLMAuth        = errors.New("the LLM server refused the request: set OMLX_API_KEY to its API key")
	errLLMUnsupported = errors.New("not supported by this LLM server")
)

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
// reply. A 401 or 403 is errLLMAuth, a 404 is errLLMUnsupported, and any other
// status is one sanitized line with the start of the body.
func llmAdminDo(ctx context.Context, method, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, llmAdminBase()+path, nil)
	if err != nil {
		return nil, err
	}
	if key := strings.TrimSpace(os.Getenv("OMLX_API_KEY")); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := modelsHTTP.Do(req)
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
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		detail := ellipsize(strings.Join(strings.Fields(sanitizeTerminal(string(body))), " "), 120)
		return nil, fmt.Errorf("LLM server error %d: %s", resp.StatusCode, detail)
	}
	return body, nil
}

// fetchChatModels lists the chat models. admin reports whether the admin API
// answered; without it the list comes from omlxModels with the state unknown.
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
		for _, id := range omlxModels() {
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
