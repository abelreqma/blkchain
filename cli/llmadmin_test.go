package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// adminServer serves the LLM admin API from h and points OMLX_BASE_URL at it.
func adminServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Setenv("OMLX_BASE_URL", srv.URL+"/v1")
	t.Setenv("OMLX_API_KEY", "")
	return srv
}

func TestLLMAdminBaseIsTheOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"http://127.0.0.1:8000/v1":             "http://127.0.0.1:8000",
		"http://127.0.0.1:8000/v1/":            "http://127.0.0.1:8000",
		"https://user:pw@llm.local:9/v1?x=1#y": "https://llm.local:9",
	} {
		t.Setenv("OMLX_BASE_URL", in)
		if got := llmAdminBase(); got != want {
			t.Errorf("llmAdminBase(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFetchChatModelsParsesAndFilters(t *testing.T) {
	var gotAuth string
	adminServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/admin/api/models" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"models":[
			{"id":"big","loaded":true,"is_default":true,"model_type":"llm","estimated_size_formatted":"13.89 GB","model_context_length":262144},
			{"id":"bare"},
			{"id":"busy","is_loading":true,"model_type":"llm"},
			{"id":"emb","model_type":"embedding","loaded":true},
			{"loaded":true}
		]}`)
	})
	t.Setenv("OMLX_API_KEY", "sekrit")
	models, admin, err := fetchChatModels(context.Background())
	if err != nil || !admin {
		t.Fatalf("fetchChatModels: admin=%v err=%v", admin, err)
	}
	if gotAuth != "Bearer sekrit" {
		t.Errorf("Authorization = %q, want the bearer key", gotAuth)
	}
	want := []chatModel{
		{ID: "big", Loaded: true, Default: true, Size: "13.89 GB", Context: 262144, Known: true},
		{ID: "bare", Known: true},
		{ID: "busy", Loading: true, Known: true},
	}
	if fmt.Sprint(models) != fmt.Sprint(want) {
		t.Errorf("models = %+v\nwant     %+v", models, want)
	}
}

func TestFetchChatModelsAuthErrorNamesTheKey(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		adminServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) })
		t.Setenv("OMLX_API_KEY", "wrong-key-value")
		_, _, err := fetchChatModels(context.Background())
		if !errors.Is(err, errLLMAuth) {
			t.Fatalf("%d: err = %v, want errLLMAuth", code, err)
		}
		if msg := err.Error(); !strings.Contains(msg, "OMLX_API_KEY") || strings.Contains(msg, "wrong-key-value") || strings.Contains(msg, "\n") {
			t.Errorf("%d: auth message %q must name OMLX_API_KEY on one line without the key", code, msg)
		}
		if err := llmModelAction(context.Background(), "m", "load"); !errors.Is(err, errLLMAuth) {
			t.Errorf("%d: load err = %v, want errLLMAuth", code, err)
		}
	}
}

// Without the admin API the list falls back to the OpenAI-style model list with
// the loaded state unknown.
func TestFetchChatModelsFallsBackWithoutAdminAPI(t *testing.T) {
	adminServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			fmt.Fprint(w, `{"data":[{"id":"one"},{"id":"two"}]}`)
			return
		}
		http.NotFound(w, r)
	})
	models, admin, err := fetchChatModels(context.Background())
	if err != nil || admin {
		t.Fatalf("admin=%v err=%v, want the fallback", admin, err)
	}
	want := []chatModel{{ID: "one"}, {ID: "two"}}
	if fmt.Sprint(models) != fmt.Sprint(want) {
		t.Errorf("fallback models = %+v, want %+v", models, want)
	}
}

func TestLLMModelActionEscapesTheID(t *testing.T) {
	var uris []string
	adminServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		uris = append(uris, r.RequestURI)
	})
	for _, id := range []string{"../x", "a/b", "\x1b]0;t\x07m"} {
		uris = nil
		if err := llmModelAction(context.Background(), id, "unload"); err != nil {
			t.Fatalf("%q: %v", id, err)
		}
		want := "/admin/api/models/" + url.PathEscape(id) + "/unload"
		if len(uris) != 1 || uris[0] != want {
			t.Errorf("%q: request URI = %q, want %q", id, uris, want)
		}
		if strings.ContainsAny(uris[0], "\x1b\x07") || strings.Contains(uris[0], "/../") {
			t.Errorf("%q: unescaped URI %q", id, uris[0])
		}
	}
	for _, id := range []string{"", ".", ".."} {
		if err := llmModelAction(context.Background(), id, "load"); err == nil {
			t.Errorf("%q: want an error for a model id that is not a path segment", id)
		}
	}
}

func TestLLMAdminErrorsAreOneSanitizedLine(t *testing.T) {
	adminServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "boom\x1b]0;pwn\x07\nsecond line")
	})
	err := llmModelAction(context.Background(), "m", "load")
	if err == nil {
		t.Fatal("want an error for a 500")
	}
	if msg := err.Error(); strings.ContainsAny(msg, "\x1b\x07\n") || !strings.Contains(msg, "boom") {
		t.Errorf("error %q must be one sanitized line", msg)
	}
}

func TestFetchChatModelsCapsTheBody(t *testing.T) {
	adminServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"models":[{"id":"`+strings.Repeat("x", 2<<20)+`"}]}`)
	})
	if _, _, err := fetchChatModels(context.Background()); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("err = %v, want a too-large error", err)
	}
}

func TestFetchChatModelsHonorsTheDeadline(t *testing.T) {
	release := make(chan struct{})
	adminServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := fetchChatModels(ctx)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("err = %v after %v, want a prompt timeout", err, time.Since(start))
	}
}
