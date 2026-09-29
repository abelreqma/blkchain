package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
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

// An admin call never follows a redirect: the second server sees no request
// and so never the key, and the error says the redirect was not followed.
func TestLLMAdminNeverFollowsRedirects(t *testing.T) {
	var hits int
	var gotAuth string
	var mu sync.Mutex
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		fmt.Fprint(w, `{"models":[{"id":"x"}]}`)
	}))
	defer second.Close()
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, target := range []string{second.URL, ""} {
			adminServer(t, func(w http.ResponseWriter, r *http.Request) {
				if target == "" {
					// A same-host redirect, which net/http would send the key along to.
					if !strings.HasPrefix(r.URL.Path, "/elsewhere") {
						http.Redirect(w, r, "/elsewhere"+r.URL.Path, code)
						return
					}
					mu.Lock()
					hits++
					gotAuth = r.Header.Get("Authorization")
					mu.Unlock()
					return
				}
				http.Redirect(w, r, target+r.URL.Path, code)
			})
			t.Setenv("OMLX_API_KEY", "redirect-key")
			_, _, listErr := fetchChatModels(context.Background())
			actErr := llmModelAction(context.Background(), "m", "load")
			for _, err := range []error{listErr, actErr} {
				if err == nil || !strings.Contains(err.Error(), "redirected") || strings.Contains(err.Error(), "\n") {
					t.Errorf("%d to %q: err = %v, want one line saying the redirect was not followed", code, target, err)
				}
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 || gotAuth != "" {
		t.Errorf("the redirect target got %d requests (Authorization %q), want none", hits, gotAuth)
	}
}

// A server that echoes the Authorization header never gets the key onto the
// screen: a 401 or 403 shows no body at all, and any other status has the key
// replaced before the excerpt is shown.
func TestLLMAdminErrorsNeverShowTheKey(t *testing.T) {
	const key = "echo-me-key-123"
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError, http.StatusBadRequest} {
		adminServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			fmt.Fprintf(w, "bad request, you sent %s; key=%s", r.Header.Get("Authorization"), key)
		})
		t.Setenv("OMLX_API_KEY", key)
		err := llmModelAction(context.Background(), "m", "load")
		if err == nil {
			t.Fatalf("%d: want an error", code)
		}
		msg := err.Error()
		if strings.Contains(msg, key) {
			t.Errorf("%d: error %q shows the key", code, msg)
		}
		if code == http.StatusUnauthorized || code == http.StatusForbidden {
			if strings.Contains(msg, "you sent") {
				t.Errorf("%d: error %q shows the response body", code, msg)
			}
		} else if !strings.Contains(msg, "[redacted]") || !strings.Contains(msg, "you sent") {
			t.Errorf("%d: error %q, want the body excerpt with the key redacted", code, msg)
		}
	}
}

// The key sent over plain http to a host that is not loopback gets one
// warning per process, naming the host; the request still goes out.
func TestLLMAdminWarnsOnceAboutAnUnencryptedKey(t *testing.T) {
	var warnings []string
	prev := llmWarn
	llmWarn = func(line string) { warnings = append(warnings, line) }
	t.Cleanup(func() { llmWarn = prev; insecureKeyOnce = sync.Once{} })

	port := strings.TrimPrefix(deadLoopbackURL(t), "http://127.0.0.1")
	try := func(base, key string) {
		t.Helper()
		insecureKeyOnce = sync.Once{}
		warnings = nil
		t.Setenv("OMLX_BASE_URL", base)
		t.Setenv("OMLX_API_KEY", key)
		for i := 0; i < 3; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			llmModelAction(ctx, "m", "load")
			cancel()
		}
	}

	try("http://0.0.0.0"+port, "k")
	if len(warnings) != 1 || !strings.Contains(warnings[0], "unencrypted") || !strings.Contains(warnings[0], "0.0.0.0") {
		t.Errorf("http to a remote host: warnings = %q, want one naming the host", warnings)
	}
	if strings.Contains(strings.Join(warnings, ""), "\n") {
		t.Errorf("warning %q is not one line", warnings)
	}
	for _, base := range []string{"http://127.0.0.1" + port, "http://127.8.9.10" + port, "http://localhost" + port, "http://[::1]" + port, "https://0.0.0.0" + port} {
		if try(base, "k"); len(warnings) != 0 {
			t.Errorf("%s: warnings = %q, want none", base, warnings)
		}
	}
	if try("http://0.0.0.0"+port, ""); len(warnings) != 0 {
		t.Errorf("no key: warnings = %q, want none", warnings)
	}
}

// A body that splits the key with an escape sequence or a C1 control still
// never shows the key: the text is sanitized before the key is redacted.
func TestLLMAdminRedactsAKeySplitByControls(t *testing.T) {
	const key = "sekritvalue123"
	for _, body := range []string{"echo sekrit\x1b[0mvalue123 end", "echo sekrit\u0085value123 end", "echo sekrit\x07value123 end"} {
		adminServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, body)
		})
		t.Setenv("OMLX_API_KEY", key)
		err := llmModelAction(context.Background(), "m", "load")
		if err == nil || strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "[redacted]") {
			t.Errorf("body %q: error %v, want the key redacted", body, err)
		}
	}
}

// The model list and the health probe carry the key too, so they never follow
// a redirect: the second server sees nothing, and the redirect is reported,
// never taken for an empty list.
func TestKeyBearingModelCallsNeverFollowRedirects(t *testing.T) {
	var hits int
	var mu sync.Mutex
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		fmt.Fprint(w, `{"data":[{"id":"x"}]}`)
	}))
	defer second.Close()
	useDeadServices(t)
	adminServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/api/models" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, second.URL+r.URL.Path, http.StatusFound)
	})
	t.Setenv("OMLX_API_KEY", "k")

	if _, err := llmModels(); !errors.Is(err, errLLMRedirect) {
		t.Errorf("llmModels err = %v, want errLLMRedirect", err)
	}
	if err := probeLLM(omlxBaseURL(), "k", healthProbeTimeout); !errors.Is(err, errLLMRedirect) {
		t.Errorf("probeLLM err = %v, want errLLMRedirect", err)
	}
	if _, _, err := fetchChatModels(context.Background()); !errors.Is(err, errLLMRedirect) {
		t.Errorf("fetchChatModels err = %v, want errLLMRedirect", err)
	}
	noColor(t)
	isolateUserDirs(t)
	t.Setenv("QDRANT_GRPC_URL", "127.0.0.1:1")
	t.Setenv("HERMES_HOME", t.TempDir())
	health := captureStdout(t, func() { runHealth(nil) })
	doctor := captureStdout(t, func() { runDoctor(nil) })
	for name, out := range map[string]string{"blk health": health, "blk doctor": doctor} {
		if lineWith(out, errLLMRedirect.Error()) == "" {
			t.Errorf("%s does not report the redirect:\n%s", name, out)
		}
	}

	// The /models panel and the model picker show it too.
	m := newKeyModel(t)
	nm, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = nm.(model)
	m.overlay = newModelsPanel(m.prefs, "")
	nm, _ = m.Update(fetchModelsCmd())
	if v := nm.(model).View(); !strings.Contains(v, "redirected") {
		t.Errorf("the /models panel does not report the redirect:\n%s", v)
	}
	m.overlay = nil
	nm, _ = m.Update(m.openModelPickerCmd()())
	if v := nm.(model).View(); !strings.Contains(v, "redirected") {
		t.Errorf("the model picker does not report the redirect:\n%s", v)
	}

	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("the redirect target got %d requests, want none", hits)
	}
}
