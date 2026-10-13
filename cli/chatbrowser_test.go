package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
	"github.com/tmc/langchaingo/llms"
)

func TestChatBrowserScreenshotStaysInWorkspace(t *testing.T) {
	root := t.TempDir()
	path, err := chatBrowserScreenshot(root, []byte("png-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(root, path)); err != nil || string(data) != "png-bytes" {
		t.Fatalf("screenshot data=%q err=%v", data, err)
	}
	if _, err := chatBrowserScreenshot(root, make([]byte, 2<<20+1)); err == nil {
		t.Fatal("oversized screenshot accepted")
	}
}

func TestChatBrowserInteractiveLocalFixture(t *testing.T) {
	if os.Getenv("BLKCHAIN_CHAT_BROWSER_E2E") != "1" {
		t.Skip("set BLKCHAIN_CHAT_BROWSER_E2E=1 with the provisioned browser")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Chdir(t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><input id="name"><button id="go" onclick="document.getElementById('result').textContent='Hello '+document.getElementById('name').value;console.log('clicked')">Go</button><p id="result"></p><img src="data:image/png;base64,AA==" alt="fixture diagram"></body></html>`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	state := &chatBrowserState{}
	defer state.Close()
	reg, closeTools, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Open "+srv.URL, nil, AnswerOpts{Browser: state, requiredAction: "browser_control"})
	if err != nil {
		t.Fatal(err)
	}
	tool, ok := reg.Get("browser_control")
	if !ok {
		t.Fatal("browser_control was not offered")
	}
	call := func(in chatBrowserArgs) string {
		t.Helper()
		data, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		out, err := tool.Call(ctx, string(data))
		if err != nil || strings.Contains(out, "browser_control:") {
			t.Fatalf("browser action %+v failed: out=%q err=%v", in, out, err)
		}
		return out
	}
	if out := call(chatBrowserArgs{Op: "navigate", URL: srv.URL}); !strings.Contains(out, "id=\\\"go\\\"") && !strings.Contains(out, "id=\"go\"") {
		t.Fatalf("navigation did not return the page: %q", out)
	}
	call(chatBrowserArgs{Op: "type", Selector: "#name", Text: "Ada"})
	call(chatBrowserArgs{Op: "click", Selector: "#go"})
	closeTools()
	reg, closeTools, err = newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Show the current browser page", nil, AnswerOpts{Browser: state, requiredAction: "browser_control"})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTools()
	tool, ok = reg.Get("browser_control")
	if !ok {
		t.Fatal("browser_control was not offered on the next turn")
	}
	if out := call(chatBrowserArgs{Op: "snapshot"}); !strings.Contains(out, "Hello Ada") {
		t.Fatalf("browser state did not persist across turns: %q", out)
	}
	if out := call(chatBrowserArgs{Op: "console"}); !strings.Contains(out, "clicked") {
		t.Fatalf("console output missing: %q", out)
	}
	if out := call(chatBrowserArgs{Op: "images"}); !strings.Contains(out, "fixture diagram") {
		t.Fatalf("image listing missing: %q", out)
	}
	if out := call(chatBrowserArgs{Op: "screenshot"}); !strings.Contains(out, "screenshot saved") {
		t.Fatalf("screenshot missing: %q", out)
	}
	fake := &fakeModel{queue: []*llms.ContentResponse{textResp("visual fixture")}}
	t.Setenv("BLKCHAIN_VISION_MODEL", "fixture-vision")
	oldVision := newChatVisionModel
	newChatVisionModel = func(ragconfig.Config, string) (toolLoopModel, error) { return fake, nil }
	t.Cleanup(func() { newChatVisionModel = oldVision })
	visionRegistry, closeVision, err := newChatToolRegistry(ctx, nil, ragconfig.Config{}, nil, "Describe the current page visually", nil,
		AnswerOpts{Browser: state, requiredAction: "browser_vision"})
	if err != nil {
		t.Fatal(err)
	}
	defer closeVision()
	vision, ok := visionRegistry.Get("browser_vision")
	if !ok {
		t.Fatal("browser_vision was not offered")
	}
	out, err := vision.Call(ctx, `{"question":"What is visible?"}`)
	if err != nil || !strings.Contains(out, "visual fixture") || len(fake.seen) != 1 {
		t.Fatalf("vision call failed: out=%q err=%v", out, err)
	}
	if _, ok := fake.seen[0][1].Parts[1].(llms.ImageURLContent); !ok {
		t.Fatal("vision call did not send screenshot pixels to the model")
	}
	newChatVisionModel = oldVision
	serializedImage := false
	visionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 3<<20))
		serializedImage = strings.Contains(string(body), "data:image/png;base64,")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"serialized vision fixture"},"finish_reason":"stop"}]}`))
	}))
	defer visionServer.Close()
	t.Setenv("OMLX_BASE_URL", visionServer.URL+"/v1")
	t.Setenv("OMLX_API_KEY", "test-key")
	serializedTool := newChatBrowserVisionTool(state, loadConfig())
	serializedAnswer, err := serializedTool.Call(ctx, `{"question":"What is visible?"}`)
	if err != nil || !serializedImage || !strings.Contains(serializedAnswer, "serialized vision fixture") {
		t.Fatalf("vision transport omitted the screenshot: image=%v answer=%q err=%v", serializedImage, serializedAnswer, err)
	}
	if os.Getenv("BLKCHAIN_CHAT_VISION_E2E") == "1" {
		t.Setenv("BLKCHAIN_VISION_MODEL", "")
		liveRegistry, closeLive, err := newChatToolRegistry(ctx, nil, loadConfig(), nil, "Describe the current page visually", nil,
			AnswerOpts{Browser: state, requiredAction: "browser_vision"})
		if err != nil {
			t.Fatal(err)
		}
		defer closeLive()
		liveVision, _ := liveRegistry.Get("browser_vision")
		answer, err := liveVision.Call(ctx, `{"question":"What text is visible in the page?"}`)
		if err != nil || !strings.Contains(answer, "BLKCHAIN_VISION_MODEL") {
			t.Fatalf("missing vision model did not fail clearly: answer=%q err=%v", answer, err)
		}
	}
}
