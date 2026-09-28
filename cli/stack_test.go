package main

import (
	"os"
	"strings"
	"testing"
)

func TestHealthURL(t *testing.T) {
	cases := []struct {
		port int
		want string
	}{
		{8100, "http://127.0.0.1:8100/health"},
		{8200, "http://127.0.0.1:8200/health"},
	}
	for _, c := range cases {
		if got := healthURL(c.port); got != c.want {
			t.Errorf("healthURL(%d) = %q, want %q", c.port, got, c.want)
		}
	}
}

func TestIsHealthyStatus(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{200, true},
		{201, true},
		{299, true},
		{300, true},
		{399, true},
		{400, false},
		{404, false},
		{500, false},
		{0, false},
		{199, false},
	}
	for _, c := range cases {
		if got := isHealthyStatus(c.status); got != c.want {
			t.Errorf("isHealthyStatus(%d) = %v, want %v", c.status, got, c.want)
		}
	}
}

func TestResolveTavilyToken_EnvSet(t *testing.T) {
	// When the environment already has the token, it must win outright — the
	// zsh fallback must never even be invoked (never spawn a shell needlessly,
	// and never risk it clobbering a value the caller already resolved).
	called := false
	zsh := func() string {
		called = true
		return "from-zsh"
	}
	got := resolveTavilyToken("from-env", zsh)
	if got != "from-env" {
		t.Errorf("resolveTavilyToken() = %q, want %q", got, "from-env")
	}
	if called {
		t.Error("resolveTavilyToken() called the zsh fallback despite env being set")
	}
}

func TestResolveTavilyToken_EnvEmptyFallsBackToZsh(t *testing.T) {
	got := resolveTavilyToken("", func() string { return "from-zsh" })
	if got != "from-zsh" {
		t.Errorf("resolveTavilyToken() = %q, want %q", got, "from-zsh")
	}
}

func TestResolveTavilyToken_NilFallback(t *testing.T) {
	if got := resolveTavilyToken("", nil); got != "" {
		t.Errorf("resolveTavilyToken() = %q, want empty", got)
	}
}

func TestPidFilePath(t *testing.T) {
	got := pidFilePath("/root", "api")
	want := "/root/.run/api.pid"
	if got != want {
		t.Errorf("pidFilePath() = %q, want %q", got, want)
	}
}

func TestLogFilePath(t *testing.T) {
	got := logFilePath("/root", "embed_server")
	want := "/root/.run/embed_server.log"
	if got != want {
		t.Errorf("logFilePath() = %q, want %q", got, want)
	}
}

func TestVenvPython(t *testing.T) {
	got := venvPython("/root")
	want := "/root/.venv/bin/python"
	if got != want {
		t.Errorf("venvPython() = %q, want %q", got, want)
	}
}

func TestDockerRunQdrantArgs(t *testing.T) {
	args := dockerRunQdrantArgs("/root")
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"run -d --name blkchain-qdrant --restart unless-stopped",
		"-p 127.0.0.1:6333:6333",
		"-p 127.0.0.1:6334:6334",
		"-v /root/data/qdrant_storage:/qdrant/storage",
		"dhi.io/qdrant:1",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("dockerRunQdrantArgs() = %q, missing %q", joined, want)
		}
	}
	// The image must be the last argument (docker run syntax).
	if args[len(args)-1] != "dhi.io/qdrant:1" {
		t.Errorf("dockerRunQdrantArgs() last arg = %q, want image name", args[len(args)-1])
	}
}

func TestContainerNamePresent(t *testing.T) {
	cases := []struct {
		output string
		name   string
		want   bool
	}{
		{"blkchain-qdrant\n", "blkchain-qdrant", true},
		{"other\nblkchain-qdrant\nanother\n", "blkchain-qdrant", true},
		{"blkchain-qdrant-old\n", "blkchain-qdrant", false}, // exact match only, not substring
		{"", "blkchain-qdrant", false},
		{"other-container\n", "blkchain-qdrant", false},
	}
	for _, c := range cases {
		if got := containerNamePresent(c.output, c.name); got != c.want {
			t.Errorf("containerNamePresent(%q, %q) = %v, want %v", c.output, c.name, got, c.want)
		}
	}
}

func TestPythonPath(t *testing.T) {
	cases := []struct {
		root, existing, want string
	}{
		{"/root", "", "/root"},
		{"/root", "/other/path", "/root:/other/path"},
	}
	for _, c := range cases {
		if got := pythonPath(c.root, c.existing); got != c.want {
			t.Errorf("pythonPath(%q, %q) = %q, want %q", c.root, c.existing, got, c.want)
		}
	}
}

func TestBuildChildEnv(t *testing.T) {
	t.Setenv("PYTHONPATH", "/existing")
	env := buildChildEnv("/root", "secret-token")

	var pythonPathVal, tavilyVal string
	pythonPathCount, tavilyCount := 0, 0
	for _, e := range env {
		if strings.HasPrefix(e, "PYTHONPATH=") {
			pythonPathVal = strings.TrimPrefix(e, "PYTHONPATH=")
			pythonPathCount++
		}
		if strings.HasPrefix(e, "TAVILY_SETUP_TOKEN=") {
			tavilyVal = strings.TrimPrefix(e, "TAVILY_SETUP_TOKEN=")
			tavilyCount++
		}
	}
	if pythonPathCount != 1 {
		t.Errorf("buildChildEnv() has %d PYTHONPATH entries, want exactly 1 (no duplicates)", pythonPathCount)
	}
	if pythonPathVal != "/root:/existing" {
		t.Errorf("buildChildEnv() PYTHONPATH = %q, want %q", pythonPathVal, "/root:/existing")
	}
	if tavilyCount != 1 {
		t.Errorf("buildChildEnv() has %d TAVILY_SETUP_TOKEN entries, want exactly 1 (no duplicates)", tavilyCount)
	}
	if tavilyVal != "secret-token" {
		t.Errorf("buildChildEnv() TAVILY_SETUP_TOKEN = %q, want %q", tavilyVal, "secret-token")
	}
}

func TestBuildChildEnv_NoExistingPythonPath(t *testing.T) {
	t.Setenv("PYTHONPATH", "")
	env := buildChildEnv("/root", "")
	found := false
	for _, e := range env {
		if e == "PYTHONPATH=/root" {
			found = true
		}
	}
	if !found {
		t.Errorf("buildChildEnv() missing PYTHONPATH=/root entry, got %v", env)
	}
}

func TestReadPid(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/svc.pid"

	if _, ok := readPid(path); ok {
		t.Error("readPid() on missing file should return ok=false")
	}

	if err := os.WriteFile(path, []byte("12345\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pid, ok := readPid(path)
	if !ok || pid != 12345 {
		t.Errorf("readPid() = (%d, %v), want (12345, true)", pid, ok)
	}

	if err := os.WriteFile(path, []byte("not-a-number\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := readPid(path); ok {
		t.Error("readPid() on malformed pidfile should return ok=false")
	}
}
