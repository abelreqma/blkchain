package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"blkchain/cli/internal/ragconfig"
)

func TestHealthURL(t *testing.T) {
	cases := []struct {
		port int
		want string
	}{
		{8100, "http://127.0.0.1:8100/health"},
	}
	for _, c := range cases {
		if got := healthURL(c.port); got != c.want {
			t.Errorf("healthURL(%d) = %q, want %q", c.port, got, c.want)
		}
	}
}

func TestConfiguredEmbeddingServiceUsesSharedAddress(t *testing.T) {
	port := liveHealthPort(t)
	t.Setenv("BLKCHAIN_EMBED_HOST", "localhost")
	t.Setenv("BLKCHAIN_EMBED_PORT", strconv.Itoa(port))
	svc := configuredEmbedService()
	want := ragconfig.Load().EmbedServerURL + "/health"
	if got := healthURL(svc.port, svc.host); got != want || !health(svc.port, svc.host) {
		t.Fatalf("stack health URL=%q; want %q", got, want)
	}
	root := t.TempDir()
	out := captureStdout(t, func() {
		startPy(root, svc)
		printServiceStatus(root, svc)
		stopService(root, svc)
	})
	if !strings.Contains(out, "already up") || !strings.Contains(out, "not managed") || !strings.Contains(out, ":"+strconv.Itoa(port)) {
		t.Fatalf("lifecycle ignored configured endpoint: %s", out)
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

func TestPidFilePath(t *testing.T) {
	got := pidFilePath("/root", "embed_server")
	want := "/root/.run/embed_server.pid"
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
		"dhi.io/qdrant@sha256:047fe742edb0c61908acca3fb726b14018f5361d2e0dbabb1a94e47a72448cba",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("dockerRunQdrantArgs() = %q, missing %q", joined, want)
		}
	}
	// The image must be the last argument (docker run syntax).
	if args[len(args)-1] != "dhi.io/qdrant@sha256:047fe742edb0c61908acca3fb726b14018f5361d2e0dbabb1a94e47a72448cba" {
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

// The resident service gets the project root first on PYTHONPATH, once, and
// never the web-search key, which only blk itself reads.
func TestBuildChildEnv(t *testing.T) {
	t.Setenv("PYTHONPATH", "/existing")
	t.Setenv("TAVILY_SETUP_TOKEN", "secret-token")
	env := buildChildEnv("/root")

	var pythonPathVal string
	pythonPathCount := 0
	for _, e := range env {
		if strings.HasPrefix(e, "PYTHONPATH=") {
			pythonPathVal = strings.TrimPrefix(e, "PYTHONPATH=")
			pythonPathCount++
		}
		if strings.HasPrefix(e, "TAVILY_SETUP_TOKEN=") {
			t.Error("buildChildEnv() passes TAVILY_SETUP_TOKEN to the service")
		}
	}
	if pythonPathCount != 1 {
		t.Errorf("buildChildEnv() has %d PYTHONPATH entries, want exactly 1 (no duplicates)", pythonPathCount)
	}
	if pythonPathVal != "/root:/existing" {
		t.Errorf("buildChildEnv() PYTHONPATH = %q, want %q", pythonPathVal, "/root:/existing")
	}
}

func TestBuildChildEnv_NoExistingPythonPath(t *testing.T) {
	t.Setenv("PYTHONPATH", "")
	env := buildChildEnv("/root")
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
	path := filepath.Join(dir, "svc.pid")

	if _, ok := readPid(path); ok {
		t.Error("readPid() on missing file should return ok=false")
	}
	for _, good := range []struct {
		data string
		want int
	}{{"12345\n", 12345}, {"12345", 12345}, {"2", 2}, {"4194304\n", 4194304}} {
		if err := os.WriteFile(path, []byte(good.data), 0o600); err != nil {
			t.Fatal(err)
		}
		if pid, ok := readPid(path); !ok || pid != good.want {
			t.Errorf("readPid(%q) = (%d, %v), want (%d, true)", good.data, pid, ok, good.want)
		}
	}
	for _, bad := range []string{
		"", "\n", "0", "1", "-1", "-0", "+5", "12abc", "1 2", " 12", "12 ", "12\n\n", "12\r\n",
		"not-a-number\n", "4194305", "99999999999999999999", strings.Repeat("0", 31) + "12",
	} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if pid, ok := readPid(path); ok {
			t.Errorf("readPid(%q) = %d, want no valid pid", bad, pid)
		}
	}

	// A symlink to a valid pid file, and a directory, are not pid files.
	target := filepath.Join(dir, "target.pid")
	if err := os.WriteFile(target, []byte("12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pid")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if pid, ok := readPid(link); ok {
		t.Errorf("readPid(symlink) = %d, want no valid pid", pid)
	}
	if pid, ok := readPid(dir); ok {
		t.Errorf("readPid(directory) = %d, want no valid pid", pid)
	}
}

// sleeperEnv makes the test binary a stand-in child for the stop tests: started
// with it set, the binary sleeps instead of running the tests, whatever its
// argument vector says. The tests only ever signal these children.
const sleeperEnv = "BLK_TEST_SLEEPER"

func init() {
	if os.Getenv(sleeperEnv) == "1" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

// startSleeper starts the test's own child from the file exe ("" for the test
// binary) with exactly the argument vector argv, so it reads like whatever
// process argv names. It returns the child, already waited on in the
// background.
func startSleeper(t *testing.T, exe string, argv ...string) (*exec.Cmd, <-chan struct{}) {
	t.Helper()
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			t.Fatal(err)
		}
	}
	c := &exec.Cmd{Path: exe, Args: argv, Env: append(os.Environ(), sleeperEnv+"=1")}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { c.Wait(); close(done) }()
	t.Cleanup(func() { c.Process.Kill(); <-done })
	return c, done
}

// fakeVenv makes root/.venv/bin/python a symlink to the test binary, the way a
// real venv python is a symlink to its interpreter, and returns its path.
func fakeVenv(t *testing.T, root string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	py := venvPython(root)
	if err := os.MkdirAll(filepath.Dir(py), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, py); err != nil {
		t.Fatal(err)
	}
	return py
}

// fakePkill puts a pkill on PATH that records any call, so a test can prove the
// stop path never falls back to matching command lines.
func fakePkill(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "pkill.log")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "pkill"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return log
}

func writePidFile(t *testing.T, root, name string, pid int) {
	t.Helper()
	writePidText(t, root, name, strconv.Itoa(pid)+"\n")
}

func writePidText(t *testing.T, root, name, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, ".run"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidFilePath(root, name), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// testSvc is embed_server on port, so a test never probes the real :8100.
func testSvc(port int) pyService {
	return pyService{name: embedServerSvc.name, module: embedServerSvc.module, port: port}
}

// deadPort is a loopback port nothing listens on.
func deadPort(t *testing.T) int {
	t.Helper()
	u, err := url.Parse(deadLoopbackURL(t))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// liveHealthPort serves GET /health on a loopback port and returns the port.
func liveHealthPort(t *testing.T) int {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// terminateService sends SIGTERM, polls the port, and escalates to SIGKILL only
// when the service does not go down within the window. kill/up/sleep are
// injected so the escalation logic is exercised without real processes.
func TestTerminateServiceEscalatesOnlyWhenPortStaysUp(t *testing.T) {
	cases := []struct {
		name         string
		sigtermErr   error
		up           []bool // consumed in order; the last value repeats
		wantSignals  []syscall.Signal
		wantErr      bool
		wantEscalate bool
	}{
		{
			name:        "SIGTERM failure signals nothing further",
			sigtermErr:  errors.New("no such process"),
			up:          []bool{true},
			wantSignals: []syscall.Signal{syscall.SIGTERM},
			wantErr:     true,
		},
		{
			name:        "port down immediately, no SIGKILL",
			up:          []bool{false},
			wantSignals: []syscall.Signal{syscall.SIGTERM},
		},
		{
			name:        "port dies within the window, no SIGKILL",
			up:          []bool{true, true, false},
			wantSignals: []syscall.Signal{syscall.SIGTERM},
		},
		{
			name:         "port never dies, escalates to SIGKILL",
			up:           []bool{true},
			wantSignals:  []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL},
			wantEscalate: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var signals []syscall.Signal
			kill := func(_ int, sig syscall.Signal) error {
				signals = append(signals, sig)
				if sig == syscall.SIGTERM {
					return tc.sigtermErr
				}
				return nil
			}
			upCall := 0
			up := func(_ int) bool {
				i := upCall
				if i >= len(tc.up) {
					i = len(tc.up) - 1
				}
				upCall++
				return tc.up[i]
			}
			escalated, err := terminateService(1234, 9, kill, up, func(time.Duration) {})

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if escalated != tc.wantEscalate {
				t.Fatalf("escalated = %v, want %v", escalated, tc.wantEscalate)
			}
			if len(signals) != len(tc.wantSignals) {
				t.Fatalf("signals = %v, want %v", signals, tc.wantSignals)
			}
			for i, s := range tc.wantSignals {
				if signals[i] != s {
					t.Fatalf("signals = %v, want %v", signals, tc.wantSignals)
				}
			}
		})
	}
}

func TestStopServiceSignalsTheRecordedMatchingPid(t *testing.T) {
	root := t.TempDir()
	py := fakeVenv(t, root)
	svc := testSvc(deadPort(t))
	c, done := startSleeper(t, py, py, "-m", svc.module)
	writePidFile(t, root, svc.name, c.Process.Pid)

	out := captureStdout(t, func() { stopService(root, svc) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the recorded embed_server pid was not stopped")
	}
	if !strings.Contains(out, "embed_server: stopped") {
		t.Errorf("output = %q, want it to say stopped", out)
	}
	if _, err := os.Stat(pidFilePath(root, svc.name)); !os.IsNotExist(err) {
		t.Errorf("pid file still present after stop: %v", err)
	}
}

// Only a process whose argument vector is exactly the venv python, -m, and the
// module is signaled. Text that merely contains the module, another python,
// and a longer module name are all left alone.
func TestStopServiceNeverSignalsAnotherProcess(t *testing.T) {
	log := fakePkill(t)
	for name, argv := range map[string]func(root string) []string{
		"one argument holding the text": func(root string) []string {
			return []string{venvPython(root), "-m blkchain.embed_server"}
		},
		"python -c with the text": func(root string) []string {
			return []string{"python3", "-c", "pass", "notes about -m blkchain.embed_server usage"}
		},
		"another python": func(root string) []string {
			return []string{"/usr/bin/python3", "-m", "blkchain.embed_server"}
		},
		"a longer module name": func(root string) []string {
			return []string{venvPython(root), "-m", "blkchain.embed_server_evil"}
		},
		"an extra argument": func(root string) []string {
			return []string{venvPython(root), "-m", "blkchain.embed_server", "--evil"}
		},
		"some other module": func(root string) []string {
			return []string{venvPython(root), "-m", "some.other_module"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			py := fakeVenv(t, root)
			svc := testSvc(deadPort(t))
			exe := ""
			if argv(root)[0] == py {
				exe = py
			}
			c, done := startSleeper(t, exe, argv(root)...)
			writePidFile(t, root, svc.name, c.Process.Pid)

			out := captureStdout(t, func() { stopService(root, svc) })
			select {
			case <-done:
				t.Fatal("a process that is not embed_server was signaled")
			case <-time.After(300 * time.Millisecond):
			}
			if !strings.Contains(out, "embed_server: not running") {
				t.Errorf("output = %q, want it to say not running", out)
			}
		})
	}
	if b, _ := os.ReadFile(log); len(b) > 0 {
		t.Errorf("pkill was run: %q", b)
	}
}

// A pid file that is not a plain pid of another process (0, 1, a negative
// value, or a symlink to a matching pid) signals nothing.
func TestStopServiceRefusesInvalidPidFiles(t *testing.T) {
	log := fakePkill(t)
	for _, text := range []string{"0\n", "1\n", "-1\n"} {
		root := t.TempDir()
		writePidText(t, root, embedServerSvc.name, text)
		out := captureStdout(t, func() { stopService(root, testSvc(deadPort(t))) })
		if !strings.Contains(out, "embed_server: not running (no valid pid file)") {
			t.Errorf("pid file %q: output = %q, want no valid pid file", text, out)
		}
	}

	root := t.TempDir()
	py := fakeVenv(t, root)
	svc := testSvc(deadPort(t))
	c, done := startSleeper(t, py, py, "-m", svc.module)
	target := filepath.Join(t.TempDir(), "elsewhere.pid")
	if err := os.WriteFile(target, []byte(strconv.Itoa(c.Process.Pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".run"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, pidFilePath(root, svc.name)); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() { stopService(root, svc) })
	select {
	case <-done:
		t.Fatal("a pid read through a symlinked pid file was signaled")
	case <-time.After(300 * time.Millisecond):
	}
	if !strings.Contains(out, "no valid pid file") {
		t.Errorf("symlinked pid file: output = %q, want no valid pid file", out)
	}
	if b, _ := os.ReadFile(log); len(b) > 0 {
		t.Errorf("pkill was run: %q", b)
	}
}

func TestStopServiceWithoutPidFileDoesNothing(t *testing.T) {
	root := t.TempDir()
	log := fakePkill(t)
	out := captureStdout(t, func() { stopService(root, testSvc(deadPort(t))) })
	if !strings.Contains(out, "embed_server: not running (no valid pid file)") {
		t.Errorf("output = %q, want it to say not running", out)
	}
	if b, _ := os.ReadFile(log); len(b) > 0 {
		t.Errorf("pkill was run with no pid file: %q", b)
	}
}

// With no valid pid file but the port answering, blk down and blk status say
// so on one line and name the lsof command that finds the process. Nothing is
// signaled.
func TestNoPidFileButPortAnswersPointsToLsof(t *testing.T) {
	log := fakePkill(t)
	port := liveHealthPort(t)
	svc := testSvc(port)
	want := fmt.Sprintf("lsof -nP -iTCP:%d -sTCP:LISTEN", port)

	root := t.TempDir()
	down := captureStdout(t, func() { stopService(root, svc) })
	status := captureStdout(t, func() { printServiceStatus(root, svc) })
	for name, out := range map[string]string{"down": down, "status": status} {
		var hits []string
		for _, ln := range strings.Split(out, "\n") {
			if strings.Contains(ln, want) {
				hits = append(hits, ln)
			}
		}
		if len(hits) != 1 || !strings.Contains(hits[0], "no valid pid file") {
			t.Errorf("%s output = %q, want one line naming the missing pid file and %q", name, out, want)
		}
	}
	if strings.Contains(down, "stopped") {
		t.Errorf("down output = %q, must not claim a stop", down)
	}
	if b, _ := os.ReadFile(log); len(b) > 0 {
		t.Errorf("pkill was run: %q", b)
	}

	// With a valid pid file, status says nothing about lsof.
	c, _ := startSleeper(t, "", venvPython(root), "-m", svc.module)
	writePidFile(t, root, svc.name, c.Process.Pid)
	if out := captureStdout(t, func() { printServiceStatus(root, svc) }); strings.Contains(out, "lsof") {
		t.Errorf("status with a valid pid file = %q, want no lsof hint", out)
	}
}

func TestHTTPGetBoundsTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("qdrant "))
		w.Write(bytes.Repeat([]byte("x"), 4<<20))
	}))
	defer srv.Close()
	status, body, err := httpGet(srv.URL)
	if err != nil || status != http.StatusOK {
		t.Fatalf("httpGet: status %d err %v", status, err)
	}
	if len(body) > maxHealthBodyBytes || !strings.HasPrefix(body, "qdrant") {
		t.Errorf("body is %d bytes, want the start of it, at most %d", len(body), maxHealthBodyBytes)
	}
}

// The project root reached through a symlink at blk down, and by its real path
// at blk up, still names the same venv python, so the service stops.
func TestStopServiceMatchesThroughASymlinkedRoot(t *testing.T) {
	real := t.TempDir()
	py := fakeVenv(t, real)
	link := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	svc := testSvc(deadPort(t))
	c, done := startSleeper(t, py, py, "-m", svc.module)
	writePidFile(t, link, svc.name, c.Process.Pid)

	out := captureStdout(t, func() { stopService(link, svc) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("the service was not stopped through the symlinked root: %q", out)
	}
	if !strings.Contains(out, "embed_server: stopped") {
		t.Errorf("output = %q, want stopped", out)
	}
}

// A valid pid file whose process is not the service: while the port answers
// the file is kept, nothing is signaled, and the unmanaged line says how to
// find the process; with the port dead the stale file is removed.
func TestStopServiceMismatchKeepsThePidFileWhileThePortAnswers(t *testing.T) {
	log := fakePkill(t)
	for _, live := range []bool{true, false} {
		root := t.TempDir()
		fakeVenv(t, root)
		port := deadPort(t)
		if live {
			port = liveHealthPort(t)
		}
		svc := testSvc(port)
		c, done := startSleeper(t, "", venvPython(root), "-m", "some.other_module")
		writePidFile(t, root, svc.name, c.Process.Pid)

		out := captureStdout(t, func() { stopService(root, svc) })
		select {
		case <-done:
			t.Fatal("a process that is not the service was signaled")
		case <-time.After(300 * time.Millisecond):
		}
		_, err := os.Stat(pidFilePath(root, svc.name))
		lsof := fmt.Sprintf("lsof -nP -iTCP:%d -sTCP:LISTEN", port)
		if live {
			if err != nil {
				t.Errorf("port answering: the pid file was removed (%v)", err)
			}
			if !strings.Contains(out, "not managed by this blk") || !strings.Contains(out, lsof) || strings.Count(strings.TrimRight(out, "\n"), "\n") != 0 {
				t.Errorf("port answering: output = %q, want the one unmanaged line with %q", out, lsof)
			}
		} else {
			if !os.IsNotExist(err) {
				t.Errorf("port dead: the stale pid file is still there (%v)", err)
			}
			if !strings.Contains(out, "embed_server: not running") {
				t.Errorf("port dead: output = %q, want not running", out)
			}
		}
	}
	if b, _ := os.ReadFile(log); len(b) > 0 {
		t.Errorf("pkill was run: %q", b)
	}
}

// isService needs the exact argv and the executable to be the venv python.
func TestIsServiceChecksTheExecutablePath(t *testing.T) {
	root := t.TempDir()
	py := fakeVenv(t, root)
	args := []string{py, "-m", embedServerSvc.module}
	if !isService(root, py, args, embedServerSvc.module) {
		t.Error("the venv python running the module does not match")
	}
	if isService(root, "/usr/bin/true", args, embedServerSvc.module) {
		t.Error("another executable with the same argv matched")
	}
	if isService(root, py, []string{"", py, "-m"}, embedServerSvc.module) {
		t.Error("an empty argv[0] matched")
	}
}
