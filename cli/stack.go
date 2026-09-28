package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// stack.go is a native Go reimplementation of scripts/stack.sh (`blk
// up|down|status`), preserving its behavior: paths, the qdrant container
// lifecycle, the two resident Python services (embed_server, api), the
// Tavily token handoff, and detached/child-process semantics. See
// scripts/stack.sh for the shell version this ports (kept in place; not
// removed by this change).

// qdrantContainer is the fixed docker container name for the vector store.
const qdrantContainer = "blkchain-qdrant"

// pyService describes one of the two resident Python services the stack
// manages, in the order stack.sh starts them (embed_server, then api).
type pyService struct {
	name   string
	module string
	port   int
}

var (
	embedServerSvc = pyService{name: "embed_server", module: "blkchain.embed_server", port: 8100}
	apiSvc         = pyService{name: "api", module: "blkchain.api", port: 8200}
)

// runDir returns <root>/.run, creating it if necessary (mirrors stack.sh's
// RUN="$ROOT/.run"; mkdir -p "$RUN").
func runDir(root string) (string, error) {
	dir := filepath.Join(root, ".run")
	if err := privateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// pidFilePath and logFilePath are the per-service files under <root>/.run
// stack.sh reads/writes (<name>.pid, <name>.log).
func pidFilePath(root, name string) string { return filepath.Join(root, ".run", name+".pid") }
func logFilePath(root, name string) string { return filepath.Join(root, ".run", name+".log") }

// venvPython is <root>/.venv/bin/python, the interpreter stack.sh/start_mcp.sh
// run resident services and the MCP server with.
func venvPython(root string) string { return filepath.Join(root, ".venv", "bin", "python") }

// --- health checks ---

const qdrantURL = "http://127.0.0.1:6333/"

// healthURL builds the URL polled to decide whether a resident service at
// port is up (mirrors stack.sh's health(): curl -m 2 http://127.0.0.1:$1/health).
func healthURL(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d/health", port)
}

var httpTimeout = 2 * time.Second

// httpGet performs a GET with the 2s timeout stack.sh's curl -m 2 uses,
// returning the status code and body. err is non-nil only on a transport
// failure (connection refused, timeout, DNS, ...).
func httpGet(url string) (status int, body string, err error) {
	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

// isHealthyStatus reports whether a status code counts as healthy: any
// 2xx/3xx (BUILD-BRIEF.md's health() spec).
func isHealthyStatus(status int) bool {
	return status >= 200 && status < 400
}

// health reports whether the service at port answers its /health endpoint.
func health(port int) bool {
	status, _, err := httpGet(healthURL(port))
	return err == nil && isHealthyStatus(status)
}

// qhealth reports whether qdrant is reachable and its root response mentions
// "qdrant" — mirrors stack.sh's qhealth() (curl | grep -q qdrant).
func qhealth() bool {
	_, body, err := httpGet(qdrantURL)
	return err == nil && strings.Contains(body, "qdrant")
}

// --- Tavily token resolution ---

// resolveTavilyToken is the pure decision behind tavilyToken: the environment
// wins if set; otherwise fall back to zshLookup. Factored out so the env-set
// branch is unit-testable without shelling out to zsh. The token value itself
// must never be logged — callers report only whether one was found.
func resolveTavilyToken(envVal string, zshLookup func() string) string {
	if envVal != "" {
		return envVal
	}
	if zshLookup == nil {
		return ""
	}
	return zshLookup()
}

// tavilyTokenFromZsh mirrors stack.sh's fallback:
// zsh -ic 'print -rn -- ${TAVILY_SETUP_TOKEN:-}'
// (a login/interactive shell so it picks up the operator's own zsh env files).
func tavilyTokenFromZsh() string {
	out, err := exec.Command("zsh", "-ic", "print -rn -- ${TAVILY_SETUP_TOKEN:-}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// tavilyToken resolves the Tavily web-search token exactly like stack.sh.
func tavilyToken() string {
	return resolveTavilyToken(os.Getenv("TAVILY_SETUP_TOKEN"), tavilyTokenFromZsh)
}

// --- qdrant container management ---

// containerNamePresent is the pure parsing logic behind qdrantContainerExists:
// an exact (not substring) line match against `docker ps -a --format
// '{{.Names}}'` output, mirroring `grep -qx`.
func containerNamePresent(output, name string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == name {
			return true
		}
	}
	return false
}

// qdrantContainerExists reports whether a container named blkchain-qdrant
// already exists (running or stopped).
func qdrantContainerExists() (bool, error) {
	out, err := exec.Command("docker", "ps", "-a", "--format", "{{.Names}}").Output()
	if err != nil {
		return false, err
	}
	return containerNamePresent(string(out), qdrantContainer), nil
}

// dockerRunQdrantArgs builds the `docker run` argv that creates the qdrant
// container fresh, mirroring stack.sh/start_qdrant.sh exactly: name, restart
// policy, both ports bound to loopback only, and the persistent storage
// volume under <root>/data/qdrant_storage.
func dockerRunQdrantArgs(root string) []string {
	return []string{
		"run", "-d", "--name", qdrantContainer, "--restart", "unless-stopped",
		"-p", "127.0.0.1:6333:6333", "-p", "127.0.0.1:6334:6334",
		"-v", filepath.Join(root, "data", "qdrant_storage") + ":/qdrant/storage",
		"dhi.io/qdrant@sha256:047fe742edb0c61908acca3fb726b14018f5361d2e0dbabb1a94e47a72448cba",
	}
}

// --- resident Python service start/stop ---

// pythonPath builds the PYTHONPATH value stack.sh's start_py sets:
// PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" — the project root first, with
// any existing PYTHONPATH preserved after it.
func pythonPath(root, existing string) string {
	if existing == "" {
		return root
	}
	return root + ":" + existing
}

// buildChildEnv builds the environment for a detached resident service:
// the current process environment with PYTHONPATH and TAVILY_SETUP_TOKEN
// replaced (never duplicated), mirroring stack.sh exporting both before
// backgrounding the child.
func buildChildEnv(root, tavily string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	existingPP := ""
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "PYTHONPATH=") {
			existingPP = strings.TrimPrefix(e, "PYTHONPATH=")
			continue
		}
		if strings.HasPrefix(e, "TAVILY_SETUP_TOKEN=") {
			continue
		}
		env = append(env, e)
	}
	env = append(env, "PYTHONPATH="+pythonPath(root, existingPP), "TAVILY_SETUP_TOKEN="+tavily)
	return env
}

// readPid reads an integer pid from a stack .pid file.
func readPid(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	return pid, true
}

// startPy starts a resident Python service if it isn't already healthy,
// detached so it survives `blk` exiting (Setpgid mimics stack.sh's
// nohup ... &), logging stdout+stderr to <root>/.run/<name>.log and recording
// its pid to <root>/.run/<name>.pid, then polls health for up to 90s —
// mirrors stack.sh's start_py().
func startPy(root string, svc pyService, tavily string) {
	if health(svc.port) {
		printSvcLine(true, svc.name, "already up", svc.port)
		return
	}

	python := venvPython(root)
	logPath := logFilePath(root, svc.name)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		printSvcFail(svc.name, "could not open log "+logPath)
		return
	}
	defer logFile.Close()
	if err := logFile.Chmod(0o600); err != nil {
		printSvcFail(svc.name, "could not secure log "+logPath)
		return
	}

	cmd := exec.Command(python, "-m", svc.module)
	cmd.Dir = root
	cmd.Env = buildChildEnv(root, tavily)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		printSvcFail(svc.name, "FAILED to start: "+err.Error())
		return
	}
	pid := cmd.Process.Pid
	if err := os.WriteFile(pidFilePath(root, svc.name), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		printSvcFail(svc.name, fmt.Sprintf("started (pid %d) but failed to record pidfile", pid))
	}
	// Detach: blk neither waits on nor owns this process from here on.
	_ = cmd.Process.Release()

	for i := 0; i < 90 && !health(svc.port); i++ {
		time.Sleep(1 * time.Second)
	}
	if health(svc.port) {
		printSvcLine(true, svc.name, fmt.Sprintf("up, pid %d", pid), svc.port)
	} else {
		printSvcFail(svc.name, fmt.Sprintf("FAILED to become healthy (see %s)", logPath))
	}
}

// stopPy stops a resident service: kill the pidfile's pid, falling back to
// `pkill -f <name>` if that fails, then remove the pidfile — mirrors
// stack.sh's stop_py().
func stopPy(root, name string) {
	pidPath := pidFilePath(root, name)
	if pid, ok := readPid(pidPath); ok && syscall.Kill(pid, syscall.SIGTERM) == nil {
		os.Remove(pidPath)
		fmt.Printf("  %s %s\n", OK.Render(Glyph(GlyphOK)), Body.Render(name+": stopped"))
		return
	}
	if err := exec.Command("pkill", "-f", name).Run(); err == nil {
		os.Remove(pidPath)
		fmt.Printf("  %s %s\n", OK.Render(Glyph(GlyphOK)), Body.Render(name+": stopped"))
		return
	}
	fmt.Printf("  %s %s\n", Fail.Render(Glyph(GlyphErr)), Body.Render(name+": not running"))
}

// --- themed line helpers ---

func printSvcLine(ok bool, name, state string, port int) {
	fmt.Printf("  %s %s\n", check(ok), Body.Render(name+": ")+Meta.Render(fmt.Sprintf("%s (:%d)", state, port)))
}

func printSvcFail(name, detail string) {
	fmt.Printf("  %s %s\n", Fail.Render(Glyph(GlyphErr)), Body.Render(name+": ")+Meta.Render(detail))
}

// --- up / down / status ---

// runStackUp brings the stack up: qdrant, then embed_server, then api —
// mirrors stack.sh's `up` case exactly.
func runStackUp(root string) error {
	fmt.Println(H1.Render("blk up") + "  " + Meta.Render("starting the stack"))

	upQdrant(root)
	token := tavilyToken()
	startPy(root, embedServerSvc, token)
	startPy(root, apiSvc, token)

	if token != "" {
		fmt.Printf("  %s %s\n", OK.Render(Glyph(GlyphOK)), Body.Render("tavily: ")+Meta.Render("web fallback enabled"))
	} else {
		fmt.Printf("  %s %s\n", Caut.Render(Glyph(GlyphWarn)), Body.Render("tavily: ")+Meta.Render("token not found (web fallback off)"))
	}
	return nil
}

// upQdrant brings up the qdrant container: skip if already healthy, start
// the existing container if one exists, otherwise create it fresh — mirrors
// stack.sh's `up` case's qdrant branch.
func upQdrant(root string) {
	if qhealth() {
		printSvcLine(true, "qdrant", "already up", 6333)
		return
	}
	exists, err := qdrantContainerExists()
	if err == nil && exists {
		if err := exec.Command("docker", "start", qdrantContainer).Run(); err != nil {
			printSvcFail("qdrant", "FAILED to start")
		} else {
			printSvcLine(true, "qdrant", "started", 6333)
		}
		return
	}
	if err := exec.Command("docker", dockerRunQdrantArgs(root)...).Run(); err != nil {
		printSvcFail("qdrant", "FAILED to create")
	} else {
		printSvcLine(true, "qdrant", "created", 6333)
	}
}

// runStackDown stops the stack: api, then embed_server, then qdrant —
// mirrors stack.sh's `down` case exactly.
func runStackDown(root string) error {
	fmt.Println(H1.Render("blk down") + "  " + Meta.Render("stopping the stack"))

	stopPy(root, apiSvc.name)
	stopPy(root, embedServerSvc.name)

	if err := exec.Command("docker", "stop", qdrantContainer).Run(); err != nil {
		fmt.Printf("  %s %s\n", Fail.Render(Glyph(GlyphErr)), Body.Render("qdrant: ")+Meta.Render("not running"))
	} else {
		fmt.Printf("  %s %s\n", OK.Render(Glyph(GlyphOK)), Body.Render("qdrant: stopped"))
	}
	return nil
}

// runStackStatus prints the up/down state of all three services — mirrors
// stack.sh's `status` case exactly.
func runStackStatus(root string) error {
	printStatusLine("qdrant", qhealth(), 6333)
	printStatusLine("embed_server", health(embedServerSvc.port), embedServerSvc.port)
	printStatusLine("api", health(apiSvc.port), apiSvc.port)
	return nil
}

func printStatusLine(name string, up bool, port int) {
	state := "down"
	if up {
		state = "up"
	}
	fmt.Printf("  %s %s %s\n", check(up), Body.Render(pad(name+":", 13)), Meta.Render(fmt.Sprintf("%s (:%d)", state, port)))
}

// runStack dispatches `blk up|down|status` to the native implementation
// above, replacing the old shell-out to scripts/stack.sh.
func runStack(cmd string) error {
	root, err := projectRoot()
	if err != nil {
		return err
	}
	if _, err := runDir(root); err != nil {
		return fmt.Errorf("stack: %w", err)
	}
	switch cmd {
	case "up":
		return runStackUp(root)
	case "down":
		return runStackDown(root)
	case "status":
		return runStackStatus(root)
	default:
		return fmt.Errorf("stack: unknown command %q", cmd)
	}
}
