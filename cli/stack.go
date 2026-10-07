package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"blkchain/cli/internal/ragconfig"
)

// stack.go is `blk up|down|status`: the qdrant container lifecycle and the
// resident Python embed_server, started detached so it outlives blk.

// qdrantContainer is the fixed docker container name for the vector store.
const qdrantContainer = "blkchain-qdrant"

// pyService describes a resident Python service the stack manages.
type pyService struct {
	name   string
	module string
	host   string
	port   int
}

var embedServerSvc = pyService{name: "embed_server", module: "blkchain.embed_server", port: 8100}

func configuredEmbedService() pyService {
	svc := embedServerSvc
	svc.host, svc.port = ragconfig.EmbeddingAddress()
	return svc
}

// runDir returns <root>/.run, creating it private if necessary.
func runDir(root string) (string, error) {
	dir := filepath.Join(root, ".run")
	if err := privateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// pidFilePath and logFilePath are the per-service files under <root>/.run
// (<name>.pid, <name>.log).
func pidFilePath(root, name string) string { return filepath.Join(root, ".run", name+".pid") }
func logFilePath(root, name string) string { return filepath.Join(root, ".run", name+".log") }

// venvPython is <root>/.venv/bin/python, the interpreter the resident service
// and `blk add` run with.
func venvPython(root string) string { return filepath.Join(root, ".venv", "bin", "python") }

// --- health checks ---

const qdrantURL = "http://127.0.0.1:6333/"

// healthURL builds the URL polled to decide whether a resident service at
// port is up.
func healthURL(port int, hosts ...string) string {
	host := "127.0.0.1"
	if len(hosts) > 0 && hosts[0] != "" {
		host = hosts[0]
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/health"
}

const httpTimeout = 2 * time.Second

// maxHealthBodyBytes caps how much of a health reply is read.
const maxHealthBodyBytes = 1 << 20

// httpGet performs a GET with a 2s timeout, returning the status code and at most maxHealthBodyBytes of the body. err is
// non-nil only on a transport failure (connection refused, timeout, DNS, ...).
func httpGet(url string) (status int, body string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := localHTTP.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxHealthBodyBytes))
	return resp.StatusCode, string(b), nil
}

// isHealthyStatus reports whether a status code counts as healthy: any
// 2xx/3xx.
func isHealthyStatus(status int) bool {
	return status >= 200 && status < 400
}

// health reports whether the service at port answers its /health endpoint.
func health(port int, hosts ...string) bool {
	status, _, err := httpGet(healthURL(port, hosts...))
	return err == nil && isHealthyStatus(status)
}

// qhealth reports whether qdrant is reachable and its root response mentions
// "qdrant".
func qhealth() bool {
	_, body, err := httpGet(qdrantURL)
	return err == nil && strings.Contains(body, "qdrant")
}

// --- qdrant container management ---

// containerNamePresent is the pure parsing logic behind qdrantContainerExists:
// an exact (not substring) line match against `docker ps -a --format
// '{{.Names}}'` output.
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
// container fresh: name, restart policy, both ports bound to loopback only,
// the persistent storage volume under <root>/data/qdrant_storage, and the image
// pinned by digest.
func dockerRunQdrantArgs(root string) []string {
	return []string{
		"run", "-d", "--name", qdrantContainer, "--restart", "unless-stopped",
		"-p", "127.0.0.1:6333:6333", "-p", "127.0.0.1:6334:6334",
		"-v", filepath.Join(root, "data", "qdrant_storage") + ":/qdrant/storage",
		"dhi.io/qdrant@sha256:047fe742edb0c61908acca3fb726b14018f5361d2e0dbabb1a94e47a72448cba",
	}
}

// --- resident Python service start/stop ---

// pythonPath builds the resident service's PYTHONPATH: the project root first,
// with any existing PYTHONPATH preserved after it.
func pythonPath(root, existing string) string {
	if existing == "" {
		return root
	}
	return root + ":" + existing
}

// buildChildEnv builds the environment for a detached resident service: the
// current process environment with PYTHONPATH replaced (never duplicated) and
// without the web-search key, which only blk reads.
func buildChildEnv(root string) []string {
	env := stripEnv(stripEnv(os.Environ(), "PYTHONPATH"), tavilyAPIKeyEnv)
	return append(env, "PYTHONPATH="+pythonPath(root, os.Getenv("PYTHONPATH")))
}

// maxPid is the largest pid readPid accepts (the Linux pid_max ceiling).
const maxPid = 4194304

// readPid reads the pid a stack .pid file records. The file must be a regular
// file, not a symlink, of at most 32 bytes that holds a decimal pid above 1 and
// at most maxPid, with one optional trailing newline. Anything else is no pid.
func readPid(path string) (int, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 32 {
		return 0, false
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(data) > 32 {
		return 0, false
	}
	s := strings.TrimSuffix(string(data), "\n")
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	pid, err := strconv.Atoi(s)
	if err != nil || pid <= 1 || pid > maxPid {
		return 0, false
	}
	return pid, true
}

// startPy starts a resident Python service if it isn't already healthy,
// detached so it survives `blk` exiting (its own process group), logging
// stdout and stderr to <root>/.run/<name>.log and recording its pid to
// <root>/.run/<name>.pid, then polls health for up to 90s.
func startPy(root string, svc pyService) {
	if health(svc.port, svc.host) {
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
	cmd.Env = buildChildEnv(root)
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

	for i := 0; i < 90 && !health(svc.port, svc.host); i++ {
		time.Sleep(1 * time.Second)
	}
	if health(svc.port, svc.host) {
		printSvcLine(true, svc.name, fmt.Sprintf("up, pid %d", pid), svc.port)
	} else {
		printSvcFail(svc.name, fmt.Sprintf("FAILED to become healthy (see %s)", logPath))
	}
}

// stopService stops a resident service by the pid its pid file records, and
// only after runsService confirms that pid is still the service blk started,
// so a pid the system has since given to another process is never signaled.
// Only that one pid is signaled, never a process group. It sends SIGTERM, waits
// for the port to go down, and escalates to SIGKILL if it does not exit in time
// (see terminateService). When the pid file is missing, invalid, or names
// another process while the port answers, nothing is signaled, the pid file is
// kept, and one line says how to find the process. A pid file whose process is
// gone and whose port is dead is stale and removed.
func stopService(root string, svc pyService) {
	pidPath := pidFilePath(root, svc.name)
	pid, ok := readPid(pidPath)
	if !ok {
		if health(svc.port, svc.host) {
			fmt.Printf("  %s %s\n", Caut.Render(Glyph(GlyphWarn)), Body.Render(unmanagedNote(svc)))
			return
		}
		fmt.Printf("  %s %s\n", Fail.Render(Glyph(GlyphErr)), Body.Render(svc.name+": not running (no valid pid file)"))
		return
	}
	if !runsService(root, pid, svc.module) {
		if health(svc.port, svc.host) {
			fmt.Printf("  %s %s\n", Caut.Render(Glyph(GlyphWarn)), Body.Render(unmanagedNote(svc)))
			return
		}
		os.Remove(pidPath)
		fmt.Printf("  %s %s\n", Fail.Render(Glyph(GlyphErr)), Body.Render(svc.name+": not running"))
		return
	}
	escalated, err := terminateService(pid, svc.port, syscall.Kill, func(port int) bool {
		return health(port, svc.host)
	}, time.Sleep)
	if err != nil {
		os.Remove(pidPath)
		fmt.Printf("  %s %s\n", Fail.Render(Glyph(GlyphErr)), Body.Render(svc.name+": not running"))
		return
	}
	os.Remove(pidPath)
	stopped := svc.name + ": stopped"
	if escalated {
		stopped = svc.name + ": stopped (forced)"
	}
	fmt.Printf("  %s %s\n", OK.Render(Glyph(GlyphOK)), Body.Render(stopped))
}

// shutdownPolls and shutdownPollWait bound how long terminateService waits for a
// SIGTERM'd service to exit before escalating: shutdownPolls probes spaced
// shutdownPollWait apart, about 10s total.
const (
	shutdownPolls    = 50
	shutdownPollWait = 200 * time.Millisecond
)

// terminateService sends SIGTERM to pid, then polls the service's port until it
// stops answering or shutdownPolls elapse; if the port is still up at the end it
// escalates to SIGKILL, so a service that ignores SIGTERM does not leave blk
// reporting "stopped" while the process lingers. Only that one pid is signaled,
// never a process group. kill, up, and sleep are injected so the escalation
// logic is testable without real processes or wall-clock waits; the real caller
// passes syscall.Kill, health, and time.Sleep. It returns an error only when the
// initial SIGTERM fails (the pid is gone or not ours), in which case nothing
// further is signaled. escalated reports whether SIGKILL was sent.
func terminateService(pid, port int, kill func(int, syscall.Signal) error, up func(int) bool, sleep func(time.Duration)) (escalated bool, err error) {
	if err := kill(pid, syscall.SIGTERM); err != nil {
		return false, err
	}
	for i := 0; i < shutdownPolls; i++ {
		if !up(port) {
			return false, nil
		}
		sleep(shutdownPollWait)
	}
	if up(port) {
		_ = kill(pid, syscall.SIGKILL)
		return true, nil
	}
	return false, nil
}

// unmanagedNote is the one line blk down and blk status print when svc's port
// answers but no valid pid file names the process, so blk cannot tell which
// process to stop. It names the command that finds the process.
func unmanagedNote(svc pyService) string {
	return fmt.Sprintf("%s: :%d answers but is not managed by this blk (no valid pid file names it); find the process with lsof -nP -iTCP:%d -sTCP:LISTEN",
		svc.name, svc.port, svc.port)
}

// runsService reports whether process pid is the service blk started (see
// isService).
func runsService(root string, pid int, module string) bool {
	exe, args, err := processArgs(pid)
	return err == nil && isService(root, exe, args, module)
}

// isService reports whether a process with executable exe and argument vector
// args is the service blk started: args is exactly the project's venv python,
// -m, and module, and exe is that python. processArgs keeps the argument
// boundaries, so one argument that merely contains "-m module" does not match.
// argv[0] is compared with its directory's symlinks resolved, so a project root
// spelled through a symlink still matches, while the venv python itself is not
// resolved to the interpreter other venvs share. exe is compared fully
// resolved.
func isService(root, exe string, args []string, module string) bool {
	py := venvPython(root)
	if len(args) != 3 || args[1] != "-m" || args[2] != module {
		return false
	}
	if filepath.Base(args[0]) != filepath.Base(py) || resolvedPath(filepath.Dir(args[0])) != resolvedPath(filepath.Dir(py)) {
		return false
	}
	return resolvedPath(exe) == resolvedPath(py)
}

// resolvedPath is p with every symlink resolved, or p itself when that fails.
func resolvedPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// --- themed line helpers ---

func printSvcLine(ok bool, name, state string, port int) {
	fmt.Printf("  %s %s\n", check(ok), Body.Render(name+": ")+Meta.Render(fmt.Sprintf("%s (:%d)", state, port)))
}

func printSvcFail(name, detail string) {
	fmt.Printf("  %s %s\n", Fail.Render(Glyph(GlyphErr)), Body.Render(name+": ")+Meta.Render(detail))
}

// --- up / down / status ---

// runStackUp brings the stack up: qdrant, then embed_server. The tavily line
// reports whether blk itself has the web-search key that ask reads.
func runStackUp(root string) {
	fmt.Println(H1.Render("blk up") + "  " + Meta.Render("starting the stack"))

	upQdrant(root)
	startPy(root, configuredEmbedService())

	if tavilyKey() != "" {
		fmt.Printf("  %s %s\n", OK.Render(Glyph(GlyphOK)), Body.Render("tavily: ")+Meta.Render("web fallback enabled"))
	} else {
		fmt.Printf("  %s %s\n", Caut.Render(Glyph(GlyphWarn)), Body.Render("tavily: ")+Meta.Render("token not found (web fallback off)"))
	}
}

// upQdrant brings up the qdrant container: skip if already healthy, start
// the existing container if one exists, otherwise create it fresh.
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

// runStackDown stops the stack: embed_server, then qdrant.
func runStackDown(root string) {
	fmt.Println(H1.Render("blk down") + "  " + Meta.Render("stopping the stack"))

	stopService(root, configuredEmbedService())

	if err := exec.Command("docker", "stop", qdrantContainer).Run(); err != nil {
		fmt.Printf("  %s %s\n", Fail.Render(Glyph(GlyphErr)), Body.Render("qdrant: ")+Meta.Render("not running"))
	} else {
		fmt.Printf("  %s %s\n", OK.Render(Glyph(GlyphOK)), Body.Render("qdrant: stopped"))
	}
}

// runStackStatus prints the up/down state of qdrant and embed_server.
func runStackStatus(root string) {
	printStatusLine("qdrant", qhealth(), 6333)
	printServiceStatus(root, configuredEmbedService())
}

// printServiceStatus prints svc's up/down line, and when it is up without a
// valid pid file, the one line that says so.
func printServiceStatus(root string, svc pyService) {
	up := health(svc.port, svc.host)
	printStatusLine(svc.name, up, svc.port)
	if _, ok := readPid(pidFilePath(root, svc.name)); up && !ok {
		fmt.Printf("  %s %s\n", Caut.Render(Glyph(GlyphWarn)), Meta.Render(unmanagedNote(svc)))
	}
}

func printStatusLine(name string, up bool, port int) {
	state := "down"
	if up {
		state = "up"
	}
	fmt.Printf("  %s %s %s\n", check(up), Body.Render(pad(name+":", 13)), Meta.Render(fmt.Sprintf("%s (:%d)", state, port)))
}

// runStack dispatches `blk up|down|status`.
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
		runStackUp(root)
	case "down":
		runStackDown(root)
	case "status":
		runStackStatus(root)
	default:
		return fmt.Errorf("stack: unknown command %q", cmd)
	}
	return nil
}
