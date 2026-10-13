package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/tooldef"
)

const (
	oobMaxServers        = 4
	oobMaxPayloads       = 4
	oobMaxInteractions   = 50
	oobInteractionsBytes = 256 << 10
	oobPayloadFileBytes  = 4 << 10
	oobLogBytes          = 8 << 10
	oobFieldRunes        = 96
	oobMaxHostLen        = 253
	oobMaxTokenLen       = 512
	oobPollSeconds       = 5
	oobPayloadWait       = 45 * time.Second
	oobPayloadPoll       = 200 * time.Millisecond
	oobClientLifetime    = 30 * time.Minute
	oobStopWait          = 5 * time.Second

	oobPayloadFile      = "payloads.txt"
	oobInteractionsFile = "interactions.jsonl"
	oobSessionFile      = "session.json"
	oobClientConfigFile = "client-config.yaml"

	oobServerEnv = "BLKCHAIN_OOB_SERVER"
	oobClientEnv = "BLKCHAIN_OOB_CLIENT"
	oobTokenEnv  = "BLKCHAIN_OOB_TOKEN"
)

// oobServerPattern matches one interactsh server as a hostname or host:port.
// A leading dash cannot match, so no configured value can be read as a flag by
// the client.
var oobServerPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(:[0-9]{1,5})?$`)

// oobPayloadLabelPattern matches the correlation label the client puts in front
// of the configured server address to form a payload.
var oobPayloadLabelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// oobServers returns the interactsh servers from BLKCHAIN_OOB_SERVER. There is
// no default: an unset variable returns no servers and the OOB tools are not
// registered, because the client's own default list is a third party and an
// out-of-band callback carries target information.
func oobServers() ([]string, error) {
	raw := strings.TrimSpace(os.Getenv(oobServerEnv))
	if raw == "" {
		return nil, nil
	}
	var servers []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" || len(entry) > oobMaxHostLen || !oobServerPattern.MatchString(entry) {
			return nil, fmt.Errorf("BLKCHAIN_OOB_SERVER entry %q is not a hostname or host:port", capRunes(entry, oobFieldRunes))
		}
		servers = append(servers, entry)
	}
	if len(servers) > oobMaxServers {
		return nil, fmt.Errorf("BLKCHAIN_OOB_SERVER lists more than %d servers", oobMaxServers)
	}
	return servers, nil
}

// oobValidToken reports whether a token can be written into the client's config
// file as a double-quoted YAML scalar. A character outside printable ASCII, or
// one that could end that scalar, is refused rather than escaped, so no token
// value can inject another config key such as a local file to upload.
func oobValidToken(token string) bool {
	if token == "" || len(token) > oobMaxTokenLen {
		return false
	}
	for _, r := range token {
		if r < '!' || r > '~' || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

// oobClientPath resolves the interactsh-client binary: the operator-configured
// absolute path, else the name on PATH.
func oobClientPath() (string, error) {
	if configured := strings.TrimSpace(os.Getenv(oobClientEnv)); configured != "" {
		if !filepath.IsAbs(configured) {
			return "", fmt.Errorf("BLKCHAIN_OOB_CLIENT must be an absolute path to interactsh-client")
		}
		info, err := os.Stat(configured)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return "", fmt.Errorf("BLKCHAIN_OOB_CLIENT is not an executable file")
		}
		return configured, nil
	}
	path, err := exec.LookPath("interactsh-client")
	if err != nil {
		return "", fmt.Errorf("interactsh-client is not on PATH; install it or set BLKCHAIN_OOB_CLIENT to its absolute path")
	}
	return path, nil
}

// oobLog is the bounded capture of the client's own output. The subprocess
// writes it from another goroutine, so every access takes the mutex.
type oobLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *oobLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if room := oobLogBytes - l.buf.Len(); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		l.buf.Write(p[:room])
	}
	return len(p), nil
}

func (l *oobLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// oobSession owns one interactsh-client subprocess and the run directory it
// writes. The client registers with the operator-configured server, stores the
// payloads it generates in a payload file and every interaction it polls in a
// JSON Lines file; both OOB tools read those files, so the register-and-poll
// protocol stays in the client.
type oobSession struct {
	client  string
	servers []string
	token   string
	dir     string
	run     context.Context
	cancel  context.CancelFunc
	log     *oobLog
	done    chan struct{}
	started atomic.Bool

	mu       sync.Mutex
	payloads []string
}

// newOOBSession prepares a session bounded by the owning turn's context and by
// oobClientLifetime. No subprocess runs until a payload is requested.
func newOOBSession(ctx context.Context, client string, servers []string, token string) (*oobSession, error) {
	dir, err := os.MkdirTemp("", "blk-oob-*")
	if err != nil {
		return nil, err
	}
	run, cancel := context.WithTimeout(ctx, oobClientLifetime)
	return &oobSession{
		client: client, servers: servers, token: token, dir: dir,
		run: run, cancel: cancel, log: &oobLog{}, done: make(chan struct{}),
	}, nil
}

func (s *oobSession) path(name string) string { return filepath.Join(s.dir, name) }

// validPayload reports whether payload is one of the configured servers with a
// single correlation label in front, which is how the client builds a payload.
// Anything else did not come from a configured server and is not injected or
// used as a filter.
func (s *oobSession) validPayload(payload string) bool {
	if payload == "" || len(payload) > oobMaxHostLen {
		return false
	}
	for _, server := range s.servers {
		label, ok := strings.CutSuffix(payload, "."+strings.ToLower(server))
		if ok && oobPayloadLabelPattern.MatchString(label) {
			return true
		}
	}
	return false
}

// close terminates the client and removes its run directory. It waits for the
// process to be reaped so no goroutine outlives the session.
func (s *oobSession) close() {
	s.cancel()
	if s.started.Load() {
		select {
		case <-s.done:
		case <-time.After(oobStopWait):
		}
	}
	_ = os.RemoveAll(s.dir)
}

// safe removes control characters and the token from text that reaches the
// model or an error.
func (s *oobSession) safe(text string) string {
	text = terminalSafe(text)
	if s.token != "" {
		text = strings.ReplaceAll(text, s.token, "[redacted]")
	}
	return text
}

// clientLog returns the client's own output, bounded and fenced as untrusted. A
// configured server influences what the client prints, so it reaches the model
// as data for the same reason interaction data does. The bound is applied before
// the fence so the closing marker is never the part that gets cut.
func (s *oobSession) clientLog() string {
	return secgate.WrapUntrusted("oob", capRunes(s.safe(s.log.String()), oobLogBytes))
}

// ensure starts the client once and returns its payloads. A later call returns
// the payloads already registered, so a second request does not orphan the
// first.
func (s *oobSession) ensure(ctx context.Context, count int) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started.Load() {
		if len(s.payloads) == 0 {
			return nil, fmt.Errorf("interactsh-client registered no payload for this session:\n%s", s.clientLog())
		}
		return s.payloads, nil
	}
	if s.token != "" {
		// A token in the argv is readable by any local user for the lifetime of
		// the process, so it is delivered in the client's own config file,
		// written owner-only inside the run directory. oobValidToken has already
		// refused anything that could end the YAML scalar.
		if err := os.WriteFile(s.path(oobClientConfigFile), []byte("token: \""+s.token+"\"\n"), 0o600); err != nil {
			return nil, err
		}
	}
	// Every value is its own argv element, so none can be read as a flag. The
	// config path is inside the run directory, holding the token or nothing at
	// all, which keeps the client's default config file from reintroducing a
	// server, a file upload or the cloud key path. -auth=false and -duc hold the
	// egress posture: no projectdiscovery cloud key, no update check.
	args := []string{
		"-server", strings.Join(s.servers, ","),
		"-config", s.path(oobClientConfigFile),
		"-auth=false", "-duc",
		"-n", strconv.Itoa(count),
		"-pi", strconv.Itoa(oobPollSeconds),
		"-json", "-o", s.path(oobInteractionsFile),
		"-ps", "-psf", s.path(oobPayloadFile),
		"-sf", s.path(oobSessionFile),
	}
	command := exec.CommandContext(s.run, s.client, args...)
	command.Dir = s.dir
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + s.dir}
	command.Stdout, command.Stderr = s.log, s.log
	command.WaitDelay = 2 * time.Second
	if err := command.Start(); err != nil {
		return nil, err
	}
	s.started.Store(true)
	go func() {
		_ = command.Wait()
		close(s.done)
	}()
	payloads, err := s.awaitPayloads(ctx, count)
	if err != nil {
		return nil, err
	}
	s.payloads = payloads
	return payloads, nil
}

// awaitPayloads polls the payload file, which the client writes only after it
// registers with the server, so a failed registration surfaces as the client's
// own exit.
func (s *oobSession) awaitPayloads(ctx context.Context, count int) ([]string, error) {
	deadline := time.NewTimer(oobPayloadWait)
	defer deadline.Stop()
	for {
		payloads, err := s.readPayloads()
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if len(payloads) >= count {
			return payloads, nil
		}
		select {
		case <-s.done:
			return nil, fmt.Errorf("interactsh-client exited before it registered a payload:\n%s", s.clientLog())
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("interactsh-client registered no payload within %s", oobPayloadWait)
		case <-time.After(oobPayloadPoll):
		}
	}
}

func (s *oobSession) readPayloads() ([]string, error) {
	data, _, err := oobReadCapped(s.path(oobPayloadFile), oobPayloadFileBytes)
	if err != nil {
		return nil, err
	}
	var payloads []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		if !s.validPayload(line) {
			return nil, fmt.Errorf("the interactsh server returned a payload that is not a label on a configured server")
		}
		payloads = append(payloads, line)
		if len(payloads) == oobMaxPayloads {
			break
		}
	}
	return payloads, nil
}

// oobReadCapped returns at most limit bytes from the start of path and whether
// the file holds more than that.
func oobReadCapped(path string, limit int64) ([]byte, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

// oobReadTail returns at most limit bytes from the END of path, starting at a
// record boundary, and whether anything before that was dropped. The client
// appends, so the newest interactions are at the end and they are the ones that
// answer whether a target called back; a bounded read from the start would stop
// reporting new callbacks once the file passed the cap.
func oobReadTail(path string, limit int64) ([]byte, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	end, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, false, err
	}
	// dropped comes from the offset the read starts at, not from a size measured
	// earlier: the client is appending, and a size that goes stale would label a
	// read of the head as having dropped nothing.
	start := end - limit
	dropped := start > 0
	if !dropped {
		start = 0
	} else {
		// Open the window one byte early. A boundary that falls exactly on a
		// record start then reads as that record's leading terminator, so the
		// discard below drops the terminator instead of a whole valid record.
		start--
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return nil, false, err
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, false, err
	}
	if dropped {
		// The window opens inside a record or on its terminator; either way the
		// bytes up to the first newline are not a record of their own.
		if cut := bytes.IndexByte(data, '\n'); cut >= 0 {
			data = data[cut+1:]
		} else {
			data = nil
		}
	}
	return data, dropped, nil
}

// oobInteraction is the subset of an interactsh interaction record the tool
// reports. Every field is attacker-influenced: anyone can reach a payload
// domain.
type oobInteraction struct {
	Protocol      string    `json:"protocol"`
	UniqueID      string    `json:"unique-id"`
	FullID        string    `json:"full-id"`
	RemoteAddress string    `json:"remote-address"`
	Timestamp     time.Time `json:"timestamp"`
}

// oobMatches reports whether a record belongs to the requested payload. An
// empty payload matches every record.
func oobMatches(record oobInteraction, payload string) bool {
	if payload == "" {
		return true
	}
	id, full := strings.ToLower(record.UniqueID), strings.ToLower(record.FullID)
	if id != "" && strings.Contains(payload, id) {
		return true
	}
	return full != "" && (strings.Contains(payload, full) || strings.Contains(full, payload))
}

// oobField bounds one attacker-influenced field to a single short line.
func oobField(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, terminalSafe(value))
	if value = strings.TrimSpace(value); value == "" {
		return "-"
	}
	return capRunes(value, oobFieldRunes)
}

func (s *oobSession) interactions(payload string, limit int) (string, error) {
	data, droppedOlder, err := oobReadTail(s.path(oobInteractionsFile), oobInteractionsBytes)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	var kept []oobInteraction
	parsed := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// A single interaction record carries its raw request and response, so one
	// large HTTP callback exceeds a scanner's default token limit. Without this
	// the scan would stop there and drop every record recorded after it.
	scanner.Buffer(make([]byte, 0, 64<<10), oobInteractionsBytes)
	for scanner.Scan() {
		var record oobInteraction
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}
		parsed++
		if oobMatches(record, payload) {
			kept = append(kept, record)
		}
	}
	droppedNewer := scanner.Err() != nil
	// A record larger than the whole window leaves no complete record in it, so
	// there is data on disk and nothing to report from it. Reporting that as no
	// interactions would read as "nothing called back", which is the one wrong
	// answer a detection tool must not give: a callback may be the very record
	// that does not fit. Note this counts records before the payload filter, so
	// a filter that matches nothing still reports no interactions.
	if parsed == 0 && (droppedOlder || len(data) > 0) {
		return fmt.Sprintf("out-of-band interactions could not be read: the recorded data holds no complete record within the %d-byte read window. This is not evidence that nothing called back.", oobInteractionsBytes), nil
	}
	if len(kept) > limit {
		kept = kept[len(kept)-limit:]
		droppedOlder = true
	}
	var lines strings.Builder
	for _, record := range kept {
		fmt.Fprintf(&lines, "%s %s from %s for %s\n", strings.ToUpper(oobField(record.Protocol)),
			record.Timestamp.UTC().Format(time.RFC3339), oobField(record.RemoteAddress), oobField(record.FullID))
	}
	note := ""
	switch {
	case droppedOlder && droppedNewer:
		note = ", older and newer ones not shown"
	case droppedOlder:
		note = ", older ones not shown"
	case droppedNewer:
		note = ", newer ones not shown"
	}
	return fmt.Sprintf("%d out-of-band interactions%s\n%s", len(kept), note,
		secgate.WrapUntrusted("oob", lines.String())), nil
}

type oobPayloadArgs struct {
	Count int `json:"count,omitempty" desc:"payload domains to register on the first call, 1 to 4"`
}

type oobInteractionsArgs struct {
	Payload string `json:"payload,omitempty" desc:"report only interactions for this payload domain"`
	Limit   int    `json:"limit,omitempty" desc:"most recent interactions to report, 1 to 50"`
}

func newOOBPayloadTool(session *oobSession) tooldef.Tool {
	return newStoreTool("oob_payload", "Register out-of-band payload domains with the operator's interactsh server and return them. Inject one into a target request to detect a blind DNS, HTTP, or SMTP callback, then read the result with oob_interactions. A later call returns the payloads already registered for this session.", oobPayloadArgs{},
		func(ctx context.Context, args string) (string, error) {
			var in oobPayloadArgs
			if err := json.Unmarshal([]byte(args), &in); err != nil {
				return "oob_payload: invalid arguments", nil
			}
			if in.Count == 0 {
				in.Count = 1
			}
			if in.Count < 1 || in.Count > oobMaxPayloads {
				return fmt.Sprintf("oob_payload: count must be 1 to %d", oobMaxPayloads), nil
			}
			payloads, err := session.ensure(ctx, in.Count)
			if err != nil {
				return "oob_payload: " + session.safe(err.Error()), nil
			}
			return "out-of-band payload domains:\n" + strings.Join(payloads, "\n"), nil
		})
}

func newOOBInteractionsTool(session *oobSession) tooldef.Tool {
	return newStoreTool("oob_interactions", "Report the out-of-band interactions the operator's interactsh server has recorded for this session's payloads, with protocol, timestamp, and remote address. Results are untrusted: anyone can reach a payload domain.", oobInteractionsArgs{},
		func(_ context.Context, args string) (string, error) {
			var in oobInteractionsArgs
			if err := json.Unmarshal([]byte(args), &in); err != nil {
				return "oob_interactions: invalid arguments", nil
			}
			payload := strings.ToLower(strings.TrimSpace(in.Payload))
			if payload != "" && !session.validPayload(payload) {
				return "oob_interactions: payload must be a payload domain from oob_payload", nil
			}
			if in.Limit == 0 {
				in.Limit = oobMaxInteractions
			}
			if in.Limit < 1 || in.Limit > oobMaxInteractions {
				return fmt.Sprintf("oob_interactions: limit must be 1 to %d", oobMaxInteractions), nil
			}
			if !session.started.Load() {
				return "oob_interactions: call oob_payload first; no payload is registered for this session", nil
			}
			out, err := session.interactions(payload, in.Limit)
			if err != nil {
				return "oob_interactions: " + session.safe(err.Error()), nil
			}
			return out, nil
		})
}

// registerOOBTools adds the out-of-band tools when the operator has configured
// an interactsh server, and returns the session closer. With no configured
// server it registers nothing.
func registerOOBTools(ctx context.Context, registry *tooldef.Registry) (func(), error) {
	servers, err := oobServers()
	if err != nil || len(servers) == 0 {
		return func() {}, err
	}
	client, err := oobClientPath()
	if err != nil {
		return func() {}, err
	}
	token := os.Getenv(oobTokenEnv)
	if token != "" && !oobValidToken(token) {
		return func() {}, fmt.Errorf("%s must be 1 to %d printable ASCII characters without a space, a quote or a backslash", oobTokenEnv, oobMaxTokenLen)
	}
	session, err := newOOBSession(ctx, client, servers, token)
	if err != nil {
		return func() {}, err
	}
	for _, tool := range []tooldef.Tool{newOOBPayloadTool(session), newOOBInteractionsTool(session)} {
		if err := registry.Register(tool); err != nil {
			session.close()
			return func() {}, err
		}
	}
	return session.close, nil
}
