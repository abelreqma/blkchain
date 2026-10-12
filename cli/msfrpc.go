package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"blkchain/cli/internal/secgate"
	"github.com/vmihailenco/msgpack/v5"
)

type msfRPCTransport struct {
	endpoint string
	user     string
	password string
	session  string
	host     string
	client   *http.Client
	mu       sync.Mutex
}

func buildFootholdMSFRPC(f *secgate.Foothold) (*footholdTransport, error) {
	password, ok := os.LookupEnv(f.PasswordEnv)
	if !ok || password == "" {
		return nil, errors.New("metasploit RPC password environment variable is unset")
	}
	return &footholdTransport{msf: &msfRPCTransport{endpoint: f.RPC, user: f.User, password: password, session: f.Session, host: f.Host,
		client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, secrets: map[string][]byte{}}, nil
}

func (m *msfRPCTransport) call(ctx context.Context, method string, args ...any) (map[string]any, error) {
	requestArgs := append([]any{method}, args...)
	body, err := msgpack.Marshal(requestArgs)
	if err != nil || len(body) > 1<<20 {
		return nil, errors.New("metasploit RPC request exceeds limit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid Metasploit RPC request")
	}
	req.Header.Set("Content-Type", "binary/message-pack")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, errors.New("metasploit RPC unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metasploit RPC status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if err != nil || len(data) > 4<<20 {
		return nil, errors.New("metasploit RPC response exceeds limit")
	}
	var result map[string]any
	if err := msgpack.Unmarshal(data, &result); err != nil || result == nil {
		return nil, errors.New("invalid Metasploit RPC response")
	}
	if failed, _ := result["error"].(bool); failed {
		return nil, errors.New("metasploit RPC rejected request")
	}
	return result, nil
}

func (m *msfRPCTransport) login(ctx context.Context) (string, error) {
	result, err := m.call(ctx, "auth.login", m.user, m.password)
	if err != nil || result["result"] != "success" {
		return "", errors.New("metasploit RPC authentication failed")
	}
	token, ok := result["token"].(string)
	if !ok || token == "" {
		return "", errors.New("metasploit RPC token missing")
	}
	return token, nil
}

func (m *msfRPCTransport) active(ctx context.Context) error {
	token, err := m.login(ctx)
	if err != nil {
		return err
	}
	return m.activeWithToken(ctx, token)
}

func (m *msfRPCTransport) activeWithToken(ctx context.Context, token string) error {
	result, err := m.call(ctx, "session.list", token)
	if err != nil {
		return err
	}
	session, ok := result[m.session].(map[string]any)
	if !ok || session["type"] != "shell" {
		return errors.New("metasploit command shell session is not active")
	}
	host := msfString(session["target_host"])
	if host == "" {
		peer, _, err := net.SplitHostPort(msfString(session["tunnel_peer"]))
		if err != nil {
			return errors.New("metasploit session peer is unavailable")
		}
		host = peer
	}
	if net.ParseIP(host) == nil || !net.ParseIP(host).Equal(net.ParseIP(m.host)) {
		return errors.New("metasploit session peer does not match the approved foothold")
	}
	return nil
}

func msfString(v any) string {
	switch value := v.(type) {
	case string:
		return value
	case []byte:
		return string(value)
	case int8, int16, int32, int64, int, uint8, uint16, uint32, uint64, uint:
		return fmt.Sprint(value)
	default:
		return ""
	}
}

func (m *msfRPCTransport) read(ctx context.Context, token, pointer string) (string, string, error) {
	result, err := m.call(ctx, "session.shell_read", token, m.session, pointer)
	if err != nil {
		return "", "", err
	}
	seq := msfString(result["seq"])
	if _, err := strconv.ParseUint(seq, 10, 64); err != nil {
		return "", "", errors.New("invalid Metasploit shell read pointer")
	}
	data := msfString(result["data"])
	if len(data) > 4<<20 {
		return "", "", errors.New("metasploit shell output exceeds limit")
	}
	return seq, data, nil
}

func runMSFRPCStages(ctx context.Context, m *msfRPCTransport, stages []pipelineStage, limit int, timeout time.Duration) (runResult, []isolatedStageResult) {
	if m == nil || limit < 1 || timeout < time.Second {
		return runResult{Err: errors.New("metasploit RPC carrier unavailable")}, nil
	}
	argv := make([][]string, len(stages))
	for i, stage := range stages {
		argv[i] = append([]string{stage.Binary}, stage.Args...)
	}
	receipt, err := newSessionCommand(argv)
	if err != nil {
		return runResult{Err: err}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	token, err := m.login(ctx)
	if err != nil {
		return runResult{Err: err}, nil
	}
	if err := m.activeWithToken(ctx, token); err != nil {
		return runResult{Err: err}, nil
	}
	pointer, _, err := m.read(ctx, token, "0")
	if err != nil {
		return runResult{Err: err}, nil
	}
	result, err := m.call(ctx, "session.shell_write", token, m.session, receipt.text)
	if err != nil {
		return runResult{Err: err}, nil
	}
	if n, err := strconv.Atoi(msfString(result["write_count"])); err != nil || n != len(receipt.text) {
		return runResult{Err: errors.New("metasploit shell write incomplete")}, nil
	}
	var output strings.Builder
	for {
		select {
		case <-ctx.Done():
			return runResult{Err: ctx.Err(), TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded)}, nil
		default:
		}
		var data string
		pointer, data, err = m.read(ctx, token, pointer)
		if err != nil {
			return runResult{Err: err}, nil
		}
		if output.Len()+len(data) > limit+8192 {
			return runResult{Err: errors.New("metasploit shell output exceeds limit")}, nil
		}
		output.WriteString(data)
		response, complete, parseErr := receipt.parse([]byte(output.String()), limit)
		if parseErr != nil {
			return runResult{Err: parseErr}, nil
		}
		if complete {
			out := make([]isolatedStageResult, len(stages))
			for i := range out {
				out[i].ExitCode = -1
			}
			out[len(out)-1] = isolatedStageResult{Stdout: response.Output, ExitCode: response.ExitCode}
			run := runResult{Output: response.Output, Stdout: response.Output, ExitCode: response.ExitCode}
			if response.ExitCode != 0 {
				run.Err = fmt.Errorf("exit status %d", response.ExitCode)
			}
			return run, out
		}
		select {
		case <-ctx.Done():
			return runResult{Err: ctx.Err(), TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded)}, nil
		case <-time.After(50 * time.Millisecond):
		}
	}
}
