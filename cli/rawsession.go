package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type rawSessionRequest struct {
	Operation string     `json:"operation"`
	Token     string     `json:"token"`
	Args      []string   `json:"args"`
	Stages    [][]string `json:"stages,omitempty"`
	Limit     int        `json:"limit"`
	Timeout   int        `json:"timeout_seconds"`
}

type rawSessionResponse struct {
	Output    string `json:"output,omitempty"`
	ExitCode  int    `json:"exit_code"`
	Error     string `json:"error,omitempty"`
	Connected bool   `json:"connected,omitempty"`
}

type rawBroker struct {
	shellListener   net.Listener
	controlListener net.Listener
	token           string
	expires         time.Time
	stateMu         sync.Mutex
	execMu          sync.Mutex
	shell           net.Conn
	ready           chan struct{}
	closed          bool
	closeOnce       sync.Once
	controlSlots    chan struct{}
	done            chan struct{}
}

func newRawBroker(ctx context.Context, port int, expires time.Time) (*rawBroker, error) {
	if port < 0 || port > 65535 || !expires.After(time.Now()) {
		return nil, errors.New("invalid raw session listener bounds")
	}
	shell, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	control, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = shell.Close()
		return nil, err
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		_ = shell.Close()
		_ = control.Close()
		return nil, err
	}
	b := &rawBroker{shellListener: shell, controlListener: control, token: hex.EncodeToString(secret[:]),
		expires: expires, controlSlots: make(chan struct{}, 8), ready: make(chan struct{}), done: make(chan struct{})}
	go b.acceptShells()
	go b.acceptControl()
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(time.Until(expires)):
		}
		b.Close()
	}()
	return b, nil
}

func (b *rawBroker) ShellAddr() string     { return b.shellListener.Addr().String() }
func (b *rawBroker) ControlAddr() string   { return b.controlListener.Addr().String() }
func (b *rawBroker) Token() string         { return b.token }
func (b *rawBroker) Done() <-chan struct{} { return b.done }

func (b *rawBroker) Close() {
	b.closeOnce.Do(func() {
		_ = b.shellListener.Close()
		_ = b.controlListener.Close()
		b.stateMu.Lock()
		b.closed = true
		if b.shell != nil {
			_ = b.shell.Close()
			b.shell = nil
		} else {
			close(b.ready)
		}
		b.stateMu.Unlock()
		close(b.done)
	})
}

func (b *rawBroker) acceptShells() {
	for {
		conn, err := b.shellListener.Accept()
		if err != nil {
			return
		}
		b.stateMu.Lock()
		if b.closed || b.shell != nil {
			_ = conn.Close()
		} else {
			b.shell = conn
			close(b.ready)
		}
		b.stateMu.Unlock()
	}
}

func (b *rawBroker) acceptControl() {
	for {
		conn, err := b.controlListener.Accept()
		if err != nil {
			return
		}
		select {
		case b.controlSlots <- struct{}{}:
			go func() {
				defer func() { <-b.controlSlots }()
				b.handleControl(conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (b *rawBroker) handleControl(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	decoder := json.NewDecoder(io.LimitReader(conn, 65537))
	var request rawSessionRequest
	if err := decoder.Decode(&request); err != nil {
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || subtle.ConstantTimeCompare([]byte(request.Token), []byte(b.token)) != 1 {
		return
	}
	if request.Operation == "status" {
		b.stateMu.Lock()
		connected := b.shell != nil && !b.closed
		b.stateMu.Unlock()
		_ = json.NewEncoder(conn).Encode(rawSessionResponse{Connected: connected})
		return
	}
	if request.Operation == "close" {
		_ = json.NewEncoder(conn).Encode(rawSessionResponse{})
		b.Close()
		return
	}
	if request.Operation != "exec" {
		return
	}
	if request.Timeout < 1 || request.Timeout > 300 || request.Limit < 1 || request.Limit > 4<<20 {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(request.Timeout+2) * time.Second))
	stages := request.Stages
	if len(request.Args) > 0 {
		if len(stages) > 0 {
			return
		}
		stages = [][]string{request.Args}
	}
	response, err := b.exec(stages, request.Limit, time.Duration(request.Timeout)*time.Second)
	if err != nil {
		response.Error = err.Error()
	}
	_ = json.NewEncoder(conn).Encode(response)
}

func (b *rawBroker) exec(stages [][]string, limit int, timeout time.Duration) (rawSessionResponse, error) {
	if len(stages) == 0 || len(stages) > 3 {
		return rawSessionResponse{}, errors.New("invalid raw session command")
	}
	receipt, err := newSessionCommand(stages)
	if err != nil {
		return rawSessionResponse{}, err
	}
	b.execMu.Lock()
	defer b.execMu.Unlock()
	b.stateMu.Lock()
	shell := b.shell
	closed := b.closed
	b.stateMu.Unlock()
	if closed || shell == nil || !time.Now().Before(b.expires) {
		return rawSessionResponse{}, errors.New("raw session unavailable")
	}
	if err := shell.SetDeadline(time.Now().Add(timeout)); err != nil {
		return rawSessionResponse{}, err
	}
	if n, err := io.WriteString(shell, receipt.text); err != nil || n != len(receipt.text) {
		b.dropShell(shell)
		return rawSessionResponse{}, errors.New("raw session write failed")
	}
	data := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for {
		n, err := shell.Read(chunk)
		if n > 0 {
			data = append(data, chunk[:n]...)
			if len(data) > limit+8192 {
				b.dropShell(shell)
				return rawSessionResponse{}, errors.New("raw session output exceeds limit")
			}
			response, complete, parseErr := receipt.parse(data, limit)
			if parseErr != nil {
				b.dropShell(shell)
				return rawSessionResponse{}, parseErr
			}
			if complete {
				return response, nil
			}
		}
		if err != nil {
			b.dropShell(shell)
			return rawSessionResponse{}, errors.New("raw session read failed")
		}
	}
}

func (b *rawBroker) dropShell(shell net.Conn) {
	b.stateMu.Lock()
	if b.shell == shell {
		_ = b.shell.Close()
		b.shell = nil
		b.ready = make(chan struct{})
	}
	b.stateMu.Unlock()
}

func rawBrokerRequestPipeline(ctx context.Context, address, token string, stages [][]string, limit int, timeout time.Duration) (rawSessionResponse, error) {
	return rawBrokerExecRequest(ctx, address, rawSessionRequest{Operation: "exec", Token: token, Stages: stages}, limit, timeout)
}

func rawBrokerExecRequest(ctx context.Context, address string, request rawSessionRequest, limit int, timeout time.Duration) (rawSessionResponse, error) {
	if timeout < time.Second || timeout > 300*time.Second || limit < 1 || limit > 4<<20 {
		return rawSessionResponse{}, errors.New("invalid raw session request bounds")
	}
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return rawSessionResponse{}, errors.New("raw session broker unavailable")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(timeout + 3*time.Second))
	request.Limit = limit
	request.Timeout = int(timeout.Seconds())
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return rawSessionResponse{}, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			return rawSessionResponse{}, err
		}
	}
	var response rawSessionResponse
	if err := json.NewDecoder(io.LimitReader(conn, int64(limit)*6+4096)).Decode(&response); err != nil {
		return rawSessionResponse{}, errors.New("raw session response missing or invalid")
	}
	if response.Error != "" {
		return response, fmt.Errorf("raw session: %s", response.Error)
	}
	if len(response.Output) > limit {
		return rawSessionResponse{}, errors.New("raw session response exceeds limit")
	}
	return response, nil
}

func runRawSessionStages(ctx context.Context, record *rawSessionRecord, stages []pipelineStage, limit int, timeout time.Duration) (runResult, []isolatedStageResult) {
	if record == nil || len(stages) == 0 || len(stages) > 3 {
		return runResult{Err: errors.New("raw session requires one to three command stages")}, nil
	}
	argv := make([][]string, len(stages))
	outputs := make([]isolatedStageResult, len(stages))
	for i, stage := range stages {
		argv[i] = append([]string{stage.Binary}, stage.Args...)
		outputs[i].ExitCode = -1
	}
	response, err := rawBrokerRequestPipeline(ctx, record.ControlAddress, record.Token, argv, limit, timeout)
	if err != nil {
		return runResult{Err: err}, outputs
	}
	result := runResult{Output: response.Output, Stdout: response.Output, ExitCode: response.ExitCode}
	if response.ExitCode != 0 {
		result.Err = fmt.Errorf("exit status %d", response.ExitCode)
	}
	outputs[len(outputs)-1] = isolatedStageResult{Stdout: response.Output, ExitCode: response.ExitCode}
	return result, outputs
}

func rawBrokerStatus(ctx context.Context, address, token string) (bool, error) {
	response, err := rawBrokerControl(ctx, address, rawSessionRequest{Operation: "status", Token: token})
	return response.Connected, err
}

func rawBrokerClose(ctx context.Context, address, token string) error {
	_, err := rawBrokerControl(ctx, address, rawSessionRequest{Operation: "close", Token: token})
	return err
}

func rawBrokerControl(ctx context.Context, address string, request rawSessionRequest) (rawSessionResponse, error) {
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return rawSessionResponse{}, errors.New("raw session broker unavailable")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return rawSessionResponse{}, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			return rawSessionResponse{}, err
		}
	}
	var response rawSessionResponse
	if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&response); err != nil {
		return rawSessionResponse{}, errors.New("raw session control response missing")
	}
	return response, nil
}
