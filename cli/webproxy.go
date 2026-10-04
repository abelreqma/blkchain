package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
	"github.com/gorilla/websocket"
)

//go:embed webproxy.js
var webProxyScript string

type webProxyMessage struct {
	Kind      string      `json:"kind"`
	ID        string      `json:"id,omitempty"`
	URL       string      `json:"url,omitempty"`
	Method    string      `json:"method,omitempty"`
	Headers   http.Header `json:"headers,omitempty"`
	Body      []byte      `json:"body,omitempty"`
	Status    int         `json:"status,omitempty"`
	Port      int         `json:"port,omitempty"`
	Opcode    int         `json:"opcode,omitempty"`
	Code      int         `json:"code,omitempty"`
	Protocol  string      `json:"protocol,omitempty"`
	Protocols []string    `json:"protocols,omitempty"`
	Key       string      `json:"key,omitempty"`
	Cert      string      `json:"cert,omitempty"`
}
type webProxySocket struct {
	Conn     *webacquire.WebSocket
	URL      string
	ID       string
	Sequence atomic.Int64
	Queue    chan webProxyMessage
}
type webProxy struct {
	Driver    *webPlaywrightDriver
	ID        string
	Cmd       *exec.Cmd
	Input     io.WriteCloser
	Cancel    context.CancelFunc
	writeMu   sync.Mutex
	mu        sync.Mutex
	Sockets   map[string]*webProxySocket
	ready     chan int
	done      chan struct{}
	wg        sync.WaitGroup
	httpSlots chan struct{}
	Activity  atomic.Int64
}

func webProxyCertificate() (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "blk browser proxy"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})), nil
}
func (d *webPlaywrightDriver) startProxy() (string, error) {
	cert, key, err := webProxyCertificate()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithCancel(context.Background())
	bin := os.Getenv("BLKCHAIN_DOCKER_BIN")
	if bin == "" {
		bin = "docker"
	}
	cmd := exec.CommandContext(ctx, bin, "exec", "-i", "--user", "1000:1000", os.Getenv("BLKCHAIN_PLAYWRIGHT_CONTAINER"), "node", "-e", webProxyScript)
	input, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return "", err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return "", err
	}
	cmd.Stderr = &webLimitedBuffer{limit: 4096}
	p := &webProxy{Driver: d, ID: webanalysis.Hash([]byte(cert)), Cmd: cmd, Input: input, Cancel: cancel, Sockets: map[string]*webProxySocket{}, ready: make(chan int, 1), done: make(chan struct{}), httpSlots: make(chan struct{}, 16)}
	if err = cmd.Start(); err != nil {
		cancel()
		return "", errors.New("isolated browser proxy unavailable")
	}
	d.proxy = p
	go p.read(output)
	if err = p.write(webProxyMessage{Kind: "config", Cert: cert, Key: key}); err != nil {
		p.Close()
		return "", err
	}
	select {
	case port := <-p.ready:
		if port < 1 || port > 65535 {
			p.Close()
			return "", errors.New("invalid proxy endpoint")
		}
		return "http://127.0.0.1:" + strconv.Itoa(port), nil
	case <-p.done:
		p.Close()
		return "", errors.New("isolated browser proxy failed")
	case <-time.After(10 * time.Second):
		p.Close()
		return "", errors.New("isolated browser proxy startup timed out")
	}
}
func (p *webProxy) write(m webProxyMessage) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.Activity.Store(time.Now().UnixNano())
	return json.NewEncoder(p.Input).Encode(m)
}
func (p *webProxy) context() context.Context {
	p.Driver.stateMu.RLock()
	ctx := p.Driver.actionCtx
	p.Driver.stateMu.RUnlock()
	if ctx == nil {
		c, cancel := context.WithCancel(context.Background())
		cancel()
		return c
	}
	return ctx
}
func (p *webProxy) read(r io.Reader) {
	defer close(p.done)
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 65536), 2<<20)
	for scan.Scan() {
		var m webProxyMessage
		if json.Unmarshal(scan.Bytes(), &m) != nil {
			break
		}
		p.Activity.Store(time.Now().UnixNano())
		switch m.Kind {
		case "ready":
			p.ready <- m.Port
		case "http", "open":
			select {
			case p.httpSlots <- struct{}{}:
				p.wg.Add(1)
				go func() {
					defer p.wg.Done()
					defer func() { <-p.httpSlots }()
					if m.Kind == "http" {
						p.http(m)
					} else {
						p.open(m)
					}
				}()
			default:
				_ = p.write(webProxyMessage{Kind: map[bool]string{true: "http", false: "opened"}[m.Kind == "http"], ID: m.ID, Status: 429})
			}
		case "send":
			p.mu.Lock()
			s := p.Sockets[m.ID]
			p.mu.Unlock()
			if s != nil {
				select {
				case s.Queue <- m:
				default:
					p.gap(s.URL, "WebSocket message queue limit")
					s.Conn.Close()
				}
			}
		case "close", "limit":
			p.mu.Lock()
			s := p.Sockets[m.ID]
			p.mu.Unlock()
			if s != nil {
				if m.Kind == "limit" {
					p.gap(s.URL, "WebSocket message or input limit")
				}
				s.Conn.Close()
			}
		}
	}
	if scan.Err() != nil {
		p.gap("", "browser proxy stream limit or failure")
	}
}
func (p *webProxy) gap(raw, reason string) {
	if p.Driver.observe != nil {
		_ = p.Driver.observe(webObservation{Artifact: webanalysis.Artifact{Kind: "collection-gap", URL: raw, Role: p.Driver.role, Gap: reason}})
	}
}
func (p *webProxy) headers(raw string, h http.Header) http.Header {
	canonical := http.Header{}
	for k, values := range h {
		for _, value := range values {
			canonical.Add(k, value)
		}
	}
	h = canonical
	u, _ := url.Parse(raw)
	if u != nil && p.Driver.sessionOrigin != "" && u.Scheme+"://"+u.Host != p.Driver.sessionOrigin {
		for key := range h {
			if webanalysis.Sensitive(key) {
				h.Del(key)
			}
		}
	}
	if u != nil && p.Driver.sessionOrigin != "" && (u.Scheme == "https" || u.Scheme == "http") && u.Scheme+"://"+u.Host == p.Driver.sessionOrigin {
		for k, v := range p.Driver.sessionHeaders {
			h[k] = append([]string(nil), v...)
		}
	}
	return h
}
func (p *webProxy) http(m webProxyMessage) {
	ctx := p.context()
	d := p.Driver
	r := webacquire.Request{Method: m.Method, URL: m.URL, Headers: p.headers(m.URL, m.Headers), Body: m.Body}
	var out webacquire.Response
	err := errors.New("request budget or cancellation")
	if d.requests.Add(1) <= webMaxPageRequests && d.broker != nil && ctx.Err() == nil {
		out, err = d.broker.Once(ctx, r)
	}
	kind, resource := "response", r.Headers.Get("Sec-Fetch-Dest")
	if resource == "script" || resource == "worker" || resource == "sharedworker" || resource == "serviceworker" || strings.Contains(out.Headers.Get("Content-Type"), "javascript") {
		kind = "script"
	}
	if resource == "document" || resource == "iframe" {
		kind = "html"
		resource = "document"
	}
	if resource == "empty" {
		resource = "fetch"
	}
	example := d.cdpRequest(webanalysis.RequestExample{ResourceType: resource, URL: r.URL, Method: r.Method, Headers: r.Headers, Body: string(r.Body), Role: d.role, Status: out.Status})
	artifact := webanalysis.Artifact{DocumentURL: r.Headers.Get("Referer"), Kind: kind, URL: r.URL, FinalURL: out.FinalURL, Headers: out.Headers, Status: out.Status, MIME: out.Headers.Get("Content-Type"), Role: d.role, Complete: out.Complete, Gap: out.Gap}
	if resource == "worker" || resource == "sharedworker" || resource == "serviceworker" {
		artifact.DocumentURL = r.URL
	}
	if err != nil {
		artifact.Gap = "request denied or transfer failed"
	}
	if d.observe != nil {
		if e := d.observe(webObservation{Artifact: artifact, Body: out.Body, Request: example}); e != nil {
			err = e
		}
	}
	status := out.Status
	if err != nil {
		status = 403
		out.Body = nil
		out.Headers = nil
	}
	if status == 0 {
		status = 502
	}
	for _, k := range []string{"Connection", "Transfer-Encoding", "Content-Length", "Upgrade", "Proxy-Authenticate"} {
		out.Headers.Del(k)
	}
	_ = p.write(webProxyMessage{Kind: "http", ID: m.ID, Status: status, Headers: out.Headers, Body: out.Body})
}
func (p *webProxy) open(m webProxyMessage) {
	ctx := p.context()
	d := p.Driver
	_, target, err := webacquire.WebSocketURL(m.URL)
	var conn *webacquire.WebSocket
	var out webacquire.Response
	h := m.Headers
	if err == nil {
		h = p.headers(target, h)
		if d.broker == nil {
			err = errors.New("broker missing")
		} else {
			conn, out, err = d.broker.OpenWebSocket(ctx, m.URL, h, m.Protocols)
		}
	}
	if d.observe != nil {
		e := d.observe(webObservation{Artifact: webanalysis.Artifact{Kind: "websocket-handshake", URL: m.URL, FinalURL: m.URL, Headers: out.Headers, Status: out.Status, Role: d.role, Complete: out.Complete, Gap: out.Gap}, Body: out.Body, Request: webanalysis.RequestExample{ResourceType: "websocket", URL: m.URL, Method: "GET", Headers: h, Role: d.role, Status: out.Status, SocketID: webanalysis.ID(p.ID, m.ID)}})
		if e != nil {
			err = e
		}
	}
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		p.gap(m.URL, "WebSocket handshake denied or failed")
		_ = p.write(webProxyMessage{Kind: "opened", ID: m.ID, Status: 403})
		return
	}
	s := &webProxySocket{Conn: conn, URL: m.URL, ID: m.ID, Queue: make(chan webProxyMessage, 16)}
	p.mu.Lock()
	if len(p.Sockets) >= 16 {
		p.mu.Unlock()
		conn.Close()
		p.gap(m.URL, "WebSocket connection limit")
		_ = p.write(webProxyMessage{Kind: "opened", ID: m.ID, Status: 429})
		return
	}
	p.Sockets[m.ID] = s
	p.mu.Unlock()
	if err = p.write(webProxyMessage{Kind: "opened", ID: m.ID, Status: 101, Protocol: conn.Conn.Subprotocol()}); err != nil {
		conn.Close()
		return
	}
	p.wg.Add(2)
	go func() {
		defer p.wg.Done()
		defer conn.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case <-p.done:
				return
			case message := <-s.Queue:
				err := conn.Send(ctx, message.Opcode, message.Body)
				if e := p.message(s, "sent", message.Opcode, message.Body, err == nil); e != nil && err == nil {
					err = e
				}
				if err != nil {
					p.gap(s.URL, "WebSocket message denied or transfer limit")
					_ = p.write(webProxyMessage{Kind: "closed", ID: s.ID, Code: 1008})
					return
				}
			}
		}
	}()
	go func() {
		defer p.wg.Done()
		defer conn.Close()
		for {
			opcode, body, err := conn.Receive()
			if err != nil {
				if !websocket.IsCloseError(err, 1000, 1001, 1005) && ctx.Err() == nil {
					p.gap(s.URL, "WebSocket receive interrupted or message limit")
				}
				_ = p.write(webProxyMessage{Kind: "closed", ID: s.ID, Code: 1000})
				return
			}
			if err = p.message(s, "received", opcode, body, true); err != nil {
				return
			}
			if err = p.write(webProxyMessage{Kind: "message", ID: s.ID, Opcode: opcode, Body: body}); err != nil {
				return
			}
		}
	}()
}
func (p *webProxy) message(s *webProxySocket, direction string, opcode int, body []byte, accepted bool) error {
	d := p.Driver
	if d.observe == nil {
		return nil
	}
	encoded := string(body)
	encoding := "utf-8"
	if opcode == websocket.BinaryMessage || !utf8.Valid(body) {
		encoded = base64.StdEncoding.EncodeToString(body)
		encoding = "base64"
	}
	example := webanalysis.RequestExample{ResourceType: "websocket", URL: s.URL, Method: "GET", Role: d.role, Status: 101, Body: encoded, SocketID: webanalysis.ID(p.ID, s.ID), Sequence: int(s.Sequence.Add(1)), Direction: direction, Opcode: opcode, Encoding: encoding, Denied: !accepted}
	artifact := webanalysis.Artifact{Kind: "websocket-message", URL: s.URL, FinalURL: s.URL, Role: d.role, Complete: accepted}
	if !accepted {
		artifact.Gap = "WebSocket message not sent"
		example.Status = 0
	}
	return d.observe(webObservation{Artifact: artifact, Body: body, Request: example})
}
func (p *webProxy) settle(ctx context.Context) {
	start := time.Now()
	p.Activity.Store(start.UnixNano())
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Since(start) > 2*time.Second || time.Since(start) > time.Second && time.Since(time.Unix(0, p.Activity.Load())) > 250*time.Millisecond {
				return
			}
		}
	}
}
func (p *webProxy) Close() {
	p.mu.Lock()
	for _, s := range p.Sockets {
		s.Conn.Close()
	}
	p.mu.Unlock()
	p.Cancel()
	_ = p.Input.Close()
	_ = p.Cmd.Wait()
	<-p.done
	p.wg.Wait()
}
