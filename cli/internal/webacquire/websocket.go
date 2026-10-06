package webacquire

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const MaxWSMessage = 256 << 10
const MaxWSMessages = 250

func WebSocketURL(raw string) (*url.URL, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, "", errors.New("absolute WebSocket URL required")
	}
	h := *u
	h.Scheme = "http"
	if u.Scheme == "wss" {
		h.Scheme = "https"
	}
	if _, err = URL(h.String()); err != nil || u.Fragment != "" {
		return nil, "", errors.New("invalid WebSocket URL")
	}
	return u, h.String(), nil
}

type WebSocket struct {
	Conn    *websocket.Conn
	broker  *Broker
	request Request
	stop    func() bool
	count   atomic.Int64
}

type socketConn struct {
	net.Conn
	broker      *Broker
	headerBytes int
	headers     atomic.Bool
}

func (c *socketConn) Read(p []byte) (int, error) {
	if !c.headers.Load() {
		if c.headerBytes >= 64<<10 {
			return 0, ErrLimit
		}
		if len(p) > (64<<10)-c.headerBytes {
			p = p[:(64<<10)-c.headerBytes]
		}
	}
	n, err := c.broker.readWire(c.Conn, p)
	if !c.headers.Load() {
		c.headerBytes += n
	}
	return n, err
}

func (c *socketConn) Write(p []byte) (int, error) {
	reserved := c.broker.reserveWire(len(p))
	if reserved != len(p) {
		c.broker.refundWire(reserved)
		return 0, ErrLimit
	}
	n, err := c.Conn.Write(p)
	c.broker.refundWire(reserved - n)
	return n, err
}

func (b *Broker) OpenWebSocket(ctx context.Context, raw string, headers http.Header, protocols []string) (*WebSocket, Response, error) {
	out := Response{URL: raw, FinalURL: raw}
	u, target, err := WebSocketURL(raw)
	if err != nil {
		return nil, out, err
	}
	r := Request{URL: target, Method: "GET", Headers: headers.Clone()}
	if err = validateHeaders(r.Headers); err != nil {
		return nil, out, err
	}
	if b.Policy.Authorize == nil || b.Policy.IPAllowed == nil {
		return nil, out, errors.New("web request policy missing")
	}
	if err = b.Policy.Authorize(ctx, r); err != nil {
		return nil, out, err
	}
	if err = b.claim(0); err != nil {
		return nil, out, err
	}
	resolve := b.Policy.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	ips, err := resolve(ctx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return nil, out, errors.New("web destination resolution failed")
	}
	for _, ip := range ips {
		if !b.Policy.IPAllowed(ip) {
			return nil, out, errors.New("web destination resolves outside scope")
		}
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "wss" {
			port = "443"
		}
	}
	pinned := net.JoinHostPort(ips[0].String(), port)
	h := headers.Clone()
	if h == nil {
		h = http.Header{}
	}
	for _, k := range []string{"Connection", "Upgrade", "Host", "Content-Length", "Transfer-Encoding", "Proxy-Authorization", "Proxy-Connection", "Sec-Websocket-Key", "Sec-Websocket-Version", "Sec-Websocket-Extensions", "Sec-Websocket-Protocol"} {
		h.Del(k)
	}
	if len(protocols) > 20 {
		return nil, out, ErrLimit
	}
	for _, p := range protocols {
		if p == "" || len(p) > 128 || strings.ContainsAny(p, " \r\n\x00,;") {
			return nil, out, errors.New("invalid WebSocket subprotocol")
		}
	}
	var counted *socketConn
	wrap := func(c net.Conn) net.Conn { counted = &socketConn{Conn: c, broker: b}; return counted }
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second, ReadBufferSize: 4096, WriteBufferSize: 4096, Subprotocols: protocols,
		NetDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			c, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, pinned)
			if e != nil {
				return nil, e
			}
			return wrap(c), nil
		},
		NetDialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}}
			c, e := d.DialContext(ctx, network, pinned)
			if e != nil {
				return nil, e
			}
			return wrap(c), nil
		},
	}
	conn, resp, err := dialer.DialContext(ctx, raw, h)
	if resp != nil {
		out.Status = resp.StatusCode
		out.Headers = resp.Header.Clone()
	}
	if err != nil {
		if resp != nil && resp.Body != nil {
			out.Body, _ = io.ReadAll(io.LimitReader(resp.Body, int64(b.bodyLimit())))
			_ = resp.Body.Close()
			if accountErr := b.account(len(out.Body)); accountErr != nil {
				return nil, out, accountErr
			}
		}
		out.Gap = "WebSocket handshake failed or denied"
		return nil, out, errors.New(out.Gap)
	}
	counted.headers.Store(true)
	messageLimit := MaxWSMessage
	if b.bodyLimit() < messageLimit {
		messageLimit = b.bodyLimit()
	}
	conn.SetReadLimit(int64(messageLimit))
	out.Complete = true
	s := &WebSocket{Conn: conn, broker: b, request: r}
	s.stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
	return s, out, nil
}

func (s *WebSocket) Send(ctx context.Context, kind int, data []byte) error {
	messageLimit := MaxWSMessage
	if s.broker.bodyLimit() < messageLimit {
		messageLimit = s.broker.bodyLimit()
	}
	if len(data) > messageLimit || s.count.Add(1) > MaxWSMessages {
		return ErrLimit
	}
	if kind != websocket.TextMessage && kind != websocket.BinaryMessage {
		return errors.New("unsupported WebSocket message")
	}
	r := s.request
	r.Method = "WEBSOCKET"
	r.Body = data
	if err := s.broker.Policy.Authorize(ctx, r); err != nil {
		return err
	}
	if err := s.broker.claim(0); err != nil {
		return err
	}
	if err := s.broker.account(len(data)); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = s.Conn.SetWriteDeadline(deadline)
	return s.Conn.WriteMessage(kind, data)
}

func (s *WebSocket) Receive() (int, []byte, error) {
	kind, data, err := s.Conn.ReadMessage()
	if err != nil {
		return kind, nil, err
	}
	if s.count.Add(1) > MaxWSMessages {
		return kind, nil, ErrLimit
	}
	if err = s.broker.account(len(data)); err != nil {
		return kind, nil, err
	}
	return kind, data, nil
}

func (s *WebSocket) Close() {
	if s.stop != nil {
		s.stop()
	}
	_ = s.Conn.Close()
}
