package webacquire

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const MaxBody = 4 << 20
const MaxTotal = 64 << 20
const MaxRequests = 500

var ErrLimit = errors.New("web acquisition limit exhausted")

type Request struct {
	Method, URL string
	Headers     http.Header
	Body        []byte
}
type Response struct {
	URL      string      `json:"url"`
	FinalURL string      `json:"final_url"`
	Status   int         `json:"status"`
	Headers  http.Header `json:"headers"`
	Body     []byte      `json:"-"`
	Complete bool        `json:"complete"`
	Gap      string      `json:"gap,omitempty"`
}
type Policy struct {
	Authorize func(context.Context, Request) error
	IPAllowed func(net.IP) bool
	Resolve   func(context.Context, string) ([]net.IP, error)
}
type Broker struct {
	Policy                     Policy
	mu                         sync.Mutex
	requests, bytes, wireBytes int
}

func (b *Broker) Usage() (int, int) { b.mu.Lock(); defer b.mu.Unlock(); return b.requests, b.bytes }
func (b *Broker) claim(n int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.requests >= MaxRequests || b.bytes >= MaxTotal || b.wireBytes+n > MaxTotal {
		return ErrLimit
	}
	b.requests++
	b.wireBytes += n
	return nil
}
func (b *Broker) account(n int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.bytes+n > MaxTotal {
		return ErrLimit
	}
	b.bytes += n
	return nil
}

type wireReader struct {
	broker *Broker
	reader io.Reader
}

func (b *Broker) reserveWire(n int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if remaining := MaxTotal - b.wireBytes; n > remaining {
		n = remaining
	}
	b.wireBytes += n
	return n
}
func (b *Broker) refundWire(n int) { b.mu.Lock(); b.wireBytes -= n; b.mu.Unlock() }
func (b *Broker) readWire(reader io.Reader, p []byte) (int, error) {
	reserved := b.reserveWire(len(p))
	if reserved <= 0 {
		return 0, ErrLimit
	}
	n, err := reader.Read(p[:reserved])
	b.refundWire(reserved - n)
	return n, err
}
func (r wireReader) Read(p []byte) (int, error) { return r.broker.readWire(r.reader, p) }
func validateHeaders(h http.Header) error {
	if len(h) > 100 {
		return ErrLimit
	}
	size := 0
	for k, vs := range h {
		size += len(k)
		for _, v := range vs {
			size += len(v)
			if strings.ContainsAny(k+v, "\r\n\x00") {
				return errors.New("invalid request header")
			}
		}
	}
	if size > 64<<10 {
		return ErrLimit
	}
	return nil
}

func URL(raw string) (*url.URL, error) {
	if len(raw) > 8192 || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errors.New("invalid web URL")
	}
	u, e := url.Parse(raw)
	if e != nil || u == nil || u.User != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("absolute HTTP URL without userinfo required")
	}
	if strings.ContainsAny(u.Hostname(), " \\%/") {
		return nil, errors.New("invalid URL host")
	}
	return u, nil
}
func Passive(method string) bool { return method == "GET" || method == "HEAD" || method == "OPTIONS" }
func (b *Broker) Fetch(ctx context.Context, r Request) (Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if r.Method == "" {
		r.Method = "GET"
	}
	r.Method = strings.ToUpper(r.Method)
	if len(r.Body) > 1<<20 {
		return Response{}, ErrLimit
	}
	origin := r.URL
	for hop := 0; hop <= 10; hop++ {
		out, err := b.Once(ctx, r)
		if err != nil {
			return out, err
		}
		if out.Status == 429 && Passive(r.Method) {
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return out, ctx.Err()
			case <-timer.C:
			}
			out, err = b.Once(ctx, r)
			if err != nil {
				return out, err
			}
		}
		out.URL = origin
		loc := out.Headers.Get("Location")
		if out.Status < 300 || out.Status >= 400 || loc == "" || !Passive(r.Method) {
			return out, nil
		}
		old, _ := URL(r.URL)
		ref, e := url.Parse(loc)
		if e != nil {
			return out, errors.New("invalid redirect")
		}
		next := old.ResolveReference(ref)
		if _, e = URL(next.String()); e != nil {
			return out, e
		}
		if old.Scheme != next.Scheme || !strings.EqualFold(old.Host, next.Host) {
			r.Headers = nil
			r.Body = nil
		}
		r.URL = next.String()
	}
	return Response{}, errors.New("redirect limit exhausted")
}
func (b *Broker) Once(ctx context.Context, r Request) (Response, error) {
	out := Response{URL: r.URL, FinalURL: r.URL}
	if r.Method == "" {
		r.Method = "GET"
	}
	r.Method = strings.ToUpper(r.Method)
	if len(r.Body) > 1<<20 || len(r.Headers) > 100 {
		return out, ErrLimit
	}
	if err := validateHeaders(r.Headers); err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	u, err := URL(r.URL)
	if err != nil {
		return out, err
	}
	if b.Policy.Authorize == nil || b.Policy.IPAllowed == nil {
		return out, errors.New("web request policy missing")
	}
	if err = b.Policy.Authorize(ctx, r); err != nil {
		return out, err
	}
	if err = b.claim(len(r.Body)); err != nil {
		return out, err
	}
	resolver := b.Policy.Resolve
	if resolver == nil {
		resolver = func(ctx context.Context, h string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", h)
		}
	}
	ips, err := resolver(ctx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return out, errors.New("web destination resolution failed")
	}
	for _, ip := range ips {
		if !b.Policy.IPAllowed(ip) {
			return out, errors.New("web destination resolves outside scope")
		}
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	pinned := net.JoinHostPort(ips[0].String(), port)
	tr := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, pinned)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, bytes.NewReader(r.Body))
	if err != nil {
		return out, errors.New("invalid HTTP request")
	}
	req.Header = r.Headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	for _, name := range []string{"Host", "Content-Length", "Transfer-Encoding", "Connection", "Proxy-Authorization", "Proxy-Connection", "Upgrade"} {
		req.Header.Del(name)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := client.Do(req)
	if err != nil {
		return out, errors.New("web transfer failed")
	}
	defer resp.Body.Close()
	out.Status = resp.StatusCode
	out.Headers = resp.Header.Clone()
	wire, err := io.ReadAll(io.LimitReader(wireReader{broker: b, reader: resp.Body}, MaxBody+1))
	if err != nil {
		out.Gap = "transfer interrupted"
		return out, err
	}
	if len(wire) > MaxBody {
		out.Gap = "compressed transfer exceeds limit"
		return out, ErrLimit
	}
	data := wire
	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "", "identity":
	case "gzip":
		z, e := gzip.NewReader(bytes.NewReader(wire))
		if e != nil {
			out.Gap = "invalid gzip response"
			return out, e
		}
		data, err = io.ReadAll(io.LimitReader(z, MaxBody+1))
		_ = z.Close()
		if err != nil {
			out.Gap = "decompression failed"
			return out, err
		}
	default:
		out.Gap = "unsupported content encoding"
		return out, errors.New(out.Gap)
	}
	if len(data) > MaxBody {
		out.Gap = "decompressed body exceeds limit"
		return out, ErrLimit
	}
	if err = b.account(len(data)); err != nil {
		out.Gap = "aggregate byte limit"
		return out, err
	}
	out.Body = data
	out.Complete = true
	out.Headers.Del("Content-Encoding")
	out.Headers.Del("Transfer-Encoding")
	out.Headers.Set("Content-Length", fmt.Sprint(len(data)))
	return out, nil
}
