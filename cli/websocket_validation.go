package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"blkchain/cli/internal/webacquire"
	"blkchain/cli/internal/webanalysis"
	"blkchain/cli/internal/webcollect"
)

type webSocketFrame struct {
	Opcode   int    `json:"opcode"`
	Body     string `json:"body"`
	Encoding string `json:"encoding,omitempty"`
}
type webSocketStep struct {
	Send   *webSocketFrame `json:"send,omitempty"`
	Expect *webSocketFrame `json:"expect,omitempty"`
}
type webSocketPlan struct {
	Adapter   string          `json:"adapter"`
	Protocols []string        `json:"protocols,omitempty"`
	Steps     []webSocketStep `json:"steps"`
}

func webSocketFrameBytes(f webSocketFrame) ([]byte, error) {
	body := []byte(f.Body)
	if f.Encoding == "base64" {
		var err error
		body, err = base64.StdEncoding.Strict().DecodeString(f.Body)
		if err != nil {
			return nil, errors.New("invalid WebSocket frame encoding")
		}
	} else if f.Encoding != "" {
		return nil, errors.New("unsupported WebSocket frame encoding")
	}
	if f.Opcode != 1 && f.Opcode != 2 || len(body) > webacquire.MaxWSMessage || f.Opcode == 1 && !utf8.Valid(body) {
		return nil, errors.New("invalid WebSocket frame or message limit")
	}
	return body, nil
}

func webSocketDecodePlan(data []byte) (webSocketPlan, error) {
	var plan webSocketPlan
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&plan); err != nil || plan.Adapter != "exact-message" || len(plan.Steps) < 2 || len(plan.Steps) > 20 || len(plan.Protocols) > 20 {
		return plan, errors.New("WebSocket validation requires a bounded exact-message transcript")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return plan, errors.New("invalid WebSocket transcript trailing data")
	}
	sent, expected, total := false, false, 0
	for _, step := range plan.Steps {
		if (step.Send == nil) == (step.Expect == nil) {
			return plan, errors.New("each WebSocket step requires send or expect")
		}
		frame := step.Send
		if frame == nil {
			frame = step.Expect
			if !sent {
				return plan, errors.New("WebSocket expectation requires a preceding send")
			}
			expected = true
		} else {
			sent = true
		}
		body, err := webSocketFrameBytes(*frame)
		if err != nil {
			return plan, err
		}
		total += len(body)
	}
	if !sent || !expected || total > 1<<20 {
		return plan, errors.New("WebSocket exchange or transcript byte limit")
	}
	for _, protocol := range plan.Protocols {
		if protocol == "" || len(protocol) > 128 || strings.ContainsAny(protocol, " \r\n\x00,;") {
			return plan, errors.New("invalid WebSocket subprotocol")
		}
	}
	return plan, nil
}

func webValidateSocket(ctx context.Context, svc *webcollect.Service, op webanalysis.Operation, role webSessionRole, headers http.Header, plan webSocketPlan, task string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw := op.Origin + op.Path
	if op.Query != "" {
		raw += "?" + op.Query
	}
	_, target, err := webacquire.WebSocketURL(raw)
	if err != nil || strings.ContainsAny(raw, "{}") {
		return errors.New("WebSocket URL requires supplied runtime values")
	}
	if role.Origin != "" && !webSameOrigin(target, role.Origin) {
		return errors.New("WebSocket origin differs from session")
	}
	u, _ := url.Parse(raw)
	for k := range u.Query() {
		if webanalysis.Sensitive(k) {
			return errors.New("WebSocket URL requires credential refresh")
		}
	}
	conn, out, err := svc.Broker.OpenWebSocket(ctx, raw, headers, plan.Protocols)
	socketID := webanalysis.ID(op.ID, webanalysis.Now(), role.Name)
	record := func(kind string, body []byte, e webanalysis.RequestExample) (string, error) {
		saveCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		a, err := svc.Accept(saveCtx, webanalysis.Artifact{Kind: kind, URL: raw, Role: role.Name, Status: e.Status, Complete: !e.Denied}, body, 0)
		if err != nil {
			return "", err
		}
		e.Artifact = a.ID
		if err = svc.Observe(saveCtx, e); err != nil {
			return "", err
		}
		return a.ID, nil
	}
	_, saveErr := record("websocket-handshake", out.Body, webanalysis.RequestExample{ResourceType: "websocket", URL: raw, Method: "GET", Headers: headers, Role: role.Name, Status: out.Status, SocketID: socketID, Subprotocol: out.Headers.Get("Sec-WebSocket-Protocol"), Denied: err != nil})
	if saveErr != nil {
		if conn != nil {
			conn.Close()
		}
		return saveErr
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	if len(plan.Protocols) > 0 {
		selected := conn.Conn.Subprotocol()
		found := false
		for _, p := range plan.Protocols {
			found = found || p == selected
		}
		if !found {
			return errors.New("WebSocket subprotocol was not negotiated")
		}
	}
	artifacts := []string{}
	for i, step := range plan.Steps {
		frame := step.Send
		direction := "sent"
		var body []byte
		opcode := 0
		if frame != nil {
			body, _ = webSocketFrameBytes(*frame)
			opcode = frame.Opcode
			err = conn.Send(ctx, opcode, body)
		} else {
			direction = "received"
			_ = conn.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			opcode, body, err = conn.Receive()
		}
		example := webanalysis.RequestExample{ResourceType: "websocket", URL: raw, Method: "GET", Role: role.Name, Status: 101, SocketID: socketID, Sequence: i + 1, Direction: direction, Opcode: opcode, Denied: err != nil}
		example.Body = string(body)
		if opcode == 2 || !utf8.Valid(body) {
			example.Body = base64.StdEncoding.EncodeToString(body)
			example.Encoding = "base64"
		}
		id, saveErr := record("websocket-message", body, example)
		if saveErr != nil {
			return saveErr
		}
		if err != nil {
			return errors.New("WebSocket message exchange interrupted or denied")
		}
		if step.Expect != nil {
			expected, _ := webSocketFrameBytes(*step.Expect)
			if opcode != step.Expect.Opcode || !bytes.Equal(body, expected) {
				return errors.New("WebSocket application response did not match supplied expectation")
			}
		}
		artifacts = append(artifacts, id)
	}
	op.Validation = "application-exchange-validated"
	op.Exchange = &webanalysis.ExchangeValidation{Adapter: plan.Adapter, Role: role.Name, At: webanalysis.Now(), Artifacts: artifacts}
	return svc.Store.PutWeb(ctx, "operation", op.ID, task, op)
}

func webReplaySocket(ctx context.Context, svc *webcollect.Service, op webanalysis.Operation, o webOpts) (err error) {
	defer func() {
		if err != nil {
			if e := svc.RecordGap(ctx, o.role, "websocket", op.Origin+op.Path, err.Error()); e != nil {
				err = e
			}
		}
	}()
	if o.values == "" || o.example != 0 {
		return errors.New("WebSocket replay requires --values with an application message transcript")
	}
	data, err := webReadFile(o.values, 1<<20)
	if err != nil {
		return err
	}
	plan, err := webSocketDecodePlan(data)
	if err != nil {
		return err
	}
	roles, err := webLoadSessions(o.session)
	if err != nil {
		return err
	}
	role := roles[0]
	if o.role != "" {
		found := false
		for _, r := range roles {
			if r.Name == o.role {
				role = r
				found = true
			}
		}
		if !found {
			return errors.New("WebSocket replay role missing")
		}
	}
	if len(role.Storage) > 0 || role.Login != nil {
		return errors.New("WebSocket replay requires refreshed header or cookie credentials; browser state cannot be inferred")
	}
	headers, err := webRoleHeaders(role)
	if err != nil {
		return err
	}
	return webValidateSocket(ctx, svc, op, role, headers, plan, o.task)
}
