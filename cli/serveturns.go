package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// serveturns.go holds the two turn endpoints of `blk serve`: one that answers
// with the whole turn as JSON and one that streams it as Server-Sent Events.
// Both run the runNativeTurn the command line, the plain REPL, the TUI and the
// MCP server run, so this transport adds a way in and not a second agent.
//
// A turn always continues a session this server created, so both routes hang
// off one session's path and the collection route is the only way to open one.

// The two turn routes, as suffixes of a session's path.
const (
	serveTurnsSuffix       = "/turns"
	serveTurnsStreamSuffix = "/turns/stream"
)

// serveTurnIn is a turn's request body. It mirrors mcpChatIn's field set so the
// two transports accept the same turn, without the session id, which this
// transport takes from the path.
type serveTurnIn struct {
	Message    string `json:"message"`
	Agent      string `json:"agent,omitempty"`
	ToolHost   string `json:"tool_host,omitempty"`
	BrowserCDP string `json:"browser_cdp,omitempty"`
	ForceRag   bool   `json:"force_rag,omitempty"`
	WebOnly    bool   `json:"web_only,omitempty"`
}

// errServeNoBody refuses a turn that carries no body. requireJSONBody returns
// early at ContentLength == 0, so a bodiless POST passes the content-type
// defense entirely; without this it would run a turn with an empty message.
var errServeNoBody = errors.New("a turn requires an application/json body")

// errServeBadBody marks a body that does not decode as a turn.
var errServeBadBody = errors.New("the request body is not a turn")

// callerVantage reports the vantage of one request. A caller is local only when
// it reached a loopback-bound server from a loopback peer: on a wide bind the
// Host control does not run, and a loopback peer there is produced by any
// tunnel, published container port or local proxy, so the peer address proves
// nothing about who originated the request. The bind's rule is read from the
// field computed once in newServeServer, so this can never be laxer than the
// exposure that was opened.
func (s *serveServer) callerVantage(r *http.Request) clientVantage {
	if s.hostMode != serveHostLoopback {
		return vantageRemote
	}
	return vantageForRemoteAddr(r.RemoteAddr)
}

// serveTurnSessionID extracts the session id from a turn path by removing the
// route's suffix and validating what is left. The id comes from the caller, so
// it reaches no file path without passing serveSessionIDFromPath.
func serveTurnSessionID(p, suffix string) (string, error) {
	base, ok := strings.CutSuffix(p, suffix)
	if !ok {
		return "", fmt.Errorf("%w: not a turn path", errServeBadSessionID)
	}
	return serveSessionIDFromPath(base)
}

// serveTurnGate validates and gates one turn request, returning the session to
// continue and the decoded body. Both routes share it, and every refusal it
// makes happens before a turn runs. The order mirrors mcpChatResult's, so the
// two transports refuse the same request for the same reason.
func (s *serveServer) serveTurnGate(r *http.Request, suffix string) (string, serveTurnIn, error) {
	var in serveTurnIn
	id, err := serveTurnSessionID(r.URL.Path, suffix)
	if err != nil {
		return "", in, err
	}
	if !s.owned.touch(id) {
		return "", in, errChatForeignSession
	}
	if r.ContentLength == 0 {
		return "", in, errServeNoBody
	}
	// The body is read through r.Body as the guard chain installed it, so the
	// MaxBytesReader's bound still applies. A chunked body declares no length,
	// so its refusal arrives here as *http.MaxBytesError instead of as the
	// chain's pre-handler 413, and serveTurnRefusal maps both to 413.
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.Is(err, io.EOF):
			return "", in, errServeNoBody
		case errors.As(err, &tooLarge):
			return "", in, err
		default:
			return "", in, errServeBadBody
		}
	}
	// A loopback peer is not by itself proof of a local process: a page in the
	// operator's browser reaches loopback, and so does a local reverse proxy.
	// What makes vantageLocal honest here is that the three browser defenses
	// ran in the guard chain before any handler, so a request that reaches this
	// line has already passed all three. That composition is the control, which
	// makes the chain's order load-bearing rather than incidental.
	if err := checkChatVantage(s.callerVantage(r), in.ToolHost, in.BrowserCDP); err != nil {
		return "", in, err
	}
	if in.ForceRag && in.WebOnly {
		return "", in, usageErr("turn: web_only cannot be combined with force_rag")
	}
	if len(in.Message) > mcpChatMaxMessage {
		return "", in, usageErr("turn: message exceeds %d bytes", mcpChatMaxMessage)
	}
	return id, in, nil
}

// serveRunTurn runs one gated turn under cfg.RequestTimeout, the same bound the
// three local surfaces and the MCP server use, and records ownership of the
// session the turn returns.
func (s *serveServer) serveRunTurn(ctx context.Context, id string, in serveTurnIn, stream func([]byte), action func(tool, status string)) (turnResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout())
	defer cancel()
	res, err := runNativeTurn(ctx, s.rc, s.cfg, turnRequest{
		Question:   in.Message,
		SessionID:  id,
		Agent:      in.Agent,
		ToolHost:   in.ToolHost,
		BrowserCDP: in.BrowserCDP,
		ForceRag:   in.ForceRag,
		WebOnly:    in.WebOnly,
		Stream:     stream,
		Action:     action,
	})
	s.owned.own(res.SessionID)
	return res, timeoutOrErr(err)
}

// serveTurnRefusal maps one gate or turn error to a status and a message. The
// message is chosen here rather than taken from the error, except for a usage
// error, whose text this code writes from a format string and which is
// sanitized before it is reflected.
func serveTurnRefusal(err error) (int, string) {
	var tooLarge *http.MaxBytesError
	var ue *usageError
	switch {
	case errors.Is(err, errServeBadSessionID):
		return http.StatusBadRequest, "invalid session id"
	case errors.Is(err, errChatForeignSession):
		return http.StatusForbidden, "this session was not created by this server"
	case errors.Is(err, errServeNoBody):
		return http.StatusUnsupportedMediaType, "a turn requires an application/json body"
	case errors.As(err, &tooLarge):
		return http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", serveMaxBody)
	case errors.Is(err, errServeBadBody):
		return http.StatusBadRequest, "the request body is not a turn"
	case errors.Is(err, errChatLocalHostRefused), errors.Is(err, errChatBrowserCDPRefused):
		return http.StatusForbidden, "this option is available only to a local caller"
	case errors.Is(err, errSessionNotFound):
		return http.StatusNotFound, "session not found"
	case errors.Is(err, errRequestTimeout):
		return http.StatusGatewayTimeout, errRequestTimeout.Error()
	case errors.As(err, &ue):
		return http.StatusBadRequest, sanitizeTerminal(ue.Error())
	default:
		return http.StatusInternalServerError, "the turn could not be run"
	}
}

// handleTurn runs one turn and answers with the whole result, the fields blk
// ask --json reports. A turn that produced an answer and still did not finish
// cleanly carries both, as the MCP chat tool reports the same condition.
func (s *serveServer) handleTurn(w http.ResponseWriter, r *http.Request) {
	id, in, err := s.serveTurnGate(r, serveTurnsSuffix)
	if err != nil {
		code, msg := serveTurnRefusal(err)
		serveRefuse(w, code, msg)
		return
	}
	res, err := s.serveRunTurn(r.Context(), id, in, nil, nil)
	if err != nil && strings.TrimSpace(res.Answer) == "" {
		code, msg := serveTurnRefusal(err)
		serveRefuse(w, code, msg)
		return
	}
	out := mcpChatOut{turnResult: res}
	if err != nil {
		out.Error = sanitizeTerminal(err.Error())
	}
	serveWriteJSON(w, http.StatusOK, out)
}

// handleTurnStream runs one turn and streams it as Server-Sent Events. The
// event names and payload keys are the ones blk's own gateway client parsed, so
// a client written against that gateway reads this server unchanged.
//
// The status is written before the turn starts, so a turn that fails after the
// first byte reports run.failed inside the stream rather than as a status.
func (s *serveServer) handleTurnStream(w http.ResponseWriter, r *http.Request) {
	id, in, err := s.serveTurnGate(r, serveTurnsStreamSuffix)
	if err != nil {
		code, msg := serveTurnRefusal(err)
		serveRefuse(w, code, msg)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	ctl := http.NewResponseController(w)
	_ = ctl.Flush()

	// The turn's callbacks run inside runNativeTurn on this goroutine, so one
	// event is written at a time. A write that fails is dropped: the turn is
	// bounded by its own deadline and the request context ends the stream.
	emit := func(name string, payload any) {
		if serveSSEEvent(w, name, payload) == nil {
			_ = ctl.Flush()
		}
	}
	res, err := s.serveRunTurn(r.Context(), id, in,
		func(chunk []byte) {
			if len(chunk) > 0 {
				emit("assistant.delta", map[string]string{"delta": string(chunk)})
			}
		},
		func(tool, status string) {
			if status == "running" {
				emit("tool.started", map[string]string{"tool": tool})
				return
			}
			payload := map[string]string{"tool": tool}
			if status == string(ToolFailed) {
				payload["error"] = "the tool call failed"
			}
			emit("tool.completed", payload)
		})
	if err != nil {
		emit("run.failed", map[string]string{"error": sanitizeTerminal(err.Error())})
		return
	}
	emit("run.completed", map[string]any{
		"usage": map[string]int{"completion_tokens": res.Usage.CompletionTokens},
	})
}

// serveSSEEvent writes one Server-Sent Event. The payload is JSON-encoded,
// which is what keeps a newline inside a value from ending the data line and
// splitting one event into two.
func serveSSEEvent(w io.Writer, name string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, body)
	return err
}
