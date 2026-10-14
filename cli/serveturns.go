package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"blkchain/cli/internal/retrieval"
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
// continue, the decoded body and the release of the turn's admission slot. Both
// routes share it, and every refusal it makes happens before a turn runs, which
// is what lets the stream route answer a refusal as a status rather than as an
// event inside a 200.
//
// The slot is taken here, and handed back as a value every caller has to
// receive, so no route runs a turn outside the bound by omission: the compiler
// requires the receive, and a release that is received and dropped holds the
// slot instead of leaving the turn unbounded. The acquisition is last, after
// every validation, so a refused request takes no slot, and on any error the
// release is nil.
//
// The order is not mcpChatResult's: ownership is checked before the vantage
// gate here and after it there, so a request that is both a foreign session and
// an operator-reach request from a remote peer is refused for a different
// reason on each transport. Both refuse it, and the transport forces the
// difference, because this one knows the session from the path before it has
// read a body at all.
func (s *serveServer) serveTurnGate(r *http.Request, suffix string) (string, serveTurnIn, func(), error) {
	var in serveTurnIn
	id, err := serveTurnSessionID(r.URL.Path, suffix)
	if err != nil {
		return "", in, nil, err
	}
	if !s.owned.touch(id) {
		return "", in, nil, errChatForeignSession
	}
	if r.ContentLength == 0 {
		return "", in, nil, errServeNoBody
	}
	// The body is read through r.Body as the guard chain installed it, so the
	// MaxBytesReader's bound still applies. A chunked body declares no length,
	// so its refusal arrives here as *http.MaxBytesError instead of as the
	// chain's pre-handler 413, and serveTurnRefusal maps both to 413.
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.Is(err, io.EOF):
			return "", in, nil, errServeNoBody
		case errors.As(err, &tooLarge):
			return "", in, nil, err
		default:
			return "", in, nil, errServeBadBody
		}
	}
	// A loopback peer is not by itself proof of a local process: a page in the
	// operator's browser reaches loopback, and so does a local reverse proxy.
	// What makes vantageLocal honest here is that the three browser defenses
	// ran in the guard chain before any handler, so a request that reaches this
	// line has already passed all three. That composition is the control, which
	// makes the chain's order load-bearing rather than incidental.
	if err := checkChatVantage(s.callerVantage(r), in.ToolHost, in.BrowserCDP); err != nil {
		return "", in, nil, err
	}
	if in.ForceRag && in.WebOnly {
		return "", in, nil, usageErr("turn: web_only cannot be combined with force_rag")
	}
	// An empty message is refused here rather than inside the turn, which raises
	// its own missing-question error after the stream route has already sent its
	// headers. The wording is runNativeTurn's, so the same bad request answers
	// 400 with one message on both routes.
	if strings.TrimSpace(in.Message) == "" {
		return "", in, nil, usageErr("turn: missing question")
	}
	if len(in.Message) > mcpChatMaxMessage {
		return "", in, nil, usageErr("turn: message exceeds %d bytes", mcpChatMaxMessage)
	}
	release, err := s.turns.acquire(id)
	if err != nil {
		return "", in, nil, err
	}
	return id, in, release, nil
}

// serveTurnClient is the retrieval client for one turn: the server's client
// with the saved reranker switch applied, as every other turn surface applies
// it per call, so a /models change reaches a running server without a restart.
// A server built without a client has none to copy.
func (s *serveServer) serveTurnClient() *retrieval.Client {
	if s.rc == nil {
		return nil
	}
	return followPrefs(s.rc, loadPrefs())
}

// serveRunTurn runs one gated turn under cfg.RequestTimeout, the same bound the
// three local surfaces and the MCP server use, and records ownership of the
// session the turn returns.
func (s *serveServer) serveRunTurn(ctx context.Context, id string, in serveTurnIn, v clientVantage, stream func([]byte), action func(tool, status string)) (turnResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout())
	defer cancel()
	res, err := runNativeTurn(ctx, s.serveTurnClient(), s.cfg, turnRequest{
		Question:   in.Message,
		SessionID:  id,
		Agent:      in.Agent,
		ToolHost:   in.ToolHost,
		BrowserCDP: in.BrowserCDP,
		ForceRag:   in.ForceRag,
		WebOnly:    in.WebOnly,
		Stream:     stream,
		Action:     action,
		Vantage:    v,
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
	case errors.Is(err, errServeTurnInFlight):
		return http.StatusConflict, "a turn is already in flight on this session"
	case errors.Is(err, errServeBusy):
		return http.StatusServiceUnavailable, fmt.Sprintf("%d turns are already in flight; retry when one finishes", serveMaxConcurrentTurns)
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
	id, in, release, err := s.serveTurnGate(r, serveTurnsSuffix)
	if err != nil {
		code, msg := serveTurnRefusal(err)
		serveRefuse(w, code, msg)
		return
	}
	defer release()
	res, err := s.serveRunTurn(r.Context(), id, in, s.callerVantage(r), nil, nil)
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

// handleTurnStream runs one turn and streams it as Server-Sent Events:
// tool.started and tool.completed around each tool call, assistant.delta per
// answer fragment, and one terminal run.completed or run.failed.
//
// The status is written before the turn starts, so a turn that fails after the
// first byte reports run.failed inside the stream rather than as a status. Every
// refusal the gate and the turn bound make therefore happens before the headers
// go out, and a panic past them still ends the stream on a terminal event.
func (s *serveServer) handleTurnStream(w http.ResponseWriter, r *http.Request) {
	id, in, release, err := s.serveTurnGate(r, serveTurnsStreamSuffix)
	if err != nil {
		code, msg := serveTurnRefusal(err)
		serveRefuse(w, code, msg)
		return
	}
	defer release()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	ctl := http.NewResponseController(w)
	_ = ctl.Flush()

	// The turn's callbacks run inside runNativeTurn on this goroutine, so one
	// event is written at a time. A write that fails is dropped: the turn is
	// bounded by its own deadline and the request context ends the stream.
	//
	// Reaching the byte cap ends the turn as well. Past the cap every event is
	// dropped, so a turn left running would spend the rest of its deadline
	// producing output nothing writes.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	st := &serveSSEStream{w: w, flush: ctl.Flush, onCap: cancel}

	// The status is already 200, so a panic would end a chunked body with no
	// terminal event, which a client cannot tell from a connection cut. The
	// stream says the turn did not finish, then the panic goes on unwinding so
	// net/http's own handling of it is unchanged. The release above is deferred
	// first, so it still runs.
	defer func() {
		if p := recover(); p != nil {
			st.emit("run.failed", map[string]string{"error": "the turn did not finish"})
			panic(p)
		}
	}()

	res, err := s.serveRunTurn(ctx, id, in, s.callerVantage(r),
		func(chunk []byte) {
			if len(chunk) > 0 {
				st.emit("assistant.delta", map[string]string{"delta": string(chunk)})
			}
		},
		func(tool, status string) {
			if status == "running" {
				st.emit("tool.started", map[string]string{"tool": tool})
				return
			}
			// A call that did not run to completion says so on the wire. Without
			// this a call the loop's own call cap skipped arrives with the key
			// set of a call that ran, which is a false success signal in the
			// event stream of a tool used to make findings. Only ToolDone omits
			// the key, so an outcome added later reads as not completed rather
			// than as a success.
			payload := map[string]string{"tool": tool}
			switch status {
			case string(ToolDone):
			case string(ToolFailed):
				payload["error"] = "the tool call failed"
			case string(ToolSkipped):
				payload["error"] = "the tool call was skipped: the call cap was reached"
			default:
				payload["error"] = "the tool call did not complete"
			}
			st.emit("tool.completed", payload)
		})
	if err != nil {
		st.emit("run.failed", map[string]string{"error": sanitizeTerminal(err.Error())})
		return
	}
	st.emit("run.completed", map[string]any{
		"usage": map[string]int{"completion_tokens": res.Usage.CompletionTokens},
	})
}

// serveMaxSSEBytes bounds one stream's bytes. A turn's deltas are model output,
// so nothing inside the turn bounds how much of it reaches the wire: one POST
// can hold a connection while the turn marshals and writes an event per delta
// for as long as its deadline allows. 32 MiB is past any answer a turn
// produces, which is why reaching it is reported as a failure and not as the
// end of an answer.
const serveMaxSSEBytes = 32 << 20

// serveSSECapError is the terminal event's message when a stream reaches
// serveMaxSSEBytes. A stream that stopped without it would read as a complete
// answer that happened to be short.
const serveSSECapError = "the stream reached its byte limit and was cut"

// serveSSECapFrame is that event's bytes, rendered once so the budget can
// reserve room for it and the total stays inside the cap.
var serveSSECapFrame = serveSSEFrame("run.failed", map[string]string{"error": serveSSECapError})

// serveSSEStream writes one bounded Server-Sent Events stream. written counts
// the framing as well as the payload, because the cap bounds what goes on the
// wire and not what the payloads happen to hold.
type serveSSEStream struct {
	w     io.Writer
	flush func() error
	// onCap, when set, is called once the cap has been reached, after the
	// terminal event is written. It ends the turn whose output the stream can no
	// longer carry.
	onCap   func()
	written int
	capped  bool
}

// emit writes one event. The event that would carry the total past the cap is
// not written: the stream ends on the terminal event instead and every later
// event is dropped, so a client is told the stream was cut rather than left to
// read a truncated answer as a whole one.
func (st *serveSSEStream) emit(name string, payload any) {
	if st.capped {
		return
	}
	frame := serveSSEFrame(name, payload)
	if frame == nil {
		return
	}
	if st.written+len(frame)+len(serveSSECapFrame) > serveMaxSSEBytes {
		st.capped = true
		st.write(serveSSECapFrame)
		if st.onCap != nil {
			st.onCap()
		}
		return
	}
	st.write(frame)
}

// write counts what the writer took, so a short write counts short.
func (st *serveSSEStream) write(frame []byte) {
	n, err := st.w.Write(frame)
	st.written += n
	if err == nil && st.flush != nil {
		_ = st.flush()
	}
}

// serveSSEFrame renders one event's bytes, or nil for a payload that does not
// encode.
func serveSSEFrame(name string, payload any) []byte {
	var b bytes.Buffer
	if err := serveSSEEvent(&b, name, payload); err != nil {
		return nil
	}
	return b.Bytes()
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
