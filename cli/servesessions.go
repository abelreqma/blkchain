package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// servesessions.go holds the session endpoints of `blk serve`.
//
// Reads are unrestricted and writes are not, as on the MCP transport: any
// session on disk can be listed and read, and only an id this server created,
// recorded in serveServer.owned by handleCreateSession, can be continued.

// serveSessionsPath is the collection route. A session is addressed as
// serveSessionsPath + "/" + id.
const serveSessionsPath = "/v1/sessions"

// errServeBadSessionID marks a session id that is not usable as an id: empty,
// over the length cap, a selector, or not a bare filename. It is distinct from
// errSessionNotFound, which names a well-formed id that matches no session.
var errServeBadSessionID = errors.New("invalid session id")

// serveSessionIDFromPath extracts the session id from a request path. The path
// comes from the caller, so the id is validated here and no handler builds a
// file path from an id that did not pass through this function.
//
// The selectors new and last are refused by name. last resolves to the
// operator's most recent session, so accepting it would let a caller attach to
// a conversation it never created.
func serveSessionIDFromPath(p string) (string, error) {
	id, ok := strings.CutPrefix(p, serveSessionsPath+"/")
	if !ok {
		return "", fmt.Errorf("%w: not a session path", errServeBadSessionID)
	}
	if len(id) > mcpChatMaxSessionID {
		return "", fmt.Errorf("%w: over %d bytes", errServeBadSessionID, mcpChatMaxSessionID)
	}
	if sel := strings.TrimSpace(id); sel == sessionTargetNew || sel == sessionTargetLast {
		return "", fmt.Errorf("%w: a selector is not an id", errServeBadSessionID)
	}
	if !validSessionID(id) {
		return "", fmt.Errorf("%w: not a bare filename", errServeBadSessionID)
	}
	return id, nil
}

// handleCreateSession starts a session and records it as one this server may
// continue. The transcript file is written on the first turn, so the session is
// listed immediately and reads with no turns until then.
func (s *serveServer) handleCreateSession(w http.ResponseWriter, _ *http.Request) {
	sess, err := newSession()
	if err == nil {
		err = sess.ensureListed()
	}
	if err != nil {
		serveRefuse(w, http.StatusInternalServerError, "the session could not be created")
		return
	}
	s.owned.own(sess.id)
	serveWriteJSON(w, http.StatusCreated, sess.meta())
}

// sessionReadsAllowed refuses a session read when no token is set. The session
// store holds every surface's conversations, and without a token any process on
// the machine, another local account's included, can call a loopback server.
// Once a token is set the guard chain has required it on every request.
func (s *serveServer) sessionReadsAllowed(w http.ResponseWriter) bool {
	if s.token != "" {
		return true
	}
	serveRefuse(w, http.StatusForbidden, "reading sessions requires "+serveTokenEnv+" to be set")
	return false
}

// handleListSessions lists sessions newest first, whichever surface created
// them, capped at sessionResourceListCap. truncated says the cap hid some.
func (s *serveServer) handleListSessions(w http.ResponseWriter, _ *http.Request) {
	if !s.sessionReadsAllowed(w) {
		return
	}
	metas, err := listSessions()
	if err != nil {
		serveRefuse(w, http.StatusInternalServerError, "the sessions could not be listed")
		return
	}
	truncated := len(metas) > sessionResourceListCap
	if truncated {
		metas = metas[:sessionResourceListCap]
	}
	if metas == nil {
		metas = []sessionMeta{}
	}
	serveWriteJSON(w, http.StatusOK, struct {
		Sessions  []sessionMeta `json:"sessions"`
		Truncated bool          `json:"truncated"`
	}{metas, truncated})
}

// handleReadSession returns one session's listing fields and its newest turns.
// The body is the MCP session resource, so both transports bound a read the
// same way: at most sessionResourceMaxBytes, keeping the newest turns, with
// "trimmed": true in the body when anything was dropped or cut. A malformed id
// is 400 and an id that names nothing is 404.
//
// A session with no transcript yet reads as 200 with no turns rather than 404.
// The transcript is written by the first turn, so an id this server created, or
// one the listing carries, names a session that exists and has nothing in it; a
// client that creates a session and reads it back would otherwise have to treat
// 404 as "it may exist".
func (s *serveServer) handleReadSession(w http.ResponseWriter, r *http.Request) {
	if !s.sessionReadsAllowed(w) {
		return
	}
	id, err := serveSessionIDFromPath(r.URL.Path)
	if err != nil {
		serveRefuse(w, http.StatusBadRequest, "invalid session id")
		return
	}
	payload, err := mcpSessionResource(id)
	switch {
	case errors.Is(err, errSessionNotFound) && s.sessionExistsEmpty(id):
		serveWriteJSON(w, http.StatusOK, serveEmptySessionBody(id))
	case errors.Is(err, errSessionNotFound):
		serveRefuse(w, http.StatusNotFound, "session not found")
	case err != nil:
		serveRefuse(w, http.StatusInternalServerError, "the session could not be read")
	default:
		serveWriteJSON(w, http.StatusOK, json.RawMessage(payload))
	}
}

// sessionExistsEmpty reports whether an id with no transcript names a session
// that exists: one this server created, or one the listing carries because
// another surface opened it. An id that names neither is reported as missing.
func (s *serveServer) sessionExistsEmpty(id string) bool {
	if s.owned.has(id) {
		return true
	}
	metas, err := listSessions()
	if err != nil {
		return false
	}
	return slices.ContainsFunc(metas, func(m sessionMeta) bool { return m.ID == id })
}

// serveEmptySessionBody is the read body for a session with nothing in it. The
// keys are mcpSessionResource's, less the ones only a turn supplies: no title,
// no model, no "trimmed", a zero count and an empty turn list.
func serveEmptySessionBody(id string) any {
	return struct {
		ID       string        `json:"id"`
		MsgCount int           `json:"msg_count"`
		Turns    []sessionTurn `json:"turns"`
	}{ID: id, Turns: []sessionTurn{}}
}
