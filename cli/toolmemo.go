package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
)

const (
	// toolMemoMaxEntries caps the recorded calls one memo holds.
	toolMemoMaxEntries = 64
	// toolMemoMaxBytes caps the result bytes one memo holds.
	toolMemoMaxBytes = 4 << 20
)

// toolMemo holds the results of tool calls that ran to completion in earlier
// attempts of one turn's tool loop, so a failover that restarts the loop
// replays those results instead of running the tools again. An nmap run, a
// proxied request or a terminal command therefore executes once per turn even
// when the model that drove it is replaced mid-turn.
//
// A lookup matches only a result recorded by an earlier attempt and re-stamps
// it to the current attempt in place, so the nth identical call of a replay
// matches the nth identical call of the attempt that ran them, in the same order
// on every later attempt. A re-stamped entry is not matched again in the same
// attempt, and a repeat beyond the recorded count runs the tool. Two identical
// calls inside one attempt both run: a deliberate repeat is not a replay, and
// answering it from memory would manufacture a false "nothing changed".
//
// Scope is one turn in one process. Nothing here is persisted and nothing is
// consulted on a later turn: a stored result would otherwise stand in for an
// action the turn's own scope gate has not approved.
type toolMemo struct {
	mu      sync.Mutex
	attempt int
	done    map[string][]memoEntry
	count   int
	bytes   int
}

// memoEntry is one recorded result and the attempt that recorded it.
type memoEntry struct {
	attempt int
	result  string
}

func newToolMemo() *toolMemo { return &toolMemo{done: map[string][]memoEntry{}} }

// beginAttempt starts the next attempt of the turn's tool loop. Results
// recorded by any earlier attempt become replayable.
func (t *toolMemo) beginAttempt() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.attempt++
	t.mu.Unlock()
}

// lookup returns the first result recorded for key by an earlier attempt and
// stamps that entry with the current attempt, leaving its position, the entry
// count and the byte count unchanged.
func (t *toolMemo) lookup(key string) (string, bool) {
	if t == nil {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entries := t.done[key]
	for i := range entries {
		if entries[i].attempt >= t.attempt {
			continue
		}
		entries[i].attempt = t.attempt
		return entries[i].result, true
	}
	return "", false
}

// record stores the result of a call that ran to completion, stamped with the
// current attempt. Past either bound it records nothing, so a later replay runs
// that call again rather than letting the memo grow without limit.
func (t *toolMemo) record(key, result string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.count >= toolMemoMaxEntries || t.bytes+len(result) > toolMemoMaxBytes {
		return
	}
	t.done[key] = append(t.done[key], memoEntry{attempt: t.attempt, result: result})
	t.count++
	t.bytes += len(result)
}

// toolCallKey is the memo key for one call: the tool name and a SHA-256 digest
// of its whole canonicalized arguments. JSON arguments are decoded with numbers
// kept as their literal text and re-encoded, which sorts object keys at every
// depth, so key order and whitespace do not change the key while a changed value
// does, including an integer beyond float64 precision. Arguments that are not
// JSON are digested as received.
//
// The digest covers every byte of the canonical form. Truncating it would let
// two long arguments sharing a prefix collide, and would save nothing: decoding
// and re-encoding materialize the whole argument regardless, and the argument
// itself arrives inside a model response whose body llmTransport caps at
// llmMaxBodyBytes.
//
// json.Marshal replaces invalid UTF-8 inside a string with U+FFFD, so two
// arguments that differ only in invalid UTF-8 bytes share a key. That is
// accepted: tool arguments arrive from the model as JSON, and such a string is
// already malformed.
func toolCallKey(name, args string) string {
	raw := []byte(args)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) == nil {
		if _, err := dec.Token(); err == io.EOF {
			if b, err := json.Marshal(v); err == nil {
				raw = b
			}
		}
	}
	sum := sha256.Sum256(raw)
	return name + "\x00" + hex.EncodeToString(sum[:])
}
