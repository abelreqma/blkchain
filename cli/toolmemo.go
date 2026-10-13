package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
)

const (
	// toolMemoMaxArgBytes caps the argument bytes that enter one memo key. A
	// longer argument is keyed by the digest of its first toolMemoMaxArgBytes
	// bytes together with its total length, so two long arguments sharing a
	// prefix do not collide on the prefix alone.
	toolMemoMaxArgBytes = 1 << 20
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
// A lookup matches only a result recorded by an earlier attempt, and consumes
// it, so the nth identical call of a replay matches the nth identical call of
// the attempt that ran them. Two identical calls inside one attempt both run: a
// deliberate repeat is not a replay, and answering it from memory would
// manufacture a false "nothing changed".
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

// lookup returns the oldest result recorded for key by an earlier attempt and
// consumes it.
func (t *toolMemo) lookup(key string) (string, bool) {
	if t == nil {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entries := t.done[key]
	for i, e := range entries {
		if e.attempt >= t.attempt {
			continue
		}
		t.done[key] = append(entries[:i:i], entries[i+1:]...)
		t.count--
		t.bytes -= len(e.result)
		return e.result, true
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

// toolCallKey is the memo key for one call: the tool name and a digest of its
// canonicalized arguments. JSON arguments are round-tripped through
// encoding/json, which sorts object keys at every depth, so key order and
// whitespace do not change the key while a changed value does. Arguments that
// are not JSON are digested as received.
func toolCallKey(name, args string) string {
	raw := []byte(args)
	var v any
	if json.Unmarshal(raw, &v) == nil {
		if b, err := json.Marshal(v); err == nil {
			raw = b
		}
	}
	h := sha256.New()
	fmt.Fprintf(h, "%d:", len(raw))
	if len(raw) > toolMemoMaxArgBytes {
		raw = raw[:toolMemoMaxArgBytes]
	}
	h.Write(raw)
	return name + "\x00" + hex.EncodeToString(h.Sum(nil))
}
