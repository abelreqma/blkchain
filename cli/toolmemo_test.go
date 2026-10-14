package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"blkchain/cli/internal/tooldef"

	"github.com/tmc/langchaingo/llms"
)

// runToolLoopAttempt starts a new memo attempt and runs one tool loop under it,
// which is what a failover does for each model in the chain.
func runToolLoopAttempt(ctx context.Context, m toolLoopModel, reg *tooldef.Registry, msgs []llms.MessageContent, caps LoopCaps, memo *toolMemo) (string, int, error) {
	memo.beginAttempt()
	return runToolLoop(ctx, m, reg, msgs, caps)
}

func TestToolCallKeyIgnoresArgumentFormattingButNotArgumentValues(t *testing.T) {
	a := toolCallKey("run_command", `{"cmd":"id","host":"a"}`)
	b := toolCallKey("run_command", "{ \"host\" : \"a\",\n  \"cmd\": \"id\" }")
	if a != b {
		t.Error("the same arguments in a different key order and spacing produced different keys")
	}
	if c := toolCallKey("run_command", `{"cmd":"id","host":"b"}`); c == a {
		t.Error("different argument values produced the same key")
	}
	if d := toolCallKey("web_api", `{"cmd":"id","host":"a"}`); d == a {
		t.Error("a different tool with the same arguments produced the same key")
	}
	if e := toolCallKey("run_command", "not json at all"); e == a {
		t.Error("arguments that are not JSON collided with JSON arguments")
	}
}

func TestToolCallKeyDistinguishesLongArguments(t *testing.T) {
	base := strings.Repeat("x", 1<<20+16)
	if toolCallKey("t", base) == toolCallKey("t", base+"y") {
		t.Error("two long arguments of different length produced the same key")
	}
	// Same length, same first megabyte, differing only in the last byte.
	a := strings.Repeat("x", 2<<20) + "a"
	b := strings.Repeat("x", 2<<20) + "b"
	if toolCallKey("t", a) == toolCallKey("t", b) {
		t.Error("two long arguments differing only in their last byte produced the same key")
	}
	ja := `{"v":"` + strings.Repeat("x", 2<<20) + `a"}`
	jb := `{"v":"` + strings.Repeat("x", 2<<20) + `b"}`
	if toolCallKey("t", ja) == toolCallKey("t", jb) {
		t.Error("two long JSON arguments differing only in their last byte produced the same key")
	}
}

func TestToolCallKeyKeepsLargeIntegersExact(t *testing.T) {
	a := toolCallKey("t", `{"n":9007199254740992}`)
	b := toolCallKey("t", `{"n":9007199254740993}`)
	if a == b {
		t.Error("two integers beyond float64 precision produced the same key")
	}
	if c := toolCallKey("t", "{ \"n\" :  9007199254740992 }"); c != a {
		t.Error("the same integer with different spacing produced a different key")
	}
}

func TestToolCallKeySortsNestedObjectKeys(t *testing.T) {
	a := toolCallKey("t", `{"a":{"y":1,"x":[{"q":1,"p":2}]},"b":3}`)
	b := toolCallKey("t", `{"b":3,"a":{"x":[{"p":2,"q":1}],"y":1}}`)
	if a != b {
		t.Error("nested object key order changed the key")
	}
}

func TestToolMemoDoesNotAnswerARepeatInsideOneAttempt(t *testing.T) {
	// A target polled twice in one turn must be contacted twice. Answering the
	// second call from the first one's result manufactures a false "nothing
	// changed".
	m := newToolMemo()
	m.beginAttempt()
	key := toolCallKey("run_command", `{"cmd":"id"}`)
	m.record(key, "uid=0")
	if _, hit := m.lookup(key); hit {
		t.Error("a call recorded in this attempt was replayed inside the same attempt")
	}
}

func TestToolMemoReplaysEachRecordedCallOnceOnTheNextAttempt(t *testing.T) {
	m := newToolMemo()
	m.beginAttempt()
	key := toolCallKey("run_command", `{"cmd":"id"}`)
	m.record(key, "uid=0")
	m.beginAttempt()
	got, hit := m.lookup(key)
	if !hit || got != "uid=0" {
		t.Fatalf("replay: got %q hit=%v want %q true", got, hit, "uid=0")
	}
	if _, hit := m.lookup(key); hit {
		t.Error("the same recorded call replayed twice in one attempt")
	}
}

func TestToolMemoReplaysInCallOrder(t *testing.T) {
	m := newToolMemo()
	m.beginAttempt()
	key := toolCallKey("run_command", `{"cmd":"date"}`)
	m.record(key, "first")
	m.record(key, "second")
	m.beginAttempt()
	a, _ := m.lookup(key)
	b, _ := m.lookup(key)
	if a != "first" || b != "second" {
		t.Errorf("replay order: got %q then %q want %q then %q", a, b, "first", "second")
	}
}

func TestToolMemoKeepsReplayOrderAcrossAttempts(t *testing.T) {
	m := newToolMemo()
	m.beginAttempt()
	key := toolCallKey("run_command", `{"cmd":"date"}`)
	m.record(key, "first")
	m.record(key, "second")
	m.beginAttempt()
	if got, hit := m.lookup(key); !hit || got != "first" {
		t.Fatalf("attempt 2 first replay: got %q hit=%v want %q true", got, hit, "first")
	}
	m.beginAttempt()
	if got, _ := m.lookup(key); got != "first" {
		t.Errorf("attempt 3 first replay: got %q want %q", got, "first")
	}
	if got, _ := m.lookup(key); got != "second" {
		t.Errorf("attempt 3 second replay: got %q want %q", got, "second")
	}
}

func TestToolMemoHitDoesNotChangeWhatItHolds(t *testing.T) {
	m := newToolMemo()
	m.beginAttempt()
	key := toolCallKey("t", "{}")
	m.record(key, "abc")
	count, size := m.count, m.bytes
	m.beginAttempt()
	if _, hit := m.lookup(key); !hit {
		t.Fatal("no replay")
	}
	if m.count != count || m.bytes != size {
		t.Errorf("a hit changed the accounting: count %d->%d bytes %d->%d", count, m.count, size, m.bytes)
	}
}

func TestToolMemoBoundsWhatItHolds(t *testing.T) {
	m := newToolMemo()
	m.beginAttempt()
	for i := 0; i < toolMemoMaxEntries+8; i++ {
		m.record(toolCallKey("t", `{"i":`+string(rune('0'+i%10))+`}`), "r")
	}
	if m.count > toolMemoMaxEntries {
		t.Errorf("entry count: got %d want at most %d", m.count, toolMemoMaxEntries)
	}
	big := newToolMemo()
	big.beginAttempt()
	big.record(toolCallKey("t", "{}"), strings.Repeat("y", toolMemoMaxBytes+1))
	if big.count != 0 {
		t.Errorf("a result past the byte cap was recorded: count=%d", big.count)
	}
}

// callThenAnswer scripts a model that requests the tool "t" once and then
// answers.
func callThenAnswer() *fakeModel {
	return &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "t", "{}"), textResp("done")}}
}

func okTool() *fakeTool {
	return &fakeTool{name: "t", fn: func(string) (string, error) { return "ran", nil }}
}

func TestToolLoopWithNoMemoRunsEveryCall(t *testing.T) {
	// A nil memo is the default, so the engagement executors that pass none
	// behave exactly as they do today.
	tool := okTool()
	m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "t", "{}"), callResp("c2", "t", "{}"), textResp("done")}}
	if _, _, err := runToolLoop(context.Background(), m, newLoopReg(t, tool), userMsgs(), LoopCaps{MaxRounds: 5, MaxCalls: 5}); err != nil {
		t.Fatalf("runToolLoop: %v", err)
	}
	if len(tool.ran) != 2 {
		t.Errorf("tool ran %d times, want 2", len(tool.ran))
	}
}

func TestToolLoopWithNoMemoCountsCallsPerLoop(t *testing.T) {
	// Each engagement executor loop is its own step and passes no memo, so it
	// spends its own cap and the cap message counts that loop's calls.
	tool := okTool()
	reg := newLoopReg(t, tool)
	caps := LoopCaps{MaxRounds: 4, MaxCalls: 2}
	for i := 0; i < 2; i++ {
		m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "t", `{"n":1}`), callResp("c2", "t", `{"n":2}`), textResp("done")}}
		final, _, err := runToolLoop(context.Background(), m, reg, userMsgs(), caps)
		if err != nil {
			t.Fatalf("loop %d: %v", i, err)
		}
		if !strings.Contains(final, "tool call cap reached (2 calls)") {
			t.Errorf("loop %d final = %q, want its own cap reached at 2 calls", i, final)
		}
	}
	if len(tool.ran) != 4 {
		t.Errorf("tool ran %d times across two loops, want 4", len(tool.ran))
	}
}

func TestToolLoopRunsARepeatInsideOneAttemptWithAMemo(t *testing.T) {
	tool := okTool()
	memo := newToolMemo()
	caps := LoopCaps{MaxRounds: 5, MaxCalls: 5, ToolMemo: memo}
	m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "t", "{}"), callResp("c2", "t", "{}"), textResp("done")}}
	if _, _, err := runToolLoopAttempt(context.Background(), m, newLoopReg(t, tool), userMsgs(), caps, memo); err != nil {
		t.Fatalf("attempt: %v", err)
	}
	if len(tool.ran) != 2 {
		t.Errorf("tool ran %d times for two identical calls in one attempt, want 2", len(tool.ran))
	}
}

func TestToolLoopReplaysACompletedCallInsteadOfRunningItAgain(t *testing.T) {
	tool := okTool()
	reg := newLoopReg(t, tool)
	memo := newToolMemo()
	caps := LoopCaps{MaxRounds: 5, MaxCalls: 5, ToolMemo: memo}
	if _, _, err := runToolLoopAttempt(context.Background(), callThenAnswer(), reg, userMsgs(), caps, memo); err != nil {
		t.Fatalf("first attempt: %v", err)
	}
	second := callThenAnswer()
	if _, _, err := runToolLoopAttempt(context.Background(), second, reg, userMsgs(), caps, memo); err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	if len(tool.ran) != 1 {
		t.Errorf("tool ran %d times across two attempts, want 1", len(tool.ran))
	}
	got := toolResults(second)
	if len(got) != 1 || got[0].Content != "ran" {
		t.Errorf("replayed result fed to the model: %+v", got)
	}
}

func TestToolLoopReplaysAgainOnAThirdAttempt(t *testing.T) {
	tool := okTool()
	reg := newLoopReg(t, tool)
	memo := newToolMemo()
	caps := LoopCaps{MaxRounds: 5, MaxCalls: 5, ToolMemo: memo}
	for i := 0; i < 3; i++ {
		if _, _, err := runToolLoopAttempt(context.Background(), callThenAnswer(), reg, userMsgs(), caps, memo); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if len(tool.ran) != 1 {
		t.Errorf("tool ran %d times across three attempts, want 1", len(tool.ran))
	}
}

func TestToolLoopKeepsReplayOrderAcrossThreeAttempts(t *testing.T) {
	n := 0
	tool := &fakeTool{name: "t", fn: func(string) (string, error) {
		n++
		return "r" + string(rune('0'+n)), nil
	}}
	reg := newLoopReg(t, tool)
	memo := newToolMemo()
	caps := LoopCaps{MaxRounds: 5, MaxCalls: 5, ToolMemo: memo}
	twice := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", "t", "{}"), callResp("c2", "t", "{}"), textResp("done")}}
	if _, _, err := runToolLoopAttempt(context.Background(), twice, reg, userMsgs(), caps, memo); err != nil {
		t.Fatal(err)
	}
	for attempt := 2; attempt <= 3; attempt++ {
		once := callThenAnswer()
		if _, _, err := runToolLoopAttempt(context.Background(), once, reg, userMsgs(), caps, memo); err != nil {
			t.Fatal(err)
		}
		got := toolResults(once)
		if len(got) != 1 || got[0].Content != "r1" {
			t.Errorf("attempt %d first replay: %+v want r1", attempt, got)
		}
	}
	if len(tool.ran) != 2 {
		t.Errorf("tool ran %d times, want 2", len(tool.ran))
	}
}

func TestToolLoopDoesNotReplayAFailedCall(t *testing.T) {
	// A failed call was attempted and may have had a side effect before it
	// errored, and its result is an error string, not an answer. It is not a
	// result to stand in for a later call.
	tool := &fakeTool{name: "t", fn: func(string) (string, error) { return "", errors.New("some tool failure") }}
	reg := newLoopReg(t, tool)
	memo := newToolMemo()
	caps := LoopCaps{MaxRounds: 5, MaxCalls: 5, ToolMemo: memo}
	for i := 0; i < 2; i++ {
		if _, _, err := runToolLoopAttempt(context.Background(), callThenAnswer(), reg, userMsgs(), caps, memo); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if len(tool.ran) != 2 {
		t.Errorf("a failed tool ran %d times across two attempts, want 2", len(tool.ran))
	}
}

func TestToolLoopReplayStillFiresAuditCallbacksInOrder(t *testing.T) {
	tool := okTool()
	reg := newLoopReg(t, tool)
	memo := newToolMemo()
	var seen []string
	caps := LoopCaps{
		MaxRounds: 5, MaxCalls: 5, ToolMemo: memo,
		Observe: func(action, detail string) error {
			seen = append(seen, action+":"+detail)
			return nil
		},
		ObserveResult: func(name string, outcome ToolOutcome) {
			seen = append(seen, "outcome:"+name+"="+string(outcome))
		},
	}
	if _, _, err := runToolLoopAttempt(context.Background(), callThenAnswer(), reg, userMsgs(), caps, memo); err != nil {
		t.Fatal(err)
	}
	first := strings.Join(seen, "|")
	seen = nil
	if _, _, err := runToolLoopAttempt(context.Background(), callThenAnswer(), reg, userMsgs(), caps, memo); err != nil {
		t.Fatal(err)
	}
	if len(tool.ran) != 1 {
		t.Fatalf("tool ran %d times, want 1", len(tool.ran))
	}
	want := "model-tools:round=1 calls=1|tool-call:t|outcome:t=done|tool-result:t|model-final:round=2"
	if got := strings.Join(seen, "|"); got != want || got != first {
		t.Errorf("replay observed %q, original %q, want %q", got, first, want)
	}
}

func TestToolLoopReplayStillSpendsACallSlot(t *testing.T) {
	reg := newLoopReg(t, okTool())
	memo := newToolMemo()
	caps := LoopCaps{MaxRounds: 5, MaxCalls: 1, ToolMemo: memo}
	if _, _, err := runToolLoopAttempt(context.Background(), callThenAnswer(), reg, userMsgs(), caps, memo); err != nil {
		t.Fatal(err)
	}
	final, _, err := runToolLoopAttempt(context.Background(), callThenAnswer(), reg, userMsgs(), caps, memo)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(final, "tool call cap reached") {
		t.Errorf("a replayed call did not count against the call cap: final=%q", final)
	}
}

// TestToolLoopRunsAPollAgainOnTheNextAttempt pins that a call whose result is a
// reading of state that keeps changing is run again after a failover rather
// than replayed. oob_interactions reports callbacks that may have arrived since
// the first attempt polled, and process_manage's list, poll, log and wait read a
// process that kept running, so a replay would answer with the earlier reading
// as if it were current. process_manage's write and kill act on the process, so
// they are replayed like any other completed call: running them again would
// send the input twice.
func TestToolLoopRunsAPollAgainOnTheNextAttempt(t *testing.T) {
	for _, c := range []struct {
		tool, args string
		runs       int
	}{
		{"oob_interactions", `{}`, 2},
		{"process_manage", `{"action":"list"}`, 2},
		{"process_manage", `{"action":"poll","session_id":"p1"}`, 2},
		{"process_manage", `{"action":"log","session_id":"p1"}`, 2},
		{"process_manage", `{"action":"wait","session_id":"p1"}`, 2},
		{"process_manage", `{"action":"write","session_id":"p1","data":"y\n"}`, 1},
		{"process_manage", `{"action":"kill","session_id":"p1"}`, 1},
		{"process_manage", `not json`, 1},
		{"terminal", `{"command":"id"}`, 1},
	} {
		tool := &fakeTool{name: c.tool, fn: func(string) (string, error) { return "reading", nil }}
		reg := newLoopReg(t, tool)
		memo := newToolMemo()
		caps := LoopCaps{MaxRounds: 5, MaxCalls: 5, ToolMemo: memo}
		for i := 0; i < 2; i++ {
			m := &fakeModel{queue: []*llms.ContentResponse{callResp("c1", c.tool, c.args), textResp("done")}}
			if _, _, err := runToolLoopAttempt(context.Background(), m, reg, userMsgs(), caps, memo); err != nil {
				t.Fatalf("%s %s attempt %d: %v", c.tool, c.args, i, err)
			}
		}
		if len(tool.ran) != c.runs {
			t.Errorf("%s %s ran %d times across two attempts, want %d", c.tool, c.args, len(tool.ran), c.runs)
		}
	}
}
