package main

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	eng "blkchain/cli/internal/engagement"
)

func testArmTask() eng.Task {
	return eng.Task{ID: "t2", Kind: "web", Objective: "SQLi on /login", Phase: eng.PhaseExploit, Surface: eng.SurfaceWeb}
}

// y/n/esc resolve the three arm decisions; the picker never writes the reply
// channel itself (the base Update does).
func TestArmPickerKeysResolve(t *testing.T) {
	reply := make(chan ArmDecision, 1)
	var ov overlayModel = newArmPicker(testArmTask(), reply)
	for _, tc := range []struct {
		key  string
		want ArmDecision
	}{{"y", ArmApprove}, {"n", ArmSkip}} {
		_, cmd := ov.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tc.key)})
		if msg, ok := cmd().(armResolvedMsg); !ok || msg.res != tc.want || msg.reply != reply {
			t.Fatalf("key %q resolved %#v; want %v", tc.key, cmd(), tc.want)
		}
	}
	_, cmd := ov.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if msg, ok := cmd().(armResolvedMsg); !ok || msg.res != ArmStop {
		t.Fatalf("esc should resolve ArmStop, got %#v", cmd())
	}
	if len(reply) != 0 {
		t.Fatalf("the picker must not send on the reply channel")
	}
}

func TestArmMsgOpensOverlayAndReplies(t *testing.T) {
	m := newTestModel(t)
	reply := make(chan ArmDecision, 1)
	nm, _ := m.Update(armMsg{task: testArmTask(), reply: reply})
	m = nm.(model)
	if _, ok := m.overlay.(armPicker); !ok {
		t.Fatalf("armMsg should open the arm picker, got %T", m.overlay)
	}
	if len(m.footerKeys().short) == 0 {
		t.Fatalf("the arm overlay needs footer hints")
	}
	nm, cmd := m.Update(armResolvedMsg{res: ArmApprove, reply: reply})
	m = nm.(model)
	if m.overlay != nil {
		t.Fatalf("resolving should clear the overlay")
	}
	drainCmd(cmd)
	select {
	case got := <-reply:
		if got != ArmApprove {
			t.Fatalf("reply = %v; want ArmApprove", got)
		}
	default:
		t.Fatalf("resolving should send the decision on the reply channel")
	}
}

// A displaced arm request (a new one before the old is answered) fails safe: the
// old reply gets ArmSkip.
func TestArmDisplacedRepliesSkip(t *testing.T) {
	m := newTestModel(t)
	replyA := make(chan ArmDecision, 1)
	replyB := make(chan ArmDecision, 1)
	nm, _ := m.Update(armMsg{task: testArmTask(), reply: replyA})
	m = nm.(model)
	nm, cmd := m.Update(armMsg{task: testArmTask(), reply: replyB})
	m = nm.(model)
	if cmd == nil {
		t.Fatalf("displacing an arm request should answer the old one")
	}
	cmd()
	select {
	case got := <-replyA:
		if got != ArmSkip {
			t.Fatalf("displaced arm reply = %v; want ArmSkip (fail-safe)", got)
		}
	default:
		t.Fatalf("the displaced arm request was not answered")
	}
	if p, ok := m.overlay.(armPicker); !ok || p.reply != replyB {
		t.Fatalf("overlay should be the new arm picker, got %T", m.overlay)
	}
}

// ArmStop both answers the request and cancels the running engagement turn.
func TestArmStopCancelsTurn(t *testing.T) {
	m := newTestModel(t)
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	reply := make(chan ArmDecision, 1)
	nm, cmd := m.Update(armResolvedMsg{res: ArmStop, reply: reply})
	m = nm.(model)
	drainCmd(cmd)
	select {
	case <-ctx.Done():
	default:
		t.Fatalf("ArmStop should cancel the engagement turn")
	}
	select {
	case got := <-reply:
		if got != ArmStop {
			t.Fatalf("reply = %v; want ArmStop", got)
		}
	default:
		t.Fatalf("ArmStop should still answer the reply channel")
	}
}

func TestWidgetArmRequesterBridgesProg(t *testing.T) {
	fp := &fakeProg{got: make(chan tea.Msg, 1)}
	w := widgetArmRequester{prog: fp}
	done := make(chan ArmDecision, 1)
	go func() { done <- w.RequestArm(context.Background(), testArmTask()) }()
	msg := (<-fp.got).(armMsg)
	if msg.task.ID != "t2" {
		t.Fatalf("RequestArm posted the wrong task: %+v", msg.task)
	}
	msg.reply <- ArmApprove
	if got := <-done; got != ArmApprove {
		t.Fatalf("RequestArm returned %v; want the injected ArmApprove", got)
	}

	// A canceled context fails safe (ArmSkip).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	go func() { done <- w.RequestArm(ctx, testArmTask()) }()
	<-fp.got
	if got := <-done; got != ArmSkip {
		t.Fatalf("a canceled context should fail safe to ArmSkip, got %v", got)
	}

	// A nil program fails safe without blocking.
	if got := (widgetArmRequester{}).RequestArm(context.Background(), testArmTask()); got != ArmSkip {
		t.Fatalf("a nil prog should fail safe to ArmSkip, got %v", got)
	}
}

func TestArmPickerView(t *testing.T) {
	noColor(t)
	out := newArmPicker(testArmTask(), make(chan ArmDecision, 1)).View(80, 24)
	for _, w := range []string{"arm", "SQLi on /login"} {
		if !strings.Contains(out, w) {
			t.Fatalf("arm view missing %q:\n%s", w, out)
		}
	}
}

// The TUI's widget ArmRequester wires through SetReplArmRequester so runReplEngage
// can read it onto deps.ArmReq.
func TestSetReplArmRequesterWiring(t *testing.T) {
	fp := &fakeProg{got: make(chan tea.Msg, 1)}
	SetReplArmRequester(widgetArmRequester{prog: fp})
	t.Cleanup(func() { SetReplArmRequester(nil) })
	if _, ok := replArmReq().(widgetArmRequester); !ok {
		t.Fatalf("SetReplArmRequester should install the widget ArmRequester, got %T", replArmReq())
	}
}
