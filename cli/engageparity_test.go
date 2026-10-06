package main

import (
	"blkchain/cli/internal/askuser"
	eng "blkchain/cli/internal/engagement"
	"blkchain/cli/internal/ragconfig"
	"blkchain/cli/internal/secgate"
	"blkchain/cli/internal/skillcat"
	"context"
	"database/sql"
	"os"
	"reflect"
	"testing"
)

func TestRoEInteractiveDefaultsAuto(t *testing.T) {
	isolateUserDirs(t)
	m := initialModel()
	if m.hist != nil {
		defer m.hist.Close()
	}
	if m.rc != nil {
		defer m.rc.Close()
	}
	if m.engageMode != secgate.Auto {
		t.Fatal("interactive default still requires HITL")
	}
}

func TestRoEAutoBypassesGuidedIntake(t *testing.T) {
	stubRunReplEngage(t, func(context.Context, string, string, secgate.Mode, bool, toolLoopModel, searcher, ragconfig.Config, modelPrefs, *skillcat.Catalog, secgate.Confirmer, askuser.Asker, *sql.DB, string, func(int64, eng.Engagement)) (string, error) {
		return "complete", nil
	})
	m := engageReadyModel(t)
	m.engageMode = secgate.Auto
	next, _ := m.dispatchInput("/engage assess my configured scope")
	got := next.(model)
	if !got.working || got.engageIntake != nil {
		t.Fatal("auto opened guided human intake")
	}
}

func TestRoEAutoDoesNotConstructConfirmer(t *testing.T) {
	m := engageReadyModel(t)
	m.engageMode = secgate.Auto
	run, err := m.buildReplEngageRun("assess the lab")
	if err != nil {
		t.Fatal(err)
	}
	if run.confirm != nil {
		t.Fatal("auto constructed a human confirmation channel")
	}
}

func TestRoETranscriptDispatch(t *testing.T) {
	m := newTestModel(t)
	next, _ := m.dispatchInput("/transcript full")
	if next.(model).engageTranscript != "full" {
		t.Fatal("transcript command did not change session output")
	}
}

func TestPlainREPLTranscriptReachesEngageDispatch(t *testing.T) {
	isolateUserDirs(t)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldInput := os.Stdin
	os.Stdin = read
	t.Cleanup(func() { os.Stdin = oldInput; read.Close() })
	if _, err := write.WriteString("/transcript full\n/engage inspect lab\n/quit\n"); err != nil {
		t.Fatal(err)
	}
	write.Close()
	oldRun := runPlainEngage
	var called []string
	runPlainEngage = func(args []string) error {
		called = append([]string(nil), args...)
		return nil
	}
	t.Cleanup(func() { runPlainEngage = oldRun })
	if err := plainREPL(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"--transcript", "full", "inspect", "lab"}; !reflect.DeepEqual(called, want) {
		t.Fatalf("engage args = %v, want %v", called, want)
	}
}

func TestTUITranscriptReachesEngageExecution(t *testing.T) {
	m := engageReadyModel(t)
	next, _ := m.dispatchInput("/transcript full")
	m = next.(model)
	run, err := m.buildReplEngageRun("assess 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	run.ctx = context.Background()
	var displayed bool
	run.onAction = func(actionRecord) { displayed = true }
	stubRunReplEngage(t, func(ctx context.Context, _ string, _ string, _ secgate.Mode, _ bool, _ toolLoopModel, _ searcher, _ ragconfig.Config, _ modelPrefs, _ *skillcat.Catalog, _ secgate.Confirmer, _ askuser.Asker, _ *sql.DB, _ string, _ func(int64, eng.Engagement)) (string, error) {
		mode, _ := ctx.Value(replTranscriptKey{}).(string)
		callback, _ := ctx.Value(replActionKey{}).(func(actionRecord))
		if mode != "full" || callback == nil {
			t.Fatalf("TUI setting did not reach execution: mode=%q callback_missing=%t", mode, callback == nil)
		}
		callback(actionRecord{Status: "complete"})
		return "done", nil
	})
	if _, ok := engageCmd(run)().(engageDoneMsg); !ok || !displayed {
		t.Fatal("TUI action output did not reach the operator callback")
	}
}
